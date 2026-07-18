#!/usr/bin/env python3
"""Fail-closed validation for the Stage 0A contract freeze."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "contracts" / "catalog.json"
OWNERSHIP = ROOT / "ownership" / "registry.json"

REQUIRED_CONTRACTS = {
    "SourceEnvelope",
    "ModelCallEnvelope",
    "HypothesisCard",
    "ProtocolSnapshot",
    "JobSpec",
    "PolicySnapshot",
    "Permit",
    "ApprovalReceipt",
    "AttemptLease",
    "CheckpointManifest",
    "StagingEnvelope",
    "ArtifactManifest",
    "ExecutionReceipt",
    "ValidationReceipt",
    "HoldoutAccessGrant",
    "HoldoutAccessReceipt",
    "BudgetReservation",
    "SettlementReceipt",
    "DomainTrialLinkReceipt",
    "DomainArtifactReceipt",
    "ReplicationReceipt",
    "LearningDecision",
    "SourceFreezeReceipt",
    "ReuseDecisionReceipt",
    "IntegrationReceipt",
    "DeploymentApprovalReceipt",
}

_ALLOWED_OWNERS = {f"agent-{index}" for index in range(6)}


def _path_pattern_regex(pattern: str) -> re.Pattern[str]:
    """Compile the repository's small, slash-aware ownership glob language."""

    if (
        not pattern
        or pattern.startswith("/")
        or "\\" in pattern
        or any(part in {"", ".", ".."} for part in pattern.split("/"))
    ):
        raise ValueError(f"unsafe ownership pattern:{pattern}")
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*\*", ".*")
    escaped = escaped.replace(r"\*", "[^/]*")
    escaped = escaped.replace(r"\?", "[^/]")
    return re.compile(f"^{escaped}$")


def _pattern_matches(pattern: str, path: str) -> bool:
    return _path_pattern_regex(pattern).fullmatch(path) is not None


def live_repository_paths() -> tuple[str, ...]:
    """Return tracked and visible untracked paths, excluding ignored runtime data."""

    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return tuple(sorted(path for path in result.stdout.decode().split("\0") if path))


def ownership_failures(ownership: dict, live_paths: tuple[str, ...]) -> list[str]:
    """Return deterministic fail-closed ownership registry violations."""

    failures: list[str] = []
    if ownership.get("schema_version") != "1.1.0":
        failures.append("unexpected_ownership_schema_version")
    if ownership.get("frozen") is not True:
        failures.append("ownership_registry_not_frozen")
    if not ownership.get("amendment_ref"):
        failures.append("ownership_amendment_ref_missing")

    canonical = ownership.get("canonical_owners")
    reserved = ownership.get("reserved_future_paths")
    root_only = ownership.get("root_only")
    if not isinstance(canonical, dict) or not canonical:
        failures.append("canonical_owners_missing")
        canonical = {}
    if not isinstance(reserved, dict):
        failures.append("reserved_future_paths_missing")
        reserved = {}
    if not isinstance(root_only, list) or not root_only:
        failures.append("root_only_missing")
        root_only = []

    compiled: dict[str, re.Pattern[str]] = {}
    all_patterns = list(canonical) + list(reserved) + list(root_only)
    for pattern in all_patterns:
        if not isinstance(pattern, str):
            failures.append("ownership_pattern_not_string")
            continue
        if pattern in compiled:
            failures.append(f"duplicate_ownership_pattern:{pattern}")
            continue
        try:
            compiled[pattern] = _path_pattern_regex(pattern)
        except ValueError:
            failures.append(f"unsafe_ownership_pattern:{pattern}")

    for group_name, group in (("canonical", canonical), ("reserved", reserved)):
        for pattern, owner in group.items():
            if owner not in _ALLOWED_OWNERS:
                failures.append(f"invalid_{group_name}_owner:{pattern}:{owner}")

    for pattern in canonical:
        regex = compiled.get(pattern)
        if regex is not None and not any(regex.fullmatch(path) for path in live_paths):
            failures.append(f"canonical_pattern_matches_no_live_path:{pattern}")

    for pattern in reserved:
        regex = compiled.get(pattern)
        if regex is not None and any(regex.fullmatch(path) for path in live_paths):
            failures.append(f"reserved_path_is_live:{pattern}")

    for path in live_paths:
        matches = [
            pattern
            for pattern in list(canonical) + list(root_only)
            if pattern in compiled and compiled[pattern].fullmatch(path)
        ]
        if not matches:
            failures.append(f"unowned_live_path:{path}")
        elif len(matches) > 1:
            failures.append(f"ownership_overlap:{path}:{','.join(sorted(matches))}")

    return sorted(set(failures))


def fail(message: str) -> None:
    print(f"contract_validation=FAILED reason={message}")
    raise SystemExit(1)


def main() -> int:
    catalog = json.loads(CATALOG.read_text())
    ownership = json.loads(OWNERSHIP.read_text())
    contracts = catalog.get("contracts", {})

    missing = sorted(REQUIRED_CONTRACTS - contracts.keys())
    if missing:
        fail("missing_contracts:" + ",".join(missing))
    if catalog.get("schema_version") != "1.0.0":
        fail("unexpected_schema_version")
    ownership_errors = ownership_failures(ownership, live_repository_paths())
    if ownership_errors:
        fail(ownership_errors[0])
    if ownership.get("branch_pattern") != "codex/bridge-a<agent-id>-<stage-id>":
        fail("unsafe_branch_pattern")
    if ownership.get("max_active_children") != 3:
        fail("invalid_child_limit")

    for name, spec in contracts.items():
        if not spec.get("owner") or not spec.get("writer") or not spec.get("authority"):
            fail(f"missing_authority_metadata:{name}")
        fields = spec.get("required_payload", {})
        if not fields:
            fail(f"empty_payload_contract:{name}")

    if contracts["ValidationReceipt"]["writer"] != "pinned-validator":
        fail("validator_writer_drift")
    if contracts["ValidationReceipt"]["authority"] != "proposed-outcome-only":
        fail("validator_authority_drift")
    if contracts["DomainTrialLinkReceipt"]["writer"] != "domain-registry-writer":
        fail("domain_writer_drift")
    checkpoint_fields = contracts["CheckpointManifest"]["required_payload"]
    if "payload_stored_in_domain_vault" not in checkpoint_fields:
        fail("checkpoint_vault_boundary_missing")

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "generate_contracts.py"), "--check"],
        cwd=ROOT,
        check=False,
    )
    if result.returncode:
        return result.returncode

    print("contract_validation=GREEN")
    print(f"required_contracts={len(REQUIRED_CONTRACTS)}")
    print(f"catalog_contracts={len(contracts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
