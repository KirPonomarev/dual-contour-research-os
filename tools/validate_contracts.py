#!/usr/bin/env python3
"""Fail-closed validation for the Stage 0A contract freeze."""

from __future__ import annotations

import json
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
