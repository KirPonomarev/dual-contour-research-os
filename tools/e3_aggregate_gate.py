#!/usr/bin/env python3
"""Fail-closed E3 evidence validator for proposal-only evolution capability."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping

from capability_proof import (
    CapabilityProofError,
    canonical_json_sha256,
    validate_capability_proof,
)
from release_currentness import (
    ReleaseCurrentnessError,
    assess_capability_for_release,
    validate_release_currentness_context,
)


SUBJECT_SHA = "26eed42993b11551b94e7c9054fdddf0be87ca64"
SUBJECT_REF = f"git:{SUBJECT_SHA}"
EVIDENCE_FILES = {
    "docs/receipts/integration/s29-gap-genome-assurance.json": "64dba6cc110413f370f4d25189c42c5ae56f24d64ff86885a5fe8447774a57fb",
    "docs/receipts/integration/s30-challenger-assurance.json": "65ac3f85c425b8f8b5a5b2547bc6967560d9032d26feaf28b0b5eeb731acd5be",
    "docs/receipts/integration/s31-shadow-canary-assurance.json": "f41daac8080865091fec60483e5590949ee10d532255e38d8db238534753ebaf",
}
STAGE_IDS = {
    "docs/receipts/integration/s29-gap-genome-assurance.json": "s29-gap-genome-assurance",
    "docs/receipts/integration/s30-challenger-assurance.json": "s30-challenger-assurance",
    "docs/receipts/integration/s31-shadow-canary-assurance.json": "s31-shadow-canary-assurance",
}
CODE_FILES = ("src/research_bridge/evolution.py",)
POLICY_FILES = (
    "provenance/evolution-genome-gap-miner-v1.json",
    "provenance/champion-challenger-evaluation-v1.json",
    "provenance/shadow-canary-evolution-loop-v1.json",
)
FORBIDDEN_TRUE_FLAGS = (
    "autonomous_canonical_mutation", "automatic_promotion", "policy_application",
    "deployment", "live_trading", "live_security_execution",
)


class E3AggregateError(RuntimeError):
    """The frozen E3 evidence does not support the requested claim."""


def _strict_json(raw: bytes, *, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise E3AggregateError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                E3AggregateError(f"{label} contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise E3AggregateError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise E3AggregateError(f"{label} must be an object")
    return value


def _bundle_sha256(root: Path, paths: tuple[str, ...]) -> str:
    try:
        material = {
            path: hashlib.sha256((root / path).read_bytes()).hexdigest()
            for path in paths
        }
    except OSError as exc:
        raise E3AggregateError("missing E3 bundle file") from exc
    return canonical_json_sha256(material)


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def _integration(receipt: Mapping[str, object], stage_id: str) -> dict[str, object]:
    try:
        payload = receipt["payload"]
        integrity = receipt["integrity"]
        assert isinstance(payload, dict) and isinstance(integrity, dict)
        audits = payload["audit_results"]
        assert isinstance(audits, dict)
        if (
            receipt["schema_id"] != "IntegrationReceipt"
            or payload["stage_id"] != stage_id
            or integrity["payload_sha256"] != canonical_json_sha256(payload)
            or audits["contract_gate"] != "green"
            or audits["privacy_secret_scan"] != "green"
            or audits["source_mutation"] is not False
            or audits["grants_authority"] is not False
        ):
            raise E3AggregateError(f"{stage_id} integration gate is not green")
    except (AssertionError, KeyError, TypeError) as exc:
        raise E3AggregateError(f"{stage_id} integration shape mismatch") from exc
    return payload


def validate_e3_evidence(root: Path, *, subject_ref: str = SUBJECT_REF) -> dict[str, object]:
    """Bind exact S29-S31 assurance without creating evolution authority."""

    if not isinstance(subject_ref, str) or not subject_ref.startswith("git:") or len(subject_ref) != 44:
        raise E3AggregateError("aggregate subject is not an exact Git head")
    subject_sha = subject_ref[4:]
    if subject_ref != SUBJECT_REF and not _is_ancestor(root, SUBJECT_SHA, subject_sha):
        raise E3AggregateError("aggregate subject is not a descendant exact head")
    audits: dict[str, dict[str, object]] = {}
    for relative, expected_digest in EVIDENCE_FILES.items():
        try:
            raw = (root / relative).read_bytes()
        except OSError as exc:
            raise E3AggregateError(f"missing E3 evidence: {relative}") from exc
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            raise E3AggregateError(f"E3 evidence digest mismatch: {relative}")
        payload = _integration(_strict_json(raw, label=relative), STAGE_IDS[relative])
        # Stage heads are immutable audit identities and may have been integrated
        # by a reviewed cherry-pick. The signed IntegrationReceipt binds that head
        # to integration_commit_sha; only the latter must be in main ancestry.
        if not _is_ancestor(root, str(payload["integration_commit_sha"]), subject_sha):
            raise E3AggregateError("E3 integration_commit_sha is outside exact-head ancestry")
        audit = payload["audit_results"]
        assert isinstance(audit, dict)
        audits[relative] = audit

    genome = audits["docs/receipts/integration/s29-gap-genome-assurance.json"]
    challenger = audits["docs/receipts/integration/s30-challenger-assurance.json"]
    canary = audits["docs/receipts/integration/s31-shadow-canary-assurance.json"]
    if (
        genome.get("forbidden_and_unknown_kind_park") != "green"
        or genome.get("complete_blast_radius") != "green"
        or genome.get("deny_monotonicity") != "green"
        or genome.get("zero_apply_write_execution_authority") != "green"
    ):
        raise E3AggregateError("genome evidence widens mutation authority")
    if (
        challenger.get("Pareto_tradeoff_not_hidden") != "green"
        or challenger.get("safety_and_known_invalid_veto") != "green"
        or challenger.get("exact_twins_and_bindings") != "green"
        or challenger.get("zero_scalar_promotion_mutation_holdout_authority") != "green"
    ):
        raise E3AggregateError("challenger evidence overclaims uplift")
    if (
        canary.get("scope_report_archive_tamper_denied") != "green"
        or canary.get("maturity_and_capacity") != "green"
        or canary.get("all_regression_dimensions_and_failure") != "green"
        or canary.get("zero_write_execution_promotion_apply_authority") != "green"
    ):
        raise E3AggregateError("shadow canary evidence widens promotion authority")
    if any(audit.get("real_private_data_model_calls_or_external_actions") != 0 for audit in audits.values()):
        raise E3AggregateError("E3 evidence includes an external or private action")

    return {
        "status": "EVOLUTION_E3_SHADOW_PASS_FOR_FROZEN_SCOPE",
        "subject_ref": subject_ref,
        "mutation_proposal_status": "MUTATION_PROPOSAL_LOOP_PASS",
        "champion_challenger_status": "CHAMPION_CHALLENGER_PASS_FOR_FROZEN_BENCHMARK",
        "evolution_loop_status": "EVOLUTION_LOOP_SHADOW_PASS",
        "meta_evolution_status": "META_EVOLUTION_PROPOSAL_ONLY",
        "uplift_scope": "FROZEN_BENCHMARK_AND_SHADOW_NOT_PRODUCTION",
        "rollback_status": "DESCRIPTIVE_WAIT_AUTHORITY",
        "code_sha256": _bundle_sha256(root, CODE_FILES),
        "config_sha256": canonical_json_sha256(EVIDENCE_FILES),
        "policy_sha256": _bundle_sha256(root, POLICY_FILES),
        "schema_sha256": canonical_json_sha256({
            "core": "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50",
            "a1": "eab6401e6fc1460433a7b45b052c0218f3d26a90e6489a234bf2d51d2269dbe1",
        }),
        "autonomous_canonical_mutation": False,
        "automatic_promotion": False,
        "human_required_for_promotion": True,
        "policy_application": False,
        "deployment": False,
        "live_trading": False,
        "live_security_execution": False,
        "grants_authority": False,
    }


def _validate_receipt_against_evidence(
    receipt: Mapping[str, object], evidence: Mapping[str, object]
) -> dict[str, object]:
    try:
        proof = validate_capability_proof(receipt)
    except CapabilityProofError as exc:
        raise E3AggregateError("aggregate E3 capability proof is invalid") from exc
    payload = proof["payload"]
    if payload["capability_id"] != "EVOLUTION_E3_SHADOW" or payload["subject_ref"] != evidence["subject_ref"]:
        raise E3AggregateError("aggregate E3 capability identity mismatch")
    scope = payload["scope"]
    if any(scope[field] is not False for field in FORBIDDEN_TRUE_FLAGS):
        raise E3AggregateError("aggregate E3 capability claims forbidden action")
    for field in (
        "mutation_proposal_status", "champion_challenger_status",
        "evolution_loop_status", "meta_evolution_status", "uplift_scope",
        "rollback_status",
    ):
        if scope[field] != evidence[field]:
            raise E3AggregateError(f"aggregate E3 {field} does not match evidence")
    for field in ("code_sha256", "config_sha256", "policy_sha256", "schema_sha256"):
        if payload[field] != evidence[field]:
            raise E3AggregateError(f"aggregate E3 {field} is stale")
    return proof


def validate_historical_aggregate_receipt(
    root: Path, receipt: Mapping[str, object]
) -> dict[str, object]:
    """Validate immutable historical semantics without claiming currentness."""

    return _validate_receipt_against_evidence(receipt, validate_e3_evidence(root))


def validate_aggregate_receipt(
    root: Path,
    receipt: Mapping[str, object],
    *,
    currentness_context: Mapping[str, object],
) -> dict[str, object]:
    try:
        current = validate_release_currentness_context(root, currentness_context)
    except ReleaseCurrentnessError as exc:
        raise E3AggregateError("release currentness context is invalid") from exc
    evidence = validate_e3_evidence(root, subject_ref=f"git:{current['release_sha']}")
    proof = _validate_receipt_against_evidence(receipt, evidence)
    try:
        assess_capability_for_release(
            root,
            proof,
            current,
            code_sha256=str(evidence["code_sha256"]),
            config_sha256=str(evidence["config_sha256"]),
            policy_sha256=str(evidence["policy_sha256"]),
            schema_sha256=str(evidence["schema_sha256"]),
        )
    except ReleaseCurrentnessError as exc:
        raise E3AggregateError("aggregate E3 proof is not current") from exc
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--currentness", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    evidence = validate_e3_evidence(root)
    if args.receipt:
        if args.currentness is None:
            raise E3AggregateError("--currentness is required with --receipt")
        validate_aggregate_receipt(
            root,
            _strict_json(args.receipt.read_bytes(), label=str(args.receipt)),
            currentness_context=_strict_json(
                args.currentness.read_bytes(), label=str(args.currentness)
            ),
        )
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
