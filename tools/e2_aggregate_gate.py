#!/usr/bin/env python3
"""Fail-closed E2 evidence validator for frozen shadow research capabilities."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping

from capability_proof import CapabilityProofError, canonical_json_sha256, validate_capability_proof


SUBJECT_SHA = "b9fa2944c35f7edc1474c2e42c91680f1d177e19"
SUBJECT_REF = f"git:{SUBJECT_SHA}"
EVIDENCE_FILES = {
    "docs/receipts/integration/s23-knowledge-fabric-assurance.json": "f054c57ec31efbab9ea2af8d237a602139ceca90b2335854b5685745f09de32c",
    "docs/receipts/integration/s24-agenda-portfolio-assurance.json": "192339eec3c73f4915e603707be48b00079e3795e34f3b78a5cb93a4e7b90329",
    "docs/receipts/integration/s25-council-assurance.json": "b0750d48bba8184e2bce2e9814598aa3919cd360aebec1f8d427de6bb916e208",
    "docs/receipts/integration/s26-replication-assurance.json": "92999d44afda8a03d29acd2f234cd64d58b4a39ec04daceea3166ed623b6f6f3",
    "docs/receipts/integration/s27-memory-assurance.json": "b20c9f65db9d191ef599871f1b791dc1ba764477bb81e2050d3b11188019edb8",
}
STAGE_IDS = {
    "docs/receipts/integration/s23-knowledge-fabric-assurance.json": "s23-knowledge-fabric-assurance",
    "docs/receipts/integration/s24-agenda-portfolio-assurance.json": "s24-agenda-portfolio-assurance",
    "docs/receipts/integration/s25-council-assurance.json": "s25-council-assurance",
    "docs/receipts/integration/s26-replication-assurance.json": "s26-replication-assurance",
    "docs/receipts/integration/s27-memory-assurance.json": "s27-memory-assurance",
}
CODE_FILES = (
    "src/research_bridge/ledger.py",
    "src/research_bridge/evolution.py",
    "src/research_bridge/model_broker.py",
)
POLICY_FILES = (
    "provenance/model-council-tournament-v1.json",
    "provenance/evidence-replication-matrix-v1.json",
    "provenance/memory-uplift-replay-capacity-v1.json",
)
FORBIDDEN_TRUE_FLAGS = (
    "autonomous_canonical_mutation", "deployment", "live_trading",
    "live_security_execution",
)


class E2AggregateError(RuntimeError):
    """The E2 evidence set does not support the frozen claim."""


def _strict_json(raw: bytes, *, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise E2AggregateError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                E2AggregateError(f"{label} contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise E2AggregateError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise E2AggregateError(f"{label} must be an object")
    return value


def _bundle_sha256(root: Path, paths: tuple[str, ...]) -> str:
    material: dict[str, str] = {}
    for relative in paths:
        try:
            material[relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        except OSError as exc:
            raise E2AggregateError(f"missing E2 bundle file: {relative}") from exc
    return canonical_json_sha256(material)


def _integration(receipt: Mapping[str, object], *, stage_id: str) -> dict[str, object]:
    try:
        payload = receipt["payload"]
        integrity = receipt["integrity"]
        assert isinstance(payload, dict) and isinstance(integrity, dict)
        digest = canonical_json_sha256(payload)
        if receipt["schema_id"] != "IntegrationReceipt" or payload["stage_id"] != stage_id:
            raise E2AggregateError(f"{stage_id} integration identity mismatch")
        if integrity["payload_sha256"] != digest:
            raise E2AggregateError(f"{stage_id} integration integrity mismatch")
        audits = payload["audit_results"]
        assert isinstance(audits, dict)
        if (
            audits["contract_gate"] != "green"
            or audits["privacy_secret_scan"] != "green"
            or audits["source_mutation"] is not False
            or audits["grants_authority"] is not False
        ):
            raise E2AggregateError(f"{stage_id} integration gates are not green")
    except (AssertionError, KeyError, TypeError) as exc:
        raise E2AggregateError(f"{stage_id} integration shape mismatch") from exc
    return payload


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def validate_e2_evidence(root: Path, *, subject_ref: str = SUBJECT_REF) -> dict[str, object]:
    """Validate exact S23-S27 evidence without converting it into authority."""

    if subject_ref != SUBJECT_REF:
        raise E2AggregateError("aggregate subject is not the frozen exact head")
    loaded: dict[str, dict[str, object]] = {}
    payloads: dict[str, dict[str, object]] = {}
    for relative, expected in EVIDENCE_FILES.items():
        try:
            raw = (root / relative).read_bytes()
        except OSError as exc:
            raise E2AggregateError(f"missing E2 evidence: {relative}") from exc
        if hashlib.sha256(raw).hexdigest() != expected:
            raise E2AggregateError(f"E2 evidence digest mismatch: {relative}")
        loaded[relative] = _strict_json(raw, label=relative)
        payload = _integration(loaded[relative], stage_id=STAGE_IDS[relative])
        payloads[relative] = payload
        for field in ("head_sha", "integration_commit_sha"):
            if not _is_ancestor(root, str(payload[field]), SUBJECT_SHA):
                raise E2AggregateError(f"E2 {field} is outside exact-head ancestry: {relative}")

    audits = {path: payload["audit_results"] for path, payload in payloads.items()}
    knowledge = audits["docs/receipts/integration/s23-knowledge-fabric-assurance.json"]
    agenda = audits["docs/receipts/integration/s24-agenda-portfolio-assurance.json"]
    council = audits["docs/receipts/integration/s25-council-assurance.json"]
    replication = audits["docs/receipts/integration/s26-replication-assurance.json"]
    memory = audits["docs/receipts/integration/s27-memory-assurance.json"]
    assert all(isinstance(item, dict) for item in audits.values())
    if (
        knowledge.get("deterministic_restart_hash") != "green"
        or knowledge.get("scientific_truth_or_learning_overclaim") != 0
        or knowledge.get("durable_writes_from_retrieval") != 0
    ):
        raise E2AggregateError("knowledge evidence widens the shadow claim")
    if (
        agenda.get("replay_identical") != "green"
        or agenda.get("unsafe_or_exhausted_selected") != 0
        or agenda.get("budget_slot_risk_diversity_breach") != 0
        or agenda.get("durable_side_effects") != 0
    ):
        raise E2AggregateError("agenda or portfolio evidence widens the bounded claim")
    if (
        council.get("dissent_and_unanimity_non_evidentiary") != "green"
        or council.get("incomplete_ranking_withheld") != "green"
        or council.get("real_model_calls_or_cost") != 0
        or council.get("durable_or_external_side_effects") != 0
    ):
        raise E2AggregateError("council evidence was laundered into scientific evidence")
    if (
        replication.get("correlated_source_overclaim_denial") != "green"
        or replication.get("forged_sidecar_matrix_pair_island_denial") != "green"
        or replication.get("real_private_data_model_calls_or_external_actions") != 0
    ):
        raise E2AggregateError("replication evidence overclaims independence or data scope")
    if (
        memory.get("zero_observation_and_underpowered_denial") != "green"
        or memory.get("false_learn_and_debt_growth_denial") != "green"
        or memory.get("calibration_without_calibrated_claim") != "green"
        or memory.get("real_private_data_model_calls_or_external_actions") != 0
    ):
        raise E2AggregateError("memory evidence overclaims uplift or calibration")

    return {
        "status": "AUTONOMOUS_RESEARCH_E2_SHADOW_PASS_FOR_FROZEN_SCOPE",
        "subject_ref": SUBJECT_REF,
        "agenda_status": "AUTONOMOUS_RESEARCH_AGENDA_SHADOW_PASS",
        "portfolio_status": "AUTONOMOUS_PORTFOLIO_SELECTION_SHADOW_PASS",
        "falsification_status": "AUTONOMOUS_FALSIFICATION_SHADOW_PASS",
        "replication_status": "AUTONOMOUS_REPLICATION_SHADOW_PASS",
        "memory_status": "MEASUREMENT_SCOPED_POPULATION_UPLIFT_NOT_ESTABLISHED",
        "code_sha256": _bundle_sha256(root, CODE_FILES),
        "config_sha256": canonical_json_sha256(EVIDENCE_FILES),
        "policy_sha256": _bundle_sha256(root, POLICY_FILES),
        "schema_sha256": canonical_json_sha256({
            "core": "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50",
            "a1": "eab6401e6fc1460433a7b45b052c0218f3d26a90e6489a234bf2d51d2269dbe1",
        }),
        "autonomous_canonical_mutation": False,
        "human_required_for_promotion": True,
        "deployment": False,
        "live_trading": False,
        "live_security_execution": False,
        "grants_authority": False,
    }


def validate_aggregate_receipt(root: Path, receipt: Mapping[str, object]) -> dict[str, object]:
    evidence = validate_e2_evidence(root)
    try:
        proof = validate_capability_proof(receipt)
    except CapabilityProofError as exc:
        raise E2AggregateError("aggregate E2 capability proof is invalid") from exc
    payload = proof["payload"]
    if (
        payload["capability_id"] != "AUTONOMOUS_RESEARCH_E2_SHADOW"
        or payload["subject_ref"] != SUBJECT_REF
    ):
        raise E2AggregateError("aggregate E2 capability identity mismatch")
    scope = payload["scope"]
    if any(scope[field] is not False for field in FORBIDDEN_TRUE_FLAGS):
        raise E2AggregateError("aggregate E2 capability claims forbidden action")
    for field in (
        "agenda_status", "portfolio_status", "falsification_status",
        "replication_status", "memory_status",
    ):
        if scope[field] != evidence[field]:
            raise E2AggregateError(f"aggregate E2 {field} does not match evidence")
    for field in ("code_sha256", "config_sha256", "policy_sha256", "schema_sha256"):
        if payload[field] != evidence[field]:
            raise E2AggregateError(f"aggregate E2 {field} is stale")
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    evidence = validate_e2_evidence(root)
    if args.receipt:
        value = _strict_json(args.receipt.read_bytes(), label=str(args.receipt))
        validate_aggregate_receipt(root, value)
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
