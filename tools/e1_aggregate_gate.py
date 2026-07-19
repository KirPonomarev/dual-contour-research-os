#!/usr/bin/env python3
"""Fail-closed E1 aggregate evidence validator and scoped proof issuer."""

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
    issue_evolution_kernel_v1_proof,
    validate_capability_proof,
)
from release_currentness import (
    ReleaseCurrentnessError,
    assess_capability_for_release,
    validate_release_currentness_context,
)


SUBJECT_SHA = "475a68abc4ec48148f001d9b614a2b262a0dad69"
SUBJECT_REF = f"git:{SUBJECT_SHA}"
LOCAL_PROVIDER_PROOF_SHA256 = "43fafb2b354813d991da84c1a4757f88b5aee335d4861fa44d2998dcf534a399"
EVIDENCE_FILES = {
    "docs/receipts/capability/e1a-discovery-admission-fixture.json": "c0d916b065396e79043c188d213c960b8f63766f3f0e4a712db3f105469c2c87",
    "docs/receipts/capability/e1b-durable-feedback-offline.json": "d17727868f145c3e96401a10b64864aad80fdc8a0966efdc3c3531f0fba18507",
    "docs/receipts/capability/e1c-operational-self-model-offline.json": "2917f5de110182ef7ef6018fe87229e8043305daa6ab664f800b198b51486b26",
    "docs/receipts/integration/s14-provider-independent-hostile.json": "ecd24be9041eae49b23fecf610c7f09bb07051e05d2ee56ce9366fe445d5223d",
    "docs/receipts/integration/s18-provider-hostile.json": "b104195c65496165efb50bba81aaf0aed9b460fb874aaaac5161e6a27502936b",
}
CAPABILITY_IDS = (
    "A1_DISCOVERY_ADMISSION_FIXTURE",
    "A1_DURABLE_FEEDBACK",
    "OPERATIONAL_SELF_MODEL",
)
CODE_FILES = (
    "src/research_bridge/ledger.py",
    "src/research_bridge/evolution.py",
    "src/research_bridge/model_broker.py",
)
POLICY_FILES = (
    "provenance/model-provider-routing-v1.json",
    "provenance/model-provider-connected-shadow-v2.json",
    "provenance/selected-receipt-attestation-v1.json",
)
FORBIDDEN_TRUE_FLAGS = (
    "autonomous_canonical_mutation",
    "deployment",
    "live_trading",
    "live_security_execution",
)


class E1AggregateError(RuntimeError):
    """The aggregate evidence does not support the frozen claim."""


def _strict_json(raw: bytes, *, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise E1AggregateError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                E1AggregateError(f"{label} contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise E1AggregateError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise E1AggregateError(f"{label} must be an object")
    return value


def _integration(receipt: Mapping[str, object], *, stage_id: str) -> dict[str, object]:
    try:
        payload = receipt["payload"]
        integrity = receipt["integrity"]
        assert isinstance(payload, dict) and isinstance(integrity, dict)
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if receipt["schema_id"] != "IntegrationReceipt" or payload["stage_id"] != stage_id:
            raise E1AggregateError(f"{stage_id} integration identity mismatch")
        if integrity["payload_sha256"] != digest:
            raise E1AggregateError(f"{stage_id} integration integrity mismatch")
        audits = payload["audit_results"]
        assert isinstance(audits, dict)
        if audits["contract_gate"] != "green" or audits["privacy_secret_scan"] != "green":
            raise E1AggregateError(f"{stage_id} integration gates are not green")
    except (AssertionError, KeyError, TypeError) as exc:
        raise E1AggregateError(f"{stage_id} integration shape mismatch") from exc
    return payload


def _bundle_sha256(root: Path, paths: tuple[str, ...]) -> str:
    try:
        material = {
            path: hashlib.sha256((root / path).read_bytes()).hexdigest()
            for path in paths
        }
    except OSError as exc:
        raise E1AggregateError("missing E1 bundle file") from exc
    return canonical_json_sha256(material)


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def validate_e1_evidence(root: Path, *, subject_ref: str = SUBJECT_REF) -> dict[str, object]:
    """Validate the exact frozen evidence set and return its bounded claims."""

    if not isinstance(subject_ref, str) or not subject_ref.startswith("git:") or len(subject_ref) != 44:
        raise E1AggregateError("aggregate subject is not an exact Git head")
    subject_sha = subject_ref[4:]
    if subject_ref != SUBJECT_REF and not _is_ancestor(root, SUBJECT_SHA, subject_sha):
        raise E1AggregateError("aggregate subject is not a descendant exact head")
    loaded: dict[str, dict[str, object]] = {}
    for relative, expected in EVIDENCE_FILES.items():
        path = root / relative
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise E1AggregateError(f"missing E1 evidence: {relative}") from exc
        if hashlib.sha256(raw).hexdigest() != expected:
            raise E1AggregateError(f"E1 evidence digest mismatch: {relative}")
        loaded[relative] = _strict_json(raw, label=relative)

    capability_paths = tuple(EVIDENCE_FILES)[:3]
    for path, capability_id in zip(capability_paths, CAPABILITY_IDS, strict=True):
        try:
            proof = validate_capability_proof(loaded[path])
        except CapabilityProofError as exc:
            raise E1AggregateError(f"invalid capability evidence: {path}") from exc
        payload = proof["payload"]
        if payload["capability_id"] != capability_id or payload["status"] != "PASS_FOR_FROZEN_SCOPE":
            raise E1AggregateError(f"capability evidence identity mismatch: {path}")
        if payload["grants_authority"] is not False:
            raise E1AggregateError("component capability grants authority")
        ancestor = str(payload["subject_ref"])[4:]
        if not _is_ancestor(root, ancestor, subject_sha):
            raise E1AggregateError(f"capability subject is not in exact-head ancestry: {path}")

    hostile = _integration(
        loaded["docs/receipts/integration/s14-provider-independent-hostile.json"],
        stage_id="s14-provider-independent-hostile",
    )
    provider = _integration(
        loaded["docs/receipts/integration/s18-provider-hostile.json"],
        stage_id="s18-provider-hostile",
    )
    for payload, label in ((hostile, "S14"), (provider, "S18")):
        for field in ("head_sha", "integration_commit_sha"):
            sha = str(payload[field])
            if not _is_ancestor(root, sha, subject_sha):
                raise E1AggregateError(f"{label} {field} is not in exact-head ancestry")

    audits = provider["audit_results"]
    assert isinstance(audits, dict)
    required_provider = {
        "gpt_bindings": "WAIT_PROVIDER",
        "joint_error_sample_status": "INDEPENDENCE_NOT_ESTABLISHED",
        "s17_local_proof_sha256": LOCAL_PROVIDER_PROOF_SHA256,
        "additional_real_provider_calls": 0,
        "credentials_or_raw_responses_in_git": 0,
        "canonical_domain_authority_deployment_or_live_writes": 0,
    }
    if any(audits.get(key) != value for key, value in required_provider.items()):
        raise E1AggregateError("provider evidence widens or launders the frozen claim")
    hostile_audits = hostile["audit_results"]
    assert isinstance(hostile_audits, dict)
    if hostile_audits.get("provider_specific_assurance") != "deferred-until-real-shadow":
        raise E1AggregateError("fixture hostile evidence was rewritten as provider evidence")

    return {
        "status": "EVOLUTION_KERNEL_V1_SHADOW_PASS_FOR_FROZEN_SCOPE",
        "subject_ref": subject_ref,
        "fixture_capabilities": list(CAPABILITY_IDS),
        "real_provider_scope": "AVAILABLE_EVALUATED_BINDINGS_ONLY",
        "mandatory_gpt": "WAIT_PROVIDER",
        "temporary_kimi": "UNPROMOTED_NOT_ROUTABLE",
        "independence": "NOT_ESTABLISHED",
        "autonomous_idea_generation": True,
        "autonomous_a1_sandbox_admission": True,
        "autonomous_bounded_testing": True,
        "autonomous_learning_memory": True,
        "autonomous_canonical_mutation": False,
        "human_required_for_promotion": True,
        "deployment": False,
        "live_trading": False,
        "live_security_execution": False,
        "grants_authority": False,
        "code_sha256": _bundle_sha256(root, CODE_FILES),
        "config_sha256": canonical_json_sha256(EVIDENCE_FILES),
        "policy_sha256": _bundle_sha256(root, POLICY_FILES),
        "schema_sha256": canonical_json_sha256({
            "core": "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50",
            "a1": "eab6401e6fc1460433a7b45b052c0218f3d26a90e6489a234bf2d51d2269dbe1",
        }),
    }


def _validate_receipt_against_evidence(
    receipt: Mapping[str, object], evidence: Mapping[str, object], *, require_hashes: bool
) -> dict[str, object]:
    try:
        proof = validate_capability_proof(receipt)
    except CapabilityProofError as exc:
        raise E1AggregateError("aggregate capability proof is invalid") from exc
    payload = proof["payload"]
    if payload["capability_id"] != "EVOLUTION_KERNEL_V1" or payload["subject_ref"] != evidence["subject_ref"]:
        raise E1AggregateError("aggregate capability identity mismatch")
    scope = payload["scope"]
    if any(scope[field] is not False for field in FORBIDDEN_TRUE_FLAGS):
        raise E1AggregateError("aggregate capability claims forbidden authority or action")
    if scope["mandatory_gpt"] != evidence["mandatory_gpt"] or scope["temporary_kimi"] != evidence["temporary_kimi"]:
        raise E1AggregateError("aggregate provider claims do not match evidence")
    if require_hashes:
        for field in ("code_sha256", "config_sha256", "policy_sha256", "schema_sha256"):
            if payload[field] != evidence[field]:
                raise E1AggregateError(f"aggregate E1 {field} is stale")
    return proof


def validate_historical_aggregate_receipt(
    root: Path, receipt: Mapping[str, object]
) -> dict[str, object]:
    """Validate immutable historical semantics without claiming currentness."""

    return _validate_receipt_against_evidence(
        receipt, validate_e1_evidence(root), require_hashes=False
    )


def validate_aggregate_receipt(
    root: Path,
    receipt: Mapping[str, object],
    *,
    currentness_context: Mapping[str, object],
) -> dict[str, object]:
    try:
        current = validate_release_currentness_context(root, currentness_context)
    except ReleaseCurrentnessError as exc:
        raise E1AggregateError("release currentness context is invalid") from exc
    evidence = validate_e1_evidence(root, subject_ref=f"git:{current['release_sha']}")
    proof = _validate_receipt_against_evidence(receipt, evidence, require_hashes=True)
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
        raise E1AggregateError("aggregate E1 proof is not current") from exc
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--currentness", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    evidence = validate_e1_evidence(root)
    if args.receipt:
        if args.currentness is None:
            raise E1AggregateError("--currentness is required with --receipt")
        receipt = _strict_json(args.receipt.read_bytes(), label=str(args.receipt))
        currentness = _strict_json(
            args.currentness.read_bytes(), label=str(args.currentness)
        )
        validate_aggregate_receipt(root, receipt, currentness_context=currentness)
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
