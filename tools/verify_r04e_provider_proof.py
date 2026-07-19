#!/usr/bin/env python3
"""Verify the sanitized, exact-subject R04E provider capability proof."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from capability_proof import assess_capability_proof, validate_capability_proof  # noqa: E402


MANIFEST = ROOT / "provenance" / "model-provider-functional-proof-v1.json"
RECEIPT = ROOT / "docs" / "receipts" / "capability" / "r04e-provider-functional-proof.json"
SUBJECT_SHA = "e5f613e1604bd1f6ff4537a7747c037a49816307"
MANIFEST_SHA256 = "209fd9a6ee34f5f1ff60c71fc862733adc1a39b685ac0e06665d29d2ead3559d"
WORKER_SHA256 = "31864bf94b4d827f18e556ee97ebee91cfe86ccc5ee81a3e33cfa034413c4a00"
RUNTIME_POLICY_SHA256 = "8de5bbd3b7a680e5af5db99b9735e6337df0cf3055aecdca5017327ef361ca70"
CONNECTED_PROFILE_SHA256 = "63ae65247d61b918aced080e6419609459ebcbf4a3384ea29f2617e65597258c"
ROUTING_SHA256 = "37db8596a8245a6b1ea2bc5bce1495a4e7dadb314876e51397ad11dd194b3dc6"
ROLE_EVALUATION_SHA256 = "111a7ac1dc954466b19d5e408debeeefcf65c76b5b025a743a2433be910c1e75"
SCHEMA_SHA256 = "c5b21d5b2036c9001375e9251d91186c324c8d09bb3497d3233169c89cf09122"
ENVIRONMENT_REF = "environment:macos-colima-linux-container-arm64:2026-07-19"
NOW = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ProviderProofError(RuntimeError):
    """The public provider proof is stale, private, mismatched or overstated."""


def _load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderProofError(f"invalid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise ProviderProofError(f"document must be an object: {path.name}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProviderProofError("proof timestamp is invalid")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def verify() -> dict[str, object]:
    manifest = _load(MANIFEST)
    if _sha(MANIFEST) != MANIFEST_SHA256:
        raise ProviderProofError("provider proof manifest digest drifted")
    if set(manifest) != {
        "profile_id", "schema_version", "status", "classification", "issued_at",
        "valid_until", "subject", "route", "functional_proof", "claim_boundary",
        "privacy", "evidence", "invalidation_conditions",
    }:
        raise ProviderProofError("provider proof manifest shape drifted")
    if (
        manifest["profile_id"] != "model-provider-functional-proof-v1"
        or manifest["schema_version"] != "1.0.0"
        or manifest["status"] != "PASS_FOR_EXACT_R04D_SCOPE"
        or manifest["classification"] != "D1_INTERNAL_SANITIZED"
        or not (_timestamp(manifest["issued_at"]) <= _timestamp(NOW) < _timestamp(manifest["valid_until"]))
    ):
        raise ProviderProofError("provider proof identity or currentness is invalid")

    subject = manifest["subject"]
    if subject != {
        "repository": "KirPonomarev/dual-contour-research-os",
        "release_sha": SUBJECT_SHA,
        "release_tree_sha": "cc79ea72288d9530e0eb3fbce012f6b1651988ad",
        "exact_head_ci_run": 29691530310,
        "exact_head_ci_conclusion": "success",
        "worker_image_id": "sha256:ea4cb31db6eec84c6f8e77c972b6374027fdb6a8e4c34f73747ce7857287bc32",
    }:
        raise ProviderProofError("provider proof subject drifted")
    route = manifest["route"]
    if route != {
        "role": "CRITIC_DEEP",
        "binding": "gpt-5.6-sol-xhigh",
        "durable_route_provider_slot": "OPENAI_API",
        "physical_gateway_provider_slot": "OPENROUTER_API",
        "gateway_provider": "openrouter",
        "requested_api_model": "openai/gpt-5.6-sol",
        "slot_relation": "GATEWAY_TRANSPORT_DISTINCT_FROM_REQUESTED_MODEL_FAMILY",
        "upstream_provider_attested": False,
        "model_independence_established": False,
    }:
        raise ProviderProofError("provider route layers drifted or are overstated")
    functional = manifest["functional_proof"]
    if functional != {
        "input_class": "D0", "provider_calls": 1, "maximum_calls": 1,
        "maximum_total_tokens": 1024, "actual_total_tokens": 155,
        "maximum_cost_units": 1, "actual_cost_units": 1,
        "accounting_state": "RECONCILED", "budget_released": True,
        "automatic_retry": False, "output_bytes": 337,
        "output_non_vacuous": True, "restart_no_repeat": True,
        "ledger_unchanged_on_terminal_replay": True,
    }:
        raise ProviderProofError("provider functional evidence drifted")
    if functional["actual_total_tokens"] > functional["maximum_total_tokens"]:
        raise ProviderProofError("provider total usage exceeds its reservation")
    if manifest["claim_boundary"] != {
        "real_provider_route": "PASS_FOR_EXACT_BINDING_AND_GATEWAY_SCOPE",
        "fixture_claims_separate": True,
        "requested_model_slug_is_upstream_attestation": False,
        "gateway_is_model_independence_evidence": False,
        "scientific_evidence": False,
        "domain_application": "SHADOW_UNAPPLIED",
        "grants_authority": False,
    }:
        raise ProviderProofError("provider claim boundary drifted")
    privacy = manifest["privacy"]
    if not isinstance(privacy, dict) or not privacy or any(value is not False for value in privacy.values()):
        raise ProviderProofError("private provider material entered the public proof")

    expected_evidence = {
        "private_manifest_sha256": "826156b3c41c35b3c1d3498b2b62bc4d5d69b97aec51d96a64f266fb9db64cda",
        "private_spend_receipt_sha256": "4a578f47457c49c4126eb9bf92d51d9bf8d3868ba6900be1c972cd5c3af2f4ce",
        "private_output_sha256": "4e1a0a371fbdaaefa1c4d781cf6acad95b87bebe00d3421293947c73e03db1d0",
        "model_worker_sha256": WORKER_SHA256,
        "runtime_policy_sha256": RUNTIME_POLICY_SHA256,
        "role_evaluation_sha256": ROLE_EVALUATION_SHA256,
        "routing_profile_sha256": ROUTING_SHA256,
        "connected_shadow_profile_sha256": CONNECTED_PROFILE_SHA256,
        "worker_ipc_extension_sha256": "03d91f027bb6975c55d84acaef188546bcd24af9944a72f4ff9314296399d07a",
    }
    if manifest["evidence"] != expected_evidence:
        raise ProviderProofError("provider proof evidence digests drifted")
    for path, digest in (
        (ROOT / "ops/connected-worker/model_worker.py", WORKER_SHA256),
        (ROOT / "ops/connected-worker/runtime-policy.json", RUNTIME_POLICY_SHA256),
        (ROOT / "provenance/model-role-evaluation-v2.json", ROLE_EVALUATION_SHA256),
        (ROOT / "provenance/model-provider-routing-v1.json", ROUTING_SHA256),
        (ROOT / "provenance/model-provider-connected-shadow-v2.json", CONNECTED_PROFILE_SHA256),
        (ROOT / "contracts/a1/v1/CapabilityProofReceipt.schema.json", SCHEMA_SHA256),
    ):
        if _sha(path) != digest:
            raise ProviderProofError(f"bound dependency drifted: {path.name}")

    evaluation = _load(ROOT / "provenance/model-role-evaluation-v2.json")
    routing = _load(ROOT / "provenance/model-provider-routing-v1.json")
    connected = _load(ROOT / "provenance/model-provider-connected-shadow-v2.json")
    binding = "gpt-5.6-sol-xhigh"
    if (
        evaluation["roles"]["CRITIC_DEEP"]["primary"] != binding
        or evaluation["bindings"][binding]["provider"] != "openrouter"
        or evaluation["bindings"][binding]["api_identifier"] != "openai/gpt-5.6-sol"
        or routing["bindings"][binding]["provider_slot"] != "OPENAI_API"
        or connected["bindings"][binding]["provider_slot"] != "OPENROUTER_API"
        or connected["bindings"][binding]["api_model"] != "openai/gpt-5.6-sol"
    ):
        raise ProviderProofError("provider route dependency no longer matches the exact proof")

    receipt = validate_capability_proof(_load(RECEIPT))
    payload = receipt["payload"]
    assessment = assess_capability_proof(
        receipt,
        now=NOW,
        subject_ref="git:" + SUBJECT_SHA,
        code_sha256=WORKER_SHA256,
        config_sha256=RUNTIME_POLICY_SHA256,
        policy_sha256=CONNECTED_PROFILE_SHA256,
        schema_sha256=SCHEMA_SHA256,
        environment_compatibility_ref=ENVIRONMENT_REF,
    )
    if assessment.status != "PASS_FOR_FROZEN_SCOPE" or assessment.invalidation_reasons:
        raise ProviderProofError("provider capability proof is stale")
    if payload["data_refs"] != [
        "manifest:sha256:" + MANIFEST_SHA256,
        "output:sha256:4e1a0a371fbdaaefa1c4d781cf6acad95b87bebe00d3421293947c73e03db1d0",
        "private-manifest:sha256:826156b3c41c35b3c1d3498b2b62bc4d5d69b97aec51d96a64f266fb9db64cda",
        "spend-receipt:sha256:4a578f47457c49c4126eb9bf92d51d9bf8d3868ba6900be1c972cd5c3af2f4ce",
    ]:
        raise ProviderProofError("provider capability evidence refs drifted")
    public_text = json.dumps([manifest, receipt], sort_keys=True)
    for forbidden in (
        "provider.env", "private-cas:", "/var/lib/", "runtime.sqlite",
        "raw_response_ref", "body_base64", "credential_value",
    ):
        if forbidden in public_text:
            raise ProviderProofError("private provider material entered public evidence")
    return {
        "status": "PASS",
        "subject_sha": SUBJECT_SHA,
        "manifest_sha256": MANIFEST_SHA256,
        "capability_status": assessment.status,
        "provider_calls": 1,
        "actual_total_tokens": 155,
        "maximum_total_tokens": 1024,
        "output_non_vacuous": True,
        "raw_or_credential_bytes_present": False,
        "grants_authority": False,
    }


def main() -> int:
    try:
        result = verify()
    except (ProviderProofError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
