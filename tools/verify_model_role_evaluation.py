#!/usr/bin/env python3
"""Validate the additive R04A model-role evaluation and its local wait state."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "provenance" / "model-role-evaluation-v2.json"
ROLE_PROFILE = ROOT / "contracts" / "a1" / "v1" / "profiles" / "model_role_registry_v1.json"
ROUTING_PROFILE = ROOT / "provenance" / "model-provider-routing-v1.json"
CONNECTED_PROFILE = ROOT / "provenance" / "model-provider-connected-shadow-v2.json"
SOURCE_FREEZE = ROOT / "docs" / "receipts" / "source-freeze" / "r04a-model-role-metadata.json"

ROLES = {
    "SCOUT_FAST",
    "RESEARCH_WORKER",
    "CRITIC_PRIMARY",
    "CRITIC_DEEP",
    "CHIEF_SCIENTIST",
    "ARBITER_RESERVE",
}
BINDINGS = {
    "deepseek-v4-flash",
    "deepseek-v4-pro",
    "glm-5.2-max",
    "gpt-5.6-sol-xhigh",
    "gpt-5.6-sol-max",
    "qwen3.7-max-reserve",
}
EXISTING_CONNECTED_BINDINGS = BINDINGS - {"qwen3.7-max-reserve"}
EXPECTED_PRIMARIES = {
    "SCOUT_FAST": "deepseek-v4-flash",
    "RESEARCH_WORKER": "deepseek-v4-pro",
    "CRITIC_PRIMARY": "glm-5.2-max",
    "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
    "CHIEF_SCIENTIST": "gpt-5.6-sol-max",
    "ARBITER_RESERVE": None,
}
EXPECTED_FAMILIES = {
    "deepseek-v4": {"deepseek-v4-flash", "deepseek-v4-pro"},
    "gpt-5.6-sol": {"gpt-5.6-sol-xhigh", "gpt-5.6-sol-max"},
    "glm-5.2": {"glm-5.2-max"},
    "qwen3.7": {"qwen3.7-max-reserve"},
}


class EvaluationError(RuntimeError):
    pass


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _exact(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise EvaluationError(f"{label} has unexpected fields")
    return value


def _receipt_payload_digest(path: Path) -> str:
    value = json.loads(path.read_text(encoding="utf-8"))
    payload = value["payload"]
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if value["integrity"]["payload_sha256"] != digest:
        raise EvaluationError("source freeze receipt digest mismatch")
    return digest


def validate_profile(path: Path = DEFAULT_PROFILE) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvaluationError("evaluation profile is unavailable or invalid") from exc
    profile = _exact(
        value,
        {
            "profile_id",
            "schema_version",
            "observed_at",
            "status",
            "basis",
            "privacy",
            "budget",
            "bindings",
            "roles",
            "correlation_groups",
            "current_preflight",
            "invariants",
        },
        "evaluation profile",
    )
    if (
        profile["profile_id"] != "model-role-evaluation-v2"
        or profile["schema_version"] != "2.0.0"
        or profile["status"] != "WAIT_PROVIDER"
    ):
        raise EvaluationError("evaluation profile identity or state mismatch")

    basis = _exact(
        profile["basis"],
        {
            "role_registry_v1_sha256",
            "routing_v1_sha256",
            "connected_profile_v2_sha256",
            "local_preflight_sha256",
            "source_freeze_ref",
            "historical_fixture_eval_ref",
            "historical_connected_ref",
        },
        "evaluation basis",
    )
    expected_hashes = {
        "role_registry_v1_sha256": _sha(ROLE_PROFILE),
        "routing_v1_sha256": _sha(ROUTING_PROFILE),
        "connected_profile_v2_sha256": _sha(CONNECTED_PROFILE),
    }
    if any(basis[name] != digest for name, digest in expected_hashes.items()):
        raise EvaluationError("frozen dependency digest mismatch")
    if basis["source_freeze_ref"] != "source-freeze:source-freeze-r04a-model-role-metadata-20260719":
        raise EvaluationError("source freeze reference mismatch")
    _receipt_payload_digest(SOURCE_FREEZE)

    privacy = _exact(
        profile["privacy"],
        {
            "allowed_connected_input_classes",
            "parked_input_classes",
            "connected_account_controls",
            "uniform_provider_retention_claim",
            "provider_content_training_claim",
            "raw_response_public_storage",
        },
        "privacy policy",
    )
    if privacy["allowed_connected_input_classes"] != ["D0"]:
        raise EvaluationError("connected privacy scope widened")
    if set(privacy["parked_input_classes"]) != {"D1", "D2", "D3", "sealed-holdout"}:
        raise EvaluationError("parked privacy classes mismatch")
    if (
        privacy["connected_account_controls"] != "UNVERIFIED"
        or privacy["uniform_provider_retention_claim"] is not False
        or privacy["raw_response_public_storage"] is not False
    ):
        raise EvaluationError("privacy currentness is overstated")

    budget = _exact(
        profile["budget"],
        {
            "currency_normalization",
            "max_council_calls",
            "max_stage_provider_calls",
            "stage_provider_calls_observed",
            "new_payment_authority",
            "automatic_retry",
        },
        "budget policy",
    )
    if (
        budget["currency_normalization"] != "NOT_PERFORMED"
        or budget["max_council_calls"] != 4
        or budget["max_stage_provider_calls"] != 0
        or budget["stage_provider_calls_observed"] != 0
        or budget["new_payment_authority"] is not False
        or budget["automatic_retry"] is not False
    ):
        raise EvaluationError("budget or call cap mismatch")

    bindings = profile["bindings"]
    if not isinstance(bindings, Mapping) or set(bindings) != BINDINGS:
        raise EvaluationError("binding set mismatch")
    family_members: dict[str, set[str]] = {}
    for name, raw in bindings.items():
        binding = _exact(
            raw,
            {
                "provider",
                "family",
                "provenance_group",
                "api_identifier",
                "api_identifier_status",
                "fixture_evaluation",
                "connected_evaluation",
                "allowed_input_classes",
                "pricing",
                "source_refs",
            },
            f"binding {name}",
        )
        if binding["allowed_input_classes"] != ["D0"]:
            raise EvaluationError("binding privacy scope widened")
        if "VERIFIED" not in str(binding["api_identifier_status"]):
            raise EvaluationError("binding API identifier is not verified")
        if not str(binding["connected_evaluation"]).startswith(("WAIT_", "PASS_HISTORICAL_CURRENT_WAIT_")):
            raise EvaluationError("binding claims current connected availability")
        if not isinstance(binding["source_refs"], list) or not binding["source_refs"]:
            raise EvaluationError("binding lacks source references")
        pricing = binding["pricing"]
        if not isinstance(pricing, Mapping) or pricing.get("unit_tokens") != 1_000_000:
            raise EvaluationError("binding pricing unit mismatch")
        if name != "glm-5.2-max" and not str(pricing.get("status", "")).startswith("VERIFIED_"):
            raise EvaluationError("known-price binding lacks verified price")
        if name == "glm-5.2-max" and pricing.get("status") != "UNVERIFIED_CURRENT_PRICE":
            raise EvaluationError("GLM price uncertainty is not preserved")
        family_members.setdefault(str(binding["family"]), set()).add(str(name))
    if family_members != EXPECTED_FAMILIES:
        raise EvaluationError("family correlation groups mismatch")

    roles = profile["roles"]
    if not isinstance(roles, Mapping) or set(roles) != ROLES:
        raise EvaluationError("role set mismatch")
    for role, raw in roles.items():
        route = _exact(
            raw,
            {"primary", "candidate", "fallbacks", "evaluation_status", "unavailable_action"},
            f"role {role}",
        )
        if route["primary"] != EXPECTED_PRIMARIES[role]:
            raise EvaluationError("role primary differs from policy")
        candidates = ([] if route["primary"] is None else [route["primary"]]) + list(route["fallbacks"])
        if any(candidate not in BINDINGS for candidate in candidates):
            raise EvaluationError("role references unknown binding")
        if role == "ARBITER_RESERVE":
            if route["candidate"] != "qwen3.7-max-reserve" or route["fallbacks"]:
                raise EvaluationError("reserve evaluation is not inert and exact")
        elif route["candidate"] is not None:
            raise EvaluationError("active role has an unexpected candidate slot")
        if route["unavailable_action"] not in {"PARKED", "WAIT_PROVIDER"}:
            raise EvaluationError("unavailable action mismatch")
        if "WAIT" not in str(route["evaluation_status"]):
            raise EvaluationError("role omits current wait state")

    groups = profile["correlation_groups"]
    if not isinstance(groups, Mapping) or {name: set(items) for name, items in groups.items()} != EXPECTED_FAMILIES:
        raise EvaluationError("explicit correlation groups mismatch")

    preflight = profile["current_preflight"]
    if not isinstance(preflight, Mapping):
        raise EvaluationError("current preflight is invalid")
    if (
        preflight.get("configured_bindings") != []
        or preflight.get("result") != "WAIT_PROVIDER"
        or preflight.get("secrets_printed") is not False
        or set(preflight.get("binding_states", {})) != BINDINGS
        or set(preflight["binding_states"].values()) != {"WAIT_CREDENTIAL"}
    ):
        raise EvaluationError("recorded current preflight is not exact WAIT_PROVIDER")

    invariants = profile["invariants"]
    expected_invariants = {
        "model_outputs_are_untrusted",
        "caller_cannot_select_binding",
        "fallback_cannot_widen_privacy_or_authority",
        "same_family_efforts_are_correlated",
        "gateway_is_not_independence_evidence",
        "consensus_is_not_evidence",
        "reserve_is_not_routable",
        "connected_availability_is_not_claimed",
        "frozen_v1_is_unchanged",
        "grants_authority",
    }
    if not isinstance(invariants, Mapping) or set(invariants) != expected_invariants:
        raise EvaluationError("invariant set mismatch")
    if invariants["grants_authority"] is not False or any(
        invariants[name] is not True for name in expected_invariants - {"grants_authority"}
    ):
        raise EvaluationError("required invariant is weakened")
    return dict(profile)


def evaluate_preflight(profile: Mapping[str, object], available: frozenset[str]) -> dict[str, object]:
    if not isinstance(available, frozenset) or not available <= EXISTING_CONNECTED_BINDINGS:
        raise EvaluationError("local preflight contains an unknown binding")
    states = {
        name: ("CONFIGURED_UNPROVEN" if name in available else "WAIT_CREDENTIAL")
        for name in sorted(EXISTING_CONNECTED_BINDINGS)
    }
    states["qwen3.7-max-reserve"] = "WAIT_CREDENTIAL"
    recorded = profile["current_preflight"]
    assert isinstance(recorded, Mapping)
    changed = sorted(available) != recorded["configured_bindings"]
    return {
        "configured_bindings": sorted(available),
        "binding_states": states,
        "result": "REEVALUATION_REQUIRED" if changed else "WAIT_PROVIDER",
        "secrets_printed": False,
    }


def local_available_bindings() -> frozenset[str]:
    try:
        from model_provider_shadow import ConnectedShadowProfile, CredentialResolver
    except ImportError as exc:
        raise EvaluationError("connected preflight module is unavailable") from exc
    connected = ConnectedShadowProfile()
    return frozenset(connected.resolved_available_bindings(CredentialResolver()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", nargs="?", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--local-preflight", action="store_true")
    args = parser.parse_args()
    try:
        profile = validate_profile(args.profile)
        result: dict[str, object] = {
            "profile_sha256": _sha(args.profile),
            "status": profile["status"],
            "static_validation": "GREEN",
            "secrets_printed": False,
        }
        if args.local_preflight:
            local = evaluate_preflight(profile, local_available_bindings())
            result["local_preflight"] = local
            if local["result"] != "WAIT_PROVIDER":
                print(json.dumps(result, sort_keys=True))
                return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "FAILED_CLOSED", "error_type": type(exc).__name__, "secrets_printed": False}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
