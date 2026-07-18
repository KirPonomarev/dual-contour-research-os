#!/usr/bin/env python3
"""Deterministically validate the additive public A1 contract bundle."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
A1_DIR = ROOT / "contracts" / "a1" / "v1"
CATALOG_PATH = A1_DIR / "catalog.json"
CORE_CATALOG_PATH = ROOT / "contracts" / "catalog.json"
EXPECTED_CONTRACTS = {
    "MaterialEvent": ("bridge", "trusted-event-minter", "bounded-event"),
    "CandidateSpecDraft": ("bridge", "proposal-ingestor", "untrusted-proposal-only"),
    "AdmissionReceipt": ("bridge", "a1-admission-validator", "deterministic-admission-decision"),
    "CapabilityProofReceipt": ("governance", "independent-assurance-issuer", "evidence-only-no-authority"),
}
EXPECTED_PROFILES = {
    "a1_sandbox_policy",
    "authority_corridor",
    "environment_compatibility",
    "evaluator_exposure",
    "integrity_profiles",
    "ipc_compatibility",
    "model_role_registry",
    "reason_codes",
    "storage_coverage",
    "writer_issuer_matrix",
}


class ValidationError(RuntimeError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot load {path.relative_to(ROOT)}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_generator():
    path = ROOT / "tools" / "generate_a1_contracts.py"
    spec = importlib.util.spec_from_file_location("generate_a1_contracts", path)
    require(spec is not None and spec.loader is not None, "cannot load A1 generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_catalog(catalog: dict) -> None:
    require(catalog.get("catalog_id") == "dual-contour-a1-contract-catalog", "unexpected A1 catalog_id")
    require(catalog.get("schema_version") == "1.0.0", "A1 schema_version must be 1.0.0")
    require(catalog.get("status") == "freeze-candidate", "A1 catalog must remain freeze-candidate before authority receipt")
    require(catalog.get("integrity_profile_id") == "core-json-sha256-v1", "unexpected A1 integrity profile")
    require(sha256(CORE_CATALOG_PATH) == catalog.get("core_catalog_sha256"), "A1 core catalog binding mismatch")
    require(set(catalog.get("contracts", {})) == set(EXPECTED_CONTRACTS), "A1 contract set must be exact")
    require(set(catalog.get("profile_manifest", {})) == EXPECTED_PROFILES, "A1 profile manifest must be exact")

    required_common = {
        "schema_id", "schema_version", "object_id", "issued_at", "issuer",
        "contour", "classification", "payload", "integrity",
    }
    require(set(catalog.get("common_required", [])) == required_common, "A1 common envelope fields mismatch")
    for name, (owner, writer, authority) in EXPECTED_CONTRACTS.items():
        contract = catalog["contracts"][name]
        require(contract.get("owner") == owner, f"{name} owner mismatch")
        require(contract.get("writer") == writer, f"{name} writer mismatch")
        require(contract.get("authority") == authority, f"{name} authority mismatch")
        require(set(contract.get("payload_required", [])) == set(contract.get("payload_properties", {})), f"{name} payload must be fully strict")


def validate_profiles(catalog: dict) -> dict[str, dict]:
    loaded: dict[str, dict] = {}
    for name, entry in catalog["profile_manifest"].items():
        require(set(entry) == {"ref", "sha256"}, f"profile manifest entry {name} fields mismatch")
        path = A1_DIR / entry["ref"]
        require(path.is_file(), f"missing profile: {entry['ref']}")
        require(sha256(path) == entry["sha256"], f"profile hash mismatch: {entry['ref']}")
        profile = load_json(path)
        require(profile.get("schema_version") == "1.0.0", f"profile version mismatch: {name}")
        require(profile.get("status") == "freeze-candidate", f"profile status mismatch: {name}")
        loaded[name] = profile
    return loaded


def validate_writer_matrix(catalog: dict, profile: dict) -> None:
    require(set(profile.get("objects", {})) == set(EXPECTED_CONTRACTS), "writer matrix object set mismatch")
    for name, contract in catalog["contracts"].items():
        row = profile["objects"][name]
        for field in ("owner", "writer", "authority"):
            require(row.get(field) == contract.get(field), f"writer matrix {name}.{field} mismatch")
        require(row.get("may_grant_execution") is False, f"{name} cannot grant execution")
        require(row.get("may_write_domain_truth") is False, f"{name} cannot write domain truth")
    identities = profile.get("identity_rules", {})
    require(set(identities) >= {"object_id", "receipt_id", "transport_idempotency_key", "rule"}, "identity separation incomplete")


def validate_policy(profile: dict) -> None:
    required_denies = {
        "private-api", "true-unseen-holdout", "live-trading", "live-security-execution",
        "canonical-write", "domain-ledger-write", "deploy-or-reboot", "authority-escalation",
        "mixed-or-stale-vcs-identity",
    }
    require(profile.get("policy_mode") == "deny-unless-proven", "A1 policy must fail closed")
    require(required_denies <= set(profile.get("hard_denies", [])), "A1 hard-deny set incomplete")
    require(profile.get("default_decision") == "REJECT", "A1 default decision must be REJECT")
    require(set(profile.get("decisions", [])) == {"ADMIT", "REJECT", "PARK"}, "A1 decision set mismatch")
    budget = profile.get("budget_semantics", {})
    require(budget.get("reservation_required_before_external_call") is True, "reservation must precede external calls")
    require(budget.get("unknown_outcome_auto_retry") is False, "UNKNOWN must not auto-retry")
    require(budget.get("unknown_outcome_auto_release") is False, "UNKNOWN budget must not auto-release")
    require(budget.get("reconciliation_required") is True, "UNKNOWN requires reconciliation")


def validate_reason_codes(profile: dict) -> None:
    decisions = {"ADMIT", "REJECT", "PARK"}
    disclosures = set(profile.get("disclosure_classes", []))
    require(disclosures == {"PUBLIC", "OPERATOR", "RESTRICTED"}, "reason disclosure classes mismatch")
    codes = profile.get("codes", {})
    require(len(codes) >= 12, "reason registry is incomplete")
    for code, entry in codes.items():
        require(code.isupper() and 3 <= len(code) <= 64, f"invalid reason code: {code}")
        require(entry.get("decision") in decisions, f"invalid decision for {code}")
        require(entry.get("disclosure") in disclosures, f"invalid disclosure for {code}")
        require(0 < len(entry.get("public_message", "")) <= 240, f"invalid public message for {code}")
    require(profile.get("rules", {}).get("model_may_not_create_or_override_codes") is True, "models must not control reason codes")


def validate_authority(profile: dict) -> None:
    required_human = {
        "canonical-mutation", "promotion", "publication", "deployment", "live-trading",
        "live-security-execution", "true-holdout-release", "policy-expansion",
    }
    require(required_human <= set(profile.get("human_required_for", [])), "human authority boundary incomplete")
    invariants = profile.get("invariants", {})
    for name in (
        "collector_cannot_mint_trusted_material_event",
        "admission_receipt_is_not_execution_authority",
        "cli_flag_is_not_authority",
        "permit_is_single_use_and_exactly_bound",
        "bridge_cannot_write_domain_truth",
    ):
        require(invariants.get(name) is True, f"authority invariant not proven: {name}")


def validate_model_roles(profile: dict) -> None:
    required_roles = {"SCOUT_FAST", "RESEARCH_WORKER", "CRITIC_PRIMARY", "CRITIC_DEEP", "CHIEF_SCIENTIST", "ARBITER_RESERVE"}
    require(set(profile.get("roles", {})) == required_roles, "model role set mismatch")
    invariants = profile.get("invariants", {})
    for name in (
        "model_outputs_are_untrusted", "models_cannot_self_assign_roles", "models_cannot_admit_candidates",
        "models_cannot_reserve_or_release_budget", "models_cannot_issue_permits",
        "models_cannot_mutate_canonical_state", "consensus_is_not_evidence",
        "same_family_effort_levels_are_correlated", "bindings_are_replaceable_after_shadow_evaluation",
    ):
        require(invariants.get(name) is True, f"model invariant not proven: {name}")
    require(set(profile.get("call_state_machine", [])) >= {"RESERVED", "SENT", "UNKNOWN", "RECONCILED"}, "model call FSM incomplete")


def validate_special_contracts(catalog: dict) -> None:
    material = catalog["contracts"]["MaterialEvent"]
    require({"origin_class", "root_event_ref", "parent_event_ref", "root_energy", "remaining_energy", "shadow_taint"} <= set(material["payload_required"]), "MaterialEvent lineage or energy fields missing")
    candidate = catalog["contracts"]["CandidateSpecDraft"]
    require({"estimand", "null_hypothesis", "falsifier", "stop_condition", "evidence_refs", "vcs_identity"} <= set(candidate["payload_required"]), "CandidateSpecDraft scientific or identity fields missing")
    admission = catalog["contracts"]["AdmissionReceipt"]
    require({"receipt_id", "admission_snapshot_sha256", "ledger_revision", "decision_key_sha256", "transport_idempotency_key"} <= set(admission["payload_required"]), "AdmissionReceipt snapshot or identity fields missing")
    capability = catalog["contracts"]["CapabilityProofReceipt"]
    require(capability["payload_properties"].get("grants_authority") == {"const": False}, "CapabilityProofReceipt must never grant authority")
    statuses = set(capability["payload_properties"].get("status", {}).get("enum", []))
    require("PASS_FOR_FROZEN_SCOPE" in statuses and "PASS" not in statuses, "capability status must be scope-bound")


def validate_generated_schemas(catalog: dict) -> None:
    module = load_generator()
    expected = module.rendered_schemas()
    require(set(path.name for path in expected) == {f"{name}.schema.json" for name in EXPECTED_CONTRACTS}, "generated schema set mismatch")
    for path, content in expected.items():
        require(path.is_file(), f"missing generated schema: {path.relative_to(ROOT)}")
        require(path.read_text(encoding="utf-8") == content, f"generated schema drift: {path.relative_to(ROOT)}")
        schema = load_json(path)
        require(schema.get("additionalProperties") is False, f"{path.name} envelope is not strict")
        require(schema["properties"]["payload"].get("additionalProperties") is False, f"{path.name} payload is not strict")
        require(schema["properties"]["integrity"]["properties"]["profile_id"].get("const") == catalog["integrity_profile_id"], f"{path.name} integrity profile mismatch")


def main() -> int:
    try:
        catalog = load_json(CATALOG_PATH)
        validate_catalog(catalog)
        profiles = validate_profiles(catalog)
        validate_writer_matrix(catalog, profiles["writer_issuer_matrix"])
        validate_policy(profiles["a1_sandbox_policy"])
        validate_reason_codes(profiles["reason_codes"])
        validate_authority(profiles["authority_corridor"])
        validate_model_roles(profiles["model_role_registry"])
        validate_special_contracts(catalog)
        validate_generated_schemas(catalog)
    except ValidationError as exc:
        print(f"A1 contracts: RED: {exc}", file=sys.stderr)
        return 1
    print("A1 contracts: GREEN")
    print(f"A1 contracts: {len(EXPECTED_CONTRACTS)}")
    print(f"A1 profiles: {len(EXPECTED_PROFILES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
