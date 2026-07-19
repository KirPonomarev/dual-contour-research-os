#!/usr/bin/env python3
"""Pure E5 declassified MethodCard validation; no domain writer or storage."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Mapping


_SHA = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_REF = re.compile(r"^(?:contract|protocol|provenance|public|method|receipt|profile|git|sha256):[A-Za-z0-9._:@/-]{1,128}$")
_IP = re.compile(r"(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|[^0-9])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class MethodTransferError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EligibilityDecision:
    status: str
    method_card_id: str
    recipient_class: str
    recipient_write: bool = False
    grants_authority: bool = False


class MethodTransferPolicy:
    def __init__(self, path: str | Path, *, expected_sha256: str) -> None:
        raw = Path(path).read_bytes()
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), _sha(expected_sha256, "profile sha")):
            raise MethodTransferError("method transfer profile digest mismatch")
        value = _strict_json(raw, "method transfer profile")
        required = {"profile_id", "schema_version", "status", "core_catalog_sha256", "e5_catalog_sha256", "schema_sha256", "allowed_classifications", "allowed_method_families", "allowed_recipient_classes", "forbidden_field_names", "forbidden_value_patterns", "invariants"}
        if set(value) != required or value["profile_id"] != "method-card-declassification-v1" or value["status"] != "frozen-additive":
            raise MethodTransferError("method transfer profile shape drifted")
        invariants = value["invariants"]
        if not isinstance(invariants, dict) or invariants != {
            "shadow_taint_must_be_NONE": True, "domain_receipt_required": True,
            "raw_payload_allowed": False, "recipient_adoption": False,
            "scientific_truth_transfer": False, "automatic_promotion": False,
            "canonical_mutation": False, "grants_authority": False,
        }:
            raise MethodTransferError("method transfer invariants drifted")
        self.profile_sha256 = expected_sha256
        self.classifications = frozenset(value["allowed_classifications"])
        self.families = frozenset(value["allowed_method_families"])
        self.recipients = frozenset(value["allowed_recipient_classes"])
        self.forbidden_fields = frozenset(value["forbidden_field_names"])


_DRAFT_FIELDS = frozenset({
    "method_id", "method_family", "objective_class", "input_contract_refs",
    "output_contract_refs", "precondition_codes", "invariant_codes",
    "failure_mode_codes", "evaluation_protocol_ref", "provenance_refs",
    "eligible_recipient_classes", "source_shadow_taint",
})


def issue_method_card(
    policy: MethodTransferPolicy,
    draft: Mapping[str, object],
    declassification_receipt: Mapping[str, object],
    *,
    issued_at: str,
) -> dict[str, object]:
    clean = _validate_draft(policy, draft)
    receipt = _validate_receipt(policy, clean, declassification_receipt, at=issued_at)
    payload = {
        **clean,
        "declassification_receipt_ref": receipt["object_id"],
        "transfer_status": "DECLASSIFIED_METHOD_ONLY",
        "no_raw_payload": True,
        "grants_authority": False,
    }
    digest = _digest(payload)
    document = {
        "schema_id": "MethodCard", "schema_version": "1.0.0",
        "object_id": "method-card:sha256:" + digest, "issued_at": issued_at,
        "issuer": dict(receipt["issuer"]), "contour": "governance",
        "classification": receipt["classification"], "payload": payload,
        "integrity": {"payload_sha256": digest, "parent_refs": [receipt["object_id"], *clean["provenance_refs"]]},
    }
    return validate_method_card(policy, document, declassification_receipt=receipt, at=issued_at)


def validate_method_card(
    policy: MethodTransferPolicy,
    card: Mapping[str, object],
    *,
    declassification_receipt: Mapping[str, object],
    at: str,
) -> dict[str, object]:
    value = _copy(card)
    if not isinstance(value, dict) or set(value) != {"schema_id", "schema_version", "object_id", "issued_at", "issuer", "contour", "classification", "payload", "integrity"}:
        raise MethodTransferError("MethodCard envelope shape mismatch")
    payload = value["payload"]
    if not isinstance(payload, dict) or set(payload) != _DRAFT_FIELDS | {"declassification_receipt_ref", "transfer_status", "no_raw_payload", "grants_authority"}:
        raise MethodTransferError("MethodCard payload shape mismatch")
    draft = {key: payload[key] for key in _DRAFT_FIELDS}
    clean = _validate_draft(policy, draft)
    receipt = _validate_receipt(policy, clean, declassification_receipt, at=at)
    digest = _digest(payload)
    integrity = value["integrity"]
    if (
        value["schema_id"] != "MethodCard" or value["schema_version"] != "1.0.0"
        or value["object_id"] != "method-card:sha256:" + digest
        or value["issuer"] != receipt["issuer"] or value["contour"] != "governance"
        or value["classification"] != receipt["classification"]
        or payload["declassification_receipt_ref"] != receipt["object_id"]
        or payload["transfer_status"] != "DECLASSIFIED_METHOD_ONLY"
        or payload["no_raw_payload"] is not True or payload["grants_authority"] is not False
        or not isinstance(integrity, dict) or integrity.get("payload_sha256") != digest
        or integrity.get("parent_refs") != [receipt["object_id"], *clean["provenance_refs"]]
    ):
        raise MethodTransferError("MethodCard binding or authority invariant failed")
    _scan(policy, value)
    return value


def recipient_eligibility(
    policy: MethodTransferPolicy,
    card: Mapping[str, object],
    receipt: Mapping[str, object],
    *,
    recipient_class: str,
    at: str,
) -> EligibilityDecision:
    value = validate_method_card(policy, card, declassification_receipt=receipt, at=at)
    if recipient_class not in policy.recipients or recipient_class not in value["payload"]["eligible_recipient_classes"]:
        return EligibilityDecision("INELIGIBLE", value["object_id"], recipient_class)
    return EligibilityDecision("ELIGIBLE_FOR_RECIPIENT_SHADOW_ONLY", value["object_id"], recipient_class)


def _validate_draft(policy: MethodTransferPolicy, draft: Mapping[str, object]) -> dict[str, object]:
    value = _copy(draft)
    if not isinstance(value, dict) or set(value) != _DRAFT_FIELDS:
        raise MethodTransferError("MethodCard draft shape mismatch")
    if not isinstance(value["method_id"], str) or not _ID.fullmatch(value["method_id"]):
        raise MethodTransferError("method_id invalid")
    if value["method_family"] not in policy.families or value["source_shadow_taint"] != "NONE":
        raise MethodTransferError("method family or shadow taint denied")
    if not isinstance(value["objective_class"], str) or not _CODE.fullmatch(value["objective_class"]):
        raise MethodTransferError("objective class invalid")
    for field in ("precondition_codes", "invariant_codes", "failure_mode_codes"):
        _unique_strings(value[field], field, pattern=_CODE)
    for field in ("input_contract_refs", "output_contract_refs", "provenance_refs"):
        _unique_strings(value[field], field, pattern=_REF)
    if not isinstance(value["evaluation_protocol_ref"], str) or not _REF.fullmatch(value["evaluation_protocol_ref"]):
        raise MethodTransferError("evaluation protocol ref invalid")
    recipients = _unique_strings(value["eligible_recipient_classes"], "eligible recipients", pattern=_CODE)
    if not set(recipients) <= policy.recipients:
        raise MethodTransferError("recipient class denied")
    _scan(policy, value)
    return value


def _validate_receipt(policy: MethodTransferPolicy, draft: dict[str, object], receipt: Mapping[str, object], *, at: str) -> dict[str, object]:
    value = _copy(receipt)
    envelope = {"schema_id", "schema_version", "object_id", "issued_at", "issuer", "contour", "classification", "payload", "integrity"}
    if not isinstance(value, dict) or set(value) != envelope:
        raise MethodTransferError("DeclassificationReceipt envelope shape mismatch")
    payload = value["payload"]
    required = {"draft_sha256", "source_domain", "source_classification", "source_shadow_taint", "scan_profile_sha256", "reviewed_field_paths", "forbidden_match_count", "method_family", "eligible_recipient_classes", "expires_at", "raw_evidence_included", "targets_included", "strategies_included", "holdout_included", "secret_prompts_included", "grants_authority"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise MethodTransferError("DeclassificationReceipt payload shape mismatch")
    digest = _digest(payload)
    issuer = value["issuer"]
    false_fields = ("raw_evidence_included", "targets_included", "strategies_included", "holdout_included", "secret_prompts_included", "grants_authority")
    if (
        value["schema_id"] != "DeclassificationReceipt" or value["schema_version"] != "1.0.0"
        or value["object_id"] != "declassification-receipt:sha256:" + digest
        or not isinstance(issuer, dict) or set(issuer) != {"id", "authority_class"}
        or issuer.get("authority_class") != "domain-declassification-authority"
        or value["contour"] not in {"market", "security"} or payload["source_domain"] != value["contour"]
        or value["classification"] not in policy.classifications or payload["source_classification"] != value["classification"]
        or payload["source_shadow_taint"] != "NONE" or payload["scan_profile_sha256"] != policy.profile_sha256
        or payload["draft_sha256"] != _digest(draft) or payload["reviewed_field_paths"] != sorted(_DRAFT_FIELDS)
        or payload["forbidden_match_count"] != 0 or payload["method_family"] != draft["method_family"]
        or payload["eligible_recipient_classes"] != draft["eligible_recipient_classes"]
        or any(payload[field] is not False for field in false_fields)
        or not isinstance(value["integrity"], dict) or value["integrity"].get("payload_sha256") != digest
        or value["integrity"].get("parent_refs") != ["draft:sha256:" + payload["draft_sha256"]]
        or _timestamp(at) >= _timestamp(payload["expires_at"])
    ):
        raise MethodTransferError("DeclassificationReceipt binding or authority invariant failed")
    _scan(policy, value)
    return value


def _scan(policy: MethodTransferPolicy, value: object, *, key: str = "$") -> None:
    if isinstance(value, Mapping):
        for name, item in value.items():
            if str(name).lower() in policy.forbidden_fields:
                raise MethodTransferError("forbidden metadata field")
            _scan(policy, item, key=f"{key}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan(policy, item, key=f"{key}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if len(value) > 256 or "://" in value or "file:" in lowered or "/users/" in lowered or "/home/" in lowered or "/volumes/" in lowered or "../" in value or _IP.search(value) or _EMAIL.search(value) or "sk-" in lowered or "bearer " in lowered or "begin private key" in lowered:
            raise MethodTransferError("forbidden metadata value")


def _unique_strings(value: object, label: str, *, pattern: re.Pattern[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value) or len(set(value)) != len(value):
        raise MethodTransferError(f"{label} invalid")
    return tuple(value)


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise MethodTransferError("timestamp must be RFC3339 UTC")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise MethodTransferError("timestamp invalid") from exc
    if result.utcoffset() != timezone.utc.utcoffset(result):
        raise MethodTransferError("timestamp must be UTC")
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise MethodTransferError(f"{label} duplicate keys")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda item: (_ for _ in ()).throw(MethodTransferError(f"{label} non-finite")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MethodTransferError(f"{label} invalid JSON") from exc
    if not isinstance(value, dict):
        raise MethodTransferError(f"{label} must be object")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise MethodTransferError(f"{label} invalid")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_copy(item) for item in value]
    return value


__all__ = ["MethodTransferError", "MethodTransferPolicy", "EligibilityDecision", "issue_method_card", "validate_method_card", "recipient_eligibility"]
