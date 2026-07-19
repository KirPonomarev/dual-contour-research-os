#!/usr/bin/env python3
"""Pure E5 transfer-request validation ending at human/domain authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Collection, Mapping

from tools.method_card import MethodTransferPolicy, validate_method_card
from tools.recipient_shadow import RecipientShadowReport


_TOKEN = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


class GovernedTransferError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TransferDecision:
    status: str
    capability_status: str
    request_id: str
    audit_telemetry: Mapping[str, object]
    promotion_receipt_issued: bool = False
    promotion_applied: bool = False
    recipient_registry_writes: int = 0
    grants_authority: bool = False


class GovernedTransferPolicy:
    def __init__(self, path: str | Path, *, expected_sha256: str) -> None:
        raw = Path(path).read_bytes()
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
            raise GovernedTransferError("governed transfer profile digest mismatch")
        value = json.loads(raw)
        if set(value) != {"profile_id", "schema_version", "status", "method_policy_sha256", "recipient_shadow_policy_sha256", "request", "capability_status", "invariants"} or value["profile_id"] != "governed-method-transfer-v1":
            raise GovernedTransferError("governed transfer profile drifted")
        if value["invariants"] != {"declassification_chain_required": True, "recipient_shadow_required": True, "request_grants_authority": False, "promotion_receipt_issued": False, "promotion_applied": False, "recipient_registry_writes": 0, "scientific_truth_transfer": False, "policy_mutation": False, "canonical_mutation": False, "grants_authority": False}:
            raise GovernedTransferError("governed transfer invariants drifted")
        self.profile_sha256 = expected_sha256
        self.max_seconds = value["request"]["maximum_validity_seconds"]
        self.capability_status = value["capability_status"]


def build_transfer_request(
    policy: GovernedTransferPolicy,
    method_card: Mapping[str, object],
    declassification_receipt: Mapping[str, object],
    shadow_report: RecipientShadowReport,
    *, request_id: str, nonce: str, issued_at: str, expires_at: str,
) -> dict[str, object]:
    if not _TOKEN.fullmatch(request_id) or not _TOKEN.fullmatch(nonce):
        raise GovernedTransferError("request identity invalid")
    issued, expires = _timestamp(issued_at), _timestamp(expires_at)
    if not issued < expires or int((expires - issued).total_seconds()) > policy.max_seconds:
        raise GovernedTransferError("request validity invalid")
    report_digest = _digest(asdict(shadow_report))
    payload = {"request_id": request_id, "nonce": nonce, "method_card_id": method_card.get("object_id"), "declassification_receipt_id": declassification_receipt.get("object_id"), "recipient_class": shadow_report.recipient_class, "shadow_report_sha256": report_digest, "shadow_status": shadow_report.status, "issued_at": issued_at, "expires_at": expires_at, "state": "WAIT_HUMAN_DOMAIN_AUTHORITY", "promotion_receipt_ref": None, "grants_authority": False}
    digest = _digest(payload)
    return {"schema_id": "MethodTransferAuthorityRequest", "schema_version": "1.0.0", "object_id": "method-transfer-request:sha256:" + digest, "payload": payload, "integrity": {"payload_sha256": digest, "parent_refs": [str(payload["method_card_id"]), str(payload["declassification_receipt_id"]), "shadow-report:sha256:" + report_digest]}}


def validate_transfer_request(
    policy: GovernedTransferPolicy,
    method_policy: MethodTransferPolicy,
    method_card: Mapping[str, object],
    declassification_receipt: Mapping[str, object],
    shadow_report: RecipientShadowReport,
    request: Mapping[str, object],
    *, now: str, consumed_request_ids: Collection[str] = (),
) -> TransferDecision:
    validate_method_card(method_policy, method_card, declassification_receipt=declassification_receipt, at=now)
    value = _copy(request)
    if not isinstance(value, dict) or set(value) != {"schema_id", "schema_version", "object_id", "payload", "integrity"}:
        raise GovernedTransferError("request envelope invalid")
    payload = value["payload"]
    expected_keys = {"request_id", "nonce", "method_card_id", "declassification_receipt_id", "recipient_class", "shadow_report_sha256", "shadow_status", "issued_at", "expires_at", "state", "promotion_receipt_ref", "grants_authority"}
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise GovernedTransferError("request payload invalid")
    digest = _digest(payload)
    report_digest = _digest(asdict(shadow_report))
    if payload["request_id"] in consumed_request_ids:
        return _decision(policy, "REJECTED_REPLAY", str(payload["request_id"]), "REPLAY")
    if _timestamp(now) >= _timestamp(payload["expires_at"]):
        return _decision(policy, "REJECTED_EXPIRED", str(payload["request_id"]), "EXPIRED")
    if (
        value["schema_id"] != "MethodTransferAuthorityRequest" or value["schema_version"] != "1.0.0"
        or value["object_id"] != "method-transfer-request:sha256:" + digest
        or not isinstance(value["integrity"], dict) or value["integrity"].get("payload_sha256") != digest
        or payload["method_card_id"] != method_card["object_id"] or payload["declassification_receipt_id"] != declassification_receipt["object_id"]
        or payload["recipient_class"] != shadow_report.recipient_class or payload["shadow_report_sha256"] != report_digest
        or payload["shadow_status"] != "POSITIVE_SHADOW_EFFECT_NOT_ADOPTED" or shadow_report.status != payload["shadow_status"]
        or shadow_report.recipient_registry_writes != 0 or shadow_report.canonical_adoption or shadow_report.grants_authority
        or method_card["payload"]["source_shadow_taint"] != "NONE" or payload["state"] != "WAIT_HUMAN_DOMAIN_AUTHORITY"
        or payload["promotion_receipt_ref"] is not None or payload["grants_authority"] is not False
    ):
        return _decision(policy, "REJECTED_CHAIN", str(payload["request_id"]), "CHAIN_OR_AUTHORITY")
    return _decision(policy, "WAIT_HUMAN_DOMAIN_AUTHORITY", str(payload["request_id"]), "NONE")


def build_capability_proof(policy: GovernedTransferPolicy, decision: TransferDecision, *, subject_sha: str, issued_at: str, expires_at: str, evidence_refs: list[str]) -> dict[str, object]:
    if decision.status != "WAIT_HUMAN_DOMAIN_AUTHORITY" or not re.fullmatch(r"[a-f0-9]{40}", subject_sha) or not evidence_refs:
        raise GovernedTransferError("capability proof precondition failed")
    payload = {"capability": "METHOD_TRANSFER", "status": policy.capability_status, "subject_sha": subject_sha, "request_id": decision.request_id, "evidence_refs": evidence_refs, "authority_state": decision.status, "promotion_receipt_issued": False, "promotion_applied": False, "recipient_registry_writes": 0, "scientific_truth_transfer": False, "grants_authority": False, "issued_at": issued_at, "expires_at": expires_at}
    digest = _digest(payload)
    return {"schema_id": "MethodTransferCapabilityProof", "schema_version": "1.0.0", "object_id": "method-transfer-proof:sha256:" + digest, "payload": payload, "integrity": {"payload_sha256": digest, "parent_refs": evidence_refs}}


def _decision(policy: GovernedTransferPolicy, status: str, request_id: str, reason: str) -> TransferDecision:
    return TransferDecision(status, policy.capability_status if status == "WAIT_HUMAN_DOMAIN_AUTHORITY" else "NOT_ESTABLISHED", request_id, {"reason_code": reason, "declassification_checked": True, "recipient_shadow_checked": True, "recipient_registry_writes": 0, "promotion_receipt_issued": False, "promotion_applied": False})


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GovernedTransferError("timestamp invalid")
    try: result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc: raise GovernedTransferError("timestamp invalid") from exc
    if result.utcoffset() != timezone.utc.utcoffset(result): raise GovernedTransferError("timestamp invalid")
    return result


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _copy(value: object) -> object:
    if isinstance(value, Mapping): return {str(key): _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)): return [_copy(item) for item in value]
    return value


__all__ = ["GovernedTransferError", "GovernedTransferPolicy", "TransferDecision", "build_transfer_request", "validate_transfer_request", "build_capability_proof"]
