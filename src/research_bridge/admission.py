"""Fail-closed admission for the minimal offline Bridge kernel.

This module deliberately implements only the frozen Stage 1 contract subset.  It
does not execute jobs, persist state, or grant connected execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
from typing import Any

from .authority import (
    AuthorityError,
    PinnedOfflineAuthority,
    require_pinned_authority,
)


_COMMON_KEYS = {
    "schema_id",
    "schema_version",
    "object_id",
    "issued_at",
    "issuer",
    "contour",
    "classification",
    "payload",
    "integrity",
}
_ISSUER_KEYS = {"id", "authority_class"}
_INTEGRITY_KEYS = {"payload_sha256", "parent_refs"}
_JOB_PAYLOAD_KEYS = {
    "protocol_ref",
    "code_ref",
    "input_refs",
    "image_digest",
    "runner_profile",
    "network_policy",
    "resource_limits",
    "checkpoint_strategy",
    "expected_output_contract",
    "idempotency_key",
}
_PERMIT_PAYLOAD_KEYS = {
    "subject",
    "job_spec_sha256",
    "policy_snapshot_sha256",
    "code_sha256",
    "input_sha256",
    "image_digest",
    "quotas",
    "network_class",
    "not_before",
    "expires_at",
    "max_uses",
    "nonce",
}
_LEASE_PAYLOAD_KEYS = {
    "attempt_id",
    "permit_ref",
    "job_ref",
    "runner_identity",
    "fencing_epoch",
    "fencing_token",
    "issued_at",
    "expires_at",
    "checkpoint_parent_ref",
}
_CONTOURS = {"bridge", "market", "security", "governance"}
_CLASSIFICATIONS = {
    "D0_PUBLIC",
    "D1_INTERNAL_SANITIZED",
    "D2_DOMAIN_CONFIDENTIAL",
    "D3_RESTRICTED",
}
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class AdmissionError(ValueError):
    """Raised when any authority, shape, integrity, or time check fails."""


@dataclass(frozen=True)
class AdmissionGrant:
    """The complete, immutable authority passed to the canonical ledger."""

    job_id: str
    attempt_id: str
    permit_id: str
    runner_identity: str
    fencing_epoch: int
    fencing_token: str
    admitted_at: str
    admission_digest: str


def canonical_json_sha256(value: Any) -> str:
    """Return SHA-256 over deterministic UTF-8 JSON after strict JSON checking."""

    _ensure_json_value(value, "value")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # Defensive tail after strict checking.
        raise AdmissionError("value is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def admit(
    job_spec: dict[str, Any],
    permit: dict[str, Any],
    lease: dict[str, Any],
    *,
    now: datetime | str,
    authority: PinnedOfflineAuthority | None = None,
) -> AdmissionGrant:
    """Validate and bind JobSpec, Permit, and AttemptLease without side effects."""

    try:
        verifier = require_pinned_authority(authority)
    except AuthorityError as exc:
        raise AdmissionError("pinned authority verifier is required") from exc
    admitted_time = _parse_now(now)
    job_payload, job_issued = _validate_contract(job_spec, "JobSpec")
    permit_payload, permit_issued = _validate_contract(permit, "Permit")
    lease_payload, lease_issued = _validate_contract(lease, "AttemptLease")
    try:
        verifier.verify_admission(
            job_spec,
            permit,
            lease,
            now=admitted_time,
        )
    except AuthorityError as exc:
        raise AdmissionError("authority verification failed") from exc

    permit_not_before = _parse_timestamp(
        permit_payload["not_before"], "permit.payload.not_before"
    )
    permit_expires = _parse_timestamp(
        permit_payload["expires_at"], "permit.payload.expires_at"
    )
    lease_payload_issued = _parse_timestamp(
        lease_payload["issued_at"], "lease.payload.issued_at"
    )
    lease_expires = _parse_timestamp(
        lease_payload["expires_at"], "lease.payload.expires_at"
    )

    if job_issued > admitted_time:
        raise AdmissionError("job_spec is not yet issued")
    if permit_issued > admitted_time:
        raise AdmissionError("permit is not yet issued")
    if lease_issued != lease_payload_issued:
        raise AdmissionError("lease issued_at fields do not match")
    if permit_not_before >= permit_expires:
        raise AdmissionError("permit has an invalid time window")
    if admitted_time < permit_not_before:
        raise AdmissionError("permit is not yet valid")
    if admitted_time >= permit_expires:
        raise AdmissionError("permit has expired")
    if lease_payload_issued >= lease_expires:
        raise AdmissionError("lease has an invalid time window")
    if admitted_time < lease_payload_issued:
        raise AdmissionError("lease is not yet valid")
    if admitted_time >= lease_expires:
        raise AdmissionError("lease has expired")

    job_id = job_spec["object_id"]
    permit_id = permit["object_id"]
    if permit_payload["subject"] != lease_payload["runner_identity"]:
        raise AdmissionError("permit subject does not match lease runner")
    if not hmac.compare_digest(
        permit_payload["job_spec_sha256"], canonical_json_sha256(job_spec)
    ):
        raise AdmissionError("permit does not bind the supplied JobSpec")
    if job_payload["code_ref"] != f"sha256:{permit_payload['code_sha256']}":
        raise AdmissionError("permit code digest does not match job code_ref")
    if not hmac.compare_digest(
        permit_payload["input_sha256"],
        canonical_json_sha256(job_payload["input_refs"]),
    ):
        raise AdmissionError("permit input digest does not match ordered job inputs")
    if permit_payload["image_digest"] != job_payload["image_digest"]:
        raise AdmissionError("permit image digest does not match job")
    if permit_payload["max_uses"] != 1:
        raise AdmissionError("permit must authorize exactly one use")
    if job_payload["network_policy"] != "offline":
        raise AdmissionError("job network policy is not offline")
    if permit_payload["network_class"] != "offline":
        raise AdmissionError("permit network class is not offline")

    if lease_payload["job_ref"] != job_id:
        raise AdmissionError("lease does not bind the supplied job")
    if lease_payload["permit_ref"] != permit_id:
        raise AdmissionError("lease does not bind the supplied permit")

    admitted_at = _format_timestamp(admitted_time)
    admission_digest = canonical_json_sha256(
        {
            "admitted_at": admitted_at,
            "job_spec_sha256": canonical_json_sha256(job_spec),
            "lease_sha256": canonical_json_sha256(lease),
            "permit_sha256": canonical_json_sha256(permit),
        }
    )
    return AdmissionGrant(
        job_id=job_id,
        attempt_id=lease_payload["attempt_id"],
        permit_id=permit_id,
        runner_identity=lease_payload["runner_identity"],
        fencing_epoch=lease_payload["fencing_epoch"],
        fencing_token=lease_payload["fencing_token"],
        admitted_at=admitted_at,
        admission_digest=admission_digest,
    )


def _validate_contract(
    value: dict[str, Any], expected_schema: str
) -> tuple[dict[str, Any], datetime]:
    label = expected_schema.lower()
    _expect_object(value, label)
    _expect_exact_keys(value, _COMMON_KEYS, label)
    _expect_equal(value["schema_id"], expected_schema, f"{label}.schema_id")
    _expect_equal(value["schema_version"], "1.0.0", f"{label}.schema_version")
    _expect_nonempty_string(value["object_id"], f"{label}.object_id")
    issued_at = _parse_timestamp(value["issued_at"], f"{label}.issued_at")

    issuer = value["issuer"]
    _expect_object(issuer, f"{label}.issuer")
    _expect_exact_keys(issuer, _ISSUER_KEYS, f"{label}.issuer")
    _expect_nonempty_string(issuer["id"], f"{label}.issuer.id")
    _expect_nonempty_string(
        issuer["authority_class"], f"{label}.issuer.authority_class"
    )
    if not isinstance(value["contour"], str) or value["contour"] not in _CONTOURS:
        raise AdmissionError(f"{label}.contour is invalid")
    if (
        not isinstance(value["classification"], str)
        or value["classification"] not in _CLASSIFICATIONS
    ):
        raise AdmissionError(f"{label}.classification is invalid")

    payload = value["payload"]
    _expect_object(payload, f"{label}.payload")
    if expected_schema == "JobSpec":
        _validate_job_payload(payload)
    elif expected_schema == "Permit":
        _validate_permit_payload(payload)
    else:
        _validate_lease_payload(payload)

    integrity = value["integrity"]
    _expect_object(integrity, f"{label}.integrity")
    _expect_exact_keys(integrity, _INTEGRITY_KEYS, f"{label}.integrity")
    _expect_sha256(integrity["payload_sha256"], f"{label}.integrity.payload_sha256")
    _expect_string_list(integrity["parent_refs"], f"{label}.integrity.parent_refs")
    expected_integrity = canonical_json_sha256(payload)
    if not hmac.compare_digest(integrity["payload_sha256"], expected_integrity):
        raise AdmissionError(f"{label} payload integrity mismatch")
    return payload, issued_at


def _validate_job_payload(payload: dict[str, Any]) -> None:
    _expect_exact_keys(payload, _JOB_PAYLOAD_KEYS, "job_spec.payload")
    for field in _JOB_PAYLOAD_KEYS - {"input_refs", "resource_limits"}:
        _expect_nonempty_string(payload[field], f"job_spec.payload.{field}")
    _expect_string_list(payload["input_refs"], "job_spec.payload.input_refs")
    _expect_object(payload["resource_limits"], "job_spec.payload.resource_limits")
    _ensure_json_value(payload["resource_limits"], "job_spec.payload.resource_limits")


def _validate_permit_payload(payload: dict[str, Any]) -> None:
    _expect_exact_keys(payload, _PERMIT_PAYLOAD_KEYS, "permit.payload")
    for field in {
        "subject",
        "image_digest",
        "network_class",
        "not_before",
        "expires_at",
        "nonce",
    }:
        _expect_nonempty_string(payload[field], f"permit.payload.{field}")
    for field in {
        "job_spec_sha256",
        "policy_snapshot_sha256",
        "code_sha256",
        "input_sha256",
    }:
        _expect_sha256(payload[field], f"permit.payload.{field}")
    _expect_object(payload["quotas"], "permit.payload.quotas")
    _ensure_json_value(payload["quotas"], "permit.payload.quotas")
    _expect_nonnegative_integer(payload["max_uses"], "permit.payload.max_uses")
    _parse_timestamp(payload["not_before"], "permit.payload.not_before")
    _parse_timestamp(payload["expires_at"], "permit.payload.expires_at")


def _validate_lease_payload(payload: dict[str, Any]) -> None:
    _expect_exact_keys(payload, _LEASE_PAYLOAD_KEYS, "lease.payload")
    for field in _LEASE_PAYLOAD_KEYS - {"fencing_epoch"}:
        _expect_nonempty_string(payload[field], f"lease.payload.{field}")
    _expect_nonnegative_integer(payload["fencing_epoch"], "lease.payload.fencing_epoch")
    _parse_timestamp(payload["issued_at"], "lease.payload.issued_at")
    _parse_timestamp(payload["expires_at"], "lease.payload.expires_at")


def _expect_object(value: Any, path: str) -> None:
    if not isinstance(value, dict):
        raise AdmissionError(f"{path} must be an object")


def _expect_exact_keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(str(key) for key in actual - expected)
        raise AdmissionError(f"{path} shape mismatch; missing={missing}; unknown={unknown}")


def _expect_equal(value: Any, expected: str, path: str) -> None:
    if value != expected or not isinstance(value, str):
        raise AdmissionError(f"{path} must equal {expected!r}")


def _expect_nonempty_string(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value:
        raise AdmissionError(f"{path} must be a non-empty string")


def _expect_sha256(value: Any, path: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise AdmissionError(f"{path} must be a lowercase SHA-256 digest")


def _expect_string_list(value: Any, path: str) -> None:
    if not isinstance(value, list):
        raise AdmissionError(f"{path} must be an array")
    for index, item in enumerate(value):
        _expect_nonempty_string(item, f"{path}[{index}]")


def _expect_nonnegative_integer(value: Any, path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AdmissionError(f"{path} must be a non-negative integer")


def _parse_now(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise AdmissionError("now must include a timezone")
        return value.astimezone(timezone.utc)
    return _parse_timestamp(value, "now")


def _parse_timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise AdmissionError(f"{path} must be an RFC 3339 timestamp with timezone")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AdmissionError(f"{path} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AdmissionError(f"{path} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_json_value(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AdmissionError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _ensure_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AdmissionError(f"{path} contains a non-string object key")
            _ensure_json_value(item, f"{path}.{key}")
        return
    raise AdmissionError(f"{path} contains a non-JSON value")
