"""Pinned offline authority verification for the Stage 1 bridge.

This module provides a local, stdlib-only trust anchor.  Pinned issuer identity
is deliberately not described as cryptographic authenticity: no key or
signature contract is frozen for Stage 1.  Every referenced policy or approval
must be present as a complete object in an injected read-only mapping and is
then shape, integrity, issuer, time, and binding checked locally.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
from types import MappingProxyType
from typing import Any


_SUPPORTED_SCHEMAS = frozenset(
    {
        "JobSpec",
        "Permit",
        "AttemptLease",
        "PolicySnapshot",
        "ApprovalReceipt",
    }
)
_COMMON_KEYS = frozenset(
    {
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
)
_ISSUER_KEYS = frozenset({"id", "authority_class"})
_INTEGRITY_KEYS = frozenset({"payload_sha256", "parent_refs"})
_POLICY_PAYLOAD_KEYS = frozenset(
    {
        "source_repo",
        "commit_sha",
        "aggregate_sha256",
        "covered_action_classes",
        "allow_rules",
        "deny_rules",
        "valid_from",
        "valid_until",
    }
)
_APPROVAL_PAYLOAD_KEYS = frozenset(
    {
        "action_class",
        "job_spec_sha256",
        "protocol_sha256",
        "policy_sha256",
        "quotas",
        "stop_conditions",
        "expires_at",
        "nonce",
        "revoked",
    }
)
_CONTOURS = frozenset({"bridge", "market", "security", "governance"})
_CLASSIFICATIONS = frozenset(
    {
        "D0_PUBLIC",
        "D1_INTERNAL_SANITIZED",
        "D2_DOMAIN_CONFIDENTIAL",
        "D3_RESTRICTED",
    }
)
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class AuthorityError(ValueError):
    """A trust record, referenced object, or authority proof is invalid."""


@dataclass(frozen=True, slots=True)
class TrustedIssuer:
    """One exact issuer identity and authority class pinned by configuration."""

    issuer_id: str
    authority_class: str

    def __post_init__(self) -> None:
        _expect_text(self.issuer_id, "trusted issuer id")
        _expect_text(self.authority_class, "trusted authority class")


class PinnedOfflineAuthority:
    """Resolve complete objects and verify them against immutable local trust."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("PinnedOfflineAuthority cannot be subclassed")

    def __init__(
        self,
        *,
        trusted_issuers: Mapping[str, TrustedIssuer],
        policy_snapshots: Mapping[str, Mapping[str, Any]],
        approval_receipts: Mapping[str, Mapping[str, Any]],
    ) -> None:
        if not isinstance(trusted_issuers, Mapping):
            raise AuthorityError("trusted issuers must be a mapping")
        if set(trusted_issuers) != _SUPPORTED_SCHEMAS:
            raise AuthorityError("trusted issuers must pin every authority schema")
        copied_trust: dict[str, TrustedIssuer] = {}
        for schema_id in _SUPPORTED_SCHEMAS:
            record = trusted_issuers[schema_id]
            if type(record) is not TrustedIssuer:
                raise AuthorityError("trusted issuer records must be TrustedIssuer values")
            copied_trust[schema_id] = record

        self._trusted_issuers = MappingProxyType(copied_trust)
        self._policy_snapshots = _copy_object_mapping(
            policy_snapshots,
            "policy snapshot resolver",
            sha256_keys=True,
        )
        self._approval_receipts = _copy_object_mapping(
            approval_receipts,
            "approval receipt resolver",
            sha256_keys=False,
        )

    def verify_admission(
        self,
        job_spec: Mapping[str, Any],
        permit: Mapping[str, Any],
        lease: Mapping[str, Any],
        *,
        now: datetime | str,
    ) -> None:
        """Verify pinned document issuers and the Permit-bound active policy."""

        checked_at = _parse_now(now)
        self._verify_issuer(job_spec, "JobSpec")
        self._verify_issuer(permit, "Permit")
        self._verify_issuer(lease, "AttemptLease")

        permit_payload = _expect_mapping_member(permit, "payload", "permit")
        policy_digest = permit_payload.get("policy_snapshot_sha256")
        _expect_sha256(policy_digest, "permit.payload.policy_snapshot_sha256")
        policy = self._resolve_policy(policy_digest)
        self._verify_policy(policy, expected_digest=policy_digest, now=checked_at)

    def verify_resume(self, approval_ref: str, *, now: datetime | str) -> None:
        """Resolve and verify one typed approval before a global resume."""

        _expect_text(approval_ref, "approval_ref")
        checked_at = _parse_now(now)
        try:
            approval = self._approval_receipts[approval_ref]
        except KeyError as exc:
            raise AuthorityError("approval receipt is not present in the resolver") from exc

        payload, issued_at = self._validate_common(approval, "ApprovalReceipt")
        _expect_exact_keys(payload, _APPROVAL_PAYLOAD_KEYS, "approval_receipt.payload")
        self._verify_issuer(approval, "ApprovalReceipt")
        if issued_at > checked_at:
            raise AuthorityError("approval receipt is not yet issued")

        _expect_equal(
            payload.get("action_class"),
            "resume_global",
            "approval_receipt.payload.action_class",
        )
        for field in ("job_spec_sha256", "protocol_sha256", "policy_sha256"):
            _expect_sha256(payload.get(field), f"approval_receipt.payload.{field}")
        if not isinstance(payload.get("quotas"), Mapping):
            raise AuthorityError("approval_receipt.payload.quotas must be an object")
        _ensure_json_value(payload["quotas"], "approval_receipt.payload.quotas")
        if not isinstance(payload.get("stop_conditions"), list):
            raise AuthorityError(
                "approval_receipt.payload.stop_conditions must be an array"
            )
        _ensure_json_value(
            payload["stop_conditions"], "approval_receipt.payload.stop_conditions"
        )
        _expect_text(payload.get("nonce"), "approval_receipt.payload.nonce")
        if type(payload.get("revoked")) is not bool:
            raise AuthorityError("approval_receipt.payload.revoked must be boolean")
        if payload["revoked"]:
            raise AuthorityError("approval receipt is revoked")

        expires_at = _parse_timestamp(
            payload.get("expires_at"), "approval_receipt.payload.expires_at"
        )
        if issued_at >= expires_at:
            raise AuthorityError("approval receipt has an invalid time window")
        if checked_at >= expires_at:
            raise AuthorityError("approval receipt has expired")

        policy_digest = payload["policy_sha256"]
        policy = self._resolve_policy(policy_digest)
        self._verify_policy(policy, expected_digest=policy_digest, now=checked_at)

    def _resolve_policy(self, digest: str) -> Mapping[str, Any]:
        try:
            return self._policy_snapshots[digest]
        except KeyError as exc:
            raise AuthorityError("policy snapshot is not present in the resolver") from exc

    def _verify_policy(
        self,
        policy: Mapping[str, Any],
        *,
        expected_digest: str,
        now: datetime,
    ) -> None:
        payload, issued_at = self._validate_common(policy, "PolicySnapshot")
        _expect_exact_keys(payload, _POLICY_PAYLOAD_KEYS, "policy_snapshot.payload")
        self._verify_issuer(policy, "PolicySnapshot")
        if not hmac.compare_digest(_canonical_json_sha256(policy), expected_digest):
            raise AuthorityError("policy snapshot does not match its bound digest")
        if issued_at > now:
            raise AuthorityError("policy snapshot is not yet issued")

        for field in ("source_repo", "commit_sha"):
            _expect_text(payload.get(field), f"policy_snapshot.payload.{field}")
        _expect_sha256(
            payload.get("aggregate_sha256"),
            "policy_snapshot.payload.aggregate_sha256",
        )
        _expect_string_list(
            payload.get("covered_action_classes"),
            "policy_snapshot.payload.covered_action_classes",
        )
        for field in ("allow_rules", "deny_rules"):
            value = payload.get(field)
            if not isinstance(value, list):
                raise AuthorityError(f"policy_snapshot.payload.{field} must be an array")
            _ensure_json_value(value, f"policy_snapshot.payload.{field}")

        valid_from = _parse_timestamp(
            payload.get("valid_from"), "policy_snapshot.payload.valid_from"
        )
        valid_until = _parse_timestamp(
            payload.get("valid_until"), "policy_snapshot.payload.valid_until"
        )
        if valid_from >= valid_until:
            raise AuthorityError("policy snapshot has an invalid time window")
        if now < valid_from:
            raise AuthorityError("policy snapshot is not yet active")
        if now >= valid_until:
            raise AuthorityError("policy snapshot has expired")

    def _verify_issuer(self, value: Mapping[str, Any], schema_id: str) -> None:
        if not isinstance(value, Mapping):
            raise AuthorityError(f"{schema_id} must be an object")
        issuer = value.get("issuer")
        if not isinstance(issuer, Mapping) or set(issuer) != _ISSUER_KEYS:
            raise AuthorityError(f"{schema_id} issuer shape is invalid")
        actual_id = issuer.get("id")
        actual_class = issuer.get("authority_class")
        _expect_text(actual_id, f"{schema_id} issuer id")
        _expect_text(actual_class, f"{schema_id} authority class")
        trusted = self._trusted_issuers[schema_id]
        if not hmac.compare_digest(actual_id, trusted.issuer_id):
            raise AuthorityError(f"{schema_id} issuer id is not trusted")
        if not hmac.compare_digest(actual_class, trusted.authority_class):
            raise AuthorityError(f"{schema_id} authority class is not trusted")

    def _validate_common(
        self, value: Mapping[str, Any], schema_id: str
    ) -> tuple[Mapping[str, Any], datetime]:
        label = schema_id.lower()
        if not isinstance(value, Mapping):
            raise AuthorityError(f"{label} must be an object")
        _expect_exact_keys(value, _COMMON_KEYS, label)
        _expect_equal(value.get("schema_id"), schema_id, f"{label}.schema_id")
        _expect_equal(value.get("schema_version"), "1.0.0", f"{label}.schema_version")
        _expect_text(value.get("object_id"), f"{label}.object_id")
        issued_at = _parse_timestamp(value.get("issued_at"), f"{label}.issued_at")
        self._verify_issuer(value, schema_id)
        if value.get("contour") not in _CONTOURS:
            raise AuthorityError(f"{label}.contour is invalid")
        if value.get("classification") not in _CLASSIFICATIONS:
            raise AuthorityError(f"{label}.classification is invalid")

        payload = value.get("payload")
        if not isinstance(payload, Mapping):
            raise AuthorityError(f"{label}.payload must be an object")
        _ensure_json_value(payload, f"{label}.payload")
        integrity = value.get("integrity")
        if not isinstance(integrity, Mapping):
            raise AuthorityError(f"{label}.integrity must be an object")
        _expect_exact_keys(integrity, _INTEGRITY_KEYS, f"{label}.integrity")
        _expect_sha256(
            integrity.get("payload_sha256"), f"{label}.integrity.payload_sha256"
        )
        _expect_string_list(integrity.get("parent_refs"), f"{label}.integrity.parent_refs")
        expected_payload_digest = _canonical_json_sha256(payload)
        if not hmac.compare_digest(
            integrity["payload_sha256"], expected_payload_digest
        ):
            raise AuthorityError(f"{label} payload integrity mismatch")
        return payload, issued_at


def require_pinned_authority(value: object) -> PinnedOfflineAuthority:
    """Reject missing, substituted, callback, or subclassed verifier objects."""

    if type(value) is not PinnedOfflineAuthority:
        raise AuthorityError("an exact PinnedOfflineAuthority verifier is required")
    return value


def _copy_object_mapping(
    value: Mapping[str, Mapping[str, Any]],
    label: str,
    *,
    sha256_keys: bool,
) -> Mapping[str, Mapping[str, Any]]:
    if not isinstance(value, Mapping):
        raise AuthorityError(f"{label} must be a mapping")
    copied: dict[str, Mapping[str, Any]] = {}
    for key, document in value.items():
        _expect_text(key, f"{label} key")
        if sha256_keys:
            _expect_sha256(key, f"{label} key")
        if not isinstance(document, Mapping):
            raise AuthorityError(f"{label} values must be objects")
        try:
            encoded = json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            decoded = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise AuthorityError(f"{label} contains a non-JSON object") from exc
        if not isinstance(decoded, dict):
            raise AuthorityError(f"{label} values must be objects")
        # The outer resolver is immutable and the JSON object is a private deep
        # copy, so callers cannot mutate either the index or resolved contents.
        copied[key] = decoded
    return MappingProxyType(copied)


def _expect_mapping_member(
    value: Mapping[str, Any], member: str, label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityError(f"{label} must be an object")
    candidate = value.get(member)
    if not isinstance(candidate, Mapping):
        raise AuthorityError(f"{label}.{member} must be an object")
    return candidate


def _expect_exact_keys(value: Mapping[str, Any], expected: frozenset[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(str(key) for key in actual - expected)
        raise AuthorityError(f"{path} shape mismatch; missing={missing}; unknown={unknown}")


def _expect_equal(value: object, expected: str, path: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise AuthorityError(f"{path} must equal {expected!r}")


def _expect_text(value: object, path: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise AuthorityError(f"{path} must be normalized non-empty text")


def _expect_sha256(value: object, path: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise AuthorityError(f"{path} must be a lowercase SHA-256 digest")


def _expect_string_list(value: object, path: str) -> None:
    if not isinstance(value, list):
        raise AuthorityError(f"{path} must be an array")
    for index, item in enumerate(value):
        _expect_text(item, f"{path}[{index}]")


def _parse_now(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise AuthorityError("now must include a timezone")
        return value.astimezone(timezone.utc)
    return _parse_timestamp(value, "now")


def _parse_timestamp(value: object, path: str) -> datetime:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise AuthorityError(f"{path} must be an RFC 3339 timestamp with timezone")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuthorityError(f"{path} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorityError(f"{path} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _canonical_json_sha256(value: object) -> str:
    _ensure_json_value(value, "value")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuthorityError("value is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _ensure_json_value(value: object, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AuthorityError(f"{path} contains a non-finite number")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _ensure_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityError(f"{path} contains a non-string object key")
            _ensure_json_value(item, f"{path}.{key}")
        return
    raise AuthorityError(f"{path} contains a non-JSON value")


__all__ = [
    "AuthorityError",
    "PinnedOfflineAuthority",
    "TrustedIssuer",
    "require_pinned_authority",
]
