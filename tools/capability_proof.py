#!/usr/bin/env python3
"""Pure issuer and currentness validator for frozen A1 capability proofs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from types import MappingProxyType
from typing import Mapping


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_SUBJECT_RE = re.compile(r"^git:[a-f0-9]{40}$")
_DOCUMENT_KEYS = frozenset(
    {"schema_id", "schema_version", "object_id", "issued_at", "issuer", "contour", "classification", "payload", "integrity"}
)
_PAYLOAD_KEYS = frozenset(
    {
        "receipt_id", "capability_id", "subject_ref", "scope", "status",
        "proof_basis", "code_sha256", "config_sha256", "policy_sha256",
        "schema_sha256", "executor_ref", "evaluator_ref", "test_refs",
        "environment_ref", "data_refs", "issuer_independence",
        "critical_dependencies", "compatibility_dependencies",
        "environment_compatibility_ref", "negative_probe_refs", "valid_from",
        "valid_until", "invalidation_conditions", "grants_authority",
    }
)
_INTEGRITY_KEYS = frozenset({"profile_id", "payload_sha256", "parent_refs"})
_REQUIRED_SCOPE = {
    "proof_state": "SHADOW_PASS_WITH_FIXTURE_MODEL",
    "data_scope": "D0_PUBLIC_SYNTHETIC_ONLY",
    "model_route": "LOCAL_FIXTURE_ONLY",
    "real_provider": "UNPROVEN",
    "canonical_mutation": "DENIED",
    "live_trading": "DENIED",
    "live_security_execution": "DENIED",
    "domain_application": "SHADOW_UNAPPLIED",
}
_REQUIRED_NEGATIVE_PROBES = frozenset(
    {
        "probe:ipc-role-spoof-denied",
        "probe:parser-hostile-pack",
        "probe:writer-spoof-denied",
        "probe:shadow-admission-parked",
        "probe:canonical-live-authority-absent",
        "probe:mixed-head-stale",
        "probe:expired-proof-stale",
    }
)
_REQUIRED_INVALIDATIONS = frozenset(
    {
        "subject-head-drift",
        "code-hash-drift",
        "config-hash-drift",
        "policy-hash-drift",
        "schema-hash-drift",
        "environment-compatibility-drift",
        "proof-expiry",
        "negative-probe-regression",
    }
)


class CapabilityProofError(RuntimeError):
    """Capability proof issuance or validation failed closed."""


@dataclass(frozen=True, slots=True)
class CapabilityAssessment:
    status: str
    invalidation_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"PASS_FOR_FROZEN_SCOPE", "STALE"}:
            raise CapabilityProofError("assessment status is invalid")
        if self.status == "PASS_FOR_FROZEN_SCOPE" and self.invalidation_reasons:
            raise CapabilityProofError("passing assessment cannot have invalidations")
        if self.status == "STALE" and not self.invalidation_reasons:
            raise CapabilityProofError("stale assessment requires invalidations")


def issue_e1a_fixture_proof(
    payload: Mapping[str, object],
    *,
    issued_at: str,
    classification: str = "D1",
) -> Mapping[str, object]:
    """Issue only the exact bounded E1A fixture capability proof."""

    value = _validate_payload(payload)
    issued = _timestamp("issued_at", issued_at)
    valid_from = _timestamp("valid_from", value["valid_from"])
    valid_until = _timestamp("valid_until", value["valid_until"])
    if issued != valid_from or not issued < valid_until <= issued + timedelta(days=30):
        raise CapabilityProofError("proof validity window is not bounded to issuance")
    if classification not in {"D0", "D1"}:
        raise CapabilityProofError("capability proof classification is invalid")
    identity = canonical_json_sha256(value)
    document = {
        "schema_id": "CapabilityProofReceipt",
        "schema_version": "1.0.0",
        "object_id": f"capability-proof:{identity}",
        "issued_at": _format_timestamp(issued),
        "issuer": "independent-assurance-issuer",
        "contour": "governance",
        "classification": classification,
        "payload": value,
        "integrity": {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": identity,
            "parent_refs": sorted(
                set(
                    [value["subject_ref"], value["environment_compatibility_ref"]]
                    + list(value["test_refs"])
                    + list(value["negative_probe_refs"])
                )
            ),
        },
    }
    return _freeze(document)


def validate_capability_proof(receipt: Mapping[str, object]) -> dict[str, object]:
    """Validate exact document shape, integrity, and immutable proof semantics."""

    document = _exact(receipt, _DOCUMENT_KEYS, "capability proof")
    if (
        document["schema_id"] != "CapabilityProofReceipt"
        or document["schema_version"] != "1.0.0"
        or document["issuer"] != "independent-assurance-issuer"
        or document["contour"] != "governance"
        or document["classification"] not in {"D0", "D1"}
    ):
        raise CapabilityProofError("capability proof identity is invalid")
    _timestamp("issued_at", document["issued_at"])
    payload = _validate_payload(document["payload"])
    digest = canonical_json_sha256(payload)
    if document["object_id"] != f"capability-proof:{digest}":
        raise CapabilityProofError("capability proof object identity mismatch")
    integrity = _exact(document["integrity"], _INTEGRITY_KEYS, "integrity")
    if integrity["profile_id"] != "core-json-sha256-v1":
        raise CapabilityProofError("capability proof integrity profile is invalid")
    if not hmac.compare_digest(digest, _sha256("payload_sha256", integrity["payload_sha256"])):
        raise CapabilityProofError("capability proof payload digest mismatch")
    parents = _strings("parent_refs", integrity["parent_refs"], allow_empty=False)
    if payload["subject_ref"] not in parents:
        raise CapabilityProofError("capability proof parent refs omit subject")
    return document


def assess_capability_proof(
    receipt: Mapping[str, object],
    *,
    now: str,
    subject_ref: str,
    code_sha256: str,
    config_sha256: str,
    policy_sha256: str,
    schema_sha256: str,
    environment_compatibility_ref: str,
) -> CapabilityAssessment:
    """Return STALE on any relevant frozen-scope drift or expiry."""

    document = validate_capability_proof(receipt)
    payload = document["payload"]
    current = _timestamp("now", now)
    reasons: list[str] = []
    for field, observed, expected, reason in (
        ("subject_ref", subject_ref, payload["subject_ref"], "subject-head-drift"),
        ("code_sha256", code_sha256, payload["code_sha256"], "code-hash-drift"),
        ("config_sha256", config_sha256, payload["config_sha256"], "config-hash-drift"),
        ("policy_sha256", policy_sha256, payload["policy_sha256"], "policy-hash-drift"),
        ("schema_sha256", schema_sha256, payload["schema_sha256"], "schema-hash-drift"),
        (
            "environment_compatibility_ref",
            environment_compatibility_ref,
            payload["environment_compatibility_ref"],
            "environment-compatibility-drift",
        ),
    ):
        if not isinstance(observed, str) or observed != expected:
            reasons.append(reason)
    if not (_timestamp("valid_from", payload["valid_from"]) <= current < _timestamp("valid_until", payload["valid_until"])):
        reasons.append("proof-expiry")
    return CapabilityAssessment(
        status="STALE" if reasons else "PASS_FOR_FROZEN_SCOPE",
        invalidation_reasons=tuple(sorted(set(reasons))),
    )


def _validate_payload(payload: object) -> dict[str, object]:
    value = _exact(payload, _PAYLOAD_KEYS, "capability payload")
    if value["capability_id"] != "A1_DISCOVERY_ADMISSION_FIXTURE":
        raise CapabilityProofError("capability id is outside the S04 issuer scope")
    if not isinstance(value["subject_ref"], str) or _GIT_SUBJECT_RE.fullmatch(value["subject_ref"]) is None:
        raise CapabilityProofError("capability subject must be an exact Git head")
    if value["status"] != "PASS_FOR_FROZEN_SCOPE" or value["grants_authority"] is not False:
        raise CapabilityProofError("S04 proof must be scoped PASS with zero authority")
    scope = value["scope"]
    if not isinstance(scope, Mapping) or any(scope.get(key) != expected for key, expected in _REQUIRED_SCOPE.items()):
        raise CapabilityProofError("capability scope overclaims fixture evidence")
    if set(scope) != set(_REQUIRED_SCOPE) | {"environments"}:
        raise CapabilityProofError("capability scope shape is not frozen")
    if _strings("scope.environments", scope["environments"], allow_empty=False) != ["linux-ci", "macos-development"]:
        raise CapabilityProofError("capability environments are not the tested fixture pair")
    proof_basis = value["proof_basis"]
    if not isinstance(proof_basis, list) or not proof_basis or any(not isinstance(item, Mapping) or not item for item in proof_basis):
        raise CapabilityProofError("proof_basis must contain evidence objects")
    for name in ("code_sha256", "config_sha256", "policy_sha256", "schema_sha256"):
        _sha256(name, value[name])
    for name in (
        "receipt_id", "executor_ref", "evaluator_ref", "environment_ref",
        "environment_compatibility_ref",
    ):
        _text(name, value[name], maximum=1024)
    for name in ("test_refs", "data_refs", "critical_dependencies", "compatibility_dependencies"):
        _strings(name, value[name], allow_empty=True)
    independence = _exact(
        value["issuer_independence"],
        frozenset({"issuer_ref", "independent_of_subject", "independent_of_executor"}),
        "issuer_independence",
    )
    if independence["independent_of_subject"] is not True or independence["independent_of_executor"] is not True:
        raise CapabilityProofError("assurance issuer independence is not established")
    _text("issuer_ref", independence["issuer_ref"], maximum=1024)
    probes = frozenset(_strings("negative_probe_refs", value["negative_probe_refs"], allow_empty=False))
    if not _REQUIRED_NEGATIVE_PROBES <= probes:
        raise CapabilityProofError("required negative probes are missing")
    invalidations = frozenset(_strings("invalidation_conditions", value["invalidation_conditions"], allow_empty=False))
    if invalidations != _REQUIRED_INVALIDATIONS:
        raise CapabilityProofError("invalidation conditions are incomplete")
    _timestamp("valid_from", value["valid_from"])
    _timestamp("valid_until", value["valid_until"])
    return value


def canonical_json_sha256(value: object) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CapabilityProofError("capability proof contains non-canonical JSON data") from exc
    return hashlib.sha256(encoded).hexdigest()


def _exact(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise CapabilityProofError(f"{label} shape mismatch")
    return _copy(value)  # type: ignore[return-value]


def _strings(name: str, value: object, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, (list, tuple)) or (not allow_empty and not value):
        raise CapabilityProofError(f"{name} must be a string array")
    result = [_text(f"{name}[{index}]", item, maximum=2048) for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise CapabilityProofError(f"{name} must contain unique values")
    return result


def _text(name: str, value: object, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise CapabilityProofError(f"{name} must be bounded normalized text")
    return value


def _sha256(name: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CapabilityProofError(f"{name} must be lowercase SHA-256")
    return value


def _timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CapabilityProofError(f"{name} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CapabilityProofError(f"{name} must be RFC3339 UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise CapabilityProofError(f"{name} must be UTC")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_copy(item) for item in value]
    return value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


__all__ = [
    "CapabilityProofError", "CapabilityAssessment", "issue_e1a_fixture_proof",
    "validate_capability_proof", "assess_capability_proof", "canonical_json_sha256",
]
