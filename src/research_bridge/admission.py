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
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

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
_PERMIT_QUOTA_KEYS = {
    "accounting_policy_ref",
    "budget_scope_ref",
    "claims",
    "provider",
    "scope_limit",
    "trial_ref",
}
_SCOPE_LIMIT_KEYS = {"cost_units"}
_JOB_RESOURCE_LIMIT_KEYS = {"cost_units"}
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
_ACCOUNTING_POLICY_REF = re.compile(r"^budget-policy:sha256:[a-f0-9]{64}$")
_BUDGET_SCOPE_REF = re.compile(r"^budget-scope:sha256:[a-f0-9]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class AdmissionError(ValueError):
    """Raised when any authority, shape, integrity, or time check fails."""


@dataclass(frozen=True)
class AdmissionGrant:
    """The complete, immutable authority passed to the canonical ledger."""

    job_id: str
    attempt_id: str
    permit_id: str
    permit_nonce_sha256: str
    accounting_policy_ref: str
    budget_scope_ref: str
    claims: int
    provider: str
    scope_limit_cost_units: int
    trial_ref: str
    reservation_cost_units: int
    reservation_expires_at: str
    job_idempotency_key: str
    contour: str
    classification: str
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
    permit_nonce_sha256 = hashlib.sha256(
        permit_payload["nonce"].encode("utf-8")
    ).hexdigest()
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
    quotas = permit_payload["quotas"]
    resource_limits = job_payload["resource_limits"]
    claims = quotas["claims"]
    scope_limit_cost_units = quotas["scope_limit"]["cost_units"]
    reservation_cost_units = resource_limits["cost_units"]
    if permit_payload["max_uses"] != 1 or claims != permit_payload["max_uses"]:
        raise AdmissionError("permit must authorize exactly one use")
    if quotas["provider"] != job_payload["runner_profile"]:
        raise AdmissionError("permit budget provider does not match job runner profile")
    if reservation_cost_units > scope_limit_cost_units:
        raise AdmissionError("job reservation exceeds Permit budget scope")
    if job_payload["network_policy"] != "offline":
        raise AdmissionError("job network policy is not offline")
    if permit_payload["network_class"] != "offline":
        raise AdmissionError("permit network class is not offline")

    if lease_payload["job_ref"] != job_id:
        raise AdmissionError("lease does not bind the supplied job")
    if lease_payload["permit_ref"] != permit_id:
        raise AdmissionError("lease does not bind the supplied permit")

    admitted_at = _format_timestamp(admitted_time)
    reservation_expires_at = _format_timestamp(min(permit_expires, lease_expires))
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
        permit_nonce_sha256=permit_nonce_sha256,
        accounting_policy_ref=quotas["accounting_policy_ref"],
        budget_scope_ref=quotas["budget_scope_ref"],
        claims=claims,
        provider=quotas["provider"],
        scope_limit_cost_units=scope_limit_cost_units,
        trial_ref=quotas["trial_ref"],
        reservation_cost_units=reservation_cost_units,
        reservation_expires_at=reservation_expires_at,
        job_idempotency_key=job_payload["idempotency_key"],
        contour=job_spec["contour"],
        classification=job_spec["classification"],
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
    resource_limits = payload["resource_limits"]
    _expect_object(resource_limits, "job_spec.payload.resource_limits")
    _expect_exact_keys(
        resource_limits,
        _JOB_RESOURCE_LIMIT_KEYS,
        "job_spec.payload.resource_limits",
    )
    _expect_positive_safe_integer(
        resource_limits["cost_units"],
        "job_spec.payload.resource_limits.cost_units",
    )


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
    quotas = payload["quotas"]
    _expect_object(quotas, "permit.payload.quotas")
    _expect_exact_keys(quotas, _PERMIT_QUOTA_KEYS, "permit.payload.quotas")
    _expect_content_addressed_reference(
        quotas["accounting_policy_ref"],
        _ACCOUNTING_POLICY_REF,
        "permit.payload.quotas.accounting_policy_ref",
    )
    _expect_content_addressed_reference(
        quotas["budget_scope_ref"],
        _BUDGET_SCOPE_REF,
        "permit.payload.quotas.budget_scope_ref",
    )
    _expect_positive_safe_integer(quotas["claims"], "permit.payload.quotas.claims")
    _expect_nonempty_string(quotas["provider"], "permit.payload.quotas.provider")
    _expect_nonempty_string(quotas["trial_ref"], "permit.payload.quotas.trial_ref")
    scope_limit = quotas["scope_limit"]
    _expect_object(scope_limit, "permit.payload.quotas.scope_limit")
    _expect_exact_keys(
        scope_limit,
        _SCOPE_LIMIT_KEYS,
        "permit.payload.quotas.scope_limit",
    )
    _expect_positive_safe_integer(
        scope_limit["cost_units"],
        "permit.payload.quotas.scope_limit.cost_units",
    )
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


def _expect_positive_safe_integer(value: Any, path: str) -> None:
    if type(value) is not int or value < 1 or value > _MAX_SAFE_INTEGER:
        raise AdmissionError(f"{path} must be a positive safe integer")


def _expect_content_addressed_reference(
    value: Any,
    pattern: re.Pattern[str],
    path: str,
) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AdmissionError(f"{path} must be a content-addressed budget reference")


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


# ---------------------------------------------------------------------------
# Additive A1 discovery/admission fixture
# ---------------------------------------------------------------------------

_A1_SOURCE_TRIGGER_KEYS = {
    "trigger_id",
    "collector_id",
    "source_ref",
    "source_content_sha256",
    "observed_at",
    "summary",
    "evidence_refs",
    "transport_idempotency_key",
}
_A1_RESOURCE_KEYS = {
    "wall_seconds",
    "cpu_seconds",
    "memory_mib",
    "output_bytes",
    "tokens",
    "cost_units",
}
_A1_SNAPSHOT_KEYS = {
    "candidate_ref",
    "candidate_sha256",
    "ledger_revision",
    "as_of",
    "policy_valid",
    "policy_sha256",
    "context_sha256",
    "classification",
    "budget_state",
    "vcs_identity",
    "executor_capability_refs",
    "evaluator_capability_refs",
    "model_route_proof_ref",
    "algorithm_version",
}
_A1_BUDGET_STATE_KEYS = {
    "available_cost_units",
    "available_tokens",
    "cycle_admitted",
    "daily_admitted",
    "wip_available",
    "active_reservations",
}
_A1_MATERIALITY_DECISIONS = frozenset(
    {
        "MATERIAL",
        "NON_MATERIAL",
        "DUPLICATE_EXACT",
        "WAIT_DATA",
        "WAIT_BUDGET",
        "REJECTED_POLICY",
    }
)


class _A1AdmissionError(AdmissionError):
    """A frozen A1 contract, profile, trigger, snapshot, or draft failed closed."""


@dataclass(frozen=True, slots=True)
class _MaterialityResult:
    """Pure result of the pre-model materiality gate."""

    decision: str
    reason_code: str
    exact_key_sha256: str
    material_event: Mapping[str, object] | None
    model_calls_consumed: int = 0

    def __post_init__(self) -> None:
        if self.decision not in _A1_MATERIALITY_DECISIONS:
            raise A1AdmissionError("unknown materiality decision")
        _a1_sha(self.exact_key_sha256, "exact_key_sha256")
        if self.model_calls_consumed != 0:
            raise A1AdmissionError("MaterialityGate cannot consume model calls")
        if (self.decision == "MATERIAL") != (self.material_event is not None):
            raise A1AdmissionError("only MATERIAL may carry a MaterialEvent")


@dataclass(frozen=True, slots=True)
class _A1AdmissionSnapshot:
    """Immutable, exact-revision input to the pure A1 admission algorithm."""

    payload: Mapping[str, object]
    sha256: str

    def __post_init__(self) -> None:
        copied = _a1_json_copy(dict(self.payload), "admission_snapshot")
        if set(copied) != _A1_SNAPSHOT_KEYS:
            raise A1AdmissionError("admission snapshot shape mismatch")
        expected = canonical_json_sha256(copied)
        if not hmac.compare_digest(expected, self.sha256):
            raise A1AdmissionError("admission snapshot digest mismatch")
        object.__setattr__(self, "payload", MappingProxyType(copied))

    def to_mapping(self) -> dict[str, object]:
        return _a1_json_copy(dict(self.payload), "admission_snapshot")


@dataclass(frozen=True, slots=True)
class _A1AdmissionDecision:
    """A deterministic policy receipt that explicitly grants no execution authority."""

    decision: str
    decision_key_sha256: str
    receipt: Mapping[str, object]
    grants_execution_authority: bool = False

    def __post_init__(self) -> None:
        if self.decision not in {"ADMIT", "REJECT", "PARK"}:
            raise A1AdmissionError("unknown A1 admission decision")
        _a1_sha(self.decision_key_sha256, "decision_key_sha256")
        if self.grants_execution_authority is not False:
            raise A1AdmissionError("AdmissionReceipt cannot grant execution authority")
        copied = _a1_json_copy(dict(self.receipt), "admission_receipt")
        if copied.get("schema_id") != "AdmissionReceipt":
            raise A1AdmissionError("admission decision receipt type mismatch")
        if copied.get("payload", {}).get("decision") != self.decision:
            raise A1AdmissionError("admission decision and receipt mismatch")
        object.__setattr__(self, "receipt", MappingProxyType(copied))

    def to_mapping(self) -> dict[str, object]:
        return _a1_json_copy(dict(self.receipt), "admission_receipt")


class _A1AdmissionKernel:
    """Pure E1A fixture bound to the frozen additive contract bundle.

    This class has no database, model, network, permit, or canonical-writer
    capability. E1B may persist its outputs only through the existing durable
    control plane after a new stage is admitted.
    """

    def __init__(
        self,
        contract_root: str | Path,
        *,
        expected_a1_catalog_sha256: str,
        expected_core_catalog_sha256: str,
    ) -> None:
        if isinstance(contract_root, bytes) or not isinstance(contract_root, (str, Path)):
            raise A1AdmissionError("contract_root must be a filesystem path")
        root = Path(contract_root)
        catalog_path = root / "a1" / "v1" / "catalog.json"
        core_path = root / "catalog.json"
        try:
            catalog_bytes = catalog_path.read_bytes()
            catalog = _a1_load_json_bytes(catalog_bytes, "a1 catalog")
            core_bytes = core_path.read_bytes()
        except OSError as exc:
            raise A1AdmissionError("frozen contract bundle is unavailable") from exc
        _a1_sha(expected_a1_catalog_sha256, "expected_a1_catalog_sha256")
        _a1_sha(expected_core_catalog_sha256, "expected_core_catalog_sha256")
        catalog_sha = hashlib.sha256(catalog_bytes).hexdigest()
        if not hmac.compare_digest(catalog_sha, expected_a1_catalog_sha256):
            raise A1AdmissionError("A1 catalog does not match the trusted frozen digest")
        if catalog.get("status") != "frozen" or catalog.get("schema_version") != "1.0.0":
            raise A1AdmissionError("A1 catalog is not frozen at version 1.0.0")
        core_sha = hashlib.sha256(core_bytes).hexdigest()
        if not hmac.compare_digest(core_sha, expected_core_catalog_sha256):
            raise A1AdmissionError("Core catalog does not match the trusted frozen digest")
        if catalog.get("core_catalog_sha256") != core_sha:
            raise A1AdmissionError("A1 catalog Core binding mismatch")
        if catalog.get("integrity_profile_id") != "core-json-sha256-v1":
            raise A1AdmissionError("unsupported A1 integrity profile")

        profiles: dict[str, dict[str, object]] = {}
        manifest = catalog.get("profile_manifest")
        if not isinstance(manifest, dict):
            raise A1AdmissionError("A1 profile manifest is invalid")
        for name, entry_value in manifest.items():
            if not isinstance(name, str) or not isinstance(entry_value, dict):
                raise A1AdmissionError("A1 profile manifest entry is invalid")
            if set(entry_value) != {"ref", "sha256"}:
                raise A1AdmissionError("A1 profile manifest entry shape mismatch")
            reference = entry_value["ref"]
            expected_sha = entry_value["sha256"]
            if not isinstance(reference, str):
                raise A1AdmissionError("A1 profile reference is invalid")
            _a1_sha(expected_sha, f"profile_manifest.{name}.sha256")
            path = catalog_path.parent / reference
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise A1AdmissionError(f"A1 profile is unavailable: {name}") from exc
            if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected_sha):
                raise A1AdmissionError(f"A1 profile hash mismatch: {name}")
            profile = _a1_load_json_bytes(content, f"A1 profile {name}")
            if profile.get("status") != "frozen":
                raise A1AdmissionError(f"A1 profile is not frozen: {name}")
            profiles[name] = profile

        for required in (
            "a1_sandbox_policy",
            "reason_codes",
            "writer_issuer_matrix",
        ):
            if required not in profiles:
                raise A1AdmissionError(f"required A1 profile missing: {required}")
        contracts = catalog.get("contracts")
        if not isinstance(contracts, dict) or set(contracts) != {
            "MaterialEvent",
            "CandidateSpecDraft",
            "AdmissionReceipt",
            "CapabilityProofReceipt",
        }:
            raise A1AdmissionError("unexpected frozen A1 contract set")

        self._catalog = MappingProxyType(_a1_json_copy(catalog, "a1 catalog"))
        self._profiles = MappingProxyType(profiles)
        self._catalog_sha256 = catalog_sha
        self._core_catalog_sha256 = core_sha

    @property
    def catalog_sha256(self) -> str:
        return self._catalog_sha256

    @property
    def core_catalog_sha256(self) -> str:
        return self._core_catalog_sha256

    def materialize_source_trigger(
        self,
        trigger: Mapping[str, object],
        *,
        issued_at: datetime | str,
        policy_sha256: str,
        context_sha256: str,
        classification: str,
        ledger_revision: int,
        root_energy: Mapping[str, object],
        remaining_energy: Mapping[str, object],
        allowed_collectors: Sequence[str],
        allowed_source_prefixes: Sequence[str],
        seen_exact_sha256: Sequence[str] = (),
        active_branch: bool = True,
        budget_available: bool = True,
        wip_available: bool = True,
        suppressed_event_kinds: Sequence[str] = (),
        max_source_age_seconds: int = 86_400,
    ) -> MaterialityResult:
        """Gate one untrusted trigger and mint trusted fields only when material."""

        value = _a1_exact_mapping(trigger, _A1_SOURCE_TRIGGER_KEYS, "source_trigger")
        for field in (
            "trigger_id",
            "collector_id",
            "source_ref",
            "summary",
            "transport_idempotency_key",
        ):
            _a1_text(value[field], f"source_trigger.{field}", maximum=4096)
        _a1_sha(value["source_content_sha256"], "source_trigger.source_content_sha256")
        observed = _a1_timestamp(value["observed_at"], "source_trigger.observed_at")
        evidence_refs = _a1_string_array(
            value["evidence_refs"], "source_trigger.evidence_refs", allow_empty=True
        )
        minted_at = _parse_now(issued_at)
        _a1_sha(policy_sha256, "policy_sha256")
        _a1_sha(context_sha256, "context_sha256")
        if classification not in {"D0", "D1"}:
            raise A1AdmissionError("trusted classification must be D0 or D1")
        _a1_nonnegative_integer(ledger_revision, "ledger_revision")
        trusted_root_energy = _a1_resource_budget(root_energy, "root_energy")
        trusted_remaining = _a1_resource_budget(remaining_energy, "remaining_energy")
        for field in _A1_RESOURCE_KEYS:
            if trusted_remaining[field] > trusted_root_energy[field]:
                raise A1AdmissionError(
                    f"remaining_energy.{field} exceeds root_energy.{field}"
                )
        allowed_collector_set = _a1_text_set(allowed_collectors, "allowed_collectors")
        allowed_prefixes = _a1_text_set(allowed_source_prefixes, "allowed_source_prefixes")
        seen = _a1_sha_set(seen_exact_sha256, "seen_exact_sha256")
        suppressed = _a1_text_set(suppressed_event_kinds, "suppressed_event_kinds")
        if type(active_branch) is not bool or type(budget_available) is not bool or type(wip_available) is not bool:
            raise A1AdmissionError("materiality booleans must be strict booleans")
        if type(max_source_age_seconds) is not int or max_source_age_seconds < 0:
            raise A1AdmissionError("max_source_age_seconds must be non-negative")

        exact_key = canonical_json_sha256(
            {
                "source_content_sha256": value["source_content_sha256"],
                "source_ref": value["source_ref"],
            }
        )
        collector_allowed = value["collector_id"] in allowed_collector_set
        source_allowed = any(value["source_ref"].startswith(prefix) for prefix in allowed_prefixes)
        if not collector_allowed or not source_allowed:
            return MaterialityResult(
                "REJECTED_POLICY", "REJECTED_POLICY", exact_key, None
            )
        if not evidence_refs or observed > minted_at or (minted_at - observed).total_seconds() > max_source_age_seconds:
            return MaterialityResult("WAIT_DATA", "WAIT_DATA", exact_key, None)
        if exact_key in seen:
            return MaterialityResult(
                "DUPLICATE_EXACT", "DUPLICATE_EXACT", exact_key, None
            )
        event_kind = "SOURCE_DISCOVERY"
        if event_kind in suppressed:
            return MaterialityResult("NON_MATERIAL", "NON_MATERIAL", exact_key, None)
        if (
            not active_branch
            or not budget_available
            or not wip_available
            or trusted_remaining["tokens"] <= 0
            or trusted_remaining["cost_units"] <= 0
        ):
            return MaterialityResult("WAIT_BUDGET", "WAIT_BUDGET", exact_key, None)

        event_id = f"material-event:{exact_key}"
        payload: dict[str, object] = {
            "event_id": event_id,
            "origin_class": "EXOGENOUS",
            "origin_trigger_ref": f"source-trigger:{value['trigger_id']}",
            "event_kind": event_kind,
            "root_event_ref": event_id,
            "parent_event_ref": None,
            "policy_sha256": policy_sha256,
            "context_sha256": context_sha256,
            "root_energy": trusted_root_energy,
            "remaining_energy": trusted_remaining,
            "causal_depth": 0,
            "shadow_taint": "NONE",
            "evidence_refs": evidence_refs,
            "materiality_inputs": {
                "collector_id": value["collector_id"],
                "exact_key_sha256": exact_key,
                "source_content_sha256": value["source_content_sha256"],
                "source_ref": value["source_ref"],
            },
            "created_from_ledger_sequence": ledger_revision,
        }
        event = {
            "schema_id": "MaterialEvent",
            "schema_version": "1.0.0",
            "object_id": event_id,
            "issued_at": _format_timestamp(minted_at),
            "issuer": "trusted-event-minter",
            "contour": "bridge",
            "classification": classification,
            "payload": payload,
            "integrity": {
                "profile_id": "core-json-sha256-v1",
                "payload_sha256": canonical_json_sha256(payload),
                "parent_refs": [
                    f"source-trigger:{value['trigger_id']}",
                    f"sha256:{exact_key}",
                ],
            },
        }
        return MaterialityResult(
            "MATERIAL",
            "MATERIAL",
            exact_key,
            MappingProxyType(_a1_json_copy(event, "material_event")),
        )

    def freeze_admission_snapshot(
        self,
        candidate: Mapping[str, object],
        *,
        ledger_revision: int,
        as_of: datetime | str,
        current_head_sha: str,
        base_sha: str,
        worktree_clean: bool,
        release_manifest_sha256: str,
        context_sha256: str,
        available_cost_units: int | float,
        available_tokens: int,
        cycle_admitted: int,
        daily_admitted: int,
        wip_available: bool,
        active_reservations: Sequence[str],
        executor_capability_refs: Sequence[str],
        evaluator_capability_refs: Sequence[str],
        model_route_proof_ref: str,
    ) -> A1AdmissionSnapshot:
        """Freeze consistent read inputs; E1B will supply them from one transaction."""

        candidate_copy, candidate_payload = self._validate_candidate(candidate)
        _a1_nonnegative_integer(ledger_revision, "ledger_revision")
        frozen_at = _parse_now(as_of)
        if _a1_timestamp(candidate_copy["issued_at"], "candidate.issued_at") > frozen_at:
            raise A1AdmissionError("candidate is not yet issued at snapshot time")
        _a1_git_sha(current_head_sha, "current_head_sha")
        _a1_git_sha(base_sha, "base_sha")
        if type(worktree_clean) is not bool:
            raise A1AdmissionError("worktree_clean must be a strict boolean")
        _a1_sha(release_manifest_sha256, "release_manifest_sha256")
        _a1_sha(context_sha256, "context_sha256")
        available_cost = _a1_nonnegative_number(
            available_cost_units, "available_cost_units"
        )
        _a1_nonnegative_integer(available_tokens, "available_tokens")
        _a1_nonnegative_integer(cycle_admitted, "cycle_admitted")
        _a1_nonnegative_integer(daily_admitted, "daily_admitted")
        if type(wip_available) is not bool:
            raise A1AdmissionError("wip_available must be a strict boolean")
        reservations = _a1_string_array(
            active_reservations, "active_reservations", allow_empty=True
        )
        executor_refs = _a1_string_array(
            executor_capability_refs, "executor_capability_refs", allow_empty=True
        )
        evaluator_refs = _a1_string_array(
            evaluator_capability_refs, "evaluator_capability_refs", allow_empty=True
        )
        _a1_text(model_route_proof_ref, "model_route_proof_ref", maximum=512)

        vcs = candidate_payload["vcs_identity"]
        snapshot_payload: dict[str, object] = {
            "candidate_ref": candidate_copy["object_id"],
            "candidate_sha256": canonical_json_sha256(candidate_copy),
            "ledger_revision": ledger_revision,
            "as_of": _format_timestamp(frozen_at),
            "policy_valid": True,
            "policy_sha256": candidate_payload["policy_sha256"],
            "context_sha256": context_sha256,
            "classification": candidate_copy["classification"],
            "budget_state": {
                "available_cost_units": available_cost,
                "available_tokens": available_tokens,
                "cycle_admitted": cycle_admitted,
                "daily_admitted": daily_admitted,
                "wip_available": wip_available,
                "active_reservations": reservations,
            },
            "vcs_identity": {
                "current_head_sha": current_head_sha,
                "base_sha": base_sha,
                "worktree_clean": worktree_clean,
                "core_catalog_sha256": self._core_catalog_sha256,
                "a1_catalog_sha256": self._catalog_sha256,
                "release_manifest_sha256": release_manifest_sha256,
                "candidate_head_sha": vcs["head_sha"],
                "candidate_base_sha": vcs["base_sha"],
                "candidate_worktree_clean": vcs["worktree_clean"],
                "candidate_core_catalog_sha256": vcs["contract_catalog_sha256"],
                "candidate_a1_catalog_sha256": vcs["a1_catalog_sha256"],
                "candidate_release_manifest_sha256": vcs["release_manifest_sha256"],
            },
            "executor_capability_refs": executor_refs,
            "evaluator_capability_refs": evaluator_refs,
            "model_route_proof_ref": model_route_proof_ref,
            "algorithm_version": "a1-admission-v1",
        }
        return A1AdmissionSnapshot(
            payload=MappingProxyType(snapshot_payload),
            sha256=canonical_json_sha256(snapshot_payload),
        )

    def evaluate_candidate(
        self,
        candidate: Mapping[str, object],
        snapshot: A1AdmissionSnapshot,
    ) -> A1AdmissionDecision:
        """Return the pure admission receipt for exact candidate/snapshot bytes."""

        candidate_copy, payload = self._validate_candidate(candidate)
        if not isinstance(snapshot, A1AdmissionSnapshot):
            raise A1AdmissionError("snapshot must be A1AdmissionSnapshot")
        frozen = snapshot.to_mapping()
        if set(frozen) != _A1_SNAPSHOT_KEYS:
            raise A1AdmissionError("admission snapshot shape mismatch")
        candidate_sha = canonical_json_sha256(candidate_copy)
        if frozen["candidate_ref"] != candidate_copy["object_id"] or not hmac.compare_digest(
            frozen["candidate_sha256"], candidate_sha
        ):
            raise A1AdmissionError("snapshot does not bind the supplied candidate")
        if frozen["algorithm_version"] != "a1-admission-v1":
            raise A1AdmissionError("unsupported admission algorithm version")

        decision_key = canonical_json_sha256(
            {
                "admission_algorithm_version": "a1-admission-v1",
                "admission_snapshot_sha256": snapshot.sha256,
                "candidate_sha256": candidate_sha,
            }
        )
        decision, reason = self._decision_for(payload, candidate_copy, frozen)
        reason_entry = self._reason_entry(reason)
        disclosure = reason_entry["disclosure"]
        public_codes = [reason] if disclosure == "PUBLIC" else []
        if decision == "ADMIT":
            budget_action = "RESERVED"
            reservation_ref: str | None = f"budget-reservation:{decision_key}"
            spec_sha: str | None = candidate_sha
            retry_trigger: str | None = None
        elif decision == "PARK":
            budget_action = "PARKED"
            reservation_ref = None
            spec_sha = None
            retry_trigger = (
                "AUTHORIZED_TAINT_APPLICATION"
                if reason == "SHADOW_TAINT_RESTRICTED"
                else "BUDGET_OR_CAPABILITY_CHANGE"
            )
        else:
            budget_action = "NONE"
            reservation_ref = None
            spec_sha = None
            retry_trigger = "CANDIDATE_REVISION"

        receipt_id = f"admission-receipt:{decision_key}"
        receipt_payload: dict[str, object] = {
            "receipt_id": receipt_id,
            "candidate_ref": candidate_copy["object_id"],
            "candidate_sha256": candidate_sha,
            "admission_snapshot_sha256": snapshot.sha256,
            "algorithm_version": "a1-admission-v1",
            "decision_key_sha256": decision_key,
            "ledger_revision": frozen["ledger_revision"],
            "evaluated_at": frozen["as_of"],
            "decision": decision,
            "reason_codes": [reason],
            "public_reason_codes": public_codes,
            "disclosure_classes": [disclosure],
            "budget_action": budget_action,
            "retry_trigger": retry_trigger,
            "reservation_ref": reservation_ref,
            "spec_sha256": spec_sha,
            "core_catalog_sha256": self._core_catalog_sha256,
            "a1_catalog_sha256": self._catalog_sha256,
            "policy_sha256": payload["policy_sha256"],
            "context_sha256": frozen["context_sha256"],
            "release_manifest_sha256": frozen["vcs_identity"]["release_manifest_sha256"],
            "transport_idempotency_key": f"admission:{decision_key}",
        }
        receipt: dict[str, object] = {
            "schema_id": "AdmissionReceipt",
            "schema_version": "1.0.0",
            "object_id": f"admission-object:{canonical_json_sha256(receipt_payload)}",
            "issued_at": frozen["as_of"],
            "issuer": "a1-admission-validator",
            "contour": "bridge",
            "classification": candidate_copy["classification"],
            "payload": receipt_payload,
            "integrity": {
                "profile_id": "core-json-sha256-v1",
                "payload_sha256": canonical_json_sha256(receipt_payload),
                "parent_refs": [
                    f"candidate:{candidate_copy['object_id']}",
                    f"sha256:{candidate_sha}",
                    f"sha256:{snapshot.sha256}",
                ],
            },
        }
        return A1AdmissionDecision(
            decision=decision,
            decision_key_sha256=decision_key,
            receipt=MappingProxyType(receipt),
        )

    def _decision_for(
        self,
        payload: dict[str, object],
        candidate: dict[str, object],
        snapshot: dict[str, object],
    ) -> tuple[str, str]:
        policy = self._profiles["a1_sandbox_policy"]
        if snapshot["policy_valid"] is not True:
            return "REJECT", "POLICY_MISMATCH"
        if payload["policy_sha256"] != snapshot["policy_sha256"]:
            return "REJECT", "POLICY_MISMATCH"
        if payload["context_sha256"] != snapshot["context_sha256"]:
            return "REJECT", "CONTEXT_MISMATCH"
        if candidate["classification"] != snapshot["classification"]:
            return "REJECT", "CONTEXT_MISMATCH"

        vcs = payload["vcs_identity"]
        frozen_vcs = snapshot["vcs_identity"]
        if (
            vcs["head_sha"] != frozen_vcs["current_head_sha"]
            or vcs["base_sha"] != frozen_vcs["base_sha"]
            or vcs["worktree_clean"] is not True
            or frozen_vcs["worktree_clean"] is not True
        ):
            return "REJECT", "STALE_VCS_IDENTITY"
        if (
            vcs["contract_catalog_sha256"] != self._core_catalog_sha256
            or vcs["a1_catalog_sha256"] != self._catalog_sha256
            or vcs["release_manifest_sha256"] != frozen_vcs["release_manifest_sha256"]
        ):
            return "REJECT", "MIXED_VCS_IDENTITY"

        if not payload["evidence_refs"]:
            return "REJECT", "EMPTY_EVIDENCE_REFS"
        if payload["experiment_type"] not in set(policy["allowed_experiment_types"]):
            return "REJECT", "FORBIDDEN_DATA_CLASS"
        if not set(payload["data_classes"]) <= set(policy["allowed_data_classes"]):
            return "REJECT", "FORBIDDEN_DATA_CLASS"
        deny_flags = (
            ("holdout_access_requested", "HOLDOUT_ACCESS_DENIED"),
            ("private_api_requested", "PRIVATE_API_DENIED"),
            ("live_execution_requested", "LIVE_EXECUTION_DENIED"),
            ("canonical_write_requested", "CANONICAL_WRITE_DENIED"),
        )
        for field, code in deny_flags:
            if payload[field] is True:
                return "REJECT", code
        if payload["network_required"] is True:
            return "REJECT", "UNKNOWN_VALIDATION_FAILURE"
        if payload["shadow_taint"] == "SHADOW_UNAPPLIED":
            return "PARK", "SHADOW_TAINT_RESTRICTED"

        limits = policy["cycle_limits"]
        request = payload["resource_request"]
        for field in (
            "wall_seconds",
            "cpu_seconds",
            "memory_mib",
            "output_bytes",
            "tokens",
            "cost_units",
        ):
            limit_field = "max_" + field
            if request[field] > limits[limit_field]:
                return "PARK", "BUDGET_EXHAUSTED"
        budget = snapshot["budget_state"]
        if (
            budget["cycle_admitted"] >= limits["max_admitted_experiments"]
            or budget["daily_admitted"]
            >= policy["daily_limits"]["max_admitted_experiments"]
            or budget["wip_available"] is not True
            or request["cost_units"] > budget["available_cost_units"]
            or request["tokens"] > budget["available_tokens"]
        ):
            return "PARK", "BUDGET_EXHAUSTED"
        if not snapshot["executor_capability_refs"] or not snapshot["evaluator_capability_refs"]:
            return "PARK", "BUDGET_EXHAUSTED"
        return "ADMIT", "ADMITTED_A1"

    def _reason_entry(self, code: str) -> dict[str, object]:
        codes = self._profiles["reason_codes"].get("codes")
        if not isinstance(codes, dict) or code not in codes:
            raise A1AdmissionError("admission algorithm selected an unknown reason code")
        entry = codes[code]
        if not isinstance(entry, dict):
            raise A1AdmissionError("reason code registry entry is invalid")
        return entry

    def _validate_candidate(
        self, candidate: Mapping[str, object]
    ) -> tuple[dict[str, object], dict[str, object]]:
        value = _a1_exact_mapping(candidate, _COMMON_KEYS, "candidate")
        if value["schema_id"] != "CandidateSpecDraft" or value["schema_version"] != "1.0.0":
            raise A1AdmissionError("candidate schema identity mismatch")
        _a1_text(value["object_id"], "candidate.object_id", maximum=256)
        _a1_timestamp(value["issued_at"], "candidate.issued_at")
        if value["issuer"] != "proposal-ingestor":
            raise A1AdmissionError("candidate issuer is invalid")
        if value["contour"] != "bridge":
            raise A1AdmissionError("candidate contour is invalid")
        if value["classification"] not in {"D0", "D1"}:
            raise A1AdmissionError("candidate classification is invalid")

        spec = self._catalog["contracts"]["CandidateSpecDraft"]
        required = set(spec["payload_required"])
        payload = _a1_exact_mapping(value["payload"], required, "candidate.payload")
        for field in (
            "candidate_id",
            "event_ref",
            "root_event_ref",
            "experiment_type",
            "estimand",
            "null_hypothesis",
            "falsifier",
            "stop_condition",
            "scope",
            "expected_output",
            "executor_family",
        ):
            _a1_text(payload[field], f"candidate.payload.{field}", maximum=4096)
        _a1_positive_integer(payload["draft_revision"], "candidate.payload.draft_revision")
        payload["evidence_refs"] = _a1_string_array(
            payload["evidence_refs"], "candidate.payload.evidence_refs", allow_empty=True
        )
        groups = payload["evidence_independence_groups"]
        if not isinstance(groups, list) or not groups:
            raise A1AdmissionError("evidence_independence_groups must be non-empty")
        payload["evidence_independence_groups"] = [
            _a1_string_array(group, f"evidence_independence_groups[{index}]", allow_empty=False)
            for index, group in enumerate(groups)
        ]
        payload["model_call_refs"] = _a1_string_array(
            payload["model_call_refs"], "candidate.payload.model_call_refs", allow_empty=True
        )
        payload["critique_refs"] = _a1_string_array(
            payload["critique_refs"], "candidate.payload.critique_refs", allow_empty=True
        )
        payload["data_classes"] = _a1_string_array(
            payload["data_classes"], "candidate.payload.data_classes", allow_empty=False
        )
        payload["resource_request"] = _a1_resource_budget(
            payload["resource_request"], "candidate.payload.resource_request"
        )
        for field in (
            "network_required",
            "holdout_access_requested",
            "canonical_write_requested",
            "private_api_requested",
            "live_execution_requested",
        ):
            if type(payload[field]) is not bool:
                raise A1AdmissionError(f"candidate.payload.{field} must be a boolean")
        if payload["shadow_taint"] not in {"NONE", "SHADOW_UNAPPLIED"}:
            raise A1AdmissionError("candidate shadow_taint is invalid")
        _a1_sha(payload["policy_sha256"], "candidate.payload.policy_sha256")
        _a1_sha(payload["context_sha256"], "candidate.payload.context_sha256")

        vcs_keys = {
            "repository_id",
            "head_sha",
            "base_sha",
            "worktree_clean",
            "contract_catalog_sha256",
            "a1_catalog_sha256",
            "release_manifest_sha256",
        }
        vcs = _a1_exact_mapping(payload["vcs_identity"], vcs_keys, "candidate.payload.vcs_identity")
        _a1_text(vcs["repository_id"], "candidate.payload.vcs_identity.repository_id", maximum=256)
        _a1_git_sha(vcs["head_sha"], "candidate.payload.vcs_identity.head_sha")
        _a1_git_sha(vcs["base_sha"], "candidate.payload.vcs_identity.base_sha")
        if type(vcs["worktree_clean"]) is not bool:
            raise A1AdmissionError("candidate vcs worktree_clean must be boolean")
        for field in (
            "contract_catalog_sha256",
            "a1_catalog_sha256",
            "release_manifest_sha256",
        ):
            _a1_sha(vcs[field], f"candidate.payload.vcs_identity.{field}")
        payload["vcs_identity"] = vcs

        integrity = _a1_exact_mapping(
            value["integrity"],
            {"profile_id", "payload_sha256", "parent_refs"},
            "candidate.integrity",
        )
        if integrity["profile_id"] != "core-json-sha256-v1":
            raise A1AdmissionError("candidate integrity profile mismatch")
        _a1_sha(integrity["payload_sha256"], "candidate.integrity.payload_sha256")
        integrity["parent_refs"] = _a1_string_array(
            integrity["parent_refs"], "candidate.integrity.parent_refs", allow_empty=True
        )
        if not hmac.compare_digest(
            integrity["payload_sha256"], canonical_json_sha256(payload)
        ):
            raise A1AdmissionError("candidate payload integrity mismatch")
        value["payload"] = payload
        value["integrity"] = integrity
        return value, payload


def _a1_load_json_bytes(content: bytes, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_a1_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                A1AdmissionError(f"{label} contains non-finite {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise A1AdmissionError(f"{label} is not strict JSON") from exc
    if not isinstance(decoded, dict):
        raise A1AdmissionError(f"{label} must be a JSON object")
    return decoded


def _a1_strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise A1AdmissionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _a1_json_copy(value: object, path: str) -> Any:
    _ensure_json_value(value, path)
    try:
        return json.loads(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise A1AdmissionError(f"{path} is not strict JSON") from exc


def _a1_exact_mapping(
    value: object, expected: set[str], path: str
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise A1AdmissionError(f"{path} must be an object")
    copied = _a1_json_copy(dict(value), path)
    actual = set(copied)
    if actual != expected:
        raise A1AdmissionError(
            f"{path} shape mismatch; missing={sorted(expected - actual)}; "
            f"unknown={sorted(actual - expected)}"
        )
    return copied


def _a1_text(value: object, path: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise A1AdmissionError(f"{path} must be non-empty text within {maximum} chars")
    if value != value.strip() or any(ord(char) < 32 for char in value):
        raise A1AdmissionError(f"{path} is not normalized printable text")
    return value


def _a1_timestamp(value: object, path: str) -> datetime:
    try:
        return _parse_timestamp(value, path)
    except AdmissionError as exc:
        raise A1AdmissionError(str(exc)) from exc


def _a1_sha(value: object, path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise A1AdmissionError(f"{path} must be a lowercase SHA-256 digest")
    return value


def _a1_git_sha(value: object, path: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{40}", value) is None:
        raise A1AdmissionError(f"{path} must be a 40-hex Git commit id")
    return value


def _a1_string_array(
    value: object, path: str, *, allow_empty: bool
) -> list[str]:
    if not isinstance(value, (list, tuple)) or (not allow_empty and not value):
        raise A1AdmissionError(f"{path} must be {'an' if allow_empty else 'a non-empty'} array")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        normalized = _a1_text(item, f"{path}[{index}]", maximum=512)
        if normalized in seen:
            raise A1AdmissionError(f"{path} must contain unique values")
        seen.add(normalized)
        result.append(normalized)
    return result


def _a1_text_set(value: Sequence[str], path: str) -> frozenset[str]:
    return frozenset(_a1_string_array(value, path, allow_empty=True))


def _a1_sha_set(value: Sequence[str], path: str) -> frozenset[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise A1AdmissionError(f"{path} must be a digest sequence")
    result: set[str] = set()
    for index, item in enumerate(value):
        result.add(_a1_sha(item, f"{path}[{index}]"))
    return frozenset(result)


def _a1_nonnegative_integer(value: object, path: str) -> int:
    if type(value) is not int or value < 0 or value > _MAX_SAFE_INTEGER:
        raise A1AdmissionError(f"{path} must be a non-negative safe integer")
    return value


def _a1_positive_integer(value: object, path: str) -> int:
    if type(value) is not int or value < 1 or value > _MAX_SAFE_INTEGER:
        raise A1AdmissionError(f"{path} must be a positive safe integer")
    return value


def _a1_nonnegative_number(value: object, path: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise A1AdmissionError(f"{path} must be a non-negative number")
    if not math.isfinite(float(value)) or value < 0:
        raise A1AdmissionError(f"{path} must be a finite non-negative number")
    return value


def _a1_resource_budget(value: object, path: str) -> dict[str, int | float]:
    budget = _a1_exact_mapping(value, _A1_RESOURCE_KEYS, path)
    for field in ("wall_seconds", "cpu_seconds", "memory_mib", "output_bytes"):
        _a1_positive_integer(budget[field], f"{path}.{field}")
    _a1_nonnegative_integer(budget["tokens"], f"{path}.tokens")
    _a1_nonnegative_number(budget["cost_units"], f"{path}.cost_units")
    return budget  # type: ignore[return-value]


# Public aliases preserve the frozen Stage 1 AST surface while exposing the
# additive A1 API declared by the E1A StageEnvelope.
A1AdmissionError = _A1AdmissionError
MaterialityResult = _MaterialityResult
A1AdmissionSnapshot = _A1AdmissionSnapshot
A1AdmissionDecision = _A1AdmissionDecision
A1AdmissionKernel = _A1AdmissionKernel
