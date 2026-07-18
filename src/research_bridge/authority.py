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
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import re
from types import MappingProxyType
from typing import Any, Sequence


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
_A1_RESERVATION_REF = re.compile(r"^budget-reservation:[a-f0-9]{64}$")
_A1_COMMON_KEYS = frozenset(
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
_A1_INTEGRITY_KEYS = frozenset(
    {"profile_id", "payload_sha256", "parent_refs"}
)
_A1_RECEIPT_PAYLOAD_KEYS = frozenset(
    {
        "receipt_id",
        "candidate_ref",
        "candidate_sha256",
        "admission_snapshot_sha256",
        "algorithm_version",
        "decision_key_sha256",
        "ledger_revision",
        "evaluated_at",
        "decision",
        "reason_codes",
        "public_reason_codes",
        "disclosure_classes",
        "budget_action",
        "retry_trigger",
        "reservation_ref",
        "spec_sha256",
        "core_catalog_sha256",
        "a1_catalog_sha256",
        "policy_sha256",
        "context_sha256",
        "release_manifest_sha256",
        "transport_idempotency_key",
    }
)
_A1_CANDIDATE_PAYLOAD_KEYS = frozenset(
    {
        "candidate_id",
        "event_ref",
        "root_event_ref",
        "draft_revision",
        "experiment_type",
        "estimand",
        "null_hypothesis",
        "falsifier",
        "stop_condition",
        "scope",
        "expected_output",
        "evidence_refs",
        "evidence_independence_groups",
        "executor_family",
        "resource_request",
        "data_classes",
        "network_required",
        "holdout_access_requested",
        "canonical_write_requested",
        "private_api_requested",
        "live_execution_requested",
        "vcs_identity",
        "policy_sha256",
        "context_sha256",
        "shadow_taint",
        "model_call_refs",
        "critique_refs",
    }
)
_A1_RESOURCE_KEYS = frozenset(
    {
        "wall_seconds",
        "cpu_seconds",
        "memory_mib",
        "output_bytes",
        "tokens",
        "cost_units",
    }
)
_A1_VCS_KEYS = frozenset(
    {
        "repository_id",
        "head_sha",
        "base_sha",
        "worktree_clean",
        "contract_catalog_sha256",
        "a1_catalog_sha256",
        "release_manifest_sha256",
    }
)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


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


@dataclass(frozen=True, slots=True)
class CorridorExecutorProfile:
    """Pinned, offline-only executor identity used by the A1 authority corridor."""

    capability_ref: str
    protocol_ref: str
    code_sha256: str
    image_digest: str
    runner_identity: str
    input_ref_prefixes: tuple[str, ...] = ("cas:sha256:",)
    maximum_lifetime_seconds: int = 300
    runner_profile: str = "L0"

    def __post_init__(self) -> None:
        for field in (
            "capability_ref",
            "protocol_ref",
            "image_digest",
            "runner_identity",
        ):
            _expect_text(getattr(self, field), f"executor profile {field}")
        _expect_sha256(self.code_sha256, "executor profile code_sha256")
        if self.runner_profile != "L0":
            raise AuthorityError("authority corridor supports only the registered L0 profile")
        prefixes = tuple(self.input_ref_prefixes)
        if not prefixes or len(prefixes) != len(set(prefixes)):
            raise AuthorityError("executor input reference prefixes must be unique")
        for prefix in prefixes:
            _expect_text(prefix, "executor input reference prefix")
        object.__setattr__(self, "input_ref_prefixes", prefixes)
        if (
            type(self.maximum_lifetime_seconds) is not int
            or self.maximum_lifetime_seconds < 1
            or self.maximum_lifetime_seconds > 300
        ):
            raise AuthorityError("executor maximum lifetime must be between 1 and 300 seconds")


@dataclass(frozen=True, slots=True)
class AuthorityCorridorBundle:
    """Immutable derived authority documents; it does not itself activate execution."""

    job_spec: Mapping[str, Any]
    permit: Mapping[str, Any]
    attempt_lease: Mapping[str, Any]
    admission_receipt_ref: str
    reservation_ref: str

    def __post_init__(self) -> None:
        job = _copy_json_object(self.job_spec, "corridor JobSpec")
        permit = _copy_json_object(self.permit, "corridor Permit")
        lease = _copy_json_object(self.attempt_lease, "corridor AttemptLease")
        _expect_text(self.admission_receipt_ref, "admission_receipt_ref")
        if _A1_RESERVATION_REF.fullmatch(self.reservation_ref) is None:
            raise AuthorityError("corridor reservation_ref is invalid")
        object.__setattr__(self, "job_spec", _deep_freeze(job))
        object.__setattr__(self, "permit", _deep_freeze(permit))
        object.__setattr__(self, "attempt_lease", _deep_freeze(lease))

    def to_mapping(self) -> dict[str, object]:
        """Return detached JSON documents for the existing researchd submit path."""

        return {
            "job_spec": _json_ready(self.job_spec),
            "permit": _json_ready(self.permit),
            "lease": _json_ready(self.attempt_lease),
        }


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

    def _trusted_issuer_document(self, schema_id: str) -> dict[str, str]:
        try:
            issuer = self._trusted_issuers[schema_id]
        except KeyError as exc:
            raise AuthorityError("authority schema issuer is not pinned") from exc
        return {
            "id": issuer.issuer_id,
            "authority_class": issuer.authority_class,
        }

    def _active_policy_until(
        self, digest: str, *, now: datetime | str
    ) -> datetime:
        _expect_sha256(digest, "policy digest")
        checked_at = _parse_now(now)
        policy = self._resolve_policy(digest)
        self._verify_policy(policy, expected_digest=digest, now=checked_at)
        payload = _expect_mapping_member(policy, "payload", "policy_snapshot")
        if "offline_execution" not in payload["covered_action_classes"]:
            raise AuthorityError("policy does not cover offline execution")
        if {"network_class": "offline"} not in payload["allow_rules"]:
            raise AuthorityError("policy does not allow the offline network class")
        if {"network_class": "connected"} not in payload["deny_rules"]:
            raise AuthorityError("policy does not deny connected execution")
        return _parse_timestamp(
            payload.get("valid_until"), "policy_snapshot.payload.valid_until"
        )

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


class A1AuthorityCorridor:
    """Derive one bounded offline JobSpec/Permit/AttemptLease chain from ADMIT."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("A1AuthorityCorridor cannot be subclassed")

    def __init__(
        self,
        *,
        authority: PinnedOfflineAuthority,
        executor_profile: CorridorExecutorProfile,
        trusted_admission_receipts: Mapping[str, Mapping[str, Any]],
        expected_core_catalog_sha256: str,
        expected_a1_catalog_sha256: str,
    ) -> None:
        if type(authority) is not PinnedOfflineAuthority:
            raise AuthorityError("corridor requires exact PinnedOfflineAuthority")
        if type(executor_profile) is not CorridorExecutorProfile:
            raise AuthorityError("corridor requires exact CorridorExecutorProfile")
        _expect_sha256(
            expected_core_catalog_sha256, "expected Core catalog digest"
        )
        _expect_sha256(expected_a1_catalog_sha256, "expected A1 catalog digest")
        self._authority = authority
        self._executor = executor_profile
        self._admission_receipts = _copy_object_mapping(
            trusted_admission_receipts,
            "trusted admission receipt resolver",
            sha256_keys=False,
        )
        self._core_catalog_sha256 = expected_core_catalog_sha256
        self._a1_catalog_sha256 = expected_a1_catalog_sha256

    def issue(
        self,
        admission_receipt: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        input_refs: Sequence[str],
        lifetime_seconds: int,
    ) -> AuthorityCorridorBundle:
        """Issue deterministic documents only; researchd/ledger still activate them."""

        receipt, receipt_payload = self._admission_receipt(admission_receipt)
        candidate_value, candidate_payload = self._candidate(candidate)
        self._bind_receipt_candidate(receipt, receipt_payload, candidate_value, candidate_payload)
        normalized_inputs = self._input_refs(input_refs, candidate_payload)
        if (
            type(lifetime_seconds) is not int
            or lifetime_seconds < 1
            or lifetime_seconds > self._executor.maximum_lifetime_seconds
        ):
            raise AuthorityError("corridor lifetime exceeds the pinned executor profile")

        issued = _parse_timestamp(receipt["issued_at"], "admission receipt issued_at")
        policy_until = self._authority._active_policy_until(
            receipt_payload["policy_sha256"], now=issued
        )
        expires = min(issued + timedelta(seconds=lifetime_seconds), policy_until)
        if expires <= issued:
            raise AuthorityError("corridor authority window is empty")
        issued_at = _format_timestamp(issued)
        expires_at = _format_timestamp(expires)
        decision_key = receipt_payload["decision_key_sha256"]
        reservation_ref = receipt_payload["reservation_ref"]
        classification = {
            "D0": "D0_PUBLIC",
            "D1": "D1_INTERNAL_SANITIZED",
        }[receipt["classification"]]
        cost_units = candidate_payload["resource_request"]["cost_units"]
        if (
            type(cost_units) is not int
            or cost_units < 1
            or cost_units > _MAX_SAFE_INTEGER
        ):
            raise AuthorityError("candidate cost_units cannot enter the integer budget ledger")

        job_payload: dict[str, object] = {
            "protocol_ref": self._executor.protocol_ref,
            "code_ref": f"sha256:{self._executor.code_sha256}",
            "input_refs": normalized_inputs,
            "image_digest": self._executor.image_digest,
            "runner_profile": self._executor.runner_profile,
            "network_policy": "offline",
            "resource_limits": {"cost_units": cost_units},
            "checkpoint_strategy": "single-final-checkpoint",
            "expected_output_contract": "StagingEnvelope@1.0.0",
            "idempotency_key": f"a1-{decision_key}",
        }
        job = _sealed_document(
            schema_id="JobSpec",
            object_id=f"job-a1-{decision_key}",
            issued_at=issued_at,
            issuer=self._authority._trusted_issuer_document("JobSpec"),
            contour="bridge",
            classification=classification,
            payload=job_payload,
            parent_refs=[
                receipt["object_id"],
                candidate_value["object_id"],
                f"sha256:{receipt_payload['candidate_sha256']}",
                f"sha256:{receipt_payload['admission_snapshot_sha256']}",
                self._executor.capability_ref,
                reservation_ref,
            ],
        )

        budget_scope_sha256 = _canonical_json_sha256(
            {
                "admission_receipt_ref": receipt["object_id"],
                "candidate_sha256": receipt_payload["candidate_sha256"],
                "cost_units": cost_units,
                "policy_sha256": receipt_payload["policy_sha256"],
                "reservation_ref": reservation_ref,
            }
        )
        permit_payload: dict[str, object] = {
            "subject": self._executor.runner_identity,
            "job_spec_sha256": _canonical_json_sha256(job),
            "policy_snapshot_sha256": receipt_payload["policy_sha256"],
            "code_sha256": self._executor.code_sha256,
            "input_sha256": _canonical_json_sha256(normalized_inputs),
            "image_digest": self._executor.image_digest,
            "quotas": {
                "accounting_policy_ref": (
                    f"budget-policy:sha256:{receipt_payload['policy_sha256']}"
                ),
                "budget_scope_ref": f"budget-scope:sha256:{budget_scope_sha256}",
                "claims": 1,
                "provider": self._executor.runner_profile,
                "scope_limit": {"cost_units": cost_units},
                "trial_ref": f"trial:a1-{decision_key}",
            },
            "network_class": "offline",
            "not_before": issued_at,
            "expires_at": expires_at,
            "max_uses": 1,
            "nonce": "a1-permit:" + _canonical_json_sha256(
                {
                    "job_spec_sha256": _canonical_json_sha256(job),
                    "reservation_ref": reservation_ref,
                }
            ),
        }
        permit = _sealed_document(
            schema_id="Permit",
            object_id=f"permit-a1-{decision_key}",
            issued_at=issued_at,
            issuer=self._authority._trusted_issuer_document("Permit"),
            contour="bridge",
            classification=classification,
            payload=permit_payload,
            parent_refs=[job["object_id"], reservation_ref, receipt["object_id"]],
        )

        fencing_epoch = receipt_payload["ledger_revision"] + 1
        if fencing_epoch > _MAX_SAFE_INTEGER:
            raise AuthorityError("corridor fencing epoch exceeds the safe integer limit")
        lease_payload: dict[str, object] = {
            "attempt_id": f"attempt-a1-{decision_key}",
            "permit_ref": permit["object_id"],
            "job_ref": job["object_id"],
            "runner_identity": self._executor.runner_identity,
            "fencing_epoch": fencing_epoch,
            "fencing_token": "fence-a1-" + _canonical_json_sha256(
                {
                    "permit_sha256": _canonical_json_sha256(permit),
                    "reservation_ref": reservation_ref,
                }
            ),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "checkpoint_parent_ref": "cas:sha256:" + "0" * 64,
        }
        lease = _sealed_document(
            schema_id="AttemptLease",
            object_id=f"lease-a1-{decision_key}",
            issued_at=issued_at,
            issuer=self._authority._trusted_issuer_document("AttemptLease"),
            contour="bridge",
            classification=classification,
            payload=lease_payload,
            parent_refs=[
                job["object_id"],
                permit["object_id"],
                reservation_ref,
            ],
        )
        return AuthorityCorridorBundle(
            job_spec=job,
            permit=permit,
            attempt_lease=lease,
            admission_receipt_ref=receipt["object_id"],
            reservation_ref=reservation_ref,
        )

    def _admission_receipt(
        self, value: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        receipt = _copy_json_object(value, "AdmissionReceipt")
        _expect_exact_keys(receipt, _A1_COMMON_KEYS, "AdmissionReceipt")
        if (
            receipt.get("schema_id") != "AdmissionReceipt"
            or receipt.get("schema_version") != "1.0.0"
            or receipt.get("issuer") != "a1-admission-validator"
            or receipt.get("contour") != "bridge"
            or receipt.get("classification") not in {"D0", "D1"}
        ):
            raise AuthorityError("AdmissionReceipt identity is invalid")
        _expect_text(receipt.get("object_id"), "AdmissionReceipt object_id")
        issued = _parse_timestamp(receipt.get("issued_at"), "AdmissionReceipt issued_at")
        payload = receipt.get("payload")
        integrity = receipt.get("integrity")
        if not isinstance(payload, dict) or not isinstance(integrity, dict):
            raise AuthorityError("AdmissionReceipt payload or integrity is invalid")
        _expect_exact_keys(payload, _A1_RECEIPT_PAYLOAD_KEYS, "AdmissionReceipt.payload")
        _expect_exact_keys(integrity, _A1_INTEGRITY_KEYS, "AdmissionReceipt.integrity")
        if integrity.get("profile_id") != "core-json-sha256-v1":
            raise AuthorityError("AdmissionReceipt integrity profile is invalid")
        _expect_sha256(integrity.get("payload_sha256"), "AdmissionReceipt payload digest")
        _expect_string_list(integrity.get("parent_refs"), "AdmissionReceipt parent refs")
        if not hmac.compare_digest(
            integrity["payload_sha256"], _canonical_json_sha256(payload)
        ):
            raise AuthorityError("AdmissionReceipt payload integrity mismatch")
        for field in (
            "candidate_sha256",
            "admission_snapshot_sha256",
            "decision_key_sha256",
            "spec_sha256",
            "core_catalog_sha256",
            "a1_catalog_sha256",
            "policy_sha256",
            "context_sha256",
            "release_manifest_sha256",
        ):
            _expect_sha256(payload.get(field), f"AdmissionReceipt.payload.{field}")
        if (
            payload.get("algorithm_version") != "a1-admission-v1"
            or payload.get("decision") != "ADMIT"
            or payload.get("reason_codes") != ["ADMITTED_A1"]
            or payload.get("public_reason_codes") != ["ADMITTED_A1"]
            or payload.get("disclosure_classes") != ["PUBLIC"]
            or payload.get("budget_action") != "RESERVED"
            or payload.get("retry_trigger") is not None
        ):
            raise AuthorityError("AdmissionReceipt does not authorize corridor issuance")
        decision_key = payload["decision_key_sha256"]
        if (
            payload.get("receipt_id") != f"admission-receipt:{decision_key}"
            or payload.get("reservation_ref") != f"budget-reservation:{decision_key}"
            or payload.get("transport_idempotency_key") != f"admission:{decision_key}"
            or receipt["object_id"] != f"admission-object:{_canonical_json_sha256(payload)}"
        ):
            raise AuthorityError("AdmissionReceipt deterministic identity is invalid")
        registered = self._admission_receipts.get(receipt["object_id"])
        if registered is None or not hmac.compare_digest(
            _canonical_json_sha256(registered), _canonical_json_sha256(receipt)
        ):
            raise AuthorityError("AdmissionReceipt is not in the trusted durable resolver")
        if payload.get("core_catalog_sha256") != self._core_catalog_sha256:
            raise AuthorityError("AdmissionReceipt Core catalog binding is stale")
        if payload.get("a1_catalog_sha256") != self._a1_catalog_sha256:
            raise AuthorityError("AdmissionReceipt A1 catalog binding is stale")
        ledger_revision = payload.get("ledger_revision")
        if (
            type(ledger_revision) is not int
            or ledger_revision < 0
            or ledger_revision >= _MAX_SAFE_INTEGER
        ):
            raise AuthorityError("AdmissionReceipt ledger revision is invalid")
        if _parse_timestamp(payload.get("evaluated_at"), "evaluated_at") != issued:
            raise AuthorityError("AdmissionReceipt evaluated_at binding is invalid")
        return receipt, payload

    def _candidate(
        self, value: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        candidate = _copy_json_object(value, "CandidateSpecDraft")
        _expect_exact_keys(candidate, _A1_COMMON_KEYS, "CandidateSpecDraft")
        if (
            candidate.get("schema_id") != "CandidateSpecDraft"
            or candidate.get("schema_version") != "1.0.0"
            or candidate.get("issuer") != "proposal-ingestor"
            or candidate.get("contour") != "bridge"
            or candidate.get("classification") not in {"D0", "D1"}
        ):
            raise AuthorityError("CandidateSpecDraft identity is invalid")
        _expect_text(candidate.get("object_id"), "CandidateSpecDraft object_id")
        _parse_timestamp(candidate.get("issued_at"), "CandidateSpecDraft issued_at")
        payload = candidate.get("payload")
        integrity = candidate.get("integrity")
        if not isinstance(payload, dict) or not isinstance(integrity, dict):
            raise AuthorityError("CandidateSpecDraft payload or integrity is invalid")
        _expect_exact_keys(payload, _A1_CANDIDATE_PAYLOAD_KEYS, "CandidateSpecDraft.payload")
        _expect_exact_keys(integrity, _A1_INTEGRITY_KEYS, "CandidateSpecDraft.integrity")
        if integrity.get("profile_id") != "core-json-sha256-v1":
            raise AuthorityError("CandidateSpecDraft integrity profile is invalid")
        _expect_sha256(integrity.get("payload_sha256"), "CandidateSpecDraft payload digest")
        _expect_string_list(integrity.get("parent_refs"), "CandidateSpecDraft parent refs")
        if not hmac.compare_digest(
            integrity["payload_sha256"], _canonical_json_sha256(payload)
        ):
            raise AuthorityError("CandidateSpecDraft payload integrity mismatch")
        if payload.get("executor_family") != "registered-offline-l0":
            raise AuthorityError("candidate executor family is not registered offline L0")
        for field in (
            "network_required",
            "holdout_access_requested",
            "canonical_write_requested",
            "private_api_requested",
            "live_execution_requested",
        ):
            if payload.get(field) is not False:
                raise AuthorityError("candidate requests forbidden execution authority")
        if payload.get("shadow_taint") != "NONE":
            raise AuthorityError("shadow-tainted candidate cannot enter execution corridor")
        resources = payload.get("resource_request")
        vcs = payload.get("vcs_identity")
        if not isinstance(resources, dict) or not isinstance(vcs, dict):
            raise AuthorityError("candidate resource or VCS binding is invalid")
        _expect_exact_keys(resources, _A1_RESOURCE_KEYS, "resource_request")
        _expect_exact_keys(vcs, _A1_VCS_KEYS, "vcs_identity")
        return candidate, payload

    def _bind_receipt_candidate(
        self,
        receipt: dict[str, Any],
        receipt_payload: dict[str, Any],
        candidate: dict[str, Any],
        candidate_payload: dict[str, Any],
    ) -> None:
        candidate_sha = _canonical_json_sha256(candidate)
        if (
            receipt_payload["candidate_ref"] != candidate["object_id"]
            or not hmac.compare_digest(receipt_payload["candidate_sha256"], candidate_sha)
            or not hmac.compare_digest(receipt_payload["spec_sha256"], candidate_sha)
            or receipt["classification"] != candidate["classification"]
            or receipt_payload["policy_sha256"] != candidate_payload["policy_sha256"]
            or receipt_payload["context_sha256"] != candidate_payload["context_sha256"]
        ):
            raise AuthorityError("AdmissionReceipt does not bind the supplied candidate")
        vcs = candidate_payload["vcs_identity"]
        if (
            vcs["contract_catalog_sha256"] != self._core_catalog_sha256
            or vcs["a1_catalog_sha256"] != self._a1_catalog_sha256
            or vcs["release_manifest_sha256"]
            != receipt_payload["release_manifest_sha256"]
            or vcs["worktree_clean"] is not True
        ):
            raise AuthorityError("candidate VCS identity is stale or mixed")

    def _input_refs(
        self, input_refs: Sequence[str], candidate_payload: dict[str, Any]
    ) -> list[str]:
        if isinstance(input_refs, (str, bytes)) or not isinstance(input_refs, Sequence):
            raise AuthorityError("corridor input_refs must be a sequence")
        normalized = list(input_refs)
        if not normalized or len(normalized) != len(set(normalized)):
            raise AuthorityError("corridor input_refs must be unique and non-empty")
        evidence = candidate_payload.get("evidence_refs")
        if not isinstance(evidence, list):
            raise AuthorityError("candidate evidence_refs are invalid")
        for reference in normalized:
            _expect_text(reference, "corridor input_ref")
            if reference not in evidence or not any(
                reference.startswith(prefix)
                for prefix in self._executor.input_ref_prefixes
            ):
                raise AuthorityError("corridor input is not an admitted registered reference")
        return normalized


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


def _copy_json_object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityError(f"{path} must be an object")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        copied = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AuthorityError(f"{path} is not strict JSON") from exc
    if not isinstance(copied, dict):
        raise AuthorityError(f"{path} must be an object")
    return copied


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sealed_document(
    *,
    schema_id: str,
    object_id: str,
    issued_at: str,
    issuer: Mapping[str, str],
    contour: str,
    classification: str,
    payload: Mapping[str, object],
    parent_refs: list[str],
) -> dict[str, object]:
    document = {
        "schema_id": schema_id,
        "schema_version": "1.0.0",
        "object_id": object_id,
        "issued_at": issued_at,
        "issuer": dict(issuer),
        "contour": contour,
        "classification": classification,
        "payload": _json_ready(payload),
        "integrity": {
            "payload_sha256": _canonical_json_sha256(payload),
            "parent_refs": list(parent_refs),
        },
    }
    return _copy_json_object(document, schema_id)


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _json_ready(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


__all__ = [
    "A1AuthorityCorridor",
    "AuthorityCorridorBundle",
    "AuthorityError",
    "CorridorExecutorProfile",
    "PinnedOfflineAuthority",
    "TrustedIssuer",
    "require_pinned_authority",
]
