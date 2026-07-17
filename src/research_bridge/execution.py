"""Structural, offline execution finalizer for the Bridge control plane.

This module composes injected boundaries and reuses the canonical ledger's
budget projection validator.  It grants no subprocess, network, domain, or
scientific-outcome authority.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from research_bridge.ledger import JobLedger, LedgerError


__all__ = [
    "ExecutionError",
    "ExecutionRecord",
    "OfflineExecutionCoordinator",
    "canonical_json_sha256",
]


_ALLOWED_CLASSIFICATIONS = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_CAS_REF_RE = re.compile(r"^cas:sha256:([a-f0-9]{64})$")
_ACCOUNTING_POLICY_REF_RE = re.compile(r"^budget-policy:sha256:[a-f0-9]{64}$")
_BUDGET_SCOPE_REF_RE = re.compile(r"^budget-scope:sha256:[a-f0-9]{64}$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_EVENT_FIELDS = frozenset(
    {
        "sequence",
        "event_type",
        "job_id",
        "attempt_id",
        "fencing_epoch",
        "event_at",
        "payload",
        "previous_sha256",
        "event_sha256",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "checkpoint",
        "staging_envelope",
        "started_at",
        "ended_at",
        "resource_usage",
        "code_sha256",
        "input_sha256",
        "environment_digest",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {"sequence", "completed_ranges", "state_sha256", "relative_path", "size_bytes"}
)
_PUBLICATION_FIELDS = frozenset({"ref", "sha256", "size_bytes", "created"})
_ARTIFACT_RECORD_FIELDS = frozenset({"artifact_ref", "manifest"})
_CHECKPOINT_EVENT_PAYLOAD_FIELDS = frozenset(
    {
        "attempt_id",
        "event_at",
        "fencing_epoch",
        "fencing_token_sha256",
        "job_id",
        "payload_ref",
        "payload_stored_in_domain_vault",
        "sequence",
        "state_sha256",
    }
)


class ExecutionError(RuntimeError):
    """A fail-closed structural, ordering, or binding failure."""


@dataclass(frozen=True, slots=True)
class _ArtifactRecordSnapshot:
    artifact_ref: str
    manifest: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    """Deeply immutable references emitted only after ledger completion."""

    checkpoint_manifest: Mapping[str, Any]
    artifact_records: tuple[_ArtifactRecordSnapshot, ...]
    execution_receipt: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _Bindings:
    job_id: str
    permit_id: str
    permit_nonce_sha256: str
    lease_id: str
    attempt_id: str
    fencing_epoch: int
    fencing_token: str
    runner_identity: str
    code_sha256: str
    input_sha256: str
    environment_digest: str
    accounting_policy_ref: str
    budget_scope_ref: str
    scope_limit_cost_units: int
    trial_ref: str
    provider: str
    job_idempotency_key: str
    reservation_cost_units: int
    reservation_expires_at: str
    contour: str
    classification: str


@dataclass(frozen=True, slots=True)
class _ResultView:
    checkpoint: object
    staging_envelope: Mapping[str, Any]
    started_at: str
    ended_at: str
    resource_usage: Mapping[str, Any]
    code_sha256: str
    input_sha256: str
    environment_digest: str


@dataclass(frozen=True, slots=True)
class _CheckpointView:
    sequence: int
    completed_ranges: tuple[Any, ...]
    state_sha256: str
    relative_path: str
    size_bytes: int


class _Kernel(Protocol):
    def claim(
        self,
        job_spec: Mapping[str, Any],
        permit: Mapping[str, Any],
        lease: Mapping[str, Any],
        *,
        now: Any,
    ) -> object: ...


class _Runner(Protocol):
    def run(
        self,
        job_spec: Mapping[str, Any],
        lease: Mapping[str, Any],
        staging_root: os.PathLike[str] | str,
    ) -> object: ...


class _Store(Protocol):
    def publish(
        self,
        source_path: os.PathLike[str] | str,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> object: ...


class _Ingestor(Protocol):
    def ingest(
        self,
        staging_envelope: Mapping[str, Any],
        staging_root: os.PathLike[str] | str,
    ) -> tuple[object, ...]: ...


def canonical_json_sha256(value: Any) -> str:
    """Return SHA-256 over strict deterministic UTF-8 JSON."""

    _ensure_json_value(value, "value")
    try:
        encoded = json.dumps(
            _json_ready(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ExecutionError("value is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


class OfflineExecutionCoordinator:
    """Finalize exactly one injected offline run with receipt-last ordering."""

    def __init__(
        self,
        kernel: _Kernel,
        ledger: object,
        runner: _Runner,
        checkpoint_store: _Store,
        ingestor: _Ingestor,
        *,
        issuer_id: str = "researchd",
    ) -> None:
        _callable_method(kernel, "claim", "kernel")
        _callable_method(ledger, "checkpoint", "ledger")
        _callable_method(ledger, "complete", "ledger")
        _callable_method(runner, "run", "runner")
        _callable_method(checkpoint_store, "publish", "checkpoint_store")
        _callable_method(ingestor, "ingest", "ingestor")
        issuer = _identifier("issuer_id", issuer_id)
        _identifier("trusted ingestor issuer_id", f"{issuer}-trusted-ingestor")
        self._kernel = kernel
        self._ledger = ledger
        self._runner = runner
        self._checkpoint_store = checkpoint_store
        self._ingestor = ingestor
        self._issuer_id = issuer

    def execute(
        self,
        job_spec: Mapping[str, Any],
        permit: Mapping[str, Any],
        lease: Mapping[str, Any],
        staging_root: os.PathLike[str] | str,
        *,
        now: Any,
    ) -> ExecutionRecord:
        """Run and finalize one mechanically successful offline attempt."""

        bindings = _authority_bindings(job_spec, permit, lease)
        staging_path = _filesystem_path(staging_root)

        try:
            claim_event = self._kernel.claim(job_spec, permit, lease, now=now)
        except Exception as exc:
            raise ExecutionError("kernel claim failed; runner was not called") from exc
        budget_claim = _validate_claim_event(claim_event, bindings)

        try:
            runner_result = self._runner.run(job_spec, lease, staging_root)
        except Exception as exc:
            raise ExecutionError("offline runner failed after the durable claim") from exc

        result = _validate_runner_result(runner_result, bindings)
        checkpoint = _validate_checkpoint(result.checkpoint)
        _validate_staging_bindings(result.staging_envelope, bindings)

        checkpoint_source = staging_path.joinpath(
            *PurePosixPath(checkpoint.relative_path).parts
        )
        checkpoint_file_sha256 = _checkpoint_file_sha256(
            staging_path,
            checkpoint.relative_path,
            checkpoint.size_bytes,
        )
        try:
            publication = self._checkpoint_store.publish(
                checkpoint_source,
                expected_sha256=checkpoint_file_sha256,
                expected_size_bytes=checkpoint.size_bytes,
            )
        except Exception as exc:
            raise ExecutionError("checkpoint CAS publication failed") from exc
        checkpoint_ref = _validate_checkpoint_publication(
            publication,
            checkpoint_file_sha256,
            checkpoint.size_bytes,
        )

        try:
            checkpoint_event = self._ledger.checkpoint(
                job_id=bindings.job_id,
                attempt_id=bindings.attempt_id,
                fencing_epoch=bindings.fencing_epoch,
                fencing_token=bindings.fencing_token,
                sequence=checkpoint.sequence,
                state_sha256=checkpoint.state_sha256,
                payload_ref=checkpoint_ref,
                payload_stored_in_domain_vault=False,
                event_at=result.ended_at,
            )
        except Exception as exc:
            raise ExecutionError("durable checkpoint ledger append failed") from exc
        checkpoint_event_at = _validate_checkpoint_event(
            checkpoint_event,
            bindings,
            checkpoint,
            checkpoint_ref,
        )

        checkpoint_manifest = _construct_checkpoint_manifest(
            bindings=bindings,
            checkpoint=checkpoint,
            checkpoint_ref=checkpoint_ref,
            claim_event_sha256=_event_sha256(claim_event, "claim_event"),
            checkpoint_event_sha256=_event_sha256(
                checkpoint_event, "checkpoint_event"
            ),
            issued_at=checkpoint_event_at,
            issuer_id=self._issuer_id,
        )

        try:
            artifact_records = self._ingestor.ingest(
                result.staging_envelope,
                staging_root,
            )
        except Exception as exc:
            raise ExecutionError("trusted artifact ingestion failed") from exc
        artifact_snapshots = _validate_artifact_records(
            artifact_records,
            contour=bindings.contour,
            classification=bindings.classification,
        )
        artifact_refs = tuple(record.artifact_ref for record in artifact_snapshots)

        completion_binding = {
            "artifact_refs": list(artifact_refs),
            "checkpoint_manifest_sha256": canonical_json_sha256(checkpoint_manifest),
        }
        result_sha256 = canonical_json_sha256(completion_binding)
        try:
            completion_event = self._ledger.complete(
                job_id=bindings.job_id,
                attempt_id=bindings.attempt_id,
                fencing_epoch=bindings.fencing_epoch,
                fencing_token=bindings.fencing_token,
                result_sha256=result_sha256,
                event_at=result.ended_at,
            )
        except Exception as exc:
            raise ExecutionError("durable completion ledger append failed") from exc
        try:
            settlement_ref = _validate_completion_event(
                completion_event,
                bindings,
                budget_claim,
                result_sha256,
                result.ended_at,
            )
            execution_receipt = _construct_execution_receipt(
                bindings=bindings,
                result=result,
                artifact_refs=artifact_refs,
                checkpoint_manifest=checkpoint_manifest,
                completion_event_sha256=_event_sha256(
                    completion_event, "completion_event"
                ),
                settlement_ref=settlement_ref,
                issuer_id=self._issuer_id,
            )
            return ExecutionRecord(
                checkpoint_manifest=checkpoint_manifest,
                artifact_records=artifact_snapshots,
                execution_receipt=execution_receipt,
            )
        except Exception as exc:
            raise ExecutionError(
                "critical post-completion receipt invariant failed"
            ) from exc


def _authority_bindings(
    job_spec: Mapping[str, Any],
    permit: Mapping[str, Any],
    lease: Mapping[str, Any],
) -> _Bindings:
    job = _mapping(job_spec, "job_spec")
    permit_value = _mapping(permit, "permit")
    lease_value = _mapping(lease, "lease")
    job_payload = _mapping(job.get("payload"), "job_spec.payload")
    permit_payload = _mapping(permit_value.get("payload"), "permit.payload")
    lease_payload = _mapping(lease_value.get("payload"), "lease.payload")
    quotas = _exact_mapping(
        permit_payload.get("quotas"),
        frozenset(
            {
                "accounting_policy_ref",
                "budget_scope_ref",
                "claims",
                "provider",
                "scope_limit",
                "trial_ref",
            }
        ),
        "permit.payload.quotas",
    )
    scope_limit = _exact_mapping(
        quotas["scope_limit"],
        frozenset({"cost_units"}),
        "permit.payload.quotas.scope_limit",
    )
    resource_limits = _exact_mapping(
        job_payload.get("resource_limits"),
        frozenset({"cost_units"}),
        "job_spec.payload.resource_limits",
    )

    classifications = (
        job.get("classification"),
        permit_value.get("classification"),
        lease_value.get("classification"),
    )
    if len(set(classifications)) != 1 or classifications[0] not in _ALLOWED_CLASSIFICATIONS:
        raise ExecutionError("JobSpec, Permit and Lease must share a D0/D1 classification")
    contours = (
        job.get("contour"),
        permit_value.get("contour"),
        lease_value.get("contour"),
    )
    if len(set(contours)) != 1:
        raise ExecutionError("JobSpec, Permit and Lease contours must match")

    job_id = _identifier("job_spec.object_id", job.get("object_id"))
    permit_id = _identifier("permit.object_id", permit_value.get("object_id"))
    if lease_payload.get("job_ref") != job_id:
        raise ExecutionError("lease.payload.job_ref does not bind JobSpec")
    if lease_payload.get("permit_ref") != permit_id:
        raise ExecutionError("lease.payload.permit_ref does not bind Permit")
    input_refs = job_payload.get("input_refs")
    if not isinstance(input_refs, list):
        raise ExecutionError("job_spec.payload.input_refs must be an array")
    input_sha256 = _sha256(
        "permit.payload.input_sha256", permit_payload.get("input_sha256")
    )
    if canonical_json_sha256(input_refs) != input_sha256:
        raise ExecutionError("Permit input digest does not bind ordered JobSpec input_refs")
    scope_limit_cost_units = _positive_safe_integer(
        "permit.payload.quotas.scope_limit.cost_units", scope_limit["cost_units"]
    )
    reservation_cost_units = _positive_safe_integer(
        "job_spec.payload.resource_limits.cost_units", resource_limits["cost_units"]
    )
    if reservation_cost_units > scope_limit_cost_units:
        raise ExecutionError("job reservation exceeds Permit budget scope")
    if quotas["claims"] != 1 or permit_payload.get("max_uses") != 1:
        raise ExecutionError("Permit budget claim authority must be exactly one")
    provider = _normalized_text("permit.payload.quotas.provider", quotas["provider"])
    if provider != job_payload.get("runner_profile"):
        raise ExecutionError("budget provider does not bind JobSpec runner profile")
    permit_expires_at = _timestamp(
        "permit.payload.expires_at", permit_payload.get("expires_at")
    )
    lease_expires_at = _timestamp(
        "lease.payload.expires_at", lease_payload.get("expires_at")
    )
    reservation_expires_at = min(
        (permit_expires_at, lease_expires_at), key=_parse_timestamp
    )

    return _Bindings(
        job_id=job_id,
        permit_id=permit_id,
        permit_nonce_sha256=hashlib.sha256(
            _normalized_text(
                "permit.payload.nonce", permit_payload.get("nonce")
            ).encode("utf-8")
        ).hexdigest(),
        lease_id=_identifier("lease.object_id", lease_value.get("object_id")),
        attempt_id=_identifier("lease.payload.attempt_id", lease_payload.get("attempt_id")),
        fencing_epoch=_nonnegative_integer(
            "lease.payload.fencing_epoch", lease_payload.get("fencing_epoch")
        ),
        fencing_token=_normalized_text(
            "lease.payload.fencing_token", lease_payload.get("fencing_token")
        ),
        runner_identity=_identifier(
            "lease.payload.runner_identity", lease_payload.get("runner_identity")
        ),
        code_sha256=_sha256(
            "permit.payload.code_sha256", permit_payload.get("code_sha256")
        ),
        input_sha256=input_sha256,
        environment_digest=_normalized_text(
            "job_spec.payload.image_digest", job_payload.get("image_digest")
        ),
        accounting_policy_ref=_pattern_text(
            "permit.payload.quotas.accounting_policy_ref",
            quotas["accounting_policy_ref"],
            _ACCOUNTING_POLICY_REF_RE,
        ),
        budget_scope_ref=_pattern_text(
            "permit.payload.quotas.budget_scope_ref",
            quotas["budget_scope_ref"],
            _BUDGET_SCOPE_REF_RE,
        ),
        scope_limit_cost_units=scope_limit_cost_units,
        trial_ref=_normalized_text(
            "permit.payload.quotas.trial_ref", quotas["trial_ref"]
        ),
        provider=provider,
        job_idempotency_key=_normalized_text(
            "job_spec.payload.idempotency_key", job_payload.get("idempotency_key")
        ),
        reservation_cost_units=reservation_cost_units,
        reservation_expires_at=reservation_expires_at,
        contour=_normalized_text("job_spec.contour", contours[0]),
        classification=classifications[0],
    )


def _validate_claim_event(event: object, bindings: _Bindings) -> Any:
    values = _exact_attributes(event, _EVENT_FIELDS, "claim_event")
    _validate_event_columns(values, "claim", bindings, "claim_event")
    try:
        projection = JobLedger._validate_budget_claim_event(event)
    except LedgerError as exc:
        raise ExecutionError("claim budget projection is invalid") from exc
    payload = projection.event.payload
    expected = {
        "accounting_policy_ref": bindings.accounting_policy_ref,
        "attempt_id": bindings.attempt_id,
        "budget_scope_ref": bindings.budget_scope_ref,
        "fencing_epoch": bindings.fencing_epoch,
        "job_id": bindings.job_id,
        "permit_id": bindings.permit_id,
        "runner_identity": bindings.runner_identity,
    }
    for key, value in expected.items():
        if payload[key] != value:
            raise ExecutionError(f"claim_event.payload.{key} binding mismatch")
    if _nonnegative_integer(
        "claim_event.payload.fencing_epoch", payload["fencing_epoch"]
    ) != bindings.fencing_epoch:
        raise ExecutionError("claim_event.payload.fencing_epoch binding mismatch")
    _sha256("claim_event.payload.admission_digest", payload["admission_digest"])
    permit_nonce_sha256 = _sha256(
        "claim_event.payload.permit_nonce_sha256",
        payload["permit_nonce_sha256"],
    )
    if not hmac.compare_digest(
        permit_nonce_sha256,
        bindings.permit_nonce_sha256,
    ):
        raise ExecutionError("claim Permit nonce digest binding mismatch")
    admitted_at = _timestamp(
        "claim_event.payload.admitted_at", payload["admitted_at"]
    )
    if admitted_at != getattr(event, "event_at"):
        raise ExecutionError("claim event timestamp columns do not match payload")
    token_sha256 = _sha256(
        "claim_event.payload.fencing_token_sha256",
        payload["fencing_token_sha256"],
    )
    if not hmac.compare_digest(
        token_sha256,
        hashlib.sha256(bindings.fencing_token.encode("utf-8")).hexdigest(),
    ):
        raise ExecutionError("claim fencing token binding mismatch")
    expected_projection = {
        "accounting_policy_ref": bindings.accounting_policy_ref,
        "budget_scope_ref": bindings.budget_scope_ref,
        "scope_limit_cost_units": bindings.scope_limit_cost_units,
        "trial_ref": bindings.trial_ref,
        "provider": bindings.provider,
        "idempotency_key": bindings.job_idempotency_key,
        "reservation_cost_units": bindings.reservation_cost_units,
        "expires_at": bindings.reservation_expires_at,
    }
    for key, expected_value in expected_projection.items():
        if getattr(projection, key) != expected_value:
            raise ExecutionError(f"claim budget {key} binding mismatch")
    if (
        projection.reservation["contour"] != bindings.contour
        or projection.reservation["classification"] != bindings.classification
    ):
        raise ExecutionError("reservation outer authority binding mismatch")
    return projection


def _validate_runner_result(result: object, bindings: _Bindings) -> _ResultView:
    values = _exact_attributes(result, _RESULT_FIELDS, "runner_result")
    code_sha256 = _sha256("runner_result.code_sha256", values["code_sha256"])
    input_sha256 = _sha256("runner_result.input_sha256", values["input_sha256"])
    environment_digest = _normalized_text(
        "runner_result.environment_digest", values["environment_digest"]
    )
    if code_sha256 != bindings.code_sha256:
        raise ExecutionError("runner result code digest does not match Permit")
    if input_sha256 != bindings.input_sha256:
        raise ExecutionError("runner result input digest does not match Permit")
    if environment_digest != bindings.environment_digest:
        raise ExecutionError("runner result environment does not match JobSpec")

    started_at = _timestamp("runner_result.started_at", values["started_at"])
    ended_at = _timestamp("runner_result.ended_at", values["ended_at"])
    if _parse_timestamp(ended_at) < _parse_timestamp(started_at):
        raise ExecutionError("runner result ended_at precedes started_at")
    resource_usage = _mapping(values["resource_usage"], "runner_result.resource_usage")
    _ensure_json_value(resource_usage, "runner_result.resource_usage")
    staging_envelope = _mapping(
        values["staging_envelope"], "runner_result.staging_envelope"
    )
    _ensure_json_value(staging_envelope, "runner_result.staging_envelope")
    detached_staging_envelope = _json_ready(staging_envelope)
    if not isinstance(detached_staging_envelope, dict):
        raise ExecutionError("runner_result.staging_envelope must detach to an object")
    return _ResultView(
        checkpoint=values["checkpoint"],
        staging_envelope=detached_staging_envelope,
        started_at=started_at,
        ended_at=ended_at,
        resource_usage=_deep_freeze(resource_usage),
        code_sha256=code_sha256,
        input_sha256=input_sha256,
        environment_digest=environment_digest,
    )


def _validate_checkpoint(checkpoint: object) -> _CheckpointView:
    values = _exact_attributes(checkpoint, _CHECKPOINT_FIELDS, "runner_checkpoint")
    completed_ranges = values["completed_ranges"]
    if not isinstance(completed_ranges, (list, tuple)):
        raise ExecutionError("runner_checkpoint.completed_ranges must be an array")
    _ensure_json_value(completed_ranges, "runner_checkpoint.completed_ranges")
    return _CheckpointView(
        sequence=_nonnegative_integer("runner_checkpoint.sequence", values["sequence"]),
        completed_ranges=tuple(_deep_freeze(item) for item in completed_ranges),
        state_sha256=_sha256(
            "runner_checkpoint.state_sha256", values["state_sha256"]
        ),
        relative_path=_relative_path(
            "runner_checkpoint.relative_path", values["relative_path"]
        ),
        size_bytes=_nonnegative_integer(
            "runner_checkpoint.size_bytes", values["size_bytes"]
        ),
    )


def _validate_staging_bindings(
    staging_envelope: Mapping[str, Any], bindings: _Bindings
) -> None:
    envelope = _mapping(staging_envelope, "runner_result.staging_envelope")
    payload = _mapping(
        envelope.get("payload"), "runner_result.staging_envelope.payload"
    )
    expected = {
        "run_id": bindings.job_id,
        "attempt_id": bindings.attempt_id,
        "fencing_token": bindings.fencing_token,
        "producer_identity": bindings.runner_identity,
    }
    for key, expected_value in expected.items():
        if payload.get(key) != expected_value:
            raise ExecutionError(f"staging envelope {key} binding mismatch")
    if envelope.get("classification") != bindings.classification:
        raise ExecutionError("staging envelope classification binding mismatch")
    if envelope.get("contour") != bindings.contour:
        raise ExecutionError("staging envelope contour binding mismatch")


def _validate_checkpoint_publication(
    publication: object,
    checkpoint_file_sha256: str,
    checkpoint_size_bytes: int,
) -> str:
    values = _exact_attributes(
        publication, _PUBLICATION_FIELDS, "checkpoint_publication"
    )
    expected_ref = f"cas:sha256:{checkpoint_file_sha256}"
    if (
        values["ref"] != expected_ref
        or values["sha256"] != checkpoint_file_sha256
        or isinstance(values["size_bytes"], bool)
        or values["size_bytes"] != checkpoint_size_bytes
        or not isinstance(values["created"], bool)
    ):
        raise ExecutionError("checkpoint CAS publication binding mismatch")
    return expected_ref


def _validate_checkpoint_event(
    event: object,
    bindings: _Bindings,
    checkpoint: _CheckpointView,
    checkpoint_ref: str,
) -> str:
    values = _exact_attributes(event, _EVENT_FIELDS, "checkpoint_event")
    _validate_event_columns(values, "checkpoint", bindings, "checkpoint_event")
    payload = _exact_mapping(
        values["payload"],
        _CHECKPOINT_EVENT_PAYLOAD_FIELDS,
        "checkpoint_event.payload",
    )
    expected = {
        "attempt_id": bindings.attempt_id,
        "fencing_epoch": bindings.fencing_epoch,
        "job_id": bindings.job_id,
        "payload_ref": checkpoint_ref,
        "payload_stored_in_domain_vault": False,
        "sequence": checkpoint.sequence,
        "state_sha256": checkpoint.state_sha256,
    }
    for key, expected_value in expected.items():
        if payload[key] != expected_value:
            raise ExecutionError(f"checkpoint_event.payload.{key} binding mismatch")
    event_at = _timestamp("checkpoint_event.event_at", values["event_at"])
    if payload["event_at"] != event_at:
        raise ExecutionError("checkpoint event timestamp columns do not match payload")
    if payload["payload_stored_in_domain_vault"] is not False:
        raise ExecutionError("checkpoint event must record a non-vault CAS payload")
    if _nonnegative_integer(
        "checkpoint_event.payload.sequence", payload["sequence"]
    ) != checkpoint.sequence:
        raise ExecutionError("checkpoint event sequence binding mismatch")
    if _nonnegative_integer(
        "checkpoint_event.payload.fencing_epoch", payload["fencing_epoch"]
    ) != bindings.fencing_epoch:
        raise ExecutionError("checkpoint event fencing epoch binding mismatch")
    _validate_fencing_digest(payload["fencing_token_sha256"], bindings)
    return event_at


def _construct_checkpoint_manifest(
    *,
    bindings: _Bindings,
    checkpoint: _CheckpointView,
    checkpoint_ref: str,
    claim_event_sha256: str,
    checkpoint_event_sha256: str,
    issued_at: str,
    issuer_id: str,
) -> Mapping[str, Any]:
    payload = {
        "run_id": bindings.job_id,
        "attempt_id": bindings.attempt_id,
        "fencing_token": bindings.fencing_token,
        "completed_ranges": list(checkpoint.completed_ranges),
        "state_sha256": checkpoint.state_sha256,
        "code_sha256": bindings.code_sha256,
        "environment_digest": bindings.environment_digest,
        "sequence": checkpoint.sequence,
        "payload_ref": checkpoint_ref,
        "payload_stored_in_domain_vault": False,
    }
    binding_sha256 = canonical_json_sha256(
        {
            "checkpoint_event_sha256": checkpoint_event_sha256,
            "payload": payload,
        }
    )
    manifest = {
        "schema_id": "CheckpointManifest",
        "schema_version": "1.0.0",
        "object_id": f"checkpoint-manifest-{binding_sha256}",
        "issued_at": issued_at,
        "issuer": {
            "id": f"{issuer_id}-trusted-ingestor",
            "authority_class": "trusted-ingestor",
        },
        "contour": bindings.contour,
        "classification": bindings.classification,
        "payload": payload,
        "integrity": {
            "payload_sha256": canonical_json_sha256(payload),
            "parent_refs": [
                f"ledger:{claim_event_sha256}",
                checkpoint_ref,
                f"ledger:{checkpoint_event_sha256}",
            ],
        },
    }
    return _deep_freeze(manifest)


def _validate_artifact_records(
    records: object,
    *,
    contour: str,
    classification: str,
) -> tuple[_ArtifactRecordSnapshot, ...]:
    if not isinstance(records, tuple) or not records:
        raise ExecutionError("trusted ingestor must return a nonempty tuple")
    snapshots: list[_ArtifactRecordSnapshot] = []
    for index, record in enumerate(records):
        values = _exact_attributes(
            record, _ARTIFACT_RECORD_FIELDS, f"artifact_records[{index}]"
        )
        artifact_ref = _cas_ref(
            f"artifact_records[{index}].artifact_ref", values["artifact_ref"]
        )
        manifest = _mapping(
            values["manifest"], f"artifact_records[{index}].manifest"
        )
        _ensure_json_value(manifest, f"artifact_records[{index}].manifest")
        if manifest.get("schema_id") != "ArtifactManifest":
            raise ExecutionError("trusted artifact manifest schema_id is invalid")
        if manifest.get("contour") != contour or manifest.get("classification") != classification:
            raise ExecutionError("trusted artifact manifest scope binding mismatch")
        payload = _mapping(
            manifest.get("payload"), f"artifact_records[{index}].manifest.payload"
        )
        if payload.get("artifact_sha256") != artifact_ref.removeprefix("cas:sha256:"):
            raise ExecutionError("trusted artifact manifest digest binding mismatch")
        integrity = _mapping(
            manifest.get("integrity"),
            f"artifact_records[{index}].manifest.integrity",
        )
        if integrity.get("payload_sha256") != canonical_json_sha256(payload):
            raise ExecutionError("trusted artifact manifest payload integrity mismatch")
        snapshots.append(
            _ArtifactRecordSnapshot(
                artifact_ref=artifact_ref,
                manifest=_deep_freeze(manifest),
            )
        )
    return tuple(snapshots)


def _validate_completion_event(
    event: object,
    bindings: _Bindings,
    budget_claim: Any,
    result_sha256: str,
    event_at: str,
) -> str:
    values = _exact_attributes(event, _EVENT_FIELDS, "completion_event")
    _validate_event_columns(values, "complete", bindings, "completion_event")
    try:
        settlement = JobLedger._validate_budget_completion_event(
            event, budget_claim
        )
    except LedgerError as exc:
        raise ExecutionError("completion budget projection is invalid") from exc
    payload = event.payload
    expected = {
        "attempt_id": bindings.attempt_id,
        "event_at": event_at,
        "fencing_epoch": bindings.fencing_epoch,
        "job_id": bindings.job_id,
        "result_sha256": result_sha256,
    }
    for key, expected_value in expected.items():
        if payload[key] != expected_value:
            raise ExecutionError(f"completion_event.payload.{key} binding mismatch")
    if values["event_at"] != event_at:
        raise ExecutionError("completion event timestamp binding mismatch")
    if _nonnegative_integer(
        "completion_event.payload.fencing_epoch", payload["fencing_epoch"]
    ) != bindings.fencing_epoch:
        raise ExecutionError("completion event fencing epoch binding mismatch")
    _validate_fencing_digest(payload["fencing_token_sha256"], bindings)
    return settlement["object_id"]


def _construct_execution_receipt(
    *,
    bindings: _Bindings,
    result: _ResultView,
    artifact_refs: tuple[str, ...],
    checkpoint_manifest: Mapping[str, Any],
    completion_event_sha256: str,
    settlement_ref: str,
    issuer_id: str,
) -> Mapping[str, Any]:
    payload = {
        "permit_ref": bindings.permit_id,
        "lease_ref": bindings.lease_id,
        "job_spec_ref": bindings.job_id,
        "code_sha256": result.code_sha256,
        "input_sha256": result.input_sha256,
        "environment_digest": result.environment_digest,
        "started_at": result.started_at,
        "ended_at": result.ended_at,
        "exit_classification": "mechanical-success",
        "artifact_refs": list(artifact_refs),
        "resource_usage": result.resource_usage,
        "event_chain_head": completion_event_sha256,
    }
    receipt = {
        "schema_id": "ExecutionReceipt",
        "schema_version": "1.0.0",
        "object_id": f"execution-receipt-{canonical_json_sha256(payload)}",
        "issued_at": result.ended_at,
        "issuer": {"id": issuer_id, "authority_class": "researchd"},
        "contour": bindings.contour,
        "classification": bindings.classification,
        "payload": payload,
        "integrity": {
            "payload_sha256": canonical_json_sha256(payload),
            "parent_refs": [
                checkpoint_manifest["object_id"],
                *artifact_refs,
                settlement_ref,
                f"ledger:{completion_event_sha256}",
            ],
        },
    }
    return _deep_freeze(receipt)


def _validate_event_columns(
    values: Mapping[str, Any],
    event_type: str,
    bindings: _Bindings,
    label: str,
) -> None:
    if values["event_type"] != event_type:
        raise ExecutionError(f"{label}.event_type is invalid")
    if values["job_id"] != bindings.job_id:
        raise ExecutionError(f"{label}.job_id binding mismatch")
    if values["attempt_id"] != bindings.attempt_id:
        raise ExecutionError(f"{label}.attempt_id binding mismatch")
    if _nonnegative_integer(
        f"{label}.fencing_epoch", values["fencing_epoch"]
    ) != bindings.fencing_epoch:
        raise ExecutionError(f"{label}.fencing_epoch binding mismatch")
    if isinstance(values["sequence"], bool) or not isinstance(values["sequence"], int) or values["sequence"] <= 0:
        raise ExecutionError(f"{label}.sequence must be a positive integer")
    _timestamp(f"{label}.event_at", values["event_at"])
    _sha256(f"{label}.previous_sha256", values["previous_sha256"])
    _sha256(f"{label}.event_sha256", values["event_sha256"])


def _validate_fencing_digest(value: object, bindings: _Bindings) -> None:
    actual = _sha256("fencing_token_sha256", value)
    expected = hashlib.sha256(bindings.fencing_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ExecutionError("ledger event fencing token binding mismatch")


def _event_sha256(event: object, label: str) -> str:
    try:
        value = getattr(event, "event_sha256")
    except AttributeError as exc:
        raise ExecutionError(f"{label}.event_sha256 is unavailable") from exc
    return _sha256(f"{label}.event_sha256", value)


def _exact_attributes(
    value: object,
    expected_fields: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if isinstance(value, Mapping) or value is None:
        raise ExecutionError(f"{label} must expose structural attributes")
    names: set[str]
    if is_dataclass(value) and not isinstance(value, type):
        names = {field.name for field in fields(value)}
    elif hasattr(value, "__dict__"):
        names = set(vars(value))
    else:
        names = set()
        for cls in type(value).__mro__:
            slots = getattr(cls, "__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            names.update(name for name in slots if not name.startswith("__"))
    if names != set(expected_fields):
        raise ExecutionError(f"{label} structural fields are not exact")
    try:
        return {name: getattr(value, name) for name in expected_fields}
    except AttributeError as exc:
        raise ExecutionError(f"{label} structural field is unavailable") from exc


def _exact_mapping(
    value: object, expected_fields: frozenset[str], label: str
) -> dict[str, Any]:
    copied = _mapping(value, label)
    if set(copied) != set(expected_fields):
        raise ExecutionError(f"{label} keys are not exact")
    return copied


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionError(f"{label} must be an object")
    copied = dict(value)
    if any(not isinstance(key, str) for key in copied):
        raise ExecutionError(f"{label} keys must be text")
    return copied


def _callable_method(value: object, method: str, label: str) -> None:
    if not callable(getattr(value, method, None)):
        raise ExecutionError(f"{label} must expose callable {method}")


def _identifier(label: str, value: object) -> str:
    normalized = _normalized_text(label, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ExecutionError(f"{label} must be a normalized identifier")
    return normalized


def _normalized_text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ExecutionError(f"{label} must be normalized nonempty text")
    if len(value) > 1024 or any(ord(character) < 32 for character in value):
        raise ExecutionError(f"{label} contains invalid text")
    return value


def _sha256(label: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ExecutionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _pattern_text(label: str, value: object, pattern: re.Pattern[str]) -> str:
    normalized = _normalized_text(label, value)
    if pattern.fullmatch(normalized) is None:
        raise ExecutionError(f"{label} has an invalid content-addressed format")
    return normalized


def _cas_ref(label: str, value: object) -> str:
    if not isinstance(value, str) or _CAS_REF_RE.fullmatch(value) is None:
        raise ExecutionError(f"{label} must be a portable CAS reference")
    return value


def _nonnegative_integer(label: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExecutionError(f"{label} must be a non-negative integer")
    return value


def _positive_safe_integer(label: str, value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_SAFE_INTEGER
    ):
        raise ExecutionError(f"{label} must be a positive safe integer")
    return value


def _timestamp(label: str, value: object) -> str:
    normalized = _normalized_text(label, value)
    if _RFC3339_RE.fullmatch(normalized) is None:
        raise ExecutionError(f"{label} must be an RFC3339 timestamp")
    _parse_timestamp(normalized)
    return normalized


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutionError("timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExecutionError("timestamp must include an offset")
    return parsed


def _relative_path(label: str, value: object) -> str:
    normalized = _normalized_text(label, value)
    if normalized in {".", ".."} or normalized.startswith("/") or "\\" in normalized:
        raise ExecutionError(f"{label} must be a portable relative POSIX path")
    path = PurePosixPath(normalized)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ExecutionError(f"{label} contains a forbidden path component")
    if path.as_posix() != normalized:
        raise ExecutionError(f"{label} is not normalized")
    return normalized


def _filesystem_path(value: object) -> Path:
    if isinstance(value, bytes):
        raise ExecutionError("staging_root must be a text filesystem path")
    try:
        path = Path(os.fspath(value))
    except (TypeError, ValueError) as exc:
        raise ExecutionError("staging_root must be a filesystem path") from exc
    if not str(path) or "\x00" in str(path):
        raise ExecutionError("staging_root is invalid")
    return path


def _checkpoint_file_sha256(
    staging_root: Path,
    relative_path: str,
    expected_size_bytes: int,
) -> str:
    parts = PurePosixPath(relative_path).parts
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ExecutionError("platform cannot enforce safe checkpoint traversal")
    if os.open not in getattr(os, "supports_dir_fd", set()):
        raise ExecutionError("platform cannot enforce descriptor-relative checkpoint access")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directories: list[int] = []
    checkpoint_fd: int | None = None
    try:
        directories.append(os.open(staging_root, directory_flags))
        for part in parts[:-1]:
            directories.append(os.open(part, directory_flags, dir_fd=directories[-1]))
        checkpoint_fd = os.open(parts[-1], file_flags, dir_fd=directories[-1])
        before = os.fstat(checkpoint_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ExecutionError("checkpoint path is not a regular file")
        if before.st_size != expected_size_bytes:
            raise ExecutionError("checkpoint file size does not match runner result")
        digest = hashlib.sha256()
        actual_size = 0
        while True:
            block = os.read(checkpoint_fd, 1024 * 1024)
            if not block:
                break
            actual_size += len(block)
            if actual_size > expected_size_bytes:
                raise ExecutionError("checkpoint file exceeds runner-declared size")
            digest.update(block)
        after = os.fstat(checkpoint_fd)
        before_fields = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            getattr(before, "st_mtime_ns", None),
            getattr(before, "st_ctime_ns", None),
        )
        after_fields = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            getattr(after, "st_mtime_ns", None),
            getattr(after, "st_ctime_ns", None),
        )
        if before_fields != after_fields or actual_size != expected_size_bytes:
            raise ExecutionError("checkpoint file changed during verification")
        return digest.hexdigest()
    except ExecutionError:
        raise
    except OSError as exc:
        raise ExecutionError("checkpoint file could not be read safely") from exc
    finally:
        if checkpoint_fd is not None:
            os.close(checkpoint_fd)
        for descriptor in reversed(directories):
            os.close(descriptor)


def _ensure_json_value(value: object, label: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ExecutionError(f"{label} contains a non-finite number")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _ensure_json_value(item, f"{label}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ExecutionError(f"{label} contains a non-text key")
            _ensure_json_value(item, f"{label}.{key}")
        return
    raise ExecutionError(f"{label} contains a non-JSON value")


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _json_ready(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value
