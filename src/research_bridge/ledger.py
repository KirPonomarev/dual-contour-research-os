"""Durable append-only job ledger for the offline research bridge.

The ledger records control-plane references and integrity digests only.  It is
not a checkpoint payload store and it does not issue permits or leases.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import threading
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence


_GENESIS_SHA256 = "0" * 64
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_PAYLOAD_REF_RE = re.compile(r"^(?:cas|vault):[A-Za-z0-9][A-Za-z0-9._:/+-]{0,511}$")
_ACCOUNTING_POLICY_REF_RE = re.compile(r"^budget-policy:sha256:[a-f0-9]{64}$")
_BUDGET_SCOPE_REF_RE = re.compile(r"^budget-scope:sha256:[a-f0-9]{64}$")
_A1_RESERVATION_REF_RE = re.compile(r"^budget-reservation:[a-f0-9]{64}$")
_EMBEDDED_REF_RE = re.compile(r"^embedded:sha256:[a-f0-9]{64}$")
_EVENT_TYPES = frozenset(
    {"claim", "checkpoint", "complete", "pause", "resume", "a1_bundle"}
)
_CONTROL_EVENT_TYPES = frozenset({"pause", "resume"})
_GLOBAL_CONTROL_JOB_ID = "bridge-global-control"
_SCHEMA_V1_USER_VERSION = 1
_DATABASE_USER_VERSION = 2
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_BUDGET_ISSUER = {"id": "bridge-budget-ledger", "authority_class": "budget-ledger"}
_CONTOURS = frozenset({"bridge", "market", "security", "governance"})
_CLASSIFICATIONS = frozenset(
    {
        "D0_PUBLIC",
        "D1_INTERNAL_SANITIZED",
        "D2_DOMAIN_CONFIDENTIAL",
        "D3_RESTRICTED",
    }
)

_TABLE_V1_SQL = """CREATE TABLE bridge_job_ledger (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL
                    CHECK (event_type IN ('claim', 'checkpoint', 'complete', 'pause', 'resume')),
                job_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
                checkpoint_sequence INTEGER,
                event_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL CHECK (length(previous_sha256) = 64),
                event_sha256 TEXT NOT NULL UNIQUE CHECK (length(event_sha256) = 64),
                CHECK (
                    (event_type = 'checkpoint' AND checkpoint_sequence IS NOT NULL)
                    OR (event_type != 'checkpoint' AND checkpoint_sequence IS NULL)
                )
            )"""
_TABLE_SQL = """CREATE TABLE bridge_job_ledger (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL
                    CHECK (event_type IN ('claim', 'checkpoint', 'complete', 'pause', 'resume', 'a1_bundle')),
                job_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
                checkpoint_sequence INTEGER,
                event_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL CHECK (length(previous_sha256) = 64),
                event_sha256 TEXT NOT NULL UNIQUE CHECK (length(event_sha256) = 64),
                CHECK (
                    (event_type = 'checkpoint' AND checkpoint_sequence IS NOT NULL)
                    OR (event_type != 'checkpoint' AND checkpoint_sequence IS NULL)
                )
            )"""
_LEGACY_SCHEMA_OBJECTS = (
    ("table", "bridge_job_ledger", _TABLE_V1_SQL),
    (
        "index",
        "bridge_job_one_claim",
        """CREATE UNIQUE INDEX bridge_job_one_claim
                ON bridge_job_ledger(job_id)
                WHERE event_type = 'claim'""",
    ),
    (
        "index",
        "bridge_claim_one_permit_nonce",
        """CREATE UNIQUE INDEX bridge_claim_one_permit_nonce
                ON bridge_job_ledger(
                    json_extract(payload_json, '$.permit_nonce_sha256')
                )
                WHERE event_type = 'claim'""",
    ),
    (
        "index",
        "bridge_job_one_completion",
        """CREATE UNIQUE INDEX bridge_job_one_completion
                ON bridge_job_ledger(job_id)
                WHERE event_type = 'complete'""",
    ),
    (
        "index",
        "bridge_job_checkpoint_sequence",
        """CREATE UNIQUE INDEX bridge_job_checkpoint_sequence
                ON bridge_job_ledger(job_id, attempt_id, checkpoint_sequence)
                WHERE event_type = 'checkpoint'""",
    ),
    (
        "index",
        "bridge_control_idempotency_key",
        """CREATE UNIQUE INDEX bridge_control_idempotency_key
                ON bridge_job_ledger(attempt_id)
                WHERE event_type IN ('pause', 'resume')""",
    ),
    (
        "trigger",
        "bridge_job_ledger_no_update",
        """CREATE TRIGGER bridge_job_ledger_no_update
            BEFORE UPDATE ON bridge_job_ledger
            BEGIN
                SELECT RAISE(ABORT, 'bridge_job_ledger is append-only');
            END""",
    ),
    (
        "trigger",
        "bridge_job_ledger_no_delete",
        """CREATE TRIGGER bridge_job_ledger_no_delete
            BEFORE DELETE ON bridge_job_ledger
            BEGIN
                SELECT RAISE(ABORT, 'bridge_job_ledger is append-only');
            END""",
    ),
)
_BUDGET_INDEX_OBJECTS = (
    (
        "index",
        "bridge_claim_one_budget_reservation",
        "CREATE UNIQUE INDEX bridge_claim_one_budget_reservation ON bridge_job_ledger("
        "json_extract(payload_json, '$.budget_reservation.object_id')) "
        "WHERE event_type = 'claim'",
    ),
    (
        "index",
        "bridge_claim_one_budget_idempotency",
        "CREATE UNIQUE INDEX bridge_claim_one_budget_idempotency ON bridge_job_ledger("
        "json_extract(payload_json, '$.budget_reservation.payload.idempotency_key')) "
        "WHERE event_type = 'claim'",
    ),
    (
        "index",
        "bridge_complete_one_budget_reservation",
        "CREATE UNIQUE INDEX bridge_complete_one_budget_reservation ON bridge_job_ledger("
        "json_extract(payload_json, '$.settlement_receipt.payload.reservation_ref')) "
        "WHERE event_type = 'complete'",
    ),
)
_SCHEMA_V1_OBJECTS = _LEGACY_SCHEMA_OBJECTS + _BUDGET_INDEX_OBJECTS

_A1_OBJECT_TABLE_SQL = """CREATE TABLE bridge_a1_objects (
                object_id TEXT PRIMARY KEY,
                object_kind TEXT NOT NULL
                    CHECK (object_kind IN ('MaterialEvent', 'CandidateSpecDraft', 'AdmissionReceipt', 'CapabilityProofReceipt')),
                ledger_sequence INTEGER NOT NULL,
                classification TEXT NOT NULL CHECK (classification IN ('D0', 'D1')),
                payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
                document_json TEXT NOT NULL,
                retention_class TEXT NOT NULL
                    CHECK (retention_class IN ('ephemeral-proposal', 'durable-operational-memory', 'immutable-receipt', 'domain-owned-reference')),
                FOREIGN KEY (ledger_sequence) REFERENCES bridge_job_ledger(sequence),
                UNIQUE (ledger_sequence, object_id)
            )"""
_A1_PROJECTION_TABLE_SQL = """CREATE TABLE bridge_a1_projection_state (
                projection_name TEXT PRIMARY KEY,
                last_applied_sequence INTEGER NOT NULL,
                state_sha256 TEXT NOT NULL CHECK (length(state_sha256) = 64),
                state_json TEXT NOT NULL,
                FOREIGN KEY (last_applied_sequence) REFERENCES bridge_job_ledger(sequence)
            )"""
_A1_SCHEMA_OBJECTS = (
    ("table", "bridge_a1_objects", _A1_OBJECT_TABLE_SQL),
    ("table", "bridge_a1_projection_state", _A1_PROJECTION_TABLE_SQL),
    (
        "index",
        "bridge_a1_bundle_idempotency",
        "CREATE UNIQUE INDEX bridge_a1_bundle_idempotency ON bridge_job_ledger("
        "json_extract(payload_json, '$.idempotency_key')) WHERE event_type = 'a1_bundle'",
    ),
    (
        "index",
        "bridge_a1_object_sequence",
        "CREATE INDEX bridge_a1_object_sequence ON bridge_a1_objects(ledger_sequence, object_id)",
    ),
    (
        "trigger",
        "bridge_a1_objects_no_update",
        """CREATE TRIGGER bridge_a1_objects_no_update
            BEFORE UPDATE ON bridge_a1_objects
            BEGIN
                SELECT RAISE(ABORT, 'bridge_a1_objects is append-only');
            END""",
    ),
    (
        "trigger",
        "bridge_a1_objects_no_delete",
        """CREATE TRIGGER bridge_a1_objects_no_delete
            BEFORE DELETE ON bridge_a1_objects
            BEGIN
                SELECT RAISE(ABORT, 'bridge_a1_objects is append-only');
            END""",
    ),
    (
        "trigger",
        "bridge_a1_projection_no_regression",
        """CREATE TRIGGER bridge_a1_projection_no_regression
            BEFORE UPDATE ON bridge_a1_projection_state
            WHEN NEW.last_applied_sequence <= OLD.last_applied_sequence
            BEGIN
                SELECT RAISE(ABORT, 'bridge_a1_projection sequence must advance');
            END""",
    ),
    (
        "trigger",
        "bridge_a1_projection_no_delete",
        """CREATE TRIGGER bridge_a1_projection_no_delete
            BEFORE DELETE ON bridge_a1_projection_state
            BEGIN
                SELECT RAISE(ABORT, 'bridge_a1_projection_state cannot be deleted');
            END""",
    ),
)
_SCHEMA_V2_OBJECTS = (
    ("table", "bridge_job_ledger", _TABLE_SQL),
) + _LEGACY_SCHEMA_OBJECTS[1:] + _BUDGET_INDEX_OBJECTS + _A1_SCHEMA_OBJECTS

_A1_OBJECT_KINDS = frozenset(
    {"MaterialEvent", "CandidateSpecDraft", "AdmissionReceipt", "CapabilityProofReceipt"}
)
_A1_PROJECTION_NAMES = frozenset(
    {"material_events", "candidates", "admissions", "capabilities"}
)
_FEEDBACK_PROJECTION_NAMES = frozenset(
    {"outcome_dispositions", "experiences", "idea_tree", "feedback_outbox"}
)
_ALL_PROJECTION_NAMES = _A1_PROJECTION_NAMES | _FEEDBACK_PROJECTION_NAMES
_FEEDBACK_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s\\]{1,511}$")
_FEEDBACK_PROJECTION_ENTRY_LIMIT = 256
_PARKED_GAP_LIMIT = 16
_MAX_CAUSAL_DEPTH = 16
_MECHANICAL_AXES = frozenset({"MECHANICAL_SUCCESS", "MECHANICAL_FAILURE"})
_PROPOSED_OUTCOMES = frozenset(
    {"SUPPORTED", "REFUTED", "INCONCLUSIVE", "VALIDATED_MECHANICAL", "PROVIDER_FAILURE"}
)
_BLAME_AXES = frozenset(
    {"NONE", "INFRASTRUCTURE", "PROVIDER", "INPUT", "EXECUTOR", "UNKNOWN"}
)
_MODEL_CALL_STATES = frozenset(
    {"PROPOSED", "RESERVED", "SENT", "SUCCEEDED", "FAILED_KNOWN", "UNKNOWN", "RECONCILED"}
)
_MODEL_CALL_TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED_KNOWN", "UNKNOWN"})
_MODEL_CALL_ACTIVE_RESERVATION_STATES = frozenset(
    {"RESERVED", "SENT", "SUCCEEDED", "FAILED_KNOWN", "UNKNOWN"}
)
_MODEL_CALL_FIELDS_V1 = frozenset(
    {
        "call_id", "previous_state", "state", "request_sha256", "registry_sha256",
        "binding_revision", "role", "model_binding", "classification",
        "budget_policy_ref", "budget_scope_ref", "max_active_calls", "max_tokens",
        "max_cost_units", "max_reserved_tokens", "max_reserved_cost_units", "expires_at",
        "proposed_at", "reserved_at", "sent_at", "terminal_at", "reconciled_at",
        "response_ref", "actual_tokens", "actual_cost_units", "provider_receipt_ref",
        "failure_code", "ambiguous_usage", "budget_released", "auto_retry",
    }
)
_MODEL_CALL_FIELDS = _MODEL_CALL_FIELDS_V1 | frozenset(
    {"accounting_mode", "accounting_evidence_ref"}
)
_MODEL_ACCOUNTING_MODES = frozenset(
    {"NUMERIC_EXACT", "OBSERVED_NO_NUMERIC_COST"}
)
_MODEL_CALL_ID_RE = re.compile(r"^model-call:[a-f0-9]{64}$")
_MODEL_RESPONSE_REF_RE = re.compile(r"^cas:sha256:[a-f0-9]{64}$")
_A1_RETENTION_BY_KIND = {
    "MaterialEvent": "durable-operational-memory",
    "CandidateSpecDraft": "ephemeral-proposal",
    "AdmissionReceipt": "immutable-receipt",
    "CapabilityProofReceipt": "immutable-receipt",
}

_CLAIM_PAYLOAD_FIELDS = frozenset(
    {
        "accounting_policy_ref",
        "admission_digest",
        "admitted_at",
        "attempt_id",
        "budget_reservation",
        "budget_scope_ref",
        "fencing_epoch",
        "fencing_token_sha256",
        "job_id",
        "permit_id",
        "permit_nonce_sha256",
        "runner_identity",
        "scope_limit",
    }
)
_CLAIM_PAYLOAD_FIELDS_WITH_A1 = _CLAIM_PAYLOAD_FIELDS | frozenset(
    {"admission_reservation_ref"}
)
_COMPLETE_PAYLOAD_FIELDS = frozenset(
    {
        "attempt_id",
        "event_at",
        "fencing_epoch",
        "fencing_token_sha256",
        "job_id",
        "provider_accounting_attestation",
        "result_sha256",
        "settlement_receipt",
    }
)
_CHECKPOINT_PAYLOAD_FIELDS = frozenset(
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
_RECEIPT_FIELDS = frozenset(
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
_RESERVATION_PAYLOAD_FIELDS = frozenset(
    {
        "trial_ref",
        "job_ref",
        "provider",
        "idempotency_key",
        "hard_limits",
        "ledger_version_before",
        "expires_at",
    }
)
_SETTLEMENT_PAYLOAD_FIELDS = frozenset(
    {
        "reservation_ref",
        "actual_usage",
        "actual_cost",
        "provider_receipt_ref",
        "released_amount",
        "provider_unknown",
        "ledger_version_after",
    }
)
_ATTESTATION_FIELDS = frozenset(
    {
        "schema_id",
        "schema_version",
        "accounting_policy_ref",
        "budget_scope_ref",
        "provider",
        "reservation_ref",
        "actual_usage",
        "actual_cost",
        "released_amount",
        "provider_unknown",
        "settled_at",
    }
)


class LedgerError(RuntimeError):
    """A fail-closed ledger validation or durability error."""


@dataclass(frozen=True, slots=True)
class LedgerEvent:
    """An immutable view of one append-only ledger event."""

    sequence: int
    event_type: str
    job_id: str
    attempt_id: str
    fencing_epoch: int
    event_at: str
    payload: Mapping[str, object]
    previous_sha256: str
    event_sha256: str

    @property
    def event_id(self) -> int:
        """Return the global event sequence under an event-id name."""

        return self.sequence


@dataclass(frozen=True, slots=True)
class A1BundleRecord:
    """One atomic A1 object/projection bundle in the global event order."""

    event: LedgerEvent
    object_ids: tuple[str, ...]
    projection_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.event.event_type != "a1_bundle":
            raise LedgerError("A1 bundle record must reference an a1_bundle event")
        if not self.object_ids or len(self.object_ids) != len(set(self.object_ids)):
            raise LedgerError("A1 bundle object ids must be unique and non-empty")
        if frozenset(self.projection_names) not in {
            _A1_PROJECTION_NAMES,
            _ALL_PROJECTION_NAMES,
        }:
            raise LedgerError("A1 bundle must advance every registered projection")


@dataclass(frozen=True, slots=True)
class FeedbackBundleRecord:
    """One immutable atomic feedback projection in the global event order."""

    event: LedgerEvent
    outcome_disposition: Mapping[str, object]
    experience_record: Mapping[str, object]
    idea_node: Mapping[str, object]
    outbox_record: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.event.event_type != "a1_bundle":
            raise LedgerError("feedback bundle must use the existing A1 global event")
        if self.event.payload.get("bundle_kind") != "atomic_feedback_v1":
            raise LedgerError("feedback bundle kind is invalid")


@dataclass(frozen=True, slots=True)
class FeedbackReplayReport:
    """Immutable proof that feedback projections replay without side effects."""

    ledger_sequence_last: int
    feedback_bundle_count: int
    first_feedback_sequence: int | None
    last_feedback_sequence: int | None
    rebuilt_projection_sha256: Mapping[str, str]
    stored_projection_sha256: Mapping[str, str]
    capacity_envelope: Mapping[str, object]
    replay_sha256: str
    side_effects: bool


@dataclass(frozen=True, slots=True)
class KnowledgeFabricReport:
    """Read-only typed research memory derived from verified feedback events."""

    fabric_version: str
    ledger_sequence_last: int
    memory_enabled: bool
    query_root_event_ref: str | None
    idea_nodes: tuple[Mapping[str, object], ...]
    failure_memory: tuple[Mapping[str, object], ...]
    conflict_candidates: tuple[Mapping[str, object], ...]
    root_event_energy: tuple[Mapping[str, object], ...]
    research_debt: tuple[Mapping[str, object], ...]
    retrieval_trace: Mapping[str, object]
    fabric_sha256: str
    side_effects: bool
    claims_scientific_truth: bool
    grants_authority: bool


@dataclass(frozen=True, slots=True)
class ModelCallTransitionRecord:
    """One conservative model-call transition in the existing global order."""

    event: LedgerEvent
    snapshot: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.event.event_type != "a1_bundle":
            raise LedgerError("model call transition must use the A1 global event")
        if self.event.payload.get("bundle_kind") != "model_call_transition_v1":
            raise LedgerError("model call transition bundle kind is invalid")


@dataclass(frozen=True, slots=True)
class _BudgetProjection:
    event: LedgerEvent
    accounting_policy_ref: str
    budget_scope_ref: str
    scope_limit_cost_units: int
    reservation: Mapping[str, Any]
    reservation_ref: str
    trial_ref: str
    provider: str
    idempotency_key: str
    reservation_cost_units: int
    expires_at: str
    settlement: Mapping[str, Any] | None = None


class JobLedger:
    """One SQLite-backed, append-only canonical bridge job ledger."""

    def __init__(self, database_path: str | Path, *, timeout: float = 5.0) -> None:
        if isinstance(database_path, bytes):
            raise LedgerError("database_path must be text, not bytes")
        if not isinstance(database_path, (str, Path)):
            raise LedgerError("database_path must be a filesystem path")
        if str(database_path) == ":memory:":
            raise LedgerError("a filesystem database is required for WAL durability")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise LedgerError("timeout must be a positive number")

        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                str(database_path),
                timeout=float(timeout),
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)}")
            self._initialize_schema()
            journal_mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if journal_mode.lower() != "wal":
                raise LedgerError("SQLite WAL mode is required")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA recursive_triggers = ON")
        except (sqlite3.Error, OSError) as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise LedgerError(f"could not open durable ledger: {exc}") from exc
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise

    def _initialize_schema(self) -> None:
        version, fingerprint, object_count = self._schema_identity()
        expected_v2 = _expected_schema_fingerprint(
            _SCHEMA_V2_OBJECTS, user_version=_DATABASE_USER_VERSION
        )
        expected_v1 = _expected_schema_fingerprint(
            _SCHEMA_V1_OBJECTS, user_version=_SCHEMA_V1_USER_VERSION
        )
        if version == _DATABASE_USER_VERSION:
            if fingerprint != expected_v2:
                raise LedgerError("ledger schema fingerprint is not exact version 2")
            return
        if version not in {0, _SCHEMA_V1_USER_VERSION}:
            raise LedgerError("ledger database user_version is unsupported")

        expected_legacy = _expected_schema_fingerprint(
            _LEGACY_SCHEMA_OBJECTS, user_version=0
        )
        if version == _SCHEMA_V1_USER_VERSION and fingerprint != expected_v1:
            raise LedgerError("ledger schema fingerprint is not exact version 1")
        if version == 0 and object_count and fingerprint != expected_legacy:
            raise LedgerError("unversioned ledger schema is ambiguous")

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            version, fingerprint, object_count = self._schema_identity()
            if version == _DATABASE_USER_VERSION:
                if fingerprint != expected_v2:
                    raise LedgerError("ledger schema fingerprint is not exact version 2")
                self._connection.execute("COMMIT")
                return
            if version not in {0, _SCHEMA_V1_USER_VERSION}:
                raise LedgerError("ledger database user_version is unsupported")
            if object_count == 0:
                self._create_schema_objects(_SCHEMA_V2_OBJECTS)
            elif version == 0 and fingerprint == expected_legacy:
                row_count = self._connection.execute(
                    "SELECT COUNT(*) FROM bridge_job_ledger"
                ).fetchone()[0]
                if row_count != 0:
                    raise LedgerError("nonempty unversioned ledger requires quarantine")
                self._migrate_v1_objects_to_v2(include_budget_indexes=False)
            elif version == _SCHEMA_V1_USER_VERSION and fingerprint == expected_v1:
                self._migrate_v1_objects_to_v2(include_budget_indexes=True)
            else:
                raise LedgerError("ledger schema cannot be migrated safely")
            self._connection.execute(f"PRAGMA user_version = {_DATABASE_USER_VERSION}")
            version, fingerprint, _ = self._schema_identity()
            if version != _DATABASE_USER_VERSION or fingerprint != expected_v2:
                raise LedgerError("ledger schema version 2 creation was not exact")
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def _migrate_v1_objects_to_v2(self, *, include_budget_indexes: bool) -> None:
        """Atomically rebuild the event table and add v2 A1 projection storage."""

        index_objects = list(_LEGACY_SCHEMA_OBJECTS[1:])
        if include_budget_indexes:
            index_objects.extend(_BUDGET_INDEX_OBJECTS)
        for object_type, name, _statement in reversed(index_objects):
            keyword = "TRIGGER" if object_type == "trigger" else "INDEX"
            self._connection.execute(f"DROP {keyword} {name}")
        self._connection.execute(
            "ALTER TABLE bridge_job_ledger RENAME TO bridge_job_ledger_v1"
        )
        self._connection.execute(_TABLE_SQL)
        self._connection.execute(
            """
            INSERT INTO bridge_job_ledger (
                sequence, event_type, job_id, attempt_id, fencing_epoch,
                checkpoint_sequence, event_at, payload_json,
                previous_sha256, event_sha256
            )
            SELECT sequence, event_type, job_id, attempt_id, fencing_epoch,
                   checkpoint_sequence, event_at, payload_json,
                   previous_sha256, event_sha256
            FROM bridge_job_ledger_v1
            ORDER BY sequence
            """
        )
        self._connection.execute("DROP TABLE bridge_job_ledger_v1")
        self._create_schema_objects(_SCHEMA_V2_OBJECTS[1:])

    def _schema_identity(self) -> tuple[int, str, int]:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        rows = self._connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        manifest = tuple(
            (row["type"], row["name"], row["tbl_name"], row["sql"])
            for row in rows
        )
        identity = {"user_version": version, "objects": manifest}
        return version, _digest(_canonical_json(identity).encode("utf-8")), len(rows)

    def _create_schema_objects(
        self, objects: tuple[tuple[str, str, str], ...]
    ) -> None:
        for _object_type, _name, statement in objects:
            self._connection.execute(statement)

    def claim(
        self,
        *,
        job_id: str,
        attempt_id: str,
        permit_id: str,
        permit_nonce_sha256: str,
        runner_identity: str,
        fencing_epoch: int,
        fencing_token: str,
        admitted_at: str,
        admission_digest: str,
        accounting_policy_ref: str,
        budget_scope_ref: str,
        scope_limit_cost_units: int,
        trial_ref: str,
        provider: str,
        job_idempotency_key: str,
        reservation_cost_units: int,
        reservation_expires_at: str,
        contour: str,
        classification: str,
        admission_reservation_ref: str | None = None,
    ) -> LedgerEvent:
        """Atomically reserve hard capacity and append the sole job claim."""

        job_id = _nonempty_text("job_id", job_id)
        attempt_id = _nonempty_text("attempt_id", attempt_id)
        permit_id = _nonempty_text("permit_id", permit_id)
        permit_nonce_sha256 = _sha256(
            "permit_nonce_sha256", permit_nonce_sha256
        )
        runner_identity = _nonempty_text("runner_identity", runner_identity)
        fencing_epoch = _nonnegative_integer("fencing_epoch", fencing_epoch)
        fencing_token = _nonempty_text("fencing_token", fencing_token)
        admitted_at = _timestamp("admitted_at", admitted_at)
        admission_digest = _sha256("admission_digest", admission_digest)
        accounting_policy_ref = _pattern_text(
            "accounting_policy_ref", accounting_policy_ref, _ACCOUNTING_POLICY_REF_RE
        )
        budget_scope_ref = _pattern_text(
            "budget_scope_ref", budget_scope_ref, _BUDGET_SCOPE_REF_RE
        )
        scope_limit_cost_units = _positive_safe_integer(
            "scope_limit_cost_units", scope_limit_cost_units
        )
        trial_ref = _nonempty_text("trial_ref", trial_ref)
        provider = _nonempty_text("provider", provider)
        job_idempotency_key = _nonempty_text(
            "job_idempotency_key", job_idempotency_key
        )
        reservation_cost_units = _positive_safe_integer(
            "reservation_cost_units", reservation_cost_units
        )
        if reservation_cost_units > scope_limit_cost_units:
            raise LedgerError("reservation exceeds the immutable scope limit")
        reservation_expires_at = _timestamp(
            "reservation_expires_at", reservation_expires_at
        )
        if _timestamp_datetime(reservation_expires_at) <= _timestamp_datetime(admitted_at):
            raise LedgerError("reservation must expire after admission")
        contour = _enum_text("contour", contour, _CONTOURS)
        classification = _enum_text(
            "classification", classification, _CLASSIFICATIONS
        )
        if admission_reservation_ref is not None:
            admission_reservation_ref = _pattern_text(
                "admission_reservation_ref",
                admission_reservation_ref,
                _A1_RESERVATION_REF_RE,
            )
        fencing_token_sha256 = _digest(fencing_token.encode("utf-8"))

        request_payload = {
            "accounting_policy_ref": accounting_policy_ref,
            "admission_digest": admission_digest,
            "admitted_at": admitted_at,
            "attempt_id": attempt_id,
            "budget_scope_ref": budget_scope_ref,
            "fencing_epoch": fencing_epoch,
            "fencing_token_sha256": fencing_token_sha256,
            "job_id": job_id,
            "permit_id": permit_id,
            "permit_nonce_sha256": permit_nonce_sha256,
            "runner_identity": runner_identity,
            "scope_limit": {"cost_units": scope_limit_cost_units},
        }
        if admission_reservation_ref is not None:
            request_payload["admission_reservation_ref"] = admission_reservation_ref
        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                projections = self._budget_projection_in_transaction()
                replay = self._idempotent_budget_claim(
                    projections=projections,
                    request_payload=request_payload,
                    trial_ref=trial_ref,
                    provider=provider,
                    idempotency_key=job_idempotency_key,
                    reservation_cost_units=reservation_cost_units,
                    reservation_expires_at=reservation_expires_at,
                    contour=contour,
                    classification=classification,
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                if self._pause_snapshot_in_transaction()["paused"]:
                    raise LedgerError("global pause blocks job claims")
                self._require_unused_permit_nonce(permit_nonce_sha256)
                existing = self._connection.execute(
                    "SELECT 1 FROM bridge_job_ledger WHERE job_id = ? AND event_type = 'claim'",
                    (job_id,),
                ).fetchone()
                if existing is not None:
                    raise LedgerError("job already has a claim winner")
                self._require_budget_capacity(
                    projections=projections,
                    accounting_policy_ref=accounting_policy_ref,
                    budget_scope_ref=budget_scope_ref,
                    scope_limit_cost_units=scope_limit_cost_units,
                    reservation_cost_units=reservation_cost_units,
                )
                reservation = self._construct_budget_reservation(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    permit_id=permit_id,
                    admission_digest=admission_digest,
                    admitted_at=admitted_at,
                    accounting_policy_ref=accounting_policy_ref,
                    budget_scope_ref=budget_scope_ref,
                    trial_ref=trial_ref,
                    provider=provider,
                    idempotency_key=job_idempotency_key,
                    reservation_cost_units=reservation_cost_units,
                    expires_at=reservation_expires_at,
                    contour=contour,
                    classification=classification,
                    ledger_version_before=self._ledger_tail_sequence(),
                    admission_reservation_ref=admission_reservation_ref,
                )
                payload = {**request_payload, "budget_reservation": reservation}
                event = self._append(
                    event_type="claim",
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    checkpoint_sequence=None,
                    event_at=admitted_at,
                    payload=payload,
                )
                self._connection.execute("COMMIT")
                return event
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def pause_global(
        self,
        *,
        actor: str,
        reason: str,
        authority_ref: str,
        idempotency_key: str,
        event_at: str,
    ) -> LedgerEvent:
        """Persist one idempotent transition into the globally paused state."""

        actor = _nonempty_text("actor", actor)
        reason = _nonempty_text("reason", reason)
        authority_ref = _nonempty_text("authority_ref", authority_ref)
        idempotency_key = _nonempty_text("idempotency_key", idempotency_key)
        event_at = _timestamp("event_at", event_at)
        payload = {
            "actor": actor,
            "authority_ref": authority_ref,
            "event_at": event_at,
            "idempotency_key": idempotency_key,
            "reason": reason,
        }

        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                duplicate = self._idempotent_control_event(
                    event_type="pause",
                    idempotency_key=idempotency_key,
                    payload=payload,
                )
                if duplicate is not None:
                    self._connection.execute("COMMIT")
                    return duplicate
                if self._pause_snapshot_in_transaction()["paused"]:
                    raise LedgerError("global pause is already active")
                event = self._append(
                    event_type="pause",
                    job_id=_GLOBAL_CONTROL_JOB_ID,
                    attempt_id=idempotency_key,
                    fencing_epoch=0,
                    checkpoint_sequence=None,
                    event_at=event_at,
                    payload=payload,
                )
                self._connection.execute("COMMIT")
                return event
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def resume_global(
        self,
        *,
        actor: str,
        approval_ref: str,
        idempotency_key: str,
        event_at: str,
    ) -> LedgerEvent:
        """Persist one explicitly approved transition out of global pause."""

        actor = _nonempty_text("actor", actor)
        approval_ref = _nonempty_text("approval_ref", approval_ref)
        idempotency_key = _nonempty_text("idempotency_key", idempotency_key)
        event_at = _timestamp("event_at", event_at)
        payload = {
            "actor": actor,
            "approval_ref": approval_ref,
            "event_at": event_at,
            "idempotency_key": idempotency_key,
        }

        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                duplicate = self._idempotent_control_event(
                    event_type="resume",
                    idempotency_key=idempotency_key,
                    payload=payload,
                )
                if duplicate is not None:
                    self._connection.execute("COMMIT")
                    return duplicate
                if not self._pause_snapshot_in_transaction()["paused"]:
                    raise LedgerError("global pause is not active")
                event = self._append(
                    event_type="resume",
                    job_id=_GLOBAL_CONTROL_JOB_ID,
                    attempt_id=idempotency_key,
                    fencing_epoch=0,
                    checkpoint_sequence=None,
                    event_at=event_at,
                    payload=payload,
                )
                self._connection.execute("COMMIT")
                return event
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def is_globally_paused(self) -> bool:
        """Return durable global pause state derived from the latest control event."""

        return bool(self.pause_snapshot()["paused"])

    def pause_snapshot(self) -> dict[str, object]:
        """Return a detached, JSON-compatible snapshot of global pause state."""

        with self._lock:
            self._ensure_open()
            return self._pause_snapshot_in_transaction()

    def checkpoint(
        self,
        *,
        job_id: str,
        attempt_id: str,
        fencing_epoch: int,
        fencing_token: str,
        sequence: int,
        state_sha256: str,
        payload_ref: str,
        payload_stored_in_domain_vault: bool,
        event_at: str,
    ) -> LedgerEvent:
        """Append the next reference-only checkpoint under current fencing authority."""

        job_id = _nonempty_text("job_id", job_id)
        attempt_id = _nonempty_text("attempt_id", attempt_id)
        fencing_epoch = _nonnegative_integer("fencing_epoch", fencing_epoch)
        fencing_token = _nonempty_text("fencing_token", fencing_token)
        sequence = _nonnegative_integer("sequence", sequence)
        state_sha256 = _sha256("state_sha256", state_sha256)
        payload_ref = _payload_ref(payload_ref)
        if not isinstance(payload_stored_in_domain_vault, bool):
            raise LedgerError("payload_stored_in_domain_vault must be boolean")
        if payload_ref.startswith("vault:") != payload_stored_in_domain_vault:
            raise LedgerError("payload vault flag must match the payload_ref scheme")
        event_at = _timestamp("event_at", event_at)
        fencing_token_sha256 = _digest(fencing_token.encode("utf-8"))

        payload = {
            "attempt_id": attempt_id,
            "event_at": event_at,
            "fencing_epoch": fencing_epoch,
            "fencing_token_sha256": fencing_token_sha256,
            "job_id": job_id,
            "payload_ref": payload_ref,
            "payload_stored_in_domain_vault": payload_stored_in_domain_vault,
            "sequence": sequence,
            "state_sha256": state_sha256,
        }
        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                self._budget_projection_in_transaction()
                replay = self._idempotent_checkpoint(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    fencing_token_sha256=fencing_token_sha256,
                    checkpoint_sequence=sequence,
                    state_sha256=state_sha256,
                    payload_ref=payload_ref,
                    payload_stored_in_domain_vault=payload_stored_in_domain_vault,
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                self._require_current_fence(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    fencing_token=fencing_token,
                )
                self._require_not_completed(job_id)
                row = self._connection.execute(
                    """
                    SELECT MAX(checkpoint_sequence) AS last_sequence
                    FROM bridge_job_ledger
                    WHERE job_id = ? AND attempt_id = ? AND event_type = 'checkpoint'
                    """,
                    (job_id, attempt_id),
                ).fetchone()
                expected = 0 if row["last_sequence"] is None else row["last_sequence"] + 1
                if sequence != expected:
                    raise LedgerError(f"checkpoint sequence must be {expected}")
                claim_row = self._connection.execute(
                    """
                    SELECT event_at
                    FROM bridge_job_ledger
                    WHERE job_id = ? AND event_type = 'claim'
                    """,
                    (job_id,),
                ).fetchone()
                if claim_row is None or _timestamp_datetime(event_at) < _timestamp_datetime(
                    claim_row["event_at"]
                ):
                    raise LedgerError("checkpoint event_at precedes its claim")
                event = self._append(
                    event_type="checkpoint",
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    checkpoint_sequence=sequence,
                    event_at=event_at,
                    payload=payload,
                )
                self._connection.execute("COMMIT")
                return event
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def complete(
        self,
        *,
        job_id: str,
        attempt_id: str,
        fencing_epoch: int,
        fencing_token: str,
        result_sha256: str,
        event_at: str,
    ) -> LedgerEvent:
        """Append job completion under the current fencing authority."""

        job_id = _nonempty_text("job_id", job_id)
        attempt_id = _nonempty_text("attempt_id", attempt_id)
        fencing_epoch = _nonnegative_integer("fencing_epoch", fencing_epoch)
        fencing_token = _nonempty_text("fencing_token", fencing_token)
        result_sha256 = _sha256("result_sha256", result_sha256)
        event_at = _timestamp("event_at", event_at)
        fencing_token_sha256 = _digest(fencing_token.encode("utf-8"))

        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                projections = self._budget_projection_in_transaction()
                replay = self._idempotent_completion(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    fencing_token_sha256=fencing_token_sha256,
                    result_sha256=result_sha256,
                    event_at=event_at,
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    return replay
                self._require_current_fence(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    fencing_token=fencing_token,
                )
                self._require_not_completed(job_id)
                projection = next(
                    (item for item in projections if item.event.job_id == job_id),
                    None,
                )
                if projection is None:
                    raise LedgerError("job claim lacks an exact budget reservation")
                if projection.settlement is not None:
                    raise LedgerError("job budget reservation is already settled")
                self._require_completion_after_checkpoints(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    event_at=event_at,
                )
                ledger_version_after = self._ledger_tail_sequence() + 1
                attestation = self._construct_provider_accounting_attestation(
                    projection=projection,
                    event_at=event_at,
                )
                settlement = self._construct_settlement_receipt(
                    projection=projection,
                    attestation=attestation,
                    result_sha256=result_sha256,
                    event_at=event_at,
                    ledger_version_after=ledger_version_after,
                )
                payload = {
                    "attempt_id": attempt_id,
                    "event_at": event_at,
                    "fencing_epoch": fencing_epoch,
                    "fencing_token_sha256": fencing_token_sha256,
                    "job_id": job_id,
                    "provider_accounting_attestation": attestation,
                    "result_sha256": result_sha256,
                    "settlement_receipt": settlement,
                }
                candidate = LedgerEvent(
                    sequence=ledger_version_after,
                    event_type="complete",
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    event_at=event_at,
                    payload=_deep_freeze(payload),
                    previous_sha256=_GENESIS_SHA256,
                    event_sha256=_GENESIS_SHA256,
                )
                self._validate_budget_completion_event(candidate, projection)
                event = self._append(
                    event_type="complete",
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    checkpoint_sequence=None,
                    event_at=event_at,
                    payload=payload,
                )
                self._connection.execute("COMMIT")
                return event
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def completed_event(self, job_id: str) -> LedgerEvent:
        """Return the unique validated completion event in a read snapshot."""

        job_id = _nonempty_text("job_id", job_id)
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN")
                projections = self._budget_projection_in_transaction()
                projection = next(
                    (item for item in projections if item.event.job_id == job_id),
                    None,
                )
                if projection is None or projection.settlement is None:
                    raise LedgerError("completed event is unavailable")
                rows = self._connection.execute(
                    """
                    SELECT *
                    FROM bridge_job_ledger
                    WHERE job_id = ? AND event_type = 'complete'
                    ORDER BY sequence
                    """,
                    (job_id,),
                ).fetchall()
                if len(rows) != 1:
                    raise LedgerError("completed event is not unique")
                event = self._ledger_event_from_row(rows[0])
                if event.attempt_id != projection.event.attempt_id:
                    raise LedgerError("completed event attempt binding is invalid")
                self._connection.execute("COMMIT")
                return event
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def append_a1_bundle(
        self,
        *,
        objects: Sequence[Mapping[str, object]],
        projections: Mapping[str, Mapping[str, object]],
        idempotency_key: str,
        event_at: str,
        expected_previous_sequence: int | None = None,
    ) -> A1BundleRecord:
        """Commit A1 objects and all projections at one global ledger sequence."""

        key = _text(idempotency_key, "idempotency_key", maximum=256)
        timestamp = _timestamp("event_at", event_at)
        if expected_previous_sequence is not None:
            expected_previous_sequence = _nonnegative_integer(
                "expected_previous_sequence", expected_previous_sequence
            )
        if not isinstance(objects, Sequence) or isinstance(objects, (str, bytes)):
            raise LedgerError("A1 bundle objects must be a sequence")
        if not objects or len(objects) > 64:
            raise LedgerError("A1 bundle object count is outside the bound")
        documents = [self._validate_a1_document(value) for value in objects]
        object_ids = [value["object_id"] for value in documents]
        if len(object_ids) != len(set(object_ids)):
            raise LedgerError("A1 bundle object ids must be unique")
        if not isinstance(projections, Mapping) or set(projections) != _A1_PROJECTION_NAMES:
            raise LedgerError("A1 bundle must provide every registered projection")
        projection_states: dict[str, dict[str, object]] = {}
        for name in sorted(_A1_PROJECTION_NAMES):
            state = projections[name]
            if not isinstance(state, Mapping):
                raise LedgerError("A1 projection state must be an object")
            copied = _json_copy(state, f"projection.{name}")
            if not isinstance(copied, dict) or not copied:
                raise LedgerError("A1 projection state must be non-empty")
            projection_states[name] = copied
        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                carried_feedback = self._projection_states_locked(
                    _FEEDBACK_PROJECTION_NAMES
                )
                if carried_feedback and set(carried_feedback) != _FEEDBACK_PROJECTION_NAMES:
                    raise LedgerError("feedback projection coverage is partial")
                projection_states.update(carried_feedback)
                descriptors = [
                    {
                        "object_id": document["object_id"],
                        "object_kind": document["schema_id"],
                        "payload_sha256": document["integrity"]["payload_sha256"],
                    }
                    for document in documents
                ]
                projection_descriptors = [
                    {
                        "projection_name": name,
                        "state_sha256": _digest(
                            _canonical_json(projection_states[name]).encode("utf-8")
                        ),
                    }
                    for name in sorted(projection_states)
                ]
                bundle_payload: dict[str, object] = {
                    "idempotency_key": key,
                    "objects": descriptors,
                    "projections": projection_descriptors,
                }
                replay_row = self._connection.execute(
                    """
                    SELECT * FROM bridge_job_ledger
                    WHERE event_type = 'a1_bundle'
                      AND json_extract(payload_json, '$.idempotency_key') = ?
                    """,
                    (key,),
                ).fetchone()
                if replay_row is not None:
                    replay = self._ledger_event_from_row(replay_row)
                    replay_projections = replay.payload.get("projections")
                    if not isinstance(replay_projections, (list, tuple)):
                        raise LedgerError("persisted A1 bundle projections are invalid")
                    expected_base = {
                        name: _digest(
                            _canonical_json(projection_states[name]).encode("utf-8")
                        )
                        for name in _A1_PROJECTION_NAMES
                    }
                    actual_base = {
                        item.get("projection_name"): item.get("state_sha256")
                        for item in replay_projections
                        if isinstance(item, Mapping)
                        and item.get("projection_name") in _A1_PROJECTION_NAMES
                    }
                    if (
                        replay.payload.get("bundle_kind") is not None
                        or replay.payload.get("objects") != tuple(descriptors)
                        or actual_base != expected_base
                    ):
                        raise LedgerError("A1 bundle idempotency key was reused")
                    stored_ids = tuple(
                        row["object_id"]
                        for row in self._connection.execute(
                            "SELECT object_id FROM bridge_a1_objects WHERE ledger_sequence = ? ORDER BY object_id",
                            (replay.sequence,),
                        )
                    )
                    self._connection.execute("COMMIT")
                    return A1BundleRecord(
                        event=replay,
                        object_ids=stored_ids,
                        projection_names=tuple(
                            sorted(
                                item["projection_name"]
                                for item in replay_projections
                                if isinstance(item, Mapping)
                                and isinstance(item.get("projection_name"), str)
                            )
                        ),
                    )

                if (
                    expected_previous_sequence is not None
                    and self._ledger_tail_sequence() != expected_previous_sequence
                ):
                    raise LedgerError(
                        "A1 bundle exact pre-append ledger revision drifted"
                    )

                event = self._append(
                    event_type="a1_bundle",
                    job_id="bridge-a1-global-bundle",
                    attempt_id=f"a1-bundle:{_digest(key.encode('utf-8'))}",
                    fencing_epoch=0,
                    checkpoint_sequence=None,
                    event_at=timestamp,
                    payload=bundle_payload,
                )
                for document in documents:
                    self._connection.execute(
                        """
                        INSERT INTO bridge_a1_objects (
                            object_id, object_kind, ledger_sequence, classification,
                            payload_sha256, document_json, retention_class
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            document["object_id"],
                            document["schema_id"],
                            event.sequence,
                            document["classification"],
                            document["integrity"]["payload_sha256"],
                            _canonical_json(document),
                            _A1_RETENTION_BY_KIND[document["schema_id"]],
                        ),
                    )
                for descriptor in projection_descriptors:
                    name = descriptor["projection_name"]
                    self._connection.execute(
                        """
                        INSERT INTO bridge_a1_projection_state (
                            projection_name, last_applied_sequence, state_sha256, state_json
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(projection_name) DO UPDATE SET
                            last_applied_sequence = excluded.last_applied_sequence,
                            state_sha256 = excluded.state_sha256,
                            state_json = excluded.state_json
                        """,
                        (
                            name,
                            event.sequence,
                            descriptor["state_sha256"],
                            _canonical_json(projection_states[name]),
                        ),
                    )
                self._connection.execute("COMMIT")
                return A1BundleRecord(
                    event=event,
                    object_ids=tuple(sorted(object_ids)),
                    projection_names=tuple(sorted(projection_states)),
                )
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def _advance_a1_projections(
        self,
        *,
        projections: Mapping[str, Mapping[str, object]],
        idempotency_key: str,
        event_at: str,
    ) -> LedgerEvent:
        """Atomically advance durable A1 state without minting a new object.

        Claim, rejection, and acknowledgement are state transitions rather than
        Core/A1 contract objects.  They still share the one global ledger order
        and advance every registered projection, so a restart cannot observe a
        partially applied control transition.
        """

        key = _text(idempotency_key, "idempotency_key", maximum=256)
        timestamp = _timestamp("event_at", event_at)
        if not isinstance(projections, Mapping) or set(projections) != _A1_PROJECTION_NAMES:
            raise LedgerError("A1 projection transition must provide every registered projection")
        projection_states: dict[str, dict[str, object]] = {}
        for name in sorted(_A1_PROJECTION_NAMES):
            state = projections[name]
            if not isinstance(state, Mapping):
                raise LedgerError("A1 projection state must be an object")
            copied = _json_copy(state, f"projection.{name}")
            if not isinstance(copied, dict) or not copied:
                raise LedgerError("A1 projection state must be non-empty")
            projection_states[name] = copied
        request_sha256 = _digest(
            _canonical_json(projection_states).encode("utf-8")
        )

        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                carried_feedback = self._projection_states_locked(
                    _FEEDBACK_PROJECTION_NAMES
                )
                if carried_feedback and set(carried_feedback) != _FEEDBACK_PROJECTION_NAMES:
                    raise LedgerError("feedback projection coverage is partial")
                projection_states.update(carried_feedback)
                projection_descriptors = [
                    {
                        "projection_name": name,
                        "state_sha256": _digest(
                            _canonical_json(projection_states[name]).encode("utf-8")
                        ),
                    }
                    for name in sorted(projection_states)
                ]
                payload: dict[str, object] = {
                    "bundle_kind": "a1_projection_transition_v1",
                    "idempotency_key": key,
                    "request_sha256": request_sha256,
                    "objects": [],
                    "projections": projection_descriptors,
                }
                replay_row = self._connection.execute(
                    """
                    SELECT * FROM bridge_job_ledger
                    WHERE event_type = 'a1_bundle'
                      AND json_extract(payload_json, '$.idempotency_key') = ?
                    """,
                    (key,),
                ).fetchone()
                if replay_row is not None:
                    replay = self._ledger_event_from_row(replay_row)
                    if (
                        replay.payload.get("bundle_kind")
                        != "a1_projection_transition_v1"
                        or replay.payload.get("request_sha256") != request_sha256
                    ):
                        raise LedgerError("A1 projection idempotency key was reused")
                    self._connection.execute("COMMIT")
                    return replay

                event = self._append(
                    event_type="a1_bundle",
                    job_id="bridge-a1-projection-transition",
                    attempt_id=f"a1-projection:{_digest(key.encode('utf-8'))}",
                    fencing_epoch=0,
                    checkpoint_sequence=None,
                    event_at=timestamp,
                    payload=payload,
                )
                for descriptor in projection_descriptors:
                    name = descriptor["projection_name"]
                    self._connection.execute(
                        """
                        INSERT INTO bridge_a1_projection_state (
                            projection_name, last_applied_sequence, state_sha256, state_json
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(projection_name) DO UPDATE SET
                            last_applied_sequence = excluded.last_applied_sequence,
                            state_sha256 = excluded.state_sha256,
                            state_json = excluded.state_json
                        """,
                        (
                            name,
                            event.sequence,
                            descriptor["state_sha256"],
                            _canonical_json(projection_states[name]),
                        ),
                    )
                self._connection.execute("COMMIT")
                return event
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def append_model_call_transition(
        self,
        *,
        snapshot: Mapping[str, object],
        idempotency_key: str,
        event_at: str,
    ) -> ModelCallTransitionRecord:
        """Append one model-call state change without creating a second event order."""

        normalized = _model_call_snapshot(snapshot)
        key = _text(idempotency_key, "model call idempotency_key", maximum=256)
        timestamp = _timestamp("model call event_at", event_at)
        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                replay_row = self._connection.execute(
                    """
                    SELECT * FROM bridge_job_ledger
                    WHERE event_type = 'a1_bundle'
                      AND json_extract(payload_json, '$.idempotency_key') = ?
                    """,
                    (key,),
                ).fetchone()
                if replay_row is not None:
                    replay = self._ledger_event_from_row(replay_row)
                    if (
                        replay.payload.get("bundle_kind") != "model_call_transition_v1"
                        or replay.payload.get("model_call") != normalized
                    ):
                        raise LedgerError("model call idempotency key was reused")
                    self._connection.execute("COMMIT")
                    return _model_call_record_from_event(replay)

                latest = self._latest_model_call_states_locked()
                previous = latest.get(normalized["call_id"])
                _validate_model_call_transition(previous, normalized, timestamp)
                if normalized["state"] == "RESERVED":
                    _validate_model_call_budget(latest, normalized)

                projection_states = self._projection_states_locked(_ALL_PROJECTION_NAMES)
                if frozenset(projection_states) not in {
                    _A1_PROJECTION_NAMES,
                    _ALL_PROJECTION_NAMES,
                }:
                    raise LedgerError(
                        "model call transition requires complete A1 projections"
                    )
                projection_descriptors = [
                    {
                        "projection_name": name,
                        "state_sha256": _digest(
                            _canonical_json(projection_states[name]).encode("utf-8")
                        ),
                    }
                    for name in sorted(projection_states)
                ]
                payload: dict[str, object] = {
                    "bundle_kind": "model_call_transition_v1",
                    "idempotency_key": key,
                    "objects": [],
                    "projections": projection_descriptors,
                    "model_call": normalized,
                }
                event = self._append(
                    event_type="a1_bundle",
                    job_id="bridge-model-call",
                    attempt_id=normalized["call_id"],
                    fencing_epoch=0,
                    checkpoint_sequence=None,
                    event_at=timestamp,
                    payload=payload,
                )
                for descriptor in projection_descriptors:
                    name = descriptor["projection_name"]
                    self._connection.execute(
                        """
                        INSERT INTO bridge_a1_projection_state (
                            projection_name, last_applied_sequence, state_sha256, state_json
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(projection_name) DO UPDATE SET
                            last_applied_sequence = excluded.last_applied_sequence,
                            state_sha256 = excluded.state_sha256,
                            state_json = excluded.state_json
                        """,
                        (
                            name,
                            event.sequence,
                            descriptor["state_sha256"],
                            _canonical_json(projection_states[name]),
                        ),
                    )
                self._connection.execute("COMMIT")
                return _model_call_record_from_event(event)
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def model_call_state(self, call_id: str) -> ModelCallTransitionRecord:
        """Return the latest durable state of one model call without side effects."""

        normalized = _pattern_text("model call_id", call_id, _MODEL_CALL_ID_RE)
        history = self.model_call_history(normalized)
        if not history:
            raise LedgerError("model call is not registered")
        return history[-1]

    def model_call_history(self, call_id: str) -> tuple[ModelCallTransitionRecord, ...]:
        """Return the exact ordered state history for one model call."""

        normalized = _pattern_text("model call_id", call_id, _MODEL_CALL_ID_RE)
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                """
                SELECT * FROM bridge_job_ledger
                WHERE event_type = 'a1_bundle'
                  AND json_extract(payload_json, '$.bundle_kind') = 'model_call_transition_v1'
                  AND json_extract(payload_json, '$.model_call.call_id') = ?
                ORDER BY sequence
                """,
                (normalized,),
            ).fetchall()
        records = tuple(
            _model_call_record_from_event(self._ledger_event_from_row(row))
            for row in rows
        )
        previous: Mapping[str, object] | None = None
        for record in records:
            _validate_model_call_transition(
                previous, record.snapshot, record.event.event_at
            )
            previous = record.snapshot
        return records

    def model_call_states(self) -> tuple[ModelCallTransitionRecord, ...]:
        """Return every latest replay-validated model-call state without writes."""

        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                """
                SELECT * FROM bridge_job_ledger
                WHERE event_type = 'a1_bundle'
                  AND json_extract(payload_json, '$.bundle_kind') = 'model_call_transition_v1'
                ORDER BY sequence
                """
            ).fetchall()
        latest: dict[str, ModelCallTransitionRecord] = {}
        for row in rows:
            record = _model_call_record_from_event(self._ledger_event_from_row(row))
            call_id = record.snapshot["call_id"]
            previous = latest.get(call_id)
            _validate_model_call_transition(
                None if previous is None else previous.snapshot,
                record.snapshot,
                record.event.event_at,
            )
            latest[call_id] = record
        return tuple(latest[call_id] for call_id in sorted(latest))

    def _model_call_states(self) -> tuple[ModelCallTransitionRecord, ...]:
        """Compatibility alias; production consumers use model_call_states()."""

        return self.model_call_states()

    def _latest_model_call_states_locked(self) -> dict[str, Mapping[str, object]]:
        rows = self._connection.execute(
            """
            SELECT * FROM bridge_job_ledger
            WHERE event_type = 'a1_bundle'
              AND json_extract(payload_json, '$.bundle_kind') = 'model_call_transition_v1'
            ORDER BY sequence
            """
        ).fetchall()
        latest: dict[str, Mapping[str, object]] = {}
        for row in rows:
            record = _model_call_record_from_event(self._ledger_event_from_row(row))
            previous = latest.get(record.snapshot["call_id"])
            _validate_model_call_transition(
                previous, record.snapshot, record.event.event_at
            )
            latest[record.snapshot["call_id"]] = record.snapshot
        return latest

    def append_feedback_bundle(
        self,
        *,
        execution_ref: str,
        validation_ref: str,
        root_event_ref: str,
        parent_event_ref: str,
        contour: str,
        classification: str,
        shadow_taint: str,
        mechanical_axis: str,
        proposed_outcome: str,
        blame_axis: str,
        domain_application_ref: str | None,
        next_event_candidate: Mapping[str, object] | None,
        parked_gap_refs: Sequence[str],
        idempotency_key: str,
        event_at: str,
        next_material_event: Mapping[str, object] | None = None,
        a1_projections: Mapping[str, Mapping[str, object]] | None = None,
    ) -> FeedbackBundleRecord:
        """Atomically preserve operational feedback without asserting scientific truth."""

        documents: list[dict[str, object]] = []
        supplied_a1_states: dict[str, dict[str, object]] | None = None
        if next_material_event is not None:
            document = self._validate_a1_document(next_material_event)
            if document["schema_id"] != "MaterialEvent":
                raise LedgerError("feedback can mint only one MaterialEvent")
            documents = [document]
            if not isinstance(a1_projections, Mapping) or set(a1_projections) != _A1_PROJECTION_NAMES:
                raise LedgerError("minted feedback event requires every A1 projection")
            supplied_a1_states = {}
            for name in sorted(_A1_PROJECTION_NAMES):
                state = a1_projections[name]
                copied = _json_copy(state, f"feedback projection.{name}")
                if not isinstance(copied, dict) or not copied:
                    raise LedgerError("feedback A1 projection state must be non-empty")
                supplied_a1_states[name] = copied
        elif a1_projections is not None:
            raise LedgerError("feedback A1 projections require a minted MaterialEvent")

        request = _feedback_request(
            execution_ref=execution_ref,
            validation_ref=validation_ref,
            root_event_ref=root_event_ref,
            parent_event_ref=parent_event_ref,
            contour=contour,
            classification=classification,
            shadow_taint=shadow_taint,
            mechanical_axis=mechanical_axis,
            proposed_outcome=proposed_outcome,
            blame_axis=blame_axis,
            domain_application_ref=domain_application_ref,
            next_event_candidate=next_event_candidate,
            parked_gap_refs=parked_gap_refs,
            idempotency_key=idempotency_key,
            event_at=event_at,
            next_material_event=next_material_event,
        )
        request_sha256 = _digest(_canonical_json(request).encode("utf-8"))

        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                replay_row = self._connection.execute(
                    """
                    SELECT * FROM bridge_job_ledger
                    WHERE event_type = 'a1_bundle'
                      AND json_extract(payload_json, '$.idempotency_key') = ?
                    """,
                    (request["idempotency_key"],),
                ).fetchone()
                if replay_row is not None:
                    replay = self._ledger_event_from_row(replay_row)
                    if (
                        replay.payload.get("bundle_kind") != "atomic_feedback_v1"
                        or replay.payload.get("request_sha256") != request_sha256
                    ):
                        raise LedgerError("feedback idempotency key was reused")
                    self._connection.execute("COMMIT")
                    return _feedback_record_from_event(replay)

                prior = self._connection.execute(
                    """
                    SELECT * FROM bridge_job_ledger
                    WHERE event_type = 'a1_bundle'
                      AND json_extract(payload_json, '$.bundle_kind') = 'atomic_feedback_v1'
                      AND json_extract(payload_json, '$.feedback.outcome_disposition.execution_ref') = ?
                    """,
                    (request["execution_ref"],),
                ).fetchall()
                if prior:
                    raise LedgerError("execution already has a feedback bundle")

                base_states = (
                    supplied_a1_states
                    if supplied_a1_states is not None
                    else self._projection_states_locked(_A1_PROJECTION_NAMES)
                )
                if set(base_states) != _A1_PROJECTION_NAMES:
                    raise LedgerError("feedback requires complete A1 base projections")
                feedback_states = self._projection_states_locked(
                    _FEEDBACK_PROJECTION_NAMES
                )
                if feedback_states and set(feedback_states) != _FEEDBACK_PROJECTION_NAMES:
                    raise LedgerError("feedback projection coverage is partial")

                feedback = _construct_feedback_material(request)
                projected = _advance_feedback_states(feedback_states, feedback)
                projection_states = {**base_states, **projected}
                projection_descriptors = [
                    {
                        "projection_name": name,
                        "state_sha256": _digest(
                            _canonical_json(projection_states[name]).encode("utf-8")
                        ),
                    }
                    for name in sorted(projection_states)
                ]
                bundle_payload: dict[str, object] = {
                    "bundle_kind": "atomic_feedback_v1",
                    "idempotency_key": request["idempotency_key"],
                    "request_sha256": request_sha256,
                    "objects": [
                        {
                            "object_id": document["object_id"],
                            "object_kind": document["schema_id"],
                            "payload_sha256": document["integrity"]["payload_sha256"],
                        }
                        for document in documents
                    ],
                    "projections": projection_descriptors,
                    "feedback": feedback,
                }
                event = self._append(
                    event_type="a1_bundle",
                    job_id="bridge-a1-feedback",
                    attempt_id=f"feedback:{request_sha256}",
                    fencing_epoch=0,
                    checkpoint_sequence=None,
                    event_at=request["event_at"],
                    payload=bundle_payload,
                )
                for document in documents:
                    self._connection.execute(
                        """
                        INSERT INTO bridge_a1_objects (
                            object_id, object_kind, ledger_sequence, classification,
                            payload_sha256, document_json, retention_class
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            document["object_id"],
                            document["schema_id"],
                            event.sequence,
                            document["classification"],
                            document["integrity"]["payload_sha256"],
                            _canonical_json(document),
                            _A1_RETENTION_BY_KIND[document["schema_id"]],
                        ),
                    )
                for descriptor in projection_descriptors:
                    name = descriptor["projection_name"]
                    self._connection.execute(
                        """
                        INSERT INTO bridge_a1_projection_state (
                            projection_name, last_applied_sequence, state_sha256, state_json
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(projection_name) DO UPDATE SET
                            last_applied_sequence = excluded.last_applied_sequence,
                            state_sha256 = excluded.state_sha256,
                            state_json = excluded.state_json
                        """,
                        (
                            name,
                            event.sequence,
                            descriptor["state_sha256"],
                            _canonical_json(projection_states[name]),
                        ),
                    )
                self._connection.execute("COMMIT")
                return _feedback_record_from_event(event)
            except Exception as exc:
                self._rollback()
                self._raise_ledger_error(exc)

    def feedback_for_execution(self, execution_ref: str) -> FeedbackBundleRecord:
        """Return one terminal feedback bundle without changing durable state."""

        reference = _feedback_ref(execution_ref, "execution_ref")
        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                """
                SELECT * FROM bridge_job_ledger
                WHERE event_type = 'a1_bundle'
                  AND json_extract(payload_json, '$.bundle_kind') = 'atomic_feedback_v1'
                  AND json_extract(payload_json, '$.feedback.outcome_disposition.execution_ref') = ?
                ORDER BY sequence
                """,
                (reference,),
            ).fetchall()
        if len(rows) != 1:
            raise LedgerError("terminal feedback lookup is not unique")
        return _feedback_record_from_event(self._ledger_event_from_row(rows[0]))

    def feedback_projection_coverage(self) -> Mapping[str, Mapping[str, object]]:
        """Return exact feedback projection snapshots without side effects."""

        with self._lock:
            self._ensure_open()
            states = self._projection_states_locked(_FEEDBACK_PROJECTION_NAMES)
        return _deep_freeze(states)

    def replay_feedback(self) -> FeedbackReplayReport:
        """Rebuild feedback projections from the global ledger with zero writes."""

        with self._lock:
            self._ensure_open()
            changes_before = self._connection.total_changes
            rows = self._connection.execute(
                "SELECT * FROM bridge_job_ledger ORDER BY sequence"
            ).fetchall()
            stored_rows = self._connection.execute(
                "SELECT * FROM bridge_a1_projection_state WHERE projection_name IN (?, ?, ?, ?) ORDER BY projection_name",
                tuple(sorted(_FEEDBACK_PROJECTION_NAMES)),
            ).fetchall()

            previous_sha256 = _GENESIS_SHA256
            rebuilt: dict[str, dict[str, object]] = {}
            feedback_sequences: list[int] = []
            for expected_sequence, row in enumerate(rows, start=1):
                event = self._ledger_event_from_row(row)
                if (
                    event.sequence != expected_sequence
                    or event.previous_sha256 != previous_sha256
                ):
                    raise LedgerError("global sequence gap blocks feedback replay")
                previous_sha256 = event.event_sha256
                if event.event_type != "a1_bundle":
                    continue
                descriptors = _projection_descriptor_map(event.payload)
                if event.payload.get("bundle_kind") == "atomic_feedback_v1":
                    record = _feedback_record_from_event(event)
                    material = {
                        "outcome_disposition": _json_copy(
                            record.outcome_disposition, "replay outcome"
                        ),
                        "experience_record": _json_copy(
                            record.experience_record, "replay experience"
                        ),
                        "idea_node": _json_copy(record.idea_node, "replay idea"),
                        "outbox_record": _json_copy(
                            record.outbox_record, "replay outbox"
                        ),
                    }
                    rebuilt = _advance_feedback_states(rebuilt, material)
                    feedback_sequences.append(event.sequence)
                if rebuilt:
                    if set(descriptors).issuperset(_FEEDBACK_PROJECTION_NAMES) is False:
                        raise LedgerError("feedback replay descriptor coverage is incomplete")
                    for name in _FEEDBACK_PROJECTION_NAMES:
                        expected_digest = _digest(
                            _canonical_json(rebuilt[name]).encode("utf-8")
                        )
                        if descriptors[name] != expected_digest:
                            raise LedgerError("feedback replay descriptor digest mismatch")

            stored: dict[str, dict[str, object]] = {}
            stored_digests: dict[str, str] = {}
            for row in stored_rows:
                state = _load_json_object(row["state_json"], "stored feedback projection")
                digest = _digest(_canonical_json(state).encode("utf-8"))
                if not _constant_time_equal(digest, row["state_sha256"]):
                    raise LedgerError("stored feedback projection digest mismatch")
                stored[row["projection_name"]] = state
                stored_digests[row["projection_name"]] = digest
            if bool(rebuilt) != bool(stored):
                raise LedgerError("feedback replay and stored coverage disagree")
            if rebuilt and set(stored) != _FEEDBACK_PROJECTION_NAMES:
                raise LedgerError("stored feedback projection coverage is incomplete")
            rebuilt_digests = {
                name: _digest(_canonical_json(state).encode("utf-8"))
                for name, state in sorted(rebuilt.items())
            }
            if rebuilt_digests != stored_digests:
                raise LedgerError("rebuilt feedback projections differ from storage")

            capacity = _feedback_capacity_envelope(
                ledger_event_count=len(rows),
                feedback_bundle_count=len(feedback_sequences),
                projections=rebuilt,
            )
            material = {
                "ledger_sequence_last": len(rows),
                "feedback_bundle_count": len(feedback_sequences),
                "first_feedback_sequence": (
                    feedback_sequences[0] if feedback_sequences else None
                ),
                "last_feedback_sequence": (
                    feedback_sequences[-1] if feedback_sequences else None
                ),
                "rebuilt_projection_sha256": rebuilt_digests,
                "stored_projection_sha256": stored_digests,
                "capacity_envelope": capacity,
                "side_effects": False,
            }
            if self._connection.total_changes != changes_before:
                raise LedgerError("feedback replay attempted a durable write")
        return FeedbackReplayReport(
            ledger_sequence_last=material["ledger_sequence_last"],
            feedback_bundle_count=material["feedback_bundle_count"],
            first_feedback_sequence=material["first_feedback_sequence"],
            last_feedback_sequence=material["last_feedback_sequence"],
            rebuilt_projection_sha256=_deep_freeze(rebuilt_digests),
            stored_projection_sha256=_deep_freeze(stored_digests),
            capacity_envelope=_deep_freeze(capacity),
            replay_sha256=_digest(_canonical_json(material).encode("utf-8")),
            side_effects=False,
        )

    def research_knowledge_fabric(
        self,
        *,
        memory_enabled: bool,
        root_event_ref: str | None = None,
        limit: int = 64,
    ) -> KnowledgeFabricReport:
        """Retrieve typed operational memory without mutating or promoting it."""

        if type(memory_enabled) is not bool:
            raise LedgerError("memory_enabled must be boolean")
        query_root = (
            None
            if root_event_ref is None
            else _feedback_ref(root_event_ref, "knowledge root_event_ref")
        )
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 256:
            raise LedgerError("knowledge retrieval limit must be between 1 and 256")

        with self._lock:
            self._ensure_open()
            changes_before = self._connection.total_changes
            replay = self.replay_feedback()
            rows = self._connection.execute(
                """
                SELECT * FROM bridge_job_ledger
                WHERE event_type = 'a1_bundle'
                  AND json_extract(payload_json, '$.bundle_kind') = 'atomic_feedback_v1'
                ORDER BY sequence
                """
            ).fetchall()
            records: list[tuple[LedgerEvent, FeedbackBundleRecord]] = []
            object_ids: set[str] = set()
            execution_refs: set[str] = set()
            for row in rows:
                event = self._ledger_event_from_row(row)
                record = _feedback_record_from_event(event)
                _validate_feedback_knowledge_material(record)
                execution_ref = str(record.outcome_disposition["execution_ref"])
                if execution_ref in execution_refs:
                    raise LedgerError("knowledge fabric contains duplicate execution memory")
                execution_refs.add(execution_ref)
                identifiers = {
                    str(record.outcome_disposition["object_id"]),
                    str(record.experience_record["object_id"]),
                    str(record.idea_node["object_id"]),
                    str(record.outbox_record["object_id"]),
                }
                if len(identifiers) != 4 or object_ids.intersection(identifiers):
                    raise LedgerError("knowledge fabric contains duplicate object identity")
                object_ids.update(identifiers)
                records.append((event, record))

            matching = [
                item
                for item in records
                if query_root is None
                or item[1].idea_node["root_event_ref"] == query_root
            ]
            selected = matching[-limit:] if memory_enabled else []
            idea_nodes, failures, conflicts, energy, debt = _knowledge_views(selected)
            selected_event_refs = [
                f"ledger-event:sha256:{event.event_sha256}" for event, _ in selected
            ]
            trace: dict[str, object] = {
                "trace_type": "KnowledgeRetrievalTrace",
                "memory_enabled": memory_enabled,
                "query_root_event_ref": query_root,
                "limit": limit,
                "ledger_events_scanned": len(records),
                "matching_records": len(matching),
                "selected_records": len(selected),
                "selected_event_refs": selected_event_refs,
                "excluded": {
                    "memory_disabled": len(matching) if not memory_enabled else 0,
                    "limit": max(0, len(matching) - limit) if memory_enabled else 0,
                    "root_filter": len(records) - len(matching),
                },
                "source_replay_sha256": replay.replay_sha256,
                "side_effects": False,
            }
            material: dict[str, object] = {
                "fabric_version": "research-knowledge-fabric-v1",
                "ledger_sequence_last": replay.ledger_sequence_last,
                "memory_enabled": memory_enabled,
                "query_root_event_ref": query_root,
                "idea_nodes": idea_nodes,
                "failure_memory": failures,
                "conflict_candidates": conflicts,
                "root_event_energy": energy,
                "research_debt": debt,
                "retrieval_trace": trace,
                "side_effects": False,
                "claims_scientific_truth": False,
                "grants_authority": False,
            }
            fabric_sha256 = _digest(_canonical_json(material).encode("utf-8"))
            if self._connection.total_changes != changes_before:
                raise LedgerError("knowledge retrieval attempted a durable write")
        return KnowledgeFabricReport(
            fabric_version="research-knowledge-fabric-v1",
            ledger_sequence_last=replay.ledger_sequence_last,
            memory_enabled=memory_enabled,
            query_root_event_ref=query_root,
            idea_nodes=tuple(_deep_freeze(item) for item in idea_nodes),
            failure_memory=tuple(_deep_freeze(item) for item in failures),
            conflict_candidates=tuple(_deep_freeze(item) for item in conflicts),
            root_event_energy=tuple(_deep_freeze(item) for item in energy),
            research_debt=tuple(_deep_freeze(item) for item in debt),
            retrieval_trace=_deep_freeze(trace),
            fabric_sha256=fabric_sha256,
            side_effects=False,
            claims_scientific_truth=False,
            grants_authority=False,
        )

    def _projection_states_locked(
        self, names: frozenset[str]
    ) -> dict[str, dict[str, object]]:
        placeholders = ",".join("?" for _ in names)
        rows = self._connection.execute(
            f"SELECT * FROM bridge_a1_projection_state WHERE projection_name IN ({placeholders}) ORDER BY projection_name",
            tuple(sorted(names)),
        ).fetchall()
        states: dict[str, dict[str, object]] = {}
        for row in rows:
            state = _load_json_object(row["state_json"], "projection state")
            digest = _digest(_canonical_json(state).encode("utf-8"))
            if not _constant_time_equal(digest, row["state_sha256"]):
                raise LedgerError("projection state storage digest mismatch")
            states[row["projection_name"]] = state
        return states

    def read_a1_object(self, object_id: str) -> Mapping[str, object]:
        """Return one immutable A1 document without changing durable state."""

        reference = _text(object_id, "object_id", maximum=256)
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT document_json, payload_sha256 FROM bridge_a1_objects WHERE object_id = ?",
                (reference,),
            ).fetchone()
        if row is None:
            raise LedgerError("A1 object is not registered")
        document = _load_json_object(row["document_json"], "A1 object")
        validated = self._validate_a1_document(document)
        if not _constant_time_equal(
            validated["integrity"]["payload_sha256"], row["payload_sha256"]
        ):
            raise LedgerError("A1 object storage digest mismatch")
        return _deep_freeze(validated)

    def projection_coverage(self) -> Mapping[str, Mapping[str, object]]:
        """Return exact registered projections and their last global sequence."""

        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                "SELECT * FROM bridge_a1_projection_state ORDER BY projection_name"
            ).fetchall()
        result: dict[str, Mapping[str, object]] = {}
        for row in rows:
            state = _load_json_object(row["state_json"], "A1 projection")
            state_sha = _digest(_canonical_json(state).encode("utf-8"))
            if not _constant_time_equal(state_sha, row["state_sha256"]):
                raise LedgerError("A1 projection storage digest mismatch")
            result[row["projection_name"]] = _deep_freeze(
                {
                    "last_applied_sequence": row["last_applied_sequence"],
                    "state_sha256": row["state_sha256"],
                    "state": state,
                }
            )
        return MappingProxyType(result)

    def storage_coverage_manifest(self) -> Mapping[str, object]:
        """Describe v2 ordering and projection coverage without mutating state."""

        with self._lock:
            self._ensure_open()
            version, fingerprint, _ = self._schema_identity()
            row = self._connection.execute(
                "SELECT MAX(sequence) AS last_sequence FROM bridge_job_ledger"
            ).fetchone()
            bundle_row = self._connection.execute(
                "SELECT MAX(sequence) AS last_sequence FROM bridge_job_ledger WHERE event_type = 'a1_bundle'"
            ).fetchone()
            projections = self._connection.execute(
                "SELECT projection_name, last_applied_sequence FROM bridge_a1_projection_state ORDER BY projection_name"
            ).fetchall()
        return _deep_freeze(
            {
                "schema_version": version,
                "schema_fingerprint_sha256": fingerprint,
                "ordering_model": "single-bridge-global-sequence",
                "global_sequence_last": row["last_sequence"] or 0,
                "a1_bundle_sequence_last": bundle_row["last_sequence"] or 0,
                "registered_projections": {
                    projection["projection_name"]: projection["last_applied_sequence"]
                    for projection in projections
                },
                "invariants": {
                    "no_second_event_ledger": True,
                    "projection_state_has_no_sequence_generator": True,
                    "a1_objects_reference_global_sequence": True,
                    "atomic_bundle": True,
                },
            }
        )

    def verify_a1_coverage(self) -> bool:
        """Verify object descriptors and complete projection coverage of latest bundle."""

        with self._lock:
            self._ensure_open()
            bundle_rows = self._connection.execute(
                "SELECT * FROM bridge_job_ledger WHERE event_type = 'a1_bundle' ORDER BY sequence"
            ).fetchall()
            object_rows = self._connection.execute(
                "SELECT * FROM bridge_a1_objects ORDER BY ledger_sequence, object_id"
            ).fetchall()
            projection_rows = self._connection.execute(
                "SELECT * FROM bridge_a1_projection_state ORDER BY projection_name"
            ).fetchall()
        objects_by_sequence: dict[int, list[sqlite3.Row]] = {}
        for row in object_rows:
            objects_by_sequence.setdefault(row["ledger_sequence"], []).append(row)
            try:
                document = self._validate_a1_document(
                    _load_json_object(row["document_json"], "A1 object")
                )
            except LedgerError:
                return False
            if (
                document["object_id"] != row["object_id"]
                or document["schema_id"] != row["object_kind"]
                or document["classification"] != row["classification"]
                or document["integrity"]["payload_sha256"] != row["payload_sha256"]
            ):
                return False
        for bundle_row in bundle_rows:
            try:
                event = self._ledger_event_from_row(bundle_row)
                descriptors = event.payload["objects"]
            except (LedgerError, KeyError, TypeError):
                return False
            actual = [
                {
                    "object_id": row["object_id"],
                    "object_kind": row["object_kind"],
                    "payload_sha256": row["payload_sha256"],
                }
                for row in objects_by_sequence.get(event.sequence, [])
            ]
            if sorted(descriptors, key=lambda item: item["object_id"]) != actual:
                return False
        if not bundle_rows:
            return not object_rows and not projection_rows
        latest = bundle_rows[-1]["sequence"]
        observed_projections = {
            row["projection_name"] for row in projection_rows
        }
        return (
            observed_projections in {_A1_PROJECTION_NAMES, _ALL_PROJECTION_NAMES}
            and all(row["last_applied_sequence"] == latest for row in projection_rows)
        )

    @staticmethod
    def _validate_a1_document(value: Mapping[str, object]) -> dict[str, object]:
        document = _exact_mapping(value, _RECEIPT_FIELDS, "A1 document")
        kind = document["schema_id"]
        if kind not in _A1_OBJECT_KINDS or document["schema_version"] != "1.0.0":
            raise LedgerError("A1 document schema identity is unsupported")
        _text(document["object_id"], "A1 object_id", maximum=256)
        _timestamp("A1 issued_at", document["issued_at"])
        if document["classification"] not in {"D0", "D1"}:
            raise LedgerError("durable A1 storage accepts D0 or D1 only")
        expected_contour = "governance" if kind == "CapabilityProofReceipt" else "bridge"
        if document["contour"] != expected_contour:
            raise LedgerError("A1 document contour is invalid")
        if not isinstance(document["payload"], Mapping):
            raise LedgerError("A1 document payload must be an object")
        integrity = _exact_mapping(
            document["integrity"],
            frozenset({"profile_id", "payload_sha256", "parent_refs"}),
            "A1 document integrity",
        )
        if integrity["profile_id"] != "core-json-sha256-v1":
            raise LedgerError("A1 document integrity profile is invalid")
        digest = _digest(_canonical_json(document["payload"]).encode("utf-8"))
        if not _constant_time_equal(
            digest, _sha256("A1 payload_sha256", integrity["payload_sha256"])
        ):
            raise LedgerError("A1 document payload digest mismatch")
        _string_array(integrity["parent_refs"], "A1 parent_refs", allow_empty=True)
        return document

    def event_count(self, event_type: str | None = None) -> int:
        """Return the number of committed events, optionally for one event type."""

        with self._lock:
            self._ensure_open()
            if event_type is None:
                row = self._connection.execute(
                    "SELECT COUNT(*) AS event_count FROM bridge_job_ledger"
                ).fetchone()
            else:
                if event_type not in _EVENT_TYPES:
                    raise LedgerError("unknown event_type")
                row = self._connection.execute(
                    "SELECT COUNT(*) AS event_count FROM bridge_job_ledger WHERE event_type = ?",
                    (event_type,),
                ).fetchone()
            return int(row["event_count"])

    def verify_chain(self) -> bool:
        """Verify global sequence continuity and every committed event digest."""

        with self._lock:
            self._ensure_open()
            rows = self._connection.execute(
                "SELECT * FROM bridge_job_ledger ORDER BY sequence"
            ).fetchall()

        previous = _GENESIS_SHA256
        for expected_sequence, row in enumerate(rows, start=1):
            if row["sequence"] != expected_sequence or row["previous_sha256"] != previous:
                return False
            try:
                payload = json.loads(row["payload_json"])
            except (json.JSONDecodeError, TypeError):
                return False
            if not isinstance(payload, dict):
                return False
            material = self._hash_material(
                sequence=row["sequence"],
                event_type=row["event_type"],
                job_id=row["job_id"],
                attempt_id=row["attempt_id"],
                fencing_epoch=row["fencing_epoch"],
                event_at=row["event_at"],
                payload=payload,
                previous_sha256=row["previous_sha256"],
            )
            if not _constant_time_equal(_digest(material), row["event_sha256"]):
                return False
            previous = row["event_sha256"]
        return True

    def close(self) -> None:
        """Durably close the ledger connection; repeated calls are safe."""

        with self._lock:
            if self._closed:
                return
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            self._connection.close()
            self._closed = True

    def __enter__(self) -> JobLedger:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _begin_immediate(self) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise LedgerError(f"could not begin durable transaction: {exc}") from exc

    def _append(
        self,
        *,
        event_type: str,
        job_id: str,
        attempt_id: str,
        fencing_epoch: int,
        checkpoint_sequence: int | None,
        event_at: str,
        payload: dict[str, object],
    ) -> LedgerEvent:
        row = self._connection.execute(
            """
            SELECT sequence, event_sha256
            FROM bridge_job_ledger
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()
        ledger_sequence = 1 if row is None else row["sequence"] + 1
        previous_sha256 = _GENESIS_SHA256 if row is None else row["event_sha256"]
        material = self._hash_material(
            sequence=ledger_sequence,
            event_type=event_type,
            job_id=job_id,
            attempt_id=attempt_id,
            fencing_epoch=fencing_epoch,
            event_at=event_at,
            payload=payload,
            previous_sha256=previous_sha256,
        )
        event_sha256 = _digest(material)
        payload_json = _canonical_json(payload)
        self._connection.execute(
            """
            INSERT INTO bridge_job_ledger (
                sequence, event_type, job_id, attempt_id, fencing_epoch,
                checkpoint_sequence, event_at, payload_json,
                previous_sha256, event_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ledger_sequence,
                event_type,
                job_id,
                attempt_id,
                fencing_epoch,
                checkpoint_sequence,
                event_at,
                payload_json,
                previous_sha256,
                event_sha256,
            ),
        )
        return LedgerEvent(
            sequence=ledger_sequence,
            event_type=event_type,
            job_id=job_id,
            attempt_id=attempt_id,
            fencing_epoch=fencing_epoch,
            event_at=event_at,
            payload=_deep_freeze(payload),
            previous_sha256=previous_sha256,
            event_sha256=event_sha256,
        )

    @staticmethod
    def _hash_material(
        *,
        sequence: int,
        event_type: str,
        job_id: str,
        attempt_id: str,
        fencing_epoch: int,
        event_at: str,
        payload: dict[str, object],
        previous_sha256: str,
    ) -> bytes:
        return _canonical_json(
            {
                "attempt_id": attempt_id,
                "event_at": event_at,
                "event_type": event_type,
                "fencing_epoch": fencing_epoch,
                "job_id": job_id,
                "payload": payload,
                "previous_sha256": previous_sha256,
                "sequence": sequence,
            }
        ).encode("utf-8")

    def _ledger_tail_sequence(self) -> int:
        row = self._connection.execute(
            "SELECT MAX(sequence) AS sequence FROM bridge_job_ledger"
        ).fetchone()
        return 0 if row["sequence"] is None else int(row["sequence"])

    def _construct_budget_reservation(
        self,
        *,
        job_id: str,
        attempt_id: str,
        permit_id: str,
        admission_digest: str,
        admitted_at: str,
        accounting_policy_ref: str,
        budget_scope_ref: str,
        trial_ref: str,
        provider: str,
        idempotency_key: str,
        reservation_cost_units: int,
        expires_at: str,
        contour: str,
        classification: str,
        ledger_version_before: int,
        admission_reservation_ref: str | None,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "trial_ref": trial_ref,
            "job_ref": job_id,
            "provider": provider,
            "idempotency_key": idempotency_key,
            "hard_limits": {"cost_units": reservation_cost_units},
            "ledger_version_before": ledger_version_before,
            "expires_at": expires_at,
        }
        payload_sha256 = _digest(_canonical_json(payload).encode("utf-8"))
        parent_refs = [
            job_id,
            permit_id,
            f"attempt:{attempt_id}",
            f"admission:sha256:{admission_digest}",
            accounting_policy_ref,
            budget_scope_ref,
        ]
        if admission_reservation_ref is not None:
            parent_refs.append(admission_reservation_ref)
        return {
            "schema_id": "BudgetReservation",
            "schema_version": "1.0.0",
            "object_id": f"budget-reservation:sha256:{payload_sha256}",
            "issued_at": admitted_at,
            "issuer": dict(_BUDGET_ISSUER),
            "contour": contour,
            "classification": classification,
            "payload": payload,
            "integrity": {
                "payload_sha256": payload_sha256,
                "parent_refs": parent_refs,
            },
        }

    @staticmethod
    def _construct_provider_accounting_attestation(
        *,
        projection: _BudgetProjection,
        event_at: str,
    ) -> dict[str, object]:
        return {
            "schema_id": "OwnedOfflineAccountingAttestation",
            "schema_version": "1.0.0",
            "accounting_policy_ref": projection.accounting_policy_ref,
            "budget_scope_ref": projection.budget_scope_ref,
            "provider": projection.provider,
            "reservation_ref": projection.reservation_ref,
            "actual_usage": {"cost_units": projection.reservation_cost_units},
            "actual_cost": projection.reservation_cost_units,
            "released_amount": 0,
            "provider_unknown": True,
            "settled_at": event_at,
        }

    @staticmethod
    def _construct_settlement_receipt(
        *,
        projection: _BudgetProjection,
        attestation: dict[str, object],
        result_sha256: str,
        event_at: str,
        ledger_version_after: int,
    ) -> dict[str, object]:
        provider_ref = (
            "embedded:sha256:"
            + _digest(_canonical_json(attestation).encode("utf-8"))
        )
        payload: dict[str, object] = {
            "reservation_ref": projection.reservation_ref,
            "actual_usage": {"cost_units": projection.reservation_cost_units},
            "actual_cost": projection.reservation_cost_units,
            "provider_receipt_ref": provider_ref,
            "released_amount": 0,
            "provider_unknown": True,
            "ledger_version_after": ledger_version_after,
        }
        payload_sha256 = _digest(_canonical_json(payload).encode("utf-8"))
        return {
            "schema_id": "SettlementReceipt",
            "schema_version": "1.0.0",
            "object_id": f"settlement-receipt-{payload_sha256}",
            "issued_at": event_at,
            "issuer": dict(_BUDGET_ISSUER),
            "contour": projection.reservation["contour"],
            "classification": projection.reservation["classification"],
            "payload": payload,
            "integrity": {
                "payload_sha256": payload_sha256,
                "parent_refs": [
                    projection.reservation_ref,
                    projection.accounting_policy_ref,
                    provider_ref,
                    f"result:sha256:{result_sha256}",
                ],
            },
        }

    def _budget_projection_in_transaction(self) -> list[_BudgetProjection]:
        rows = self._connection.execute(
            "SELECT * FROM bridge_job_ledger ORDER BY sequence"
        ).fetchall()
        events: list[LedgerEvent] = []
        previous = _GENESIS_SHA256
        for expected_sequence, row in enumerate(rows, start=1):
            event = self._ledger_event_from_row(row)
            if event.sequence != expected_sequence or event.previous_sha256 != previous:
                raise LedgerError("persisted ledger chain continuity is invalid")
            previous = event.event_sha256
            events.append(event)

        by_job: dict[str, _BudgetProjection] = {}
        for event in events:
            if event.event_type != "claim":
                continue
            projection = self._validate_budget_claim_event(event)
            if event.job_id in by_job:
                raise LedgerError("persisted job has duplicate claims")
            by_job[event.job_id] = projection

        checkpoints_by_job: dict[str, list[LedgerEvent]] = {}
        next_checkpoint: dict[tuple[str, str], int] = {}
        for event in events:
            if event.event_type != "checkpoint":
                continue
            projection = by_job.get(event.job_id)
            if projection is None:
                raise LedgerError("persisted checkpoint lacks a claim")
            key = (event.job_id, event.attempt_id)
            expected_sequence = next_checkpoint.get(key, 0)
            self._validate_checkpoint_event(
                event,
                projection,
                expected_sequence=expected_sequence,
            )
            next_checkpoint[key] = expected_sequence + 1
            checkpoints_by_job.setdefault(event.job_id, []).append(event)

        for event in events:
            if event.event_type != "complete":
                continue
            projection = by_job.get(event.job_id)
            if projection is None:
                raise LedgerError("persisted completion lacks a budgeted claim")
            if projection.settlement is not None:
                raise LedgerError("persisted reservation has duplicate settlements")
            for checkpoint_event in checkpoints_by_job.get(event.job_id, []):
                if (
                    checkpoint_event.sequence >= event.sequence
                    or _timestamp_datetime(checkpoint_event.event_at)
                    > _timestamp_datetime(event.event_at)
                ):
                    raise LedgerError(
                        "persisted completion does not follow every checkpoint"
                    )
            settlement = self._validate_budget_completion_event(event, projection)
            by_job[event.job_id] = replace(projection, settlement=settlement)
        projections = sorted(by_job.values(), key=lambda item: item.event.sequence)
        self._validate_budget_aggregate_invariants(projections)
        return projections

    @staticmethod
    def _validate_checkpoint_event(
        event: LedgerEvent,
        projection: _BudgetProjection,
        *,
        expected_sequence: int,
    ) -> None:
        if (
            event.sequence <= projection.event.sequence
            or _timestamp_datetime(event.event_at)
            < _timestamp_datetime(projection.event.event_at)
        ):
            raise LedgerError("persisted checkpoint does not follow its claim")
        payload = _exact_object(
            "persisted checkpoint payload",
            event.payload,
            _CHECKPOINT_PAYLOAD_FIELDS,
        )
        checkpoint_sequence = _nonnegative_integer(
            "persisted checkpoint sequence", payload["sequence"]
        )
        if (
            payload["job_id"] != event.job_id
            or payload["attempt_id"] != event.attempt_id
            or payload["fencing_epoch"] != event.fencing_epoch
            or payload["event_at"] != event.event_at
            or event.attempt_id != projection.event.attempt_id
            or event.fencing_epoch != projection.event.fencing_epoch
            or checkpoint_sequence != expected_sequence
        ):
            raise LedgerError("persisted checkpoint bindings are invalid")
        fencing_digest = _sha256(
            "persisted checkpoint fencing_token_sha256",
            payload["fencing_token_sha256"],
        )
        if not _constant_time_equal(
            fencing_digest,
            projection.event.payload["fencing_token_sha256"],
        ):
            raise LedgerError("persisted checkpoint fencing digest is invalid")
        _sha256("persisted checkpoint state_sha256", payload["state_sha256"])
        payload_ref = _payload_ref(payload["payload_ref"])
        in_vault = payload["payload_stored_in_domain_vault"]
        if not isinstance(in_vault, bool):
            raise LedgerError("persisted checkpoint vault flag must be boolean")
        if payload_ref.startswith("vault:") != in_vault:
            raise LedgerError("persisted checkpoint vault binding is invalid")
        _timestamp("persisted checkpoint event_at", payload["event_at"])

    def _idempotent_checkpoint(
        self,
        *,
        job_id: str,
        attempt_id: str,
        fencing_epoch: int,
        fencing_token_sha256: str,
        checkpoint_sequence: int,
        state_sha256: str,
        payload_ref: str,
        payload_stored_in_domain_vault: bool,
    ) -> LedgerEvent | None:
        row = self._connection.execute(
            """
            SELECT *
            FROM bridge_job_ledger
            WHERE job_id = ? AND attempt_id = ?
                AND event_type = 'checkpoint' AND checkpoint_sequence = ?
            """,
            (job_id, attempt_id, checkpoint_sequence),
        ).fetchone()
        if row is None:
            return None
        event = self._ledger_event_from_row(row)
        payload = event.payload
        exact = (
            event.job_id == job_id
            and event.attempt_id == attempt_id
            and event.fencing_epoch == fencing_epoch
            and payload["sequence"] == checkpoint_sequence
            and payload["state_sha256"] == state_sha256
            and payload["payload_ref"] == payload_ref
            and payload["payload_stored_in_domain_vault"]
            is payload_stored_in_domain_vault
            and _constant_time_equal(
                payload["fencing_token_sha256"], fencing_token_sha256
            )
        )
        if not exact:
            raise LedgerError("checkpoint replay conflicts with persisted event")
        return event

    def _idempotent_completion(
        self,
        *,
        job_id: str,
        attempt_id: str,
        fencing_epoch: int,
        fencing_token_sha256: str,
        result_sha256: str,
        event_at: str,
    ) -> LedgerEvent | None:
        row = self._connection.execute(
            """
            SELECT *
            FROM bridge_job_ledger
            WHERE job_id = ? AND event_type = 'complete'
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        event = self._ledger_event_from_row(row)
        payload = event.payload
        exact = (
            event.job_id == job_id
            and event.attempt_id == attempt_id
            and event.fencing_epoch == fencing_epoch
            and event.event_at == event_at
            and payload["result_sha256"] == result_sha256
            and _constant_time_equal(
                payload["fencing_token_sha256"], fencing_token_sha256
            )
        )
        if not exact:
            raise LedgerError("completion replay conflicts with persisted event")
        return event

    def _require_completion_after_checkpoints(
        self,
        *,
        job_id: str,
        attempt_id: str,
        event_at: str,
    ) -> None:
        row = self._connection.execute(
            """
            SELECT event_at
            FROM bridge_job_ledger
            WHERE job_id = ? AND attempt_id = ? AND event_type = 'checkpoint'
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (job_id, attempt_id),
        ).fetchone()
        if row is not None and _timestamp_datetime(event_at) < _timestamp_datetime(
            row["event_at"]
        ):
            raise LedgerError("completion event_at precedes its latest checkpoint")

    @staticmethod
    def _validate_budget_claim_event(event: LedgerEvent) -> _BudgetProjection:
        expected_fields = (
            _CLAIM_PAYLOAD_FIELDS_WITH_A1
            if "admission_reservation_ref" in event.payload
            else _CLAIM_PAYLOAD_FIELDS
        )
        payload = _exact_object("persisted claim payload", event.payload, expected_fields)
        accounting_policy_ref = _pattern_text(
            "persisted accounting_policy_ref",
            payload["accounting_policy_ref"],
            _ACCOUNTING_POLICY_REF_RE,
        )
        budget_scope_ref = _pattern_text(
            "persisted budget_scope_ref",
            payload["budget_scope_ref"],
            _BUDGET_SCOPE_REF_RE,
        )
        scope_limit = _exact_object(
            "persisted scope_limit", payload["scope_limit"], frozenset({"cost_units"})
        )
        scope_limit_cost_units = _positive_safe_integer(
            "persisted scope limit", scope_limit["cost_units"]
        )
        if (
            payload["job_id"] != event.job_id
            or payload["attempt_id"] != event.attempt_id
            or payload["fencing_epoch"] != event.fencing_epoch
            or payload["admitted_at"] != event.event_at
        ):
            raise LedgerError("persisted claim columns do not match payload")
        _nonempty_text("persisted permit_id", payload["permit_id"])
        _nonempty_text("persisted runner_identity", payload["runner_identity"])
        _sha256("persisted permit_nonce_sha256", payload["permit_nonce_sha256"])
        _sha256("persisted admission_digest", payload["admission_digest"])
        _sha256("persisted fencing_token_sha256", payload["fencing_token_sha256"])
        _timestamp("persisted admitted_at", payload["admitted_at"])

        reservation = _validate_full_receipt(
            "persisted BudgetReservation",
            payload["budget_reservation"],
            schema_id="BudgetReservation",
        )
        reservation_payload = _exact_object(
            "persisted BudgetReservation.payload",
            reservation["payload"],
            _RESERVATION_PAYLOAD_FIELDS,
        )
        hard_limits = _exact_object(
            "persisted BudgetReservation.payload.hard_limits",
            reservation_payload["hard_limits"],
            frozenset({"cost_units"}),
        )
        reservation_cost_units = _positive_safe_integer(
            "persisted reservation cost_units", hard_limits["cost_units"]
        )
        if reservation_cost_units > scope_limit_cost_units:
            raise LedgerError("persisted reservation exceeds its scope limit")
        trial_ref = _nonempty_text(
            "persisted reservation trial_ref", reservation_payload["trial_ref"]
        )
        provider = _nonempty_text(
            "persisted reservation provider", reservation_payload["provider"]
        )
        idempotency_key = _nonempty_text(
            "persisted reservation idempotency_key",
            reservation_payload["idempotency_key"],
        )
        expires_at = _timestamp(
            "persisted reservation expires_at", reservation_payload["expires_at"]
        )
        if _timestamp_datetime(expires_at) <= _timestamp_datetime(event.event_at):
            raise LedgerError(
                "persisted reservation expires at or before admission"
            )
        ledger_version_before = _nonnegative_integer(
            "persisted reservation ledger_version_before",
            reservation_payload["ledger_version_before"],
        )
        if ledger_version_before != event.sequence - 1:
            raise LedgerError("persisted reservation ledger version is not the claim tail")
        if reservation_payload["job_ref"] != event.job_id:
            raise LedgerError("persisted reservation does not bind the job")
        if reservation["issued_at"] != event.event_at:
            raise LedgerError("persisted reservation issued_at does not bind claim")
        if reservation["issuer"] != _BUDGET_ISSUER:
            raise LedgerError("persisted reservation issuer is invalid")
        _enum_text("persisted reservation contour", reservation["contour"], _CONTOURS)
        _enum_text(
            "persisted reservation classification",
            reservation["classification"],
            _CLASSIFICATIONS,
        )
        payload_sha256 = reservation["integrity"]["payload_sha256"]
        if reservation["object_id"] != f"budget-reservation:sha256:{payload_sha256}":
            raise LedgerError("persisted reservation object_id is invalid")
        expected_parents = [
            event.job_id,
            payload["permit_id"],
            f"attempt:{event.attempt_id}",
            f"admission:sha256:{payload['admission_digest']}",
            accounting_policy_ref,
            budget_scope_ref,
        ]
        if "admission_reservation_ref" in payload:
            admission_reservation_ref = _pattern_text(
                "persisted admission_reservation_ref",
                payload["admission_reservation_ref"],
                _A1_RESERVATION_REF_RE,
            )
            expected_parents.append(admission_reservation_ref)
        if reservation["integrity"]["parent_refs"] != expected_parents:
            raise LedgerError("persisted reservation parent bindings are invalid")
        return _BudgetProjection(
            event=event,
            accounting_policy_ref=accounting_policy_ref,
            budget_scope_ref=budget_scope_ref,
            scope_limit_cost_units=scope_limit_cost_units,
            reservation=_deep_freeze(reservation),
            reservation_ref=reservation["object_id"],
            trial_ref=trial_ref,
            provider=provider,
            idempotency_key=idempotency_key,
            reservation_cost_units=reservation_cost_units,
            expires_at=expires_at,
        )

    @staticmethod
    def _validate_budget_completion_event(
        event: LedgerEvent, projection: _BudgetProjection
    ) -> Mapping[str, Any]:
        if (
            event.sequence <= projection.event.sequence
            or _timestamp_datetime(event.event_at)
            < _timestamp_datetime(projection.event.event_at)
        ):
            raise LedgerError("persisted completion does not follow its claim")
        payload = _exact_object(
            "persisted complete payload", event.payload, _COMPLETE_PAYLOAD_FIELDS
        )
        if (
            payload["job_id"] != event.job_id
            or payload["attempt_id"] != event.attempt_id
            or payload["fencing_epoch"] != event.fencing_epoch
            or payload["event_at"] != event.event_at
            or event.attempt_id != projection.event.attempt_id
            or event.fencing_epoch != projection.event.fencing_epoch
        ):
            raise LedgerError("persisted completion columns do not match claim")
        result_sha256 = _sha256(
            "persisted completion result_sha256", payload["result_sha256"]
        )
        fencing_digest = _sha256(
            "persisted completion fencing_token_sha256",
            payload["fencing_token_sha256"],
        )
        if not _constant_time_equal(
            fencing_digest,
            projection.event.payload["fencing_token_sha256"],
        ):
            raise LedgerError("persisted completion fencing digest is invalid")
        _timestamp("persisted completion event_at", payload["event_at"])

        attestation = _exact_object(
            "persisted provider accounting attestation",
            payload["provider_accounting_attestation"],
            _ATTESTATION_FIELDS,
        )
        expected_attestation = JobLedger._construct_provider_accounting_attestation(
            projection=projection,
            event_at=event.event_at,
        )
        if attestation != expected_attestation:
            raise LedgerError("persisted provider accounting attestation is invalid")
        provider_ref = (
            "embedded:sha256:"
            + _digest(_canonical_json(attestation).encode("utf-8"))
        )

        settlement = _validate_full_receipt(
            "persisted SettlementReceipt",
            payload["settlement_receipt"],
            schema_id="SettlementReceipt",
        )
        settlement_payload = _exact_object(
            "persisted SettlementReceipt.payload",
            settlement["payload"],
            _SETTLEMENT_PAYLOAD_FIELDS,
        )
        usage = _exact_object(
            "persisted SettlementReceipt.payload.actual_usage",
            settlement_payload["actual_usage"],
            frozenset({"cost_units"}),
        )
        actual_usage = _positive_safe_integer(
            "persisted settlement actual usage", usage["cost_units"]
        )
        actual_cost = _positive_safe_integer(
            "persisted settlement actual cost", settlement_payload["actual_cost"]
        )
        released_amount = _nonnegative_integer(
            "persisted settlement released amount",
            settlement_payload["released_amount"],
        )
        if (
            settlement_payload["reservation_ref"] != projection.reservation_ref
            or actual_usage != projection.reservation_cost_units
            or actual_cost != projection.reservation_cost_units
            or released_amount != 0
            or actual_cost + released_amount != projection.reservation_cost_units
            or settlement_payload["provider_unknown"] is not True
            or settlement_payload["provider_receipt_ref"] != provider_ref
            or settlement_payload["ledger_version_after"] != event.sequence
        ):
            raise LedgerError("persisted fixed-charge settlement is invalid")
        if settlement["issued_at"] != event.event_at:
            raise LedgerError("persisted settlement issued_at is invalid")
        if settlement["issuer"] != _BUDGET_ISSUER:
            raise LedgerError("persisted settlement issuer is invalid")
        if (
            settlement["contour"] != projection.reservation["contour"]
            or settlement["classification"] != projection.reservation["classification"]
        ):
            raise LedgerError("persisted settlement scope is invalid")
        payload_sha256 = settlement["integrity"]["payload_sha256"]
        if settlement["object_id"] != f"settlement-receipt-{payload_sha256}":
            raise LedgerError("persisted settlement object_id is invalid")
        expected_parents = [
            projection.reservation_ref,
            projection.accounting_policy_ref,
            provider_ref,
            f"result:sha256:{result_sha256}",
        ]
        if settlement["integrity"]["parent_refs"] != expected_parents:
            raise LedgerError("persisted settlement parent bindings are invalid")
        return _deep_freeze(settlement)

    @staticmethod
    def _validate_budget_aggregate_invariants(
        projections: list[_BudgetProjection],
    ) -> None:
        scopes: dict[str, tuple[str, int, int]] = {}
        for projection in projections:
            released = 0
            if projection.settlement is not None:
                released = int(projection.settlement["payload"]["released_amount"])
            charged = projection.reservation_cost_units - released
            existing = scopes.get(projection.budget_scope_ref)
            if existing is None:
                policy_ref = projection.accounting_policy_ref
                scope_limit = projection.scope_limit_cost_units
                used = 0
            else:
                policy_ref, scope_limit, used = existing
                if (
                    projection.accounting_policy_ref != policy_ref
                    or projection.scope_limit_cost_units != scope_limit
                ):
                    raise LedgerError(
                        "persisted budget scope policy or limit is inconsistent"
                    )
            used += charged
            if used > scope_limit:
                raise LedgerError("persisted budget scope exceeds its hard cap")
            scopes[projection.budget_scope_ref] = (policy_ref, scope_limit, used)

    def _idempotent_budget_claim(
        self,
        *,
        projections: list[_BudgetProjection],
        request_payload: dict[str, object],
        trial_ref: str,
        provider: str,
        idempotency_key: str,
        reservation_cost_units: int,
        reservation_expires_at: str,
        contour: str,
        classification: str,
    ) -> LedgerEvent | None:
        matches = [item for item in projections if item.idempotency_key == idempotency_key]
        if not matches:
            return None
        if len(matches) != 1:
            raise LedgerError("persisted budget idempotency is ambiguous")
        projection = matches[0]
        persisted_payload = dict(projection.event.payload)
        persisted_payload.pop("budget_reservation", None)
        exact = (
            persisted_payload == request_payload
            and projection.trial_ref == trial_ref
            and projection.provider == provider
            and projection.reservation_cost_units == reservation_cost_units
            and projection.expires_at == reservation_expires_at
            and projection.reservation["contour"] == contour
            and projection.reservation["classification"] == classification
        )
        if not exact:
            raise LedgerError("budget idempotency key conflicts with persisted claim")
        return projection.event

    def _require_budget_capacity(
        self,
        *,
        projections: list[_BudgetProjection],
        accounting_policy_ref: str,
        budget_scope_ref: str,
        scope_limit_cost_units: int,
        reservation_cost_units: int,
    ) -> None:
        used = 0
        for projection in projections:
            if projection.budget_scope_ref != budget_scope_ref:
                continue
            if (
                projection.accounting_policy_ref != accounting_policy_ref
                or projection.scope_limit_cost_units != scope_limit_cost_units
            ):
                raise LedgerError("persisted budget scope policy or limit conflicts")
            released = 0
            if projection.settlement is not None:
                released = int(projection.settlement["payload"]["released_amount"])
            used += projection.reservation_cost_units - released
        if used > scope_limit_cost_units:
            raise LedgerError("persisted budget scope already exceeds its hard cap")
        if used + reservation_cost_units > scope_limit_cost_units:
            raise LedgerError("budget scope hard cap exceeded")

    def _ledger_event_from_row(self, row: sqlite3.Row) -> LedgerEvent:
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise LedgerError("persisted ledger payload is invalid") from exc
        if not isinstance(payload, dict):
            raise LedgerError("persisted ledger payload is not an object")
        event_type = row["event_type"]
        if event_type not in _EVENT_TYPES:
            raise LedgerError("persisted ledger event type is invalid")
        sequence = _positive_integer("persisted sequence", row["sequence"])
        job_id = _nonempty_text("persisted job_id", row["job_id"])
        attempt_id = _nonempty_text("persisted attempt_id", row["attempt_id"])
        fencing_epoch = _nonnegative_integer(
            "persisted fencing_epoch", row["fencing_epoch"]
        )
        event_at = _timestamp("persisted event_at", row["event_at"])
        previous_sha256 = _sha256(
            "persisted previous_sha256", row["previous_sha256"]
        )
        event_sha256 = _sha256("persisted event_sha256", row["event_sha256"])
        checkpoint_sequence = row["checkpoint_sequence"]
        if event_type == "checkpoint":
            persisted_checkpoint_sequence = _nonnegative_integer(
                "persisted checkpoint_sequence", checkpoint_sequence
            )
            if payload.get("sequence") != persisted_checkpoint_sequence:
                raise LedgerError(
                    "persisted checkpoint column does not match payload"
                )
        elif checkpoint_sequence is not None:
            raise LedgerError("non-checkpoint event has a checkpoint sequence")
        material = self._hash_material(
            sequence=sequence,
            event_type=event_type,
            job_id=job_id,
            attempt_id=attempt_id,
            fencing_epoch=fencing_epoch,
            event_at=event_at,
            payload=payload,
            previous_sha256=previous_sha256,
        )
        if not _constant_time_equal(_digest(material), event_sha256):
            raise LedgerError("persisted ledger event integrity is invalid")
        return LedgerEvent(
            sequence=sequence,
            event_type=event_type,
            job_id=job_id,
            attempt_id=attempt_id,
            fencing_epoch=fencing_epoch,
            event_at=event_at,
            payload=_deep_freeze(payload),
            previous_sha256=previous_sha256,
            event_sha256=event_sha256,
        )

    def _require_current_fence(
        self,
        *,
        job_id: str,
        attempt_id: str,
        fencing_epoch: int,
        fencing_token: str,
    ) -> None:
        row = self._connection.execute(
            """
            SELECT sequence, attempt_id, fencing_epoch, payload_json
            FROM bridge_job_ledger
            WHERE job_id = ? AND event_type = 'claim'
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise LedgerError("job has no admitted claim")
        try:
            claim_payload = json.loads(row["payload_json"])
            claim_token_sha256 = _sha256(
                "persisted fencing_token_sha256",
                claim_payload["fencing_token_sha256"],
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LedgerError("claim integrity is invalid") from exc
        presented_token_sha256 = _digest(fencing_token.encode("utf-8"))
        if (
            row["attempt_id"] != attempt_id
            or row["fencing_epoch"] != fencing_epoch
            or not _constant_time_equal(claim_token_sha256, presented_token_sha256)
        ):
            raise LedgerError("stale or mismatched fencing authority")
        latest_pause = self._connection.execute(
            """
            SELECT MAX(sequence) AS sequence
            FROM bridge_job_ledger
            WHERE event_type = 'pause'
            """
        ).fetchone()
        if latest_pause["sequence"] is not None and row["sequence"] <= latest_pause["sequence"]:
            raise LedgerError("attempt was claimed before the latest global pause")

    def _require_unused_permit_nonce(self, permit_nonce_sha256: str) -> None:
        rows = self._connection.execute(
            """
            SELECT payload_json
            FROM bridge_job_ledger
            WHERE event_type = 'claim'
            ORDER BY sequence
            """
        ).fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict):
                    raise TypeError("claim payload is not an object")
                persisted_digest = _sha256(
                    "persisted permit_nonce_sha256",
                    payload["permit_nonce_sha256"],
                )
            except (json.JSONDecodeError, KeyError, TypeError, LedgerError) as exc:
                raise LedgerError(
                    "persisted claim lacks a valid Permit nonce digest"
                ) from exc
            if _constant_time_equal(persisted_digest, permit_nonce_sha256):
                raise LedgerError("Permit nonce was already used")

    def _require_not_completed(self, job_id: str) -> None:
        row = self._connection.execute(
            "SELECT 1 FROM bridge_job_ledger WHERE job_id = ? AND event_type = 'complete'",
            (job_id,),
        ).fetchone()
        if row is not None:
            raise LedgerError("job is already complete")

    def _pause_snapshot_in_transaction(self) -> dict[str, object]:
        row = self._connection.execute(
            """
            SELECT *
            FROM bridge_job_ledger
            WHERE event_type IN ('pause', 'resume')
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return {"paused": False}
        event = self._control_event_from_row(row)
        snapshot = dict(event.payload)
        snapshot.update(
            {
                "event_sha256": event.event_sha256,
                "event_type": event.event_type,
                "paused": event.event_type == "pause",
                "sequence": event.sequence,
            }
        )
        return snapshot

    def _idempotent_control_event(
        self,
        *,
        event_type: str,
        idempotency_key: str,
        payload: dict[str, object],
    ) -> LedgerEvent | None:
        row = self._connection.execute(
            """
            SELECT *
            FROM bridge_job_ledger
            WHERE event_type IN ('pause', 'resume') AND attempt_id = ?
            """,
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        event = self._control_event_from_row(row)
        if event.event_type != event_type or dict(event.payload) != payload:
            raise LedgerError("idempotency_key was already used for a different control request")
        return event

    def _control_event_from_row(self, row: sqlite3.Row) -> LedgerEvent:
        if row["event_type"] not in _CONTROL_EVENT_TYPES:
            raise LedgerError("persisted control event type is invalid")
        if row["job_id"] != _GLOBAL_CONTROL_JOB_ID or row["fencing_epoch"] != 0:
            raise LedgerError("persisted control event scope is invalid")
        try:
            payload = json.loads(row["payload_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise LedgerError("persisted control event payload is invalid") from exc
        expected_fields = (
            {"actor", "authority_ref", "event_at", "idempotency_key", "reason"}
            if row["event_type"] == "pause"
            else {"actor", "approval_ref", "event_at", "idempotency_key"}
        )
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise LedgerError("persisted control event payload is invalid")
        try:
            _nonempty_text("actor", payload["actor"])
            _nonempty_text("idempotency_key", payload["idempotency_key"])
            _timestamp("event_at", payload["event_at"])
            if row["event_type"] == "pause":
                _nonempty_text("authority_ref", payload["authority_ref"])
                _nonempty_text("reason", payload["reason"])
            else:
                _nonempty_text("approval_ref", payload["approval_ref"])
        except (KeyError, LedgerError) as exc:
            raise LedgerError("persisted control event payload is invalid") from exc
        if payload["idempotency_key"] != row["attempt_id"] or payload["event_at"] != row["event_at"]:
            raise LedgerError("persisted control event columns do not match payload")
        material = self._hash_material(
            sequence=row["sequence"],
            event_type=row["event_type"],
            job_id=row["job_id"],
            attempt_id=row["attempt_id"],
            fencing_epoch=row["fencing_epoch"],
            event_at=row["event_at"],
            payload=payload,
            previous_sha256=row["previous_sha256"],
        )
        if not _constant_time_equal(_digest(material), row["event_sha256"]):
            raise LedgerError("persisted control event integrity is invalid")
        return LedgerEvent(
            sequence=row["sequence"],
            event_type=row["event_type"],
            job_id=row["job_id"],
            attempt_id=row["attempt_id"],
            fencing_epoch=row["fencing_epoch"],
            event_at=row["event_at"],
            payload=_deep_freeze(payload),
            previous_sha256=row["previous_sha256"],
            event_sha256=row["event_sha256"],
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise LedgerError("ledger is closed")

    def _rollback(self) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")

    @staticmethod
    def _raise_ledger_error(exc: Exception) -> None:
        if isinstance(exc, LedgerError):
            raise exc
        if isinstance(exc, sqlite3.Error):
            raise LedgerError(f"durable ledger transaction failed: {exc}") from exc
        raise exc


def _model_call_snapshot(value: Mapping[str, object]) -> dict[str, object]:
    if set(value) == _MODEL_CALL_FIELDS_V1:
        snapshot = dict(value)
        snapshot["accounting_mode"] = "NUMERIC_EXACT"
        snapshot["accounting_evidence_ref"] = None
    else:
        snapshot = _exact_mapping(value, _MODEL_CALL_FIELDS, "model call snapshot")
    _pattern_text("model call_id", snapshot["call_id"], _MODEL_CALL_ID_RE)
    previous_state = snapshot["previous_state"]
    if previous_state is not None and previous_state not in _MODEL_CALL_STATES:
        raise LedgerError("model call previous_state is invalid")
    if snapshot["state"] not in _MODEL_CALL_STATES:
        raise LedgerError("model call state is invalid")
    _sha256("model call request_sha256", snapshot["request_sha256"])
    _sha256("model call registry_sha256", snapshot["registry_sha256"])
    for name in ("binding_revision", "role", "model_binding"):
        _text(snapshot[name], f"model call {name}", maximum=256)
    if snapshot["classification"] not in {"D0", "D1"}:
        raise LedgerError("model call classification must be D0 or D1")
    _pattern_text(
        "model call budget_policy_ref",
        snapshot["budget_policy_ref"],
        _ACCOUNTING_POLICY_REF_RE,
    )
    _pattern_text(
        "model call budget_scope_ref",
        snapshot["budget_scope_ref"],
        _BUDGET_SCOPE_REF_RE,
    )
    for name in (
        "max_active_calls",
        "max_tokens",
        "max_cost_units",
        "max_reserved_tokens",
        "max_reserved_cost_units",
    ):
        _positive_safe_integer(f"model call {name}", snapshot[name])
    if snapshot["max_tokens"] > snapshot["max_reserved_tokens"]:
        raise LedgerError("model call token reservation exceeds its budget scope")
    if snapshot["max_cost_units"] > snapshot["max_reserved_cost_units"]:
        raise LedgerError("model call cost reservation exceeds its budget scope")
    _timestamp("model call expires_at", snapshot["expires_at"])
    for name in (
        "proposed_at",
        "reserved_at",
        "sent_at",
        "terminal_at",
        "reconciled_at",
    ):
        if snapshot[name] is not None:
            _timestamp(f"model call {name}", snapshot[name])
    response_ref = snapshot["response_ref"]
    if response_ref is not None:
        _pattern_text("model response_ref", response_ref, _MODEL_RESPONSE_REF_RE)
    for name in ("actual_tokens", "actual_cost_units"):
        if snapshot[name] is not None:
            _nonnegative_integer(f"model call {name}", snapshot[name])
    for name in ("provider_receipt_ref", "failure_code"):
        if snapshot[name] is not None:
            _text(snapshot[name], f"model call {name}", maximum=512)
    if snapshot["accounting_mode"] not in _MODEL_ACCOUNTING_MODES:
        raise LedgerError("model call accounting_mode is invalid")
    if snapshot["accounting_evidence_ref"] is not None:
        _text(
            snapshot["accounting_evidence_ref"],
            "model call accounting_evidence_ref",
            maximum=512,
        )
    for name in ("ambiguous_usage", "budget_released", "auto_retry"):
        if type(snapshot[name]) is not bool:
            raise LedgerError(f"model call {name} must be boolean")
    if snapshot["auto_retry"] is not False:
        raise LedgerError("model call automatic retry is forbidden")
    return snapshot


def _validate_model_call_transition(
    previous: Mapping[str, object] | None,
    current: Mapping[str, object],
    event_at: str,
) -> None:
    snapshot = _model_call_snapshot(current)
    state = snapshot["state"]
    expected_previous = {
        "PROPOSED": None,
        "RESERVED": "PROPOSED",
        "SENT": "RESERVED",
        "SUCCEEDED": "SENT",
        "FAILED_KNOWN": "SENT",
        "UNKNOWN": "SENT",
        "RECONCILED": _MODEL_CALL_TERMINAL_STATES,
    }[state]
    if previous is None:
        if state != "PROPOSED" or snapshot["previous_state"] is not None:
            raise LedgerError("model call must begin at PROPOSED")
    else:
        prior = _model_call_snapshot(previous)
        allowed = (
            prior["state"] in expected_previous
            if isinstance(expected_previous, frozenset)
            else prior["state"] == expected_previous
        )
        if not allowed or snapshot["previous_state"] != prior["state"]:
            raise LedgerError("model call state transition is invalid")
        immutable = (
            "call_id", "request_sha256", "registry_sha256", "binding_revision",
            "role", "model_binding", "classification", "budget_policy_ref",
            "budget_scope_ref", "max_active_calls", "max_tokens", "max_cost_units",
            "max_reserved_tokens", "max_reserved_cost_units", "expires_at", "proposed_at",
        )
        if any(snapshot[name] != prior[name] for name in immutable):
            raise LedgerError("model call immutable reservation binding changed")

    timestamp_fields = {
        "PROPOSED": "proposed_at",
        "RESERVED": "reserved_at",
        "SENT": "sent_at",
        "SUCCEEDED": "terminal_at",
        "FAILED_KNOWN": "terminal_at",
        "UNKNOWN": "terminal_at",
        "RECONCILED": "reconciled_at",
    }
    if snapshot[timestamp_fields[state]] != event_at:
        raise LedgerError("model call transition timestamp is not event-bound")
    if (
        state != "RECONCILED"
        and _timestamp_datetime(event_at)
        > _timestamp_datetime(snapshot["expires_at"])
    ):
        raise LedgerError("model call reservation expired")

    ordered = ("proposed_at", "reserved_at", "sent_at", "terminal_at", "reconciled_at")
    required_count = {
        "PROPOSED": 1, "RESERVED": 2, "SENT": 3,
        "SUCCEEDED": 4, "FAILED_KNOWN": 4, "UNKNOWN": 4, "RECONCILED": 5,
    }[state]
    if any(snapshot[name] is None for name in ordered[:required_count]) or any(
        snapshot[name] is not None for name in ordered[required_count:]
    ):
        raise LedgerError("model call lifecycle timestamps are incomplete")
    parsed = [_timestamp_datetime(snapshot[name]) for name in ordered[:required_count]]
    if parsed != sorted(parsed):
        raise LedgerError("model call lifecycle timestamps regress")

    if state in {"PROPOSED", "RESERVED", "SENT"}:
        if any(
            snapshot[name] is not None
            for name in (
                "response_ref", "actual_tokens", "actual_cost_units",
                "provider_receipt_ref", "failure_code",
            )
        ) or snapshot["ambiguous_usage"] or snapshot["budget_released"]:
            raise LedgerError("nonterminal model call contains terminal material")
        if (
            snapshot["accounting_mode"] != "NUMERIC_EXACT"
            or snapshot["accounting_evidence_ref"] is not None
        ):
            raise LedgerError("nonterminal model call contains accounting disposition")
    elif state == "SUCCEEDED":
        if snapshot["response_ref"] is None or snapshot["failure_code"] is not None:
            raise LedgerError("successful model call requires a response and no failure")
        expected_ambiguous = (
            snapshot["actual_tokens"] is None
            or snapshot["actual_cost_units"] is None
        )
        if snapshot["ambiguous_usage"] is not expected_ambiguous:
            raise LedgerError("successful model call ambiguity flag is invalid")
        if snapshot["budget_released"]:
            raise LedgerError("success cannot release budget before reconciliation")
        if (
            snapshot["accounting_mode"] != "NUMERIC_EXACT"
            or snapshot["accounting_evidence_ref"] is not None
        ):
            raise LedgerError("success cannot predeclare observational accounting")
    elif state == "FAILED_KNOWN":
        if snapshot["failure_code"] is None or snapshot["response_ref"] is not None:
            raise LedgerError("known failure shape is invalid")
        expected_ambiguous = (
            snapshot["actual_tokens"] is None
            or snapshot["actual_cost_units"] is None
        )
        if snapshot["ambiguous_usage"] is not expected_ambiguous:
            raise LedgerError("known failure ambiguity flag is invalid")
        if snapshot["budget_released"]:
            raise LedgerError("known failure cannot release before reconciliation")
        if (
            snapshot["accounting_mode"] != "NUMERIC_EXACT"
            or snapshot["accounting_evidence_ref"] is not None
        ):
            raise LedgerError("known failure cannot predeclare observational accounting")
    elif state == "UNKNOWN":
        if (
            snapshot["failure_code"] != "AMBIGUOUS_PROVIDER_OUTCOME"
            or snapshot["ambiguous_usage"] is not True
            or snapshot["budget_released"] is not False
        ):
            raise LedgerError("UNKNOWN must retain ambiguous usage and reservation")
        if (
            snapshot["accounting_mode"] != "NUMERIC_EXACT"
            or snapshot["accounting_evidence_ref"] is not None
        ):
            raise LedgerError("UNKNOWN cannot use observational accounting")
    elif state == "RECONCILED":
        if (
            snapshot["actual_tokens"] is None
            or snapshot["provider_receipt_ref"] is None
            or snapshot["ambiguous_usage"] is not False
            or snapshot["budget_released"] is not True
        ):
            raise LedgerError("RECONCILED requires observed usage and budget release evidence")
        if snapshot["accounting_mode"] == "NUMERIC_EXACT":
            if (
                snapshot["actual_cost_units"] is None
                or snapshot["accounting_evidence_ref"] is not None
            ):
                raise LedgerError("numeric reconciliation requires exact numeric cost")
        elif (
            snapshot["actual_cost_units"] is not None
            or snapshot["accounting_evidence_ref"] is None
            or snapshot["previous_state"] not in {
                "SUCCEEDED", "FAILED_KNOWN", "UNKNOWN"
            }
            or (
                snapshot["previous_state"] == "UNKNOWN"
                and snapshot["failure_code"] != "VACUOUS_OUTPUT"
            )
        ):
            raise LedgerError(
                "observational reconciliation requires bound non-numeric evidence"
            )


def _validate_model_call_budget(
    latest: Mapping[str, Mapping[str, object]],
    candidate: Mapping[str, object],
) -> None:
    active = [
        _model_call_snapshot(value)
        for value in latest.values()
        if value["state"] in _MODEL_CALL_ACTIVE_RESERVATION_STATES
    ]
    if any(
        value["budget_policy_ref"] != candidate["budget_policy_ref"]
        or value["budget_scope_ref"] != candidate["budget_scope_ref"]
        or value["max_active_calls"] != candidate["max_active_calls"]
        or value["max_reserved_tokens"] != candidate["max_reserved_tokens"]
        or value["max_reserved_cost_units"] != candidate["max_reserved_cost_units"]
        for value in active
    ):
        raise LedgerError("active model reservations use a different budget scope")
    if len(active) + 1 > candidate["max_active_calls"]:
        raise LedgerError("model call active reservation limit exceeded")
    if sum(value["max_tokens"] for value in active) + candidate["max_tokens"] > candidate["max_reserved_tokens"]:
        raise LedgerError("model call token reservation limit exceeded")
    if sum(value["max_cost_units"] for value in active) + candidate["max_cost_units"] > candidate["max_reserved_cost_units"]:
        raise LedgerError("model call cost reservation limit exceeded")


def _model_call_record_from_event(event: LedgerEvent) -> ModelCallTransitionRecord:
    if event.payload.get("bundle_kind") != "model_call_transition_v1":
        raise LedgerError("ledger event is not a model call transition")
    snapshot = _model_call_snapshot(
        _exact_mapping(event.payload, frozenset({"bundle_kind", "idempotency_key", "objects", "projections", "model_call"}), "model call bundle")["model_call"]
    )
    if event.payload.get("objects") not in ([], ()):
        raise LedgerError("model call transition cannot persist A1 objects")
    return ModelCallTransitionRecord(event=event, snapshot=_deep_freeze(snapshot))


def _preview_feedback_material(
    *,
    execution_ref: str,
    validation_ref: str,
    root_event_ref: str,
    parent_event_ref: str,
    contour: str,
    classification: str,
    shadow_taint: str,
    mechanical_axis: str,
    proposed_outcome: str,
    blame_axis: str,
    domain_application_ref: str | None,
    next_event_candidate: Mapping[str, object] | None,
    parked_gap_refs: Sequence[str],
    idempotency_key: str,
    event_at: str,
) -> Mapping[str, object]:
    """Preview deterministic feedback identities without reading or writing state."""

    request = _feedback_request(
        execution_ref=execution_ref,
        validation_ref=validation_ref,
        root_event_ref=root_event_ref,
        parent_event_ref=parent_event_ref,
        contour=contour,
        classification=classification,
        shadow_taint=shadow_taint,
        mechanical_axis=mechanical_axis,
        proposed_outcome=proposed_outcome,
        blame_axis=blame_axis,
        domain_application_ref=domain_application_ref,
        next_event_candidate=next_event_candidate,
        parked_gap_refs=parked_gap_refs,
        idempotency_key=idempotency_key,
        event_at=event_at,
        next_material_event=None,
    )
    return _deep_freeze(_construct_feedback_material(request))


def _feedback_request(
    *,
    execution_ref: str,
    validation_ref: str,
    root_event_ref: str,
    parent_event_ref: str,
    contour: str,
    classification: str,
    shadow_taint: str,
    mechanical_axis: str,
    proposed_outcome: str,
    blame_axis: str,
    domain_application_ref: str | None,
    next_event_candidate: Mapping[str, object] | None,
    parked_gap_refs: Sequence[str],
    idempotency_key: str,
    event_at: str,
    next_material_event: Mapping[str, object] | None,
) -> dict[str, object]:
    execution = _feedback_ref(execution_ref, "execution_ref")
    if not execution.startswith("execution:"):
        raise LedgerError("execution_ref must use the execution scheme")
    validation = _feedback_ref(validation_ref, "validation_ref")
    if not validation.startswith("validation:"):
        raise LedgerError("validation_ref must use the validation scheme")
    root = _feedback_ref(root_event_ref, "root_event_ref")
    parent = _feedback_ref(parent_event_ref, "parent_event_ref")
    if contour not in _CONTOURS:
        raise LedgerError("feedback contour is invalid")
    if classification not in {"D0", "D1"}:
        raise LedgerError("feedback accepts D0 or D1 only")
    if shadow_taint not in {"NONE", "SHADOW_UNAPPLIED"}:
        raise LedgerError("feedback shadow_taint is invalid")
    if mechanical_axis not in _MECHANICAL_AXES:
        raise LedgerError("feedback mechanical_axis is invalid")
    if proposed_outcome not in _PROPOSED_OUTCOMES:
        raise LedgerError("feedback proposed_outcome is invalid")
    if blame_axis not in _BLAME_AXES:
        raise LedgerError("feedback blame_axis is invalid")
    if mechanical_axis == "MECHANICAL_SUCCESS" and blame_axis != "NONE":
        raise LedgerError("mechanical success cannot assign blame")
    if mechanical_axis == "MECHANICAL_FAILURE" and blame_axis == "NONE":
        raise LedgerError("mechanical failure requires a blame axis")
    application = None
    if domain_application_ref is not None:
        application = _feedback_ref(
            domain_application_ref, "domain_application_ref"
        )
        if shadow_taint == "SHADOW_UNAPPLIED":
            raise LedgerError("shadow feedback cannot claim domain application")
        if mechanical_axis != "MECHANICAL_SUCCESS":
            raise LedgerError("failed execution cannot claim domain application")
        if proposed_outcome in {"PROVIDER_FAILURE", "VALIDATED_MECHANICAL"}:
            raise LedgerError("non-epistemic validation cannot be domain applied")

    candidate = None
    if next_event_candidate is not None:
        candidate = _exact_mapping(
            next_event_candidate,
            frozenset(
                {"reason_code", "policy_ref", "remaining_energy", "causal_depth"}
            ),
            "next_event_candidate",
        )
        candidate = {
            "reason_code": _text(
                candidate["reason_code"], "next reason_code", maximum=128
            ),
            "policy_ref": _feedback_ref(
                candidate["policy_ref"], "next policy_ref"
            ),
            "remaining_energy": _safe_nonnegative_integer(
                "next remaining_energy", candidate["remaining_energy"]
            ),
            "causal_depth": _safe_nonnegative_integer(
                "next causal_depth", candidate["causal_depth"]
            ),
        }
    if not isinstance(parked_gap_refs, Sequence) or isinstance(
        parked_gap_refs, (str, bytes)
    ):
        raise LedgerError("parked_gap_refs must be a sequence")
    if len(parked_gap_refs) > _PARKED_GAP_LIMIT:
        raise LedgerError("parked gap bound exceeded")
    parked = tuple(
        _feedback_ref(value, f"parked_gap_refs[{index}]")
        for index, value in enumerate(parked_gap_refs)
    )
    if len(parked) != len(set(parked)):
        raise LedgerError("parked gap refs must be unique")

    return {
        "execution_ref": execution,
        "validation_ref": validation,
        "root_event_ref": root,
        "parent_event_ref": parent,
        "contour": contour,
        "classification": classification,
        "shadow_taint": shadow_taint,
        "mechanical_axis": mechanical_axis,
        "proposed_outcome": proposed_outcome,
        "blame_axis": blame_axis,
        "domain_application_ref": application,
        "next_event_candidate": candidate,
        "parked_gap_refs": list(parked),
        "idempotency_key": _text(
            idempotency_key, "feedback idempotency_key", maximum=256
        ),
        "event_at": _timestamp("feedback event_at", event_at),
        "next_material_event": (
            None
            if next_material_event is None
            else _json_copy(next_material_event, "next_material_event")
        ),
    }


def _construct_feedback_material(request: Mapping[str, object]) -> dict[str, object]:
    applied = request["domain_application_ref"] is not None
    proposed = request["proposed_outcome"]
    mechanical = request["mechanical_axis"]
    if mechanical != "MECHANICAL_SUCCESS" or proposed == "PROVIDER_FAILURE":
        epistemic_axis = "UNRESOLVED"
        memory_class = "INCONCLUSIVE"
    elif not applied:
        epistemic_axis = "UNRESOLVED"
        memory_class = "INCONCLUSIVE"
    elif proposed == "SUPPORTED":
        epistemic_axis = "SUPPORTED"
        memory_class = "POSITIVE"
    elif proposed == "REFUTED":
        epistemic_axis = "REFUTED"
        memory_class = "NEGATIVE"
    else:
        epistemic_axis = "INCONCLUSIVE"
        memory_class = "INCONCLUSIVE"

    disposition = "DOMAIN_APPLIED" if applied else "SHADOW_UNAPPLIED"
    inherited_shadow = "NONE" if applied else "SHADOW_UNAPPLIED"
    outcome_payload = {
        "execution_ref": request["execution_ref"],
        "validation_ref": request["validation_ref"],
        "mechanical_axis": mechanical,
        "epistemic_axis": epistemic_axis,
        "blame_axis": request["blame_axis"],
        "proposed_outcome": proposed,
        "disposition": disposition,
        "domain_application_ref": request["domain_application_ref"],
        "shadow_taint": inherited_shadow,
        "claims_scientific_truth": False,
        "issued_at": request["event_at"],
    }
    outcome_id = f"outcome-disposition:{_digest(_canonical_json(outcome_payload).encode('utf-8'))}"
    outcome = {"object_id": outcome_id, **outcome_payload}

    experience_payload = {
        "outcome_ref": outcome_id,
        "memory_class": memory_class,
        "mechanical_axis": mechanical,
        "epistemic_axis": epistemic_axis,
        "blame_axis": request["blame_axis"],
        "evidence_refs": [
            request["execution_ref"],
            request["validation_ref"],
            *(
                [request["domain_application_ref"]]
                if request["domain_application_ref"] is not None
                else []
            ),
        ],
        "reusable_failure": (
            memory_class == "NEGATIVE" or mechanical == "MECHANICAL_FAILURE"
        ),
        "shadow_taint": inherited_shadow,
        "claims_learning": False,
        "issued_at": request["event_at"],
    }
    experience_id = f"experience:{_digest(_canonical_json(experience_payload).encode('utf-8'))}"
    experience = {"object_id": experience_id, **experience_payload}

    trigger, derived_parked = _next_internal_trigger(request, outcome_id, inherited_shadow)
    parked_refs = list(request["parked_gap_refs"])
    if derived_parked is not None and derived_parked not in parked_refs:
        if len(parked_refs) >= _PARKED_GAP_LIMIT:
            raise LedgerError("derived parked gap exceeds the bound")
        parked_refs.append(derived_parked)
    material_event = request.get("next_material_event")
    if material_event is not None:
        _validate_next_material_event(
            material_event,
            request=request,
            outcome_ref=outcome_id,
            trigger=trigger,
            shadow_taint=inherited_shadow,
        )
    outbox_payload = {
        "outcome_ref": outcome_id,
        "status": "RUNNABLE" if trigger is not None else "WAIT_AUTHORITY",
        "runnable_count": 1 if trigger is not None else 0,
        "internal_event_trigger": trigger,
        "parked_gap_refs": parked_refs,
        "material_event_minted": material_event is not None,
        "issued_at": request["event_at"],
    }
    outbox_id = f"feedback-outbox:{_digest(_canonical_json(outbox_payload).encode('utf-8'))}"
    outbox = {"object_id": outbox_id, **outbox_payload}

    idea_payload = {
        "root_event_ref": request["root_event_ref"],
        "parent_event_ref": request["parent_event_ref"],
        "outcome_ref": outcome_id,
        "experience_ref": experience_id,
        "outbox_ref": outbox_id,
        "state": "GENERATING" if trigger is not None else "WAIT_AUTHORITY",
        "shadow_taint": inherited_shadow,
        "learned": False,
        "updated_at": request["event_at"],
    }
    idea_id = f"idea-node:{_digest(_canonical_json(idea_payload).encode('utf-8'))}"
    idea = {"object_id": idea_id, **idea_payload}
    return {
        "outcome_disposition": outcome,
        "experience_record": experience,
        "idea_node": idea,
        "outbox_record": outbox,
    }


def _next_internal_trigger(
    request: Mapping[str, object], outcome_ref: str, shadow_taint: str
) -> tuple[dict[str, object] | None, str | None]:
    candidate = request["next_event_candidate"]
    if candidate is None:
        return None, None
    if not isinstance(candidate, Mapping):
        raise LedgerError("persisted next event candidate is invalid")
    energy = candidate["remaining_energy"]
    depth = candidate["causal_depth"]
    if not isinstance(energy, int) or not isinstance(depth, int):
        raise LedgerError("persisted next event bounds are invalid")
    if energy <= 0 or depth >= _MAX_CAUSAL_DEPTH:
        parked = f"agenda-gap:{_digest(_canonical_json({'outcome_ref': outcome_ref, 'candidate': candidate}).encode('utf-8'))}"
        return None, parked
    payload = {
        "source": "trusted-outcome-projector",
        "outcome_ref": outcome_ref,
        "root_event_ref": request["root_event_ref"],
        "parent_event_ref": request["parent_event_ref"],
        "contour": request["contour"],
        "classification": request["classification"],
        "shadow_taint": shadow_taint,
        "policy_ref": candidate["policy_ref"],
        "reason_code": candidate["reason_code"],
        "causal_depth": depth + 1,
        "remaining_energy": energy - 1,
        "grants_authority": False,
    }
    return {
        "trigger_id": f"internal-trigger:{_digest(_canonical_json(payload).encode('utf-8'))}",
        **payload,
    }, None


def _validate_next_material_event(
    value: object,
    *,
    request: Mapping[str, object],
    outcome_ref: str,
    trigger: Mapping[str, object] | None,
    shadow_taint: str,
) -> None:
    if trigger is None or not isinstance(value, Mapping):
        raise LedgerError("minted MaterialEvent requires one runnable trigger")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise LedgerError("minted MaterialEvent payload is invalid")
    materiality = payload.get("materiality_inputs")
    if not isinstance(materiality, Mapping):
        raise LedgerError("minted MaterialEvent materiality is invalid")
    expected_policy = str(trigger["policy_ref"])
    if expected_policy.startswith("policy:sha256:"):
        expected_policy_sha256 = expected_policy.removeprefix("policy:sha256:")
    else:
        expected_policy_sha256 = None
    if (
        value.get("schema_id") != "MaterialEvent"
        or value.get("classification") != request["classification"]
        or value.get("contour") != request["contour"]
        or payload.get("origin_class") != "ENDOGENOUS"
        or payload.get("event_kind") != "VALIDATED_FEEDBACK"
        or payload.get("root_event_ref") != request["root_event_ref"]
        or payload.get("parent_event_ref") != request["parent_event_ref"]
        or payload.get("causal_depth") != trigger["causal_depth"]
        or payload.get("shadow_taint") != shadow_taint
        or materiality.get("outcome_ref") != outcome_ref
        or materiality.get("execution_ref") != request["execution_ref"]
        or materiality.get("validation_ref") != request["validation_ref"]
        or (
            expected_policy_sha256 is not None
            and payload.get("policy_sha256") != expected_policy_sha256
        )
    ):
        raise LedgerError("minted MaterialEvent is not bound to feedback")


def _advance_feedback_states(
    previous: Mapping[str, Mapping[str, object]],
    feedback: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    bindings = {
        "outcome_dispositions": ("outcome_disposition", "execution_ref"),
        "experiences": ("experience_record", "object_id"),
        "idea_tree": ("idea_node", "root_event_ref"),
        "feedback_outbox": ("outbox_record", "object_id"),
    }
    result: dict[str, dict[str, object]] = {}
    for projection_name, (feedback_name, key_name) in bindings.items():
        item = feedback[feedback_name]
        if not isinstance(item, Mapping):
            raise LedgerError("feedback material is invalid")
        key = item[key_name]
        if not isinstance(key, str):
            raise LedgerError("feedback projection key is invalid")
        prior = previous.get(projection_name)
        if prior is None:
            entries: dict[str, object] = {}
        else:
            state = _exact_mapping(
                prior,
                frozenset({"schema_id", "schema_version", "count", "latest_ref", "entries"}),
                f"{projection_name} projection",
            )
            if (
                state["schema_id"] != f"{projection_name}.projection"
                or state["schema_version"] != "1.0.0"
                or not isinstance(state["entries"], Mapping)
            ):
                raise LedgerError("feedback projection identity is invalid")
            entries = _json_copy(state["entries"], f"{projection_name}.entries")
            if not isinstance(entries, dict):
                raise LedgerError("feedback projection entries are invalid")
        if key not in entries and len(entries) >= _FEEDBACK_PROJECTION_ENTRY_LIMIT:
            raise LedgerError("feedback projection capacity is exhausted")
        entries[key] = _json_copy(item, feedback_name)
        latest_ref = item["object_id"]
        result[projection_name] = {
            "schema_id": f"{projection_name}.projection",
            "schema_version": "1.0.0",
            "count": len(entries),
            "latest_ref": latest_ref,
            "entries": entries,
        }
    return result


def _feedback_record_from_event(event: LedgerEvent) -> FeedbackBundleRecord:
    payload = event.payload
    if payload.get("bundle_kind") != "atomic_feedback_v1":
        raise LedgerError("ledger event is not atomic feedback")
    feedback = payload.get("feedback")
    exact = _exact_mapping(
        feedback,
        frozenset(
            {"outcome_disposition", "experience_record", "idea_node", "outbox_record"}
        ),
        "feedback material",
    )
    return FeedbackBundleRecord(
        event=event,
        outcome_disposition=_deep_freeze(
            _json_copy(exact["outcome_disposition"], "outcome_disposition")
        ),
        experience_record=_deep_freeze(
            _json_copy(exact["experience_record"], "experience_record")
        ),
        idea_node=_deep_freeze(_json_copy(exact["idea_node"], "idea_node")),
        outbox_record=_deep_freeze(
            _json_copy(exact["outbox_record"], "outbox_record")
        ),
    )


def _feedback_ref(value: object, name: str) -> str:
    normalized = _text(value, name, maximum=512)
    if (
        _FEEDBACK_REF_RE.fullmatch(normalized) is None
        or normalized.lower().startswith(("file:", "host:"))
        or normalized.startswith(("/", "~"))
    ):
        raise LedgerError(f"{name} must be a portable non-file reference")
    return normalized


def _validate_feedback_knowledge_material(record: FeedbackBundleRecord) -> None:
    outcome = _exact_mapping(
        record.outcome_disposition,
        frozenset(
            {
                "object_id", "execution_ref", "validation_ref", "mechanical_axis",
                "epistemic_axis", "blame_axis", "proposed_outcome", "disposition",
                "domain_application_ref", "shadow_taint", "claims_scientific_truth",
                "issued_at",
            }
        ),
        "knowledge outcome",
    )
    experience = _exact_mapping(
        record.experience_record,
        frozenset(
            {
                "object_id", "outcome_ref", "memory_class", "mechanical_axis",
                "epistemic_axis", "blame_axis", "evidence_refs", "reusable_failure",
                "shadow_taint", "claims_learning", "issued_at",
            }
        ),
        "knowledge experience",
    )
    idea = _exact_mapping(
        record.idea_node,
        frozenset(
            {
                "object_id", "root_event_ref", "parent_event_ref", "outcome_ref",
                "experience_ref", "outbox_ref", "state", "shadow_taint", "learned",
                "updated_at",
            }
        ),
        "knowledge idea",
    )
    outbox = _exact_mapping(
        record.outbox_record,
        frozenset(
            {
                "object_id", "outcome_ref", "status", "runnable_count",
                "internal_event_trigger", "parked_gap_refs", "material_event_minted",
                "issued_at",
            }
        ),
        "knowledge outbox",
    )
    for name, value, prefix in (
        ("outcome", outcome, "outcome-disposition:"),
        ("experience", experience, "experience:"),
        ("idea", idea, "idea-node:"),
        ("outbox", outbox, "feedback-outbox:"),
    ):
        identifier = _text(value["object_id"], f"knowledge {name} object_id", maximum=256)
        payload = {key: item for key, item in value.items() if key != "object_id"}
        if identifier != prefix + _digest(_canonical_json(payload).encode("utf-8")):
            raise LedgerError(f"knowledge {name} identity is poisoned")

    execution_ref = _feedback_ref(outcome["execution_ref"], "knowledge execution_ref")
    validation_ref = _feedback_ref(outcome["validation_ref"], "knowledge validation_ref")
    if not execution_ref.startswith("execution:") or not validation_ref.startswith("validation:"):
        raise LedgerError("knowledge evidence schemes are invalid")
    _timestamp("knowledge outcome issued_at", outcome["issued_at"])
    if outcome["mechanical_axis"] not in _MECHANICAL_AXES:
        raise LedgerError("knowledge mechanical axis is invalid")
    if outcome["proposed_outcome"] not in _PROPOSED_OUTCOMES:
        raise LedgerError("knowledge proposed outcome is invalid")
    if outcome["blame_axis"] not in _BLAME_AXES:
        raise LedgerError("knowledge blame axis is invalid")
    if (
        outcome["mechanical_axis"] == "MECHANICAL_SUCCESS"
        and outcome["blame_axis"] != "NONE"
    ) or (
        outcome["mechanical_axis"] == "MECHANICAL_FAILURE"
        and outcome["blame_axis"] == "NONE"
    ):
        raise LedgerError("knowledge mechanical blame relation is poisoned")
    if outcome["claims_scientific_truth"] is not False:
        raise LedgerError("operational memory cannot claim scientific truth")
    applied = outcome["domain_application_ref"] is not None
    if applied:
        _feedback_ref(outcome["domain_application_ref"], "knowledge domain_application_ref")
    expected_taint = "NONE" if applied else "SHADOW_UNAPPLIED"
    if (
        outcome["shadow_taint"] != expected_taint
        or outcome["disposition"] != ("DOMAIN_APPLIED" if applied else "SHADOW_UNAPPLIED")
    ):
        raise LedgerError("knowledge outcome taint or disposition is poisoned")
    if applied and (
        outcome["mechanical_axis"] != "MECHANICAL_SUCCESS"
        or outcome["proposed_outcome"] in {"PROVIDER_FAILURE", "VALIDATED_MECHANICAL"}
    ):
        raise LedgerError("knowledge domain application scope is poisoned")
    if (
        outcome["mechanical_axis"] != "MECHANICAL_SUCCESS"
        or outcome["proposed_outcome"] == "PROVIDER_FAILURE"
        or not applied
    ):
        expected_epistemic = "UNRESOLVED"
    elif outcome["proposed_outcome"] == "SUPPORTED":
        expected_epistemic = "SUPPORTED"
    elif outcome["proposed_outcome"] == "REFUTED":
        expected_epistemic = "REFUTED"
    else:
        expected_epistemic = "INCONCLUSIVE"
    if outcome["epistemic_axis"] != expected_epistemic:
        raise LedgerError("knowledge epistemic conclusion is poisoned")

    expected_evidence = [execution_ref, validation_ref]
    if applied:
        expected_evidence.append(str(outcome["domain_application_ref"]))
    if (
        experience["outcome_ref"] != outcome["object_id"]
        or experience["mechanical_axis"] != outcome["mechanical_axis"]
        or experience["epistemic_axis"] != outcome["epistemic_axis"]
        or experience["blame_axis"] != outcome["blame_axis"]
        or experience["evidence_refs"] != expected_evidence
        or experience["shadow_taint"] != expected_taint
        or experience["claims_learning"] is not False
        or experience["issued_at"] != outcome["issued_at"]
    ):
        raise LedgerError("knowledge experience lineage is poisoned")
    expected_memory = {
        "SUPPORTED": "POSITIVE", "REFUTED": "NEGATIVE",
        "INCONCLUSIVE": "INCONCLUSIVE", "UNRESOLVED": "INCONCLUSIVE",
    }[str(outcome["epistemic_axis"])]
    if experience["memory_class"] != expected_memory:
        raise LedgerError("knowledge memory class is poisoned")
    expected_failure = (
        expected_memory == "NEGATIVE" or outcome["mechanical_axis"] == "MECHANICAL_FAILURE"
    )
    if experience["reusable_failure"] is not expected_failure:
        raise LedgerError("knowledge failure classification is poisoned")

    root_ref = _feedback_ref(idea["root_event_ref"], "knowledge root_event_ref")
    parent_ref = _feedback_ref(idea["parent_event_ref"], "knowledge parent_event_ref")
    if (
        idea["outcome_ref"] != outcome["object_id"]
        or idea["experience_ref"] != experience["object_id"]
        or idea["outbox_ref"] != outbox["object_id"]
        or idea["shadow_taint"] != expected_taint
        or idea["learned"] is not False
        or idea["updated_at"] != outcome["issued_at"]
    ):
        raise LedgerError("knowledge idea lineage is poisoned")
    trigger = outbox["internal_event_trigger"]
    expected_status = "RUNNABLE" if trigger is not None else "WAIT_AUTHORITY"
    if (
        outbox["outcome_ref"] != outcome["object_id"]
        or outbox["status"] != expected_status
        or outbox["runnable_count"] != (1 if trigger is not None else 0)
        or type(outbox["material_event_minted"]) is not bool
        or (trigger is None and outbox["material_event_minted"] is not False)
        or outbox["issued_at"] != outcome["issued_at"]
        or idea["state"] != ("GENERATING" if trigger is not None else "WAIT_AUTHORITY")
    ):
        raise LedgerError("knowledge outbox state is poisoned")
    parked = outbox["parked_gap_refs"]
    if not isinstance(parked, (list, tuple)) or len(parked) > _PARKED_GAP_LIMIT:
        raise LedgerError("knowledge parked gaps are invalid")
    normalized_parked = [_feedback_ref(value, "knowledge parked gap") for value in parked]
    if len(normalized_parked) != len(set(normalized_parked)):
        raise LedgerError("knowledge parked gaps are duplicated")

    if trigger is not None:
        trigger_value = _exact_mapping(
            trigger,
            frozenset(
                {
                    "trigger_id", "source", "outcome_ref", "root_event_ref",
                    "parent_event_ref", "contour", "classification", "shadow_taint",
                    "policy_ref", "reason_code", "causal_depth", "remaining_energy",
                    "grants_authority",
                }
            ),
            "knowledge trigger",
        )
        trigger_id = _text(trigger_value["trigger_id"], "knowledge trigger_id", maximum=256)
        trigger_payload = {
            key: item for key, item in trigger_value.items() if key != "trigger_id"
        }
        if trigger_id != "internal-trigger:" + _digest(
            _canonical_json(trigger_payload).encode("utf-8")
        ):
            raise LedgerError("knowledge trigger identity is poisoned")
        if (
            trigger_value["source"] != "trusted-outcome-projector"
            or trigger_value["outcome_ref"] != outcome["object_id"]
            or trigger_value["root_event_ref"] != root_ref
            or trigger_value["parent_event_ref"] != parent_ref
            or trigger_value["shadow_taint"] != expected_taint
            or trigger_value["grants_authority"] is not False
        ):
            raise LedgerError("knowledge trigger lineage or authority is poisoned")
        if trigger_value["contour"] not in _CONTOURS or trigger_value["classification"] not in {"D0", "D1"}:
            raise LedgerError("knowledge trigger scope is invalid")
        _feedback_ref(trigger_value["policy_ref"], "knowledge trigger policy_ref")
        _text(trigger_value["reason_code"], "knowledge trigger reason_code", maximum=128)
        depth = _safe_nonnegative_integer("knowledge trigger causal_depth", trigger_value["causal_depth"])
        _safe_nonnegative_integer("knowledge trigger remaining_energy", trigger_value["remaining_energy"])
        if depth > _MAX_CAUSAL_DEPTH:
            raise LedgerError("knowledge trigger causal depth exceeds the bound")


def _knowledge_views(
    selected: Sequence[tuple[LedgerEvent, FeedbackBundleRecord]],
) -> tuple[
    list[dict[str, object]], list[dict[str, object]], list[dict[str, object]],
    list[dict[str, object]], list[dict[str, object]],
]:
    ideas: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    by_root: dict[str, list[tuple[LedgerEvent, FeedbackBundleRecord]]] = {}
    latest_by_root: dict[str, tuple[LedgerEvent, FeedbackBundleRecord]] = {}
    debt_by_key: dict[tuple[str, str], dict[str, object]] = {}

    def add_debt(
        reason_code: str,
        subject_ref: str,
        event: LedgerEvent,
        taint: str,
    ) -> None:
        key = (reason_code, subject_ref)
        debt_by_key[key] = {
            "record_type": "ResearchDebt",
            "reason_code": reason_code,
            "subject_ref": subject_ref,
            "provenance_refs": [f"ledger-event:sha256:{event.event_sha256}"],
            "shadow_taint": taint,
            "claims_scientific_truth": False,
        }

    for event, record in selected:
        outcome = record.outcome_disposition
        experience = record.experience_record
        idea = record.idea_node
        outbox = record.outbox_record
        event_ref = f"ledger-event:sha256:{event.event_sha256}"
        root = str(idea["root_event_ref"])
        by_root.setdefault(root, []).append((event, record))
        latest_by_root[root] = (event, record)
        ideas.append(
            {
                "record_type": "IdeaNode",
                "object_id": idea["object_id"],
                "root_event_ref": root,
                "parent_event_ref": idea["parent_event_ref"],
                "outcome_ref": idea["outcome_ref"],
                "experience_ref": idea["experience_ref"],
                "outbox_ref": idea["outbox_ref"],
                "state": idea["state"],
                "shadow_taint": idea["shadow_taint"],
                "learned": False,
                "provenance_refs": [event_ref, outcome["validation_ref"], outcome["execution_ref"]],
                "ledger_sequence": event.sequence,
            }
        )
        if experience["reusable_failure"] is True:
            failures.append(
                {
                    "record_type": "ReusableFailureMemory",
                    "object_id": experience["object_id"],
                    "outcome_ref": outcome["object_id"],
                    "memory_class": experience["memory_class"],
                    "mechanical_axis": experience["mechanical_axis"],
                    "blame_axis": experience["blame_axis"],
                    "evidence_refs": list(experience["evidence_refs"]),
                    "shadow_taint": experience["shadow_taint"],
                    "provenance_refs": [event_ref],
                    "claims_learning": False,
                }
            )
        if idea["shadow_taint"] == "SHADOW_UNAPPLIED":
            add_debt("SHADOW_REVIEW_REQUIRED", str(idea["object_id"]), event, "SHADOW_UNAPPLIED")
        if outcome["epistemic_axis"] == "UNRESOLVED":
            add_debt("EPISTEMIC_UNRESOLVED", str(outcome["object_id"]), event, str(idea["shadow_taint"]))
        if outbox["status"] == "WAIT_AUTHORITY":
            add_debt("WAIT_AUTHORITY", str(outbox["object_id"]), event, str(idea["shadow_taint"]))
        for parked_ref in outbox["parked_gap_refs"]:
            add_debt("PARKED_GAP", str(parked_ref), event, str(idea["shadow_taint"]))

    conflicts: list[dict[str, object]] = []
    for root in sorted(by_root):
        items = by_root[root]
        axes = {str(record.outcome_disposition["epistemic_axis"]) for _, record in items}
        if not {"SUPPORTED", "REFUTED"}.issubset(axes):
            continue
        refs = [str(record.outcome_disposition["object_id"]) for _, record in items if record.outcome_disposition["epistemic_axis"] in {"SUPPORTED", "REFUTED"}]
        event_refs = [f"ledger-event:sha256:{event.event_sha256}" for event, record in items if record.outcome_disposition["epistemic_axis"] in {"SUPPORTED", "REFUTED"}]
        conflict_payload = {
            "record_type": "ConflictCandidate",
            "root_event_ref": root,
            "axes": ["REFUTED", "SUPPORTED"],
            "outcome_refs": refs,
            "provenance_refs": event_refs,
            "status": "REPLICATION_REQUIRED",
            "shadow_taint": "NONE",
            "claims_scientific_truth": False,
        }
        conflict_payload["object_id"] = "conflict-candidate:" + _digest(
            _canonical_json(conflict_payload).encode("utf-8")
        )
        conflicts.append(conflict_payload)
        event, _ = items[-1]
        add_debt("CONFLICT_REPLICATION_REQUIRED", str(conflict_payload["object_id"]), event, "NONE")

    energy: list[dict[str, object]] = []
    for root in sorted(latest_by_root):
        event, record = latest_by_root[root]
        trigger = record.outbox_record["internal_event_trigger"]
        if isinstance(trigger, Mapping):
            remaining = trigger["remaining_energy"]
            status = "AVAILABLE" if remaining > 0 else "LAST_ALLOWED_TRIGGER"
            causal_depth = trigger["causal_depth"]
        else:
            remaining = None
            status = "NO_RUNNABLE_TRIGGER"
            causal_depth = None
        energy.append(
            {
                "record_type": "RootEventEnergy",
                "root_event_ref": root,
                "observed_remaining_energy": remaining,
                "observed_causal_depth": causal_depth,
                "status": status,
                "source_outcome_ref": record.outcome_disposition["object_id"],
                "shadow_taint": record.idea_node["shadow_taint"],
                "provenance_refs": [f"ledger-event:sha256:{event.event_sha256}"],
                "grants_authority": False,
            }
        )
    debt = [debt_by_key[key] for key in sorted(debt_by_key)]
    return ideas, failures, conflicts, energy, debt


def _safe_nonnegative_integer(name: str, value: object) -> int:
    normalized = _nonnegative_integer(name, value)
    if normalized > _MAX_SAFE_INTEGER:
        raise LedgerError(f"{name} exceeds the safe integer limit")
    return normalized


def _projection_descriptor_map(payload: Mapping[str, object]) -> dict[str, str]:
    raw = payload.get("projections")
    if not isinstance(raw, (list, tuple)):
        raise LedgerError("A1 projection descriptors are invalid")
    descriptors: dict[str, str] = {}
    for index, item in enumerate(raw):
        descriptor = _exact_mapping(
            item,
            frozenset({"projection_name", "state_sha256"}),
            f"projection descriptor[{index}]",
        )
        name = _text(
            descriptor["projection_name"],
            f"projection descriptor[{index}].projection_name",
            maximum=128,
        )
        if name in descriptors:
            raise LedgerError("A1 projection descriptor is duplicated")
        descriptors[name] = _sha256(
            f"projection descriptor[{index}].state_sha256",
            descriptor["state_sha256"],
        )
    return descriptors


def _feedback_capacity_envelope(
    *,
    ledger_event_count: int,
    feedback_bundle_count: int,
    projections: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    counts: dict[str, int] = {}
    runnable = 0
    wait_authority = 0
    for name in sorted(_FEEDBACK_PROJECTION_NAMES):
        state = projections.get(name)
        if state is None:
            counts[name] = 0
            continue
        exact = _exact_mapping(
            state,
            frozenset({"schema_id", "schema_version", "count", "latest_ref", "entries"}),
            f"capacity {name}",
        )
        count = _safe_nonnegative_integer(f"capacity {name}.count", exact["count"])
        if count > _FEEDBACK_PROJECTION_ENTRY_LIMIT:
            raise LedgerError("persisted feedback projection exceeds capacity")
        if not isinstance(exact["entries"], Mapping) or len(exact["entries"]) != count:
            raise LedgerError("persisted feedback projection count mismatch")
        counts[name] = count
        if name == "feedback_outbox":
            for record in exact["entries"].values():
                if not isinstance(record, Mapping):
                    raise LedgerError("persisted outbox record is invalid")
                status = record.get("status")
                runnable_count = record.get("runnable_count")
                if status == "RUNNABLE" and runnable_count == 1:
                    runnable += 1
                elif status == "WAIT_AUTHORITY" and runnable_count == 0:
                    wait_authority += 1
                else:
                    raise LedgerError("persisted outbox state is invalid")
    remaining = {
        name: _FEEDBACK_PROJECTION_ENTRY_LIMIT - count
        for name, count in counts.items()
    }
    return {
        "scope": "single-process-single-SQLite-writer-frozen-v1",
        "writer_count": 1,
        "ordering_model": "single-bridge-global-sequence",
        "projection_entry_limit_each": _FEEDBACK_PROJECTION_ENTRY_LIMIT,
        "parked_gap_refs_per_outcome_limit": _PARKED_GAP_LIMIT,
        "causal_depth_limit": _MAX_CAUSAL_DEPTH,
        "observed": {
            "ledger_events": ledger_event_count,
            "feedback_bundles": feedback_bundle_count,
            "projection_entries": counts,
            "projection_remaining": remaining,
            "runnable_outbox_records": runnable,
            "wait_authority_outbox_records": wait_authority,
        },
        "throughput_observation": {
            "kind": "durable-counts-not-wall-clock-rate",
            "committed_global_events": ledger_event_count,
            "committed_feedback_bundles": feedback_bundle_count,
            "rate_claimed": False,
        },
        "distributed_scale_claimed": False,
        "second_writer_authorized": False,
    }


def _expected_schema_fingerprint(
    objects: tuple[tuple[str, str, str], ...], *, user_version: int
) -> str:
    def table_name(object_type: str, name: str) -> str:
        if object_type == "table":
            return name
        if name.startswith("bridge_a1_object_") or name.startswith("bridge_a1_objects_"):
            return "bridge_a1_objects"
        if name.startswith("bridge_a1_projection_"):
            return "bridge_a1_projection_state"
        return "bridge_job_ledger"

    manifest = tuple(
        sorted(
            (
                object_type,
                name,
                table_name(object_type, name),
                statement,
            )
            for object_type, name, statement in objects
        )
    )
    identity = {"user_version": user_version, "objects": manifest}
    return _digest(_canonical_json(identity).encode("utf-8"))


def _canonical_json(value: object) -> str:
    return json.dumps(
        _json_ready(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _nonempty_text(name: str, value: object) -> str:
    if isinstance(value, bytes) or not isinstance(value, str):
        raise LedgerError(f"{name} must be text, not payload bytes")
    if not value or value != value.strip() or any(ord(character) < 32 for character in value):
        raise LedgerError(f"{name} must be non-empty normalized text")
    return value


def _nonnegative_integer(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LedgerError(f"{name} must be a non-negative integer")
    return value


def _positive_integer(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LedgerError(f"{name} must be a positive integer")
    return value


def _positive_safe_integer(name: str, value: object) -> int:
    value = _positive_integer(name, value)
    if value > _MAX_SAFE_INTEGER:
        raise LedgerError(f"{name} exceeds the safe integer limit")
    return value


def _sha256(name: str, value: object) -> str:
    value = _nonempty_text(name, value)
    if _SHA256_RE.fullmatch(value) is None:
        raise LedgerError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(name: str, value: object) -> str:
    value = _nonempty_text(name, value)
    if _RFC3339_RE.fullmatch(value) is None:
        raise LedgerError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LedgerError(f"{name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LedgerError(f"{name} must include an offset")
    return value


def _timestamp_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _pattern_text(name: str, value: object, pattern: re.Pattern[str]) -> str:
    value = _nonempty_text(name, value)
    if pattern.fullmatch(value) is None:
        raise LedgerError(f"{name} has an invalid content-addressed format")
    return value


def _enum_text(name: str, value: object, allowed: frozenset[str]) -> str:
    value = _nonempty_text(name, value)
    if value not in allowed:
        raise LedgerError(f"{name} is invalid")
    return value


def _exact_object(
    name: str, value: object, expected_fields: frozenset[str]
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LedgerError(f"{name} must be an object")
    copied = dict(value)
    if any(not isinstance(key, str) for key in copied) or set(copied) != set(
        expected_fields
    ):
        raise LedgerError(f"{name} fields are not exact")
    return copied


def _validate_full_receipt(
    name: str, value: object, *, schema_id: str
) -> dict[str, Any]:
    receipt = _exact_object(name, value, _RECEIPT_FIELDS)
    if receipt["schema_id"] != schema_id or receipt["schema_version"] != "1.0.0":
        raise LedgerError(f"{name} schema identity is invalid")
    _nonempty_text(f"{name}.object_id", receipt["object_id"])
    _timestamp(f"{name}.issued_at", receipt["issued_at"])
    issuer = _exact_object(
        f"{name}.issuer", receipt["issuer"], frozenset({"id", "authority_class"})
    )
    _nonempty_text(f"{name}.issuer.id", issuer["id"])
    _nonempty_text(
        f"{name}.issuer.authority_class", issuer["authority_class"]
    )
    _enum_text(f"{name}.contour", receipt["contour"], _CONTOURS)
    _enum_text(
        f"{name}.classification", receipt["classification"], _CLASSIFICATIONS
    )
    if not isinstance(receipt["payload"], Mapping):
        raise LedgerError(f"{name}.payload must be an object")
    integrity = _exact_object(
        f"{name}.integrity",
        receipt["integrity"],
        frozenset({"payload_sha256", "parent_refs"}),
    )
    payload_sha256 = _sha256(
        f"{name}.integrity.payload_sha256", integrity["payload_sha256"]
    )
    if payload_sha256 != _digest(
        _canonical_json(receipt["payload"]).encode("utf-8")
    ):
        raise LedgerError(f"{name} payload integrity is invalid")
    parent_refs = integrity["parent_refs"]
    if not isinstance(parent_refs, (list, tuple)):
        raise LedgerError(f"{name}.integrity.parent_refs must be an array")
    for index, ref in enumerate(parent_refs):
        _nonempty_text(f"{name}.integrity.parent_refs[{index}]", ref)
    return _json_ready(receipt)


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


def _text(value: object, name: str, *, maximum: int) -> str:
    result = _nonempty_text(name, value)
    if len(result) > maximum:
        raise LedgerError(f"{name} exceeds its text bound")
    return result


def _json_copy(value: object, name: str) -> object:
    try:
        encoded = _canonical_json(value)
        return json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise LedgerError(f"{name} is not JSON-shaped") from exc


def _exact_mapping(
    value: object, expected_fields: frozenset[str], name: str
) -> dict[str, object]:
    copied = _json_copy(value, name)
    if not isinstance(copied, dict) or set(copied) != expected_fields:
        raise LedgerError(f"{name} fields are not exact")
    return copied


def _string_array(value: object, name: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, (list, tuple)) or (not allow_empty and not value):
        raise LedgerError(f"{name} must be a string array")
    result = [
        _nonempty_text(f"{name}[{index}]", item)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise LedgerError(f"{name} must contain unique values")
    return result


def _load_json_object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, str):
        raise LedgerError(f"{name} storage value must be JSON text")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise LedgerError(f"{name} storage value is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise LedgerError(f"{name} storage value must be an object")
    return decoded


def _payload_ref(value: object) -> str:
    value = _nonempty_text("payload_ref", value)
    if _PAYLOAD_REF_RE.fullmatch(value) is None:
        raise LedgerError("payload_ref must be a portable cas: or vault: reference")
    return value


__all__ = ["LedgerError", "LedgerEvent", "A1BundleRecord", "JobLedger"]
