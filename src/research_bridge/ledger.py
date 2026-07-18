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
    ) -> A1BundleRecord:
        """Commit A1 objects and all projections at one global ledger sequence."""

        key = _text(idempotency_key, "idempotency_key", maximum=256)
        timestamp = _timestamp("event_at", event_at)
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
    ) -> FeedbackBundleRecord:
        """Atomically preserve operational feedback without asserting scientific truth."""

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

                base_states = self._projection_states_locked(_A1_PROJECTION_NAMES)
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
                    "objects": [],
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
    outbox_payload = {
        "outcome_ref": outcome_id,
        "status": "RUNNABLE" if trigger is not None else "WAIT_AUTHORITY",
        "runnable_count": 1 if trigger is not None else 0,
        "internal_event_trigger": trigger,
        "parked_gap_refs": parked_refs,
        "material_event_minted": False,
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


def _safe_nonnegative_integer(name: str, value: object) -> int:
    normalized = _nonnegative_integer(name, value)
    if normalized > _MAX_SAFE_INTEGER:
        raise LedgerError(f"{name} exceeds the safe integer limit")
    return normalized


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
