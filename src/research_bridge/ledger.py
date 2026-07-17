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
from typing import Any, Mapping


_GENESIS_SHA256 = "0" * 64
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_PAYLOAD_REF_RE = re.compile(r"^(?:cas|vault):[A-Za-z0-9][A-Za-z0-9._:/+-]{0,511}$")
_ACCOUNTING_POLICY_REF_RE = re.compile(r"^budget-policy:sha256:[a-f0-9]{64}$")
_BUDGET_SCOPE_REF_RE = re.compile(r"^budget-scope:sha256:[a-f0-9]{64}$")
_EMBEDDED_REF_RE = re.compile(r"^embedded:sha256:[a-f0-9]{64}$")
_EVENT_TYPES = frozenset({"claim", "checkpoint", "complete", "pause", "resume"})
_CONTROL_EVENT_TYPES = frozenset({"pause", "resume"})
_GLOBAL_CONTROL_JOB_ID = "bridge-global-control"
_DATABASE_USER_VERSION = 1
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

_TABLE_SQL = """CREATE TABLE bridge_job_ledger (
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
_LEGACY_SCHEMA_OBJECTS = (
    ("table", "bridge_job_ledger", _TABLE_SQL),
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
        expected_v1 = _expected_schema_fingerprint(
            _SCHEMA_V1_OBJECTS, user_version=_DATABASE_USER_VERSION
        )
        if version == _DATABASE_USER_VERSION:
            if fingerprint != expected_v1:
                raise LedgerError("ledger schema fingerprint is not exact version 1")
            return
        if version != 0:
            raise LedgerError("ledger database user_version is unsupported")

        expected_legacy = _expected_schema_fingerprint(
            _LEGACY_SCHEMA_OBJECTS, user_version=0
        )
        if object_count and fingerprint != expected_legacy:
            raise LedgerError("unversioned ledger schema is ambiguous")

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            version, fingerprint, object_count = self._schema_identity()
            if version == _DATABASE_USER_VERSION:
                if fingerprint != expected_v1:
                    raise LedgerError("ledger schema fingerprint is not exact version 1")
                self._connection.execute("COMMIT")
                return
            if version != 0:
                raise LedgerError("ledger database user_version is unsupported")
            if object_count == 0:
                self._create_schema_objects(_SCHEMA_V1_OBJECTS)
            elif fingerprint == expected_legacy:
                row_count = self._connection.execute(
                    "SELECT COUNT(*) FROM bridge_job_ledger"
                ).fetchone()[0]
                if row_count != 0:
                    raise LedgerError("nonempty unversioned ledger requires quarantine")
                self._create_schema_objects(_BUDGET_INDEX_OBJECTS)
            else:
                raise LedgerError("unversioned ledger schema is ambiguous")
            self._connection.execute(f"PRAGMA user_version = {_DATABASE_USER_VERSION}")
            version, fingerprint, _ = self._schema_identity()
            if version != _DATABASE_USER_VERSION or fingerprint != expected_v1:
                raise LedgerError("ledger schema version 1 creation was not exact")
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

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
                self._require_current_fence(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    fencing_epoch=fencing_epoch,
                    fencing_token=fencing_token,
                )
                self._require_not_completed(job_id)
                projections = self._budget_projection_in_transaction()
                projection = next(
                    (item for item in projections if item.event.job_id == job_id),
                    None,
                )
                if projection is None:
                    raise LedgerError("job claim lacks an exact budget reservation")
                if projection.settlement is not None:
                    raise LedgerError("job budget reservation is already settled")
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
                "parent_refs": [
                    job_id,
                    permit_id,
                    f"attempt:{attempt_id}",
                    f"admission:sha256:{admission_digest}",
                    accounting_policy_ref,
                    budget_scope_ref,
                ],
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

        for event in events:
            if event.event_type != "complete":
                continue
            projection = by_job.get(event.job_id)
            if projection is None:
                raise LedgerError("persisted completion lacks a budgeted claim")
            if projection.settlement is not None:
                raise LedgerError("persisted reservation has duplicate settlements")
            settlement = self._validate_budget_completion_event(event, projection)
            by_job[event.job_id] = replace(projection, settlement=settlement)
        projections = sorted(by_job.values(), key=lambda item: item.event.sequence)
        self._validate_budget_aggregate_invariants(projections)
        return projections

    @staticmethod
    def _validate_budget_claim_event(event: LedgerEvent) -> _BudgetProjection:
        payload = _exact_object(
            "persisted claim payload", event.payload, _CLAIM_PAYLOAD_FIELDS
        )
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


def _expected_schema_fingerprint(
    objects: tuple[tuple[str, str, str], ...], *, user_version: int
) -> str:
    manifest = tuple(
        sorted(
            (
                object_type,
                name,
                "bridge_job_ledger",
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


def _payload_ref(value: object) -> str:
    value = _nonempty_text("payload_ref", value)
    if _PAYLOAD_REF_RE.fullmatch(value) is None:
        raise LedgerError("payload_ref must be a portable cas: or vault: reference")
    return value


__all__ = ["LedgerError", "LedgerEvent", "JobLedger"]
