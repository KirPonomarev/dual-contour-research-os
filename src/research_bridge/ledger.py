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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


_GENESIS_SHA256 = "0" * 64
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_PAYLOAD_REF_RE = re.compile(r"^(?:cas|vault):[A-Za-z0-9][A-Za-z0-9._:/+-]{0,511}$")
_EVENT_TYPES = frozenset({"claim", "checkpoint", "complete", "pause", "resume"})
_CONTROL_EVENT_TYPES = frozenset({"pause", "resume"})
_GLOBAL_CONTROL_JOB_ID = "bridge-global-control"


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
            journal_mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if journal_mode.lower() != "wal":
                raise LedgerError("SQLite WAL mode is required")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA recursive_triggers = ON")
            self._create_schema()
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

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS bridge_job_ledger (
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
            );

            CREATE UNIQUE INDEX IF NOT EXISTS bridge_job_one_claim
                ON bridge_job_ledger(job_id)
                WHERE event_type = 'claim';

            CREATE UNIQUE INDEX IF NOT EXISTS bridge_claim_one_permit_nonce
                ON bridge_job_ledger(
                    json_extract(payload_json, '$.permit_nonce_sha256')
                )
                WHERE event_type = 'claim';

            CREATE UNIQUE INDEX IF NOT EXISTS bridge_job_one_completion
                ON bridge_job_ledger(job_id)
                WHERE event_type = 'complete';

            CREATE UNIQUE INDEX IF NOT EXISTS bridge_job_checkpoint_sequence
                ON bridge_job_ledger(job_id, attempt_id, checkpoint_sequence)
                WHERE event_type = 'checkpoint';

            CREATE UNIQUE INDEX IF NOT EXISTS bridge_control_idempotency_key
                ON bridge_job_ledger(attempt_id)
                WHERE event_type IN ('pause', 'resume');

            CREATE TRIGGER IF NOT EXISTS bridge_job_ledger_no_update
            BEFORE UPDATE ON bridge_job_ledger
            BEGIN
                SELECT RAISE(ABORT, 'bridge_job_ledger is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS bridge_job_ledger_no_delete
            BEFORE DELETE ON bridge_job_ledger
            BEGIN
                SELECT RAISE(ABORT, 'bridge_job_ledger is append-only');
            END;
            """
        )

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
    ) -> LedgerEvent:
        """Atomically append the sole winning claim for a job."""

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
        fencing_token_sha256 = _digest(fencing_token.encode("utf-8"))

        payload = {
            "admission_digest": admission_digest,
            "admitted_at": admitted_at,
            "attempt_id": attempt_id,
            "fencing_epoch": fencing_epoch,
            "fencing_token_sha256": fencing_token_sha256,
            "job_id": job_id,
            "permit_id": permit_id,
            "permit_nonce_sha256": permit_nonce_sha256,
            "runner_identity": runner_identity,
        }
        with self._lock:
            self._ensure_open()
            self._begin_immediate()
            try:
                if self._pause_snapshot_in_transaction()["paused"]:
                    raise LedgerError("global pause blocks job claims")
                self._require_unused_permit_nonce(permit_nonce_sha256)
                existing = self._connection.execute(
                    "SELECT 1 FROM bridge_job_ledger WHERE job_id = ? AND event_type = 'claim'",
                    (job_id,),
                ).fetchone()
                if existing is not None:
                    raise LedgerError("job already has a claim winner")
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

        payload = {
            "attempt_id": attempt_id,
            "event_at": event_at,
            "fencing_epoch": fencing_epoch,
            "fencing_token_sha256": fencing_token_sha256,
            "job_id": job_id,
            "result_sha256": result_sha256,
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
            payload=MappingProxyType(dict(payload)),
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
            payload=MappingProxyType(dict(payload)),
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


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


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


def _payload_ref(value: object) -> str:
    value = _nonempty_text("payload_ref", value)
    if _PAYLOAD_REF_RE.fullmatch(value) is None:
        raise LedgerError("payload_ref must be a portable cas: or vault: reference")
    return value


__all__ = ["LedgerError", "LedgerEvent", "JobLedger"]
