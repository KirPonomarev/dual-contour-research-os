"""Fail-closed consumption of immutable pre-soak deployment approvals.

This module is a local governance boundary.  It validates hash-bound release,
backup, restore, and operator approval receipts, then records one durable nonce
consumption.  It does not build images, contact a host, restore data, or deploy.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


_COMMON_FIELDS = frozenset(
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
_ISSUER_FIELDS = frozenset({"id", "authority_class"})
_INTEGRITY_FIELDS = frozenset({"payload_sha256", "parent_refs"})
_RELEASE_FIELDS = frozenset(
    {
        "release_sha",
        "image_digests",
        "policy_sha256",
        "config_sha256",
        "schema_sha256",
        "dependency_lock_sha256",
        "sbom_ref",
        "previous_release_ref",
    }
)
_BACKUP_FIELDS = frozenset(
    {
        "snapshot_id",
        "source_manifest_sha256",
        "destination_ref",
        "encrypted",
        "started_at",
        "ended_at",
        "verification_result",
    }
)
_RESTORE_FIELDS = frozenset(
    {
        "backup_ref",
        "clean_target_ref",
        "restored_manifest_sha256",
        "integrity_result",
        "recovery_point_seconds",
        "recovery_time_seconds",
    }
)
_APPROVAL_FIELDS = frozenset(
    {
        "environment",
        "release_sha",
        "image_digest",
        "policy_sha256",
        "config_sha256",
        "schema_sha256",
        "remote_ci_ref",
        "restore_receipt_ref",
        "rollback_target",
        "expires_at",
        "nonce",
    }
)
_PUBLIC_CLASSES = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_GIT_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_GENESIS_SHA256 = "0" * 64
_DATABASE_USER_VERSION = 1

_TABLE_SQL = """CREATE TABLE deployment_approval_consumption (
                sequence INTEGER PRIMARY KEY,
                approval_object_id TEXT NOT NULL UNIQUE,
                nonce_sha256 TEXT NOT NULL UNIQUE CHECK (length(nonce_sha256) = 64),
                release_sha TEXT NOT NULL CHECK (length(release_sha) = 40),
                image_digest TEXT NOT NULL,
                restore_receipt_ref TEXT NOT NULL,
                rollback_target TEXT NOT NULL,
                remote_ci_ref TEXT NOT NULL,
                consumed_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL CHECK (length(previous_sha256) = 64),
                event_sha256 TEXT NOT NULL UNIQUE CHECK (length(event_sha256) = 64)
            )"""
_SCHEMA_OBJECTS = (
    ("table", "deployment_approval_consumption", _TABLE_SQL),
    (
        "trigger",
        "deployment_approval_consumption_no_update",
        """CREATE TRIGGER deployment_approval_consumption_no_update
            BEFORE UPDATE ON deployment_approval_consumption
            BEGIN
                SELECT RAISE(ABORT, 'deployment approval consumption is append-only');
            END""",
    ),
    (
        "trigger",
        "deployment_approval_consumption_no_delete",
        """CREATE TRIGGER deployment_approval_consumption_no_delete
            BEFORE DELETE ON deployment_approval_consumption
            BEGIN
                SELECT RAISE(ABORT, 'deployment approval consumption is append-only');
            END""",
    ),
)


class DeploymentGateError(RuntimeError):
    """A deployment approval or its durable consumption was rejected."""


@dataclass(frozen=True, slots=True)
class DeploymentConsumption:
    """Immutable projection of one consumed operator approval."""

    sequence: int
    approval_object_id: str
    nonce_sha256: str
    release_sha: str
    image_digest: str
    restore_receipt_ref: str
    rollback_target: str
    remote_ci_ref: str
    consumed_at: str
    previous_sha256: str
    event_sha256: str
    bindings: Mapping[str, object]


class DeploymentApprovalConsumer:
    """Durably consume a fully-bound deployment approval exactly once."""

    def __init__(self, database_path: str | Path, *, timeout: float = 5.0) -> None:
        if isinstance(database_path, bytes) or not isinstance(database_path, (str, Path)):
            raise DeploymentGateError("database_path must be a text filesystem path")
        if str(database_path) == ":memory:":
            raise DeploymentGateError("a filesystem database is required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise DeploymentGateError("timeout must be positive")
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
            if str(journal_mode).lower() != "wal":
                raise DeploymentGateError("SQLite WAL mode is required")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA recursive_triggers = ON")
            if not self.verify_chain():
                raise DeploymentGateError("deployment consumption chain is invalid")
        except DeploymentGateError:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise
        except (sqlite3.Error, OSError) as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise DeploymentGateError(f"could not open deployment ledger: {exc}") from exc

    def consume(
        self,
        *,
        release_manifest: Mapping[str, object],
        backup_receipt: Mapping[str, object],
        restore_receipt: Mapping[str, object],
        approval_receipt: Mapping[str, object],
        expected_environment: str,
        exact_remote_ci_ref: str,
        consumed_at: str,
    ) -> DeploymentConsumption:
        """Validate all immutable bindings and atomically consume one nonce."""

        with self._lock:
            self._ensure_open()
            bindings = _validated_bindings(
                release_manifest=release_manifest,
                backup_receipt=backup_receipt,
                restore_receipt=restore_receipt,
                approval_receipt=approval_receipt,
                expected_environment=expected_environment,
                exact_remote_ci_ref=exact_remote_ci_ref,
                consumed_at=consumed_at,
            )
            approval_id = str(approval_receipt["object_id"])
            approval_payload = approval_receipt["payload"]
            assert isinstance(approval_payload, Mapping)
            nonce_sha256 = hashlib.sha256(str(approval_payload["nonce"]).encode("utf-8")).hexdigest()
            payload_json = _canonical_json(bindings)
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                last = self._connection.execute(
                    "SELECT sequence, event_sha256 FROM deployment_approval_consumption "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = 1 if last is None else int(last["sequence"]) + 1
                previous_sha256 = _GENESIS_SHA256 if last is None else str(last["event_sha256"])
                event_sha256 = _event_sha256(
                    sequence=sequence,
                    approval_object_id=approval_id,
                    nonce_sha256=nonce_sha256,
                    release_sha=str(bindings["release_sha"]),
                    image_digest=str(bindings["image_digest"]),
                    restore_receipt_ref=str(bindings["restore_receipt_ref"]),
                    rollback_target=str(bindings["rollback_target"]),
                    remote_ci_ref=str(bindings["remote_ci_ref"]),
                    consumed_at=consumed_at,
                    payload_json=payload_json,
                    previous_sha256=previous_sha256,
                )
                self._connection.execute(
                    "INSERT INTO deployment_approval_consumption "
                    "(sequence, approval_object_id, nonce_sha256, release_sha, image_digest, "
                    "restore_receipt_ref, rollback_target, remote_ci_ref, consumed_at, "
                    "payload_json, previous_sha256, event_sha256) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sequence,
                        approval_id,
                        nonce_sha256,
                        bindings["release_sha"],
                        bindings["image_digest"],
                        bindings["restore_receipt_ref"],
                        bindings["rollback_target"],
                        bindings["remote_ci_ref"],
                        consumed_at,
                        payload_json,
                        previous_sha256,
                        event_sha256,
                    ),
                )
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._rollback()
                raise DeploymentGateError("deployment approval or nonce was already consumed") from exc
            except sqlite3.Error as exc:
                self._rollback()
                raise DeploymentGateError("deployment approval consumption failed") from exc
            return DeploymentConsumption(
                sequence=sequence,
                approval_object_id=approval_id,
                nonce_sha256=nonce_sha256,
                release_sha=str(bindings["release_sha"]),
                image_digest=str(bindings["image_digest"]),
                restore_receipt_ref=str(bindings["restore_receipt_ref"]),
                rollback_target=str(bindings["rollback_target"]),
                remote_ci_ref=str(bindings["remote_ci_ref"]),
                consumed_at=consumed_at,
                previous_sha256=previous_sha256,
                event_sha256=event_sha256,
                bindings=MappingProxyType(dict(bindings)),
            )

    def verify_chain(self) -> bool:
        """Return true only when schema and the full append-only hash chain agree."""

        with self._lock:
            self._ensure_open()
            try:
                if int(self._connection.execute("PRAGMA user_version").fetchone()[0]) != _DATABASE_USER_VERSION:
                    return False
                for object_type, name, sql in _SCHEMA_OBJECTS:
                    row = self._connection.execute(
                        "SELECT sql FROM sqlite_master WHERE type = ? AND name = ?",
                        (object_type, name),
                    ).fetchone()
                    if row is None or _normalize_sql(row["sql"]) != _normalize_sql(sql):
                        return False
                previous = _GENESIS_SHA256
                expected_sequence = 1
                rows = self._connection.execute(
                    "SELECT * FROM deployment_approval_consumption ORDER BY sequence"
                ).fetchall()
                seen_approvals: set[str] = set()
                seen_nonces: set[str] = set()
                for row in rows:
                    if int(row["sequence"]) != expected_sequence or row["previous_sha256"] != previous:
                        return False
                    if row["approval_object_id"] in seen_approvals or row["nonce_sha256"] in seen_nonces:
                        return False
                    if _event_sha256(
                        sequence=int(row["sequence"]),
                        approval_object_id=str(row["approval_object_id"]),
                        nonce_sha256=str(row["nonce_sha256"]),
                        release_sha=str(row["release_sha"]),
                        image_digest=str(row["image_digest"]),
                        restore_receipt_ref=str(row["restore_receipt_ref"]),
                        rollback_target=str(row["rollback_target"]),
                        remote_ci_ref=str(row["remote_ci_ref"]),
                        consumed_at=str(row["consumed_at"]),
                        payload_json=str(row["payload_json"]),
                        previous_sha256=previous,
                    ) != row["event_sha256"]:
                        return False
                    decoded = json.loads(row["payload_json"])
                    if not isinstance(decoded, dict):
                        return False
                    seen_approvals.add(str(row["approval_object_id"]))
                    seen_nonces.add(str(row["nonce_sha256"]))
                    previous = str(row["event_sha256"])
                    expected_sequence += 1
                return True
            except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError):
                return False

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> "DeploymentApprovalConsumer":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _initialize_schema(self) -> None:
        current = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if current == 0:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                for _object_type, _name, sql in _SCHEMA_OBJECTS:
                    self._connection.execute(sql)
                self._connection.execute(f"PRAGMA user_version = {_DATABASE_USER_VERSION}")
                self._connection.execute("COMMIT")
            except sqlite3.Error:
                self._connection.execute("ROLLBACK")
                raise
        elif current != _DATABASE_USER_VERSION:
            raise DeploymentGateError("unsupported deployment ledger schema")

    def _ensure_open(self) -> None:
        if self._closed:
            raise DeploymentGateError("deployment ledger is closed")

    def _rollback(self) -> None:
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass


def _validated_bindings(
    *,
    release_manifest: Mapping[str, object],
    backup_receipt: Mapping[str, object],
    restore_receipt: Mapping[str, object],
    approval_receipt: Mapping[str, object],
    expected_environment: str,
    exact_remote_ci_ref: str,
    consumed_at: str,
) -> dict[str, object]:
    if not expected_environment or not exact_remote_ci_ref:
        raise DeploymentGateError("expected environment and exact CI reference are required")
    consumed = _timestamp(consumed_at, "consumed_at")
    release = _receipt(release_manifest, "ReleaseManifest", _RELEASE_FIELDS)
    backup = _receipt(backup_receipt, "BackupReceipt", _BACKUP_FIELDS)
    restore = _receipt(restore_receipt, "RestoreReceipt", _RESTORE_FIELDS)
    approval = _receipt(approval_receipt, "DeploymentApprovalReceipt", _APPROVAL_FIELDS)

    release_sha = _git_sha(release.get("release_sha"), "release_sha")
    image_digests = release.get("image_digests")
    if not isinstance(image_digests, list) or len(image_digests) != 1:
        raise DeploymentGateError("release must bind exactly one image digest")
    image_digest = _image_digest(image_digests[0], "release image digest")
    for field in ("policy_sha256", "config_sha256", "schema_sha256", "dependency_lock_sha256"):
        _sha256(release.get(field), f"release {field}")
    _text(release.get("sbom_ref"), "sbom_ref")
    previous_release_ref = _text(release.get("previous_release_ref"), "previous_release_ref")

    if backup.get("encrypted") is not True or backup.get("verification_result") != "VERIFIED":
        raise DeploymentGateError("backup is not encrypted and verified")
    _sha256(backup.get("source_manifest_sha256"), "backup source manifest")
    _text(backup.get("snapshot_id"), "backup snapshot_id")
    _text(backup.get("destination_ref"), "backup destination_ref")
    backup_started = _timestamp(backup.get("started_at"), "backup started_at")
    backup_ended = _timestamp(backup.get("ended_at"), "backup ended_at")
    if backup_ended < backup_started:
        raise DeploymentGateError("backup end precedes start")

    if restore.get("integrity_result") != "VERIFIED":
        raise DeploymentGateError("restore integrity is not verified")
    if restore.get("backup_ref") != backup_receipt.get("object_id"):
        raise DeploymentGateError("restore is not bound to backup receipt")
    if restore.get("restored_manifest_sha256") != backup.get("source_manifest_sha256"):
        raise DeploymentGateError("restored manifest differs from backup source")
    _text(restore.get("clean_target_ref"), "clean_target_ref")
    for field in ("recovery_point_seconds", "recovery_time_seconds"):
        value = restore.get(field)
        if type(value) is not int or value < 0:
            raise DeploymentGateError(f"restore {field} is invalid")

    if approval.get("environment") != expected_environment:
        raise DeploymentGateError("deployment environment is not authorized")
    if approval.get("release_sha") != release_sha:
        raise DeploymentGateError("approval release SHA differs from manifest")
    if approval.get("image_digest") != image_digest:
        raise DeploymentGateError("approval image digest differs from manifest")
    for field in ("policy_sha256", "config_sha256", "schema_sha256"):
        if approval.get(field) != release.get(field):
            raise DeploymentGateError(f"approval {field} differs from manifest")
    if approval.get("remote_ci_ref") != exact_remote_ci_ref:
        raise DeploymentGateError("approval is not bound to exact-head CI")
    if approval.get("restore_receipt_ref") != restore_receipt.get("object_id"):
        raise DeploymentGateError("approval is not bound to clean restore")
    if approval.get("rollback_target") != previous_release_ref:
        raise DeploymentGateError("approval rollback target differs from previous release")
    _text(approval.get("nonce"), "approval nonce")
    expires = _timestamp(approval.get("expires_at"), "approval expires_at")
    issued = _timestamp(approval_receipt.get("issued_at"), "approval issued_at")
    if issued > consumed or consumed >= expires:
        raise DeploymentGateError("deployment approval is not currently valid")

    restore_parents = _parent_refs(restore_receipt)
    if str(backup_receipt["object_id"]) not in restore_parents:
        raise DeploymentGateError("restore integrity omits backup parent")
    approval_parents = _parent_refs(approval_receipt)
    if str(release_manifest["object_id"]) not in approval_parents or str(restore_receipt["object_id"]) not in approval_parents:
        raise DeploymentGateError("approval integrity omits release or restore parent")

    return {
        "environment": expected_environment,
        "release_manifest_ref": str(release_manifest["object_id"]),
        "release_sha": release_sha,
        "image_digest": image_digest,
        "policy_sha256": release["policy_sha256"],
        "config_sha256": release["config_sha256"],
        "schema_sha256": release["schema_sha256"],
        "dependency_lock_sha256": release["dependency_lock_sha256"],
        "sbom_ref": release["sbom_ref"],
        "backup_receipt_ref": str(backup_receipt["object_id"]),
        "restore_receipt_ref": str(restore_receipt["object_id"]),
        "rollback_target": previous_release_ref,
        "remote_ci_ref": exact_remote_ci_ref,
        "approval_expires_at": approval["expires_at"],
        "external_action_authorized": False,
    }


def _receipt(value: Mapping[str, object], schema_id: str, payload_fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != _COMMON_FIELDS:
        raise DeploymentGateError(f"{schema_id} receipt shape is invalid")
    if value.get("schema_id") != schema_id or value.get("schema_version") != "1.0.0":
        raise DeploymentGateError(f"{schema_id} schema is invalid")
    _text(value.get("object_id"), f"{schema_id} object_id")
    _timestamp(value.get("issued_at"), f"{schema_id} issued_at")
    if value.get("contour") != "governance" or value.get("classification") not in _PUBLIC_CLASSES:
        raise DeploymentGateError(f"{schema_id} boundary is invalid")
    issuer = value.get("issuer")
    if not isinstance(issuer, Mapping) or set(issuer) != _ISSUER_FIELDS:
        raise DeploymentGateError(f"{schema_id} issuer is invalid")
    _text(issuer.get("id"), f"{schema_id} issuer id")
    _text(issuer.get("authority_class"), f"{schema_id} issuer class")
    payload = value.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != payload_fields:
        raise DeploymentGateError(f"{schema_id} payload shape is invalid")
    integrity = value.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != _INTEGRITY_FIELDS:
        raise DeploymentGateError(f"{schema_id} integrity shape is invalid")
    expected = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    if integrity.get("payload_sha256") != expected:
        raise DeploymentGateError(f"{schema_id} payload integrity is invalid")
    _parent_refs(value)
    return payload


def _parent_refs(receipt: Mapping[str, object]) -> list[str]:
    integrity = receipt.get("integrity")
    if not isinstance(integrity, Mapping):
        raise DeploymentGateError("receipt integrity is invalid")
    parents = integrity.get("parent_refs")
    if not isinstance(parents, list) or any(not isinstance(item, str) or not item for item in parents):
        raise DeploymentGateError("receipt parent refs are invalid")
    return parents


def _timestamp(value: object, label: str) -> datetime:
    text = _text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DeploymentGateError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DeploymentGateError(f"{label} must be timezone-aware")
    return parsed


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise DeploymentGateError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    text = _text(value, label)
    if _SHA256_RE.fullmatch(text) is None:
        raise DeploymentGateError(f"{label} is invalid")
    return text


def _image_digest(value: object, label: str) -> str:
    text = _text(value, label)
    if _IMAGE_DIGEST_RE.fullmatch(text) is None:
        raise DeploymentGateError(f"{label} is invalid")
    return text


def _git_sha(value: object, label: str) -> str:
    text = _text(value, label)
    if _GIT_SHA_RE.fullmatch(text) is None:
        raise DeploymentGateError(f"{label} is invalid")
    return text


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DeploymentGateError("receipt is not canonical JSON data") from exc


def _event_sha256(**values: object) -> str:
    return hashlib.sha256(_canonical_json(values).encode("utf-8")).hexdigest()


def _normalize_sql(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split()).lower()


__all__ = [
    "DeploymentApprovalConsumer",
    "DeploymentConsumption",
    "DeploymentGateError",
]
