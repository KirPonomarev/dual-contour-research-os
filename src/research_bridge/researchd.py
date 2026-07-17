"""Single-writer process owner for the offline Bridge runtime.

``ResearchDaemon`` composes only the already-owned Stage 1 boundaries.  It
does not create a second ledger, a scheduler, a remote listener, or authority
for domain outcomes.  One nonblocking file lock is acquired before the sole
read-write ``JobLedger`` is opened, and the AF_UNIX socket is bound last.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import threading
from typing import Any, TextIO

try:
    import fcntl
except ImportError:  # pragma: no cover - the runtime is explicitly Unix-only
    fcntl = None  # type: ignore[assignment]

from .authority import PinnedOfflineAuthority, TrustedIssuer
from .cas import ContentAddressedStore
from .control import ControlRouter
from .execution import OfflineExecutionCoordinator
from .ingestion import TrustedIngestor
from .ipc import (
    IPCError,
    PeerCredentials,
    UnixControlServer,
    resolve_peer_credentials,
)
from .kernel import BridgeKernel
from .l0 import DeterministicL0Runner
from .ledger import JobLedger


_ROOT_MODE = 0o700
_LOCK_MODE = 0o600
_DEFAULT_QUOTA_BYTES = 16 * 1024 * 1024
_DEFAULT_MAXIMUM_INPUT_BYTES = 4 * 1024 * 1024
_CONFIG_MODE = 0o600
_MAX_CONFIG_BYTES = 262_144
_MAX_CONFIG_QUOTA_BYTES = 1 << 40
_SERVICE_SCHEMA_ID = "ResearchdServiceConfig"
_SERVICE_SCHEMA_VERSION = "1.0.0"
_CONFIG_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "runtime_root",
        "runner_identity",
        "allowed_uids",
        "input_quota_bytes",
        "checkpoint_quota_bytes",
        "artifact_quota_bytes",
        "maximum_input_bytes",
        "deadline_seconds",
        "trusted_issuers",
        "policy_snapshots",
        "approval_receipts",
    }
)
_TRUSTED_SCHEMAS = frozenset(
    {
        "JobSpec",
        "Permit",
        "AttemptLease",
        "PolicySnapshot",
        "ApprovalReceipt",
    }
)
_TRUSTED_ISSUER_KEYS = frozenset({"issuer_id", "authority_class"})
_AUTHORITY_COMMON_KEYS = frozenset(
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
_AUTHORITY_ISSUER_KEYS = frozenset({"id", "authority_class"})
_AUTHORITY_INTEGRITY_KEYS = frozenset({"payload_sha256", "parent_refs"})
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
_PUBLIC_AUTHORITY_CLASSES = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_HEX_DIGITS = frozenset("0123456789abcdef")
_CONFIG_ERROR_LINE = "researchd configuration rejected\n"
_RUNTIME_ERROR_LINE = "researchd runtime failed\n"


class ResearchdError(RuntimeError):
    """The owned offline runtime could not start or complete one operation."""


class _ServiceConfigError(ValueError):
    """A service configuration was rejected before daemon startup."""


class _ServiceConfig:
    def __init__(
        self,
        *,
        runtime_root: str,
        authority: PinnedOfflineAuthority,
        allowed_uids: tuple[int, ...],
        runner_identity: str,
        input_quota_bytes: int,
        checkpoint_quota_bytes: int,
        artifact_quota_bytes: int,
        maximum_input_bytes: int,
        deadline_seconds: float,
    ) -> None:
        self.runtime_root = runtime_root
        self.authority = authority
        self.allowed_uids = allowed_uids
        self.runner_identity = runner_identity
        self.input_quota_bytes = input_quota_bytes
        self.checkpoint_quota_bytes = checkpoint_quota_bytes
        self.artifact_quota_bytes = artifact_quota_bytes
        self.maximum_input_bytes = maximum_input_bytes
        self.deadline_seconds = deadline_seconds


class _CheckpointFenceLedger:
    """Remember only the current request fence after canonical checkpointing."""

    def __init__(self, ledger: JobLedger) -> None:
        self._ledger = ledger
        self._lock = threading.RLock()
        self._claimed: tuple[str, str, str] | None = None
        self._verified: tuple[str, str, str] | None = None

    def claim(self, **keywords: object) -> object:
        event = self._ledger.claim(**keywords)  # type: ignore[arg-type]
        claimed = (
            _text("attempt_id", keywords.get("attempt_id"), maximum=256),
            _text("runner_identity", keywords.get("runner_identity"), maximum=256),
            _text("fencing_token", keywords.get("fencing_token"), maximum=1024),
        )
        with self._lock:
            self._claimed = claimed
            self._verified = None
        return event

    def checkpoint(self, **keywords: object) -> object:
        event = self._ledger.checkpoint(**keywords)  # type: ignore[arg-type]
        attempt_id = _text(
            "attempt_id", keywords.get("attempt_id"), maximum=256
        )
        fencing_token = _text(
            "fencing_token", keywords.get("fencing_token"), maximum=1024
        )
        with self._lock:
            if (
                self._claimed is None
                or self._claimed[0] != attempt_id
                or self._claimed[2] != fencing_token
            ):
                raise ResearchdError("checkpoint fence does not match the current claim")
            self._verified = self._claimed
        return event

    def complete(self, **keywords: object) -> object:
        event = self._ledger.complete(**keywords)  # type: ignore[arg-type]
        self.clear()
        return event

    def completed_event(self, job_id: str) -> object:
        return self._ledger.completed_event(job_id)

    def verify_current(
        self,
        *,
        attempt_id: object,
        producer_identity: object,
        fencing_token: object,
    ) -> bool:
        candidate = (attempt_id, producer_identity, fencing_token)
        with self._lock:
            return self._verified is not None and candidate == self._verified

    def clear(self) -> None:
        with self._lock:
            self._claimed = None
            self._verified = None


class ResearchDaemon:
    """Own one private runtime root, one ledger writer, and one local socket."""

    def __init__(
        self,
        runtime_root: str | Path,
        *,
        authority: PinnedOfflineAuthority,
        allowed_uids: Iterable[int],
        runner_identity: str,
        input_quota_bytes: int = _DEFAULT_QUOTA_BYTES,
        checkpoint_quota_bytes: int = _DEFAULT_QUOTA_BYTES,
        artifact_quota_bytes: int = _DEFAULT_QUOTA_BYTES,
        maximum_input_bytes: int = _DEFAULT_MAXIMUM_INPUT_BYTES,
        deadline_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
        credential_resolver: Callable[[Any], PeerCredentials] = resolve_peer_credentials,
    ) -> None:
        if isinstance(runtime_root, bytes) or not isinstance(runtime_root, (str, Path)):
            raise ResearchdError("runtime_root must be a text filesystem path")
        root = Path(runtime_root)
        if not str(root) or "\x00" in str(root) or ".." in root.parts:
            raise ResearchdError("runtime_root is invalid")
        try:
            allowed = frozenset(allowed_uids)
        except TypeError as exc:
            raise ResearchdError("allowed_uids must be an iterable") from exc
        if not allowed or any(type(uid) is not int or uid < 0 for uid in allowed):
            raise ResearchdError("allowed_uids must contain non-negative integers")
        for name, value in (
            ("input_quota_bytes", input_quota_bytes),
            ("checkpoint_quota_bytes", checkpoint_quota_bytes),
            ("artifact_quota_bytes", artifact_quota_bytes),
            ("maximum_input_bytes", maximum_input_bytes),
        ):
            if type(value) is not int or value <= 0:
                raise ResearchdError(f"{name} must be a positive integer")
        if clock is not None and not callable(clock):
            raise ResearchdError("clock must be callable")
        if not callable(credential_resolver):
            raise ResearchdError("credential_resolver must be callable")

        self._root = root
        self._authority = authority
        self._allowed_uids = allowed
        self._runner_identity = _text(
            "runner_identity", runner_identity, maximum=256
        )
        self._input_quota_bytes = input_quota_bytes
        self._checkpoint_quota_bytes = checkpoint_quota_bytes
        self._artifact_quota_bytes = artifact_quota_bytes
        self._maximum_input_bytes = maximum_input_bytes
        self._deadline_seconds = deadline_seconds
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._credential_resolver = credential_resolver

        self._state_lock = threading.RLock()
        self._dispatch_lock = threading.RLock()
        self._root_fd: int | None = None
        self._root_identity: tuple[int, int] | None = None
        self._lock_fd: int | None = None
        self._ledger: JobLedger | None = None
        self._fence_ledger: _CheckpointFenceLedger | None = None
        self._input_store: ContentAddressedStore | None = None
        self._checkpoint_store: ContentAddressedStore | None = None
        self._artifact_store: ContentAddressedStore | None = None
        self._coordinator: OfflineExecutionCoordinator | None = None
        self._server: UnixControlServer | None = None
        self._started = False

    @property
    def socket_path(self) -> Path:
        return self._root / "researchd.sock"

    def start(self) -> None:
        """Acquire ownership, compose the runtime, and bind AF_UNIX last."""

        with self._state_lock:
            if self._started or self._root_fd is not None:
                raise ResearchdError("researchd is already started")
            try:
                self._root_fd, self._root_identity = _open_runtime_root(self._root)
                self._lock_fd = _acquire_runtime_lock(self._root)

                ledger = JobLedger(self._root / "bridge-job-ledger.sqlite3")
                self._ledger = ledger
                if ledger.verify_chain() is not True:
                    raise ResearchdError("ledger chain verification failed")

                self._input_store = ContentAddressedStore(
                    self._root / "input-cas",
                    quota_bytes=self._input_quota_bytes,
                )
                self._checkpoint_store = ContentAddressedStore(
                    self._root / "checkpoint-cas",
                    quota_bytes=self._checkpoint_quota_bytes,
                )
                self._artifact_store = ContentAddressedStore(
                    self._root / "artifact-cas",
                    quota_bytes=self._artifact_quota_bytes,
                )
                _private_directory(self._root / "staging-by-attempt-digest")

                fence_ledger = _CheckpointFenceLedger(ledger)
                self._fence_ledger = fence_ledger
                runner = DeterministicL0Runner(
                    self._read_input,
                    clock=self._clock,
                    runner_identity=self._runner_identity,
                )
                ingestor = TrustedIngestor(
                    self._artifact_store,
                    fence_verifier=fence_ledger.verify_current,
                    clock=self._clock,
                    issuer_id="researchd-trusted-ingestor",
                )
                self._coordinator = OfflineExecutionCoordinator(
                    BridgeKernel(fence_ledger, authority=self._authority),
                    fence_ledger,
                    runner,
                    self._checkpoint_store,
                    ingestor,
                    issuer_id="researchd",
                )
                router = ControlRouter(
                    self,
                    authority=self._authority,
                    clock=self._clock,
                )
                server = UnixControlServer(
                    self.socket_path,
                    router,
                    allowed_uids=self._allowed_uids,
                    deadline_seconds=self._deadline_seconds,
                    credential_resolver=self._credential_resolver,
                )
                self._server = server
                _verify_runtime_root(
                    self._root,
                    self._root_fd,
                    self._root_identity,
                )
                server.start()
                self._started = True
            except Exception as exc:
                self._close_components()
                if isinstance(exc, ResearchdError):
                    raise
                raise ResearchdError("researchd startup failed closed") from exc

    def serve_once(self) -> object:
        """Serially accept and complete one authenticated local request."""

        server = self._require_server()
        with self._dispatch_lock:
            return server.serve_once()

    def serve_forever(self) -> None:
        """Run the serial dispatcher until ``close`` stops the server."""

        self._require_server().serve_forever()

    def close(self) -> None:
        """Close the owned socket and ledger before releasing runtime ownership."""

        with self._state_lock:
            self._close_components()

    def pause_snapshot(self) -> Mapping[str, object]:
        with self._dispatch_lock:
            return self._require_ledger().pause_snapshot()

    def pause_global(self, **keywords: object) -> object:
        with self._dispatch_lock:
            self._require_fence_ledger().clear()
            return self._require_ledger().pause_global(**keywords)  # type: ignore[arg-type]

    def resume_global(self, **keywords: object) -> object:
        with self._dispatch_lock:
            self._require_fence_ledger().clear()
            return self._require_ledger().resume_global(**keywords)  # type: ignore[arg-type]

    def submit(
        self,
        *,
        job_spec: Mapping[str, object],
        permit: Mapping[str, object],
        lease: Mapping[str, object],
        idempotency_key: str,
        now: object,
    ) -> Mapping[str, object]:
        """Execute one fresh bounded attempt; ambiguous retries must use lookup."""

        with self._dispatch_lock:
            coordinator = self._require_coordinator()
            job_payload = _mapping_member(job_spec, "payload", "job_spec")
            job_idempotency = _text(
                "job_spec.payload.idempotency_key",
                job_payload.get("idempotency_key"),
                maximum=256,
            )
            request_idempotency = _text(
                "idempotency_key", idempotency_key, maximum=256
            )
            if request_idempotency != job_idempotency:
                raise ResearchdError("submit idempotency binding is invalid")
            job_spec_ref = _text(
                "job_spec.object_id", job_spec.get("object_id"), maximum=256
            )
            lease_payload = _mapping_member(lease, "payload", "lease")
            attempt_id = _text(
                "lease.payload.attempt_id",
                lease_payload.get("attempt_id"),
                maximum=256,
            )
            staging_root = self._fresh_staging_directory(attempt_id)
            try:
                record = coordinator.execute(
                    job_spec,
                    permit,
                    lease,
                    staging_root,
                    now=now,
                )
                immediate = coordinator.lookup_execution_receipt(job_spec_ref)
                if _canonical_json_bytes(record.execution_receipt) != _canonical_json_bytes(
                    immediate
                ):
                    raise ResearchdError(
                        "submit receipt differs from canonical terminal lookup"
                    )
                return {"execution_receipt": _json_copy(immediate)}
            except ResearchdError:
                raise
            except Exception as exc:
                raise ResearchdError("offline submission failed closed") from exc
            finally:
                self._require_fence_ledger().clear()

    def lookup(self, *, job_spec_ref: str) -> Mapping[str, object]:
        """Return the canonical completed receipt through the zero-write lookup."""

        with self._dispatch_lock:
            reference = _text("job_spec_ref", job_spec_ref, maximum=256)
            try:
                receipt = self._require_coordinator().lookup_execution_receipt(
                    reference
                )
            except Exception as exc:
                raise ResearchdError("terminal receipt lookup failed closed") from exc
            return {"execution_receipt": _json_copy(receipt)}

    def _fresh_staging_directory(self, attempt_id: str) -> Path:
        digest = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()
        path = self._root / "staging-by-attempt-digest" / digest
        try:
            path.mkdir(mode=_ROOT_MODE)
        except FileExistsError as exc:
            raise ResearchdError(
                "attempt staging already exists; use lookup after an ambiguous response"
            ) from exc
        except OSError as exc:
            raise ResearchdError("attempt staging could not be created") from exc
        _validate_private_directory(path, "attempt staging directory")
        return path

    def _read_input(self, ref: str) -> bytes:
        store = self._input_store
        if store is None:
            raise ResearchdError("input store is unavailable")
        return store.read_bytes(
            ref,
            maximum_size_bytes=self._maximum_input_bytes,
        )

    def _require_server(self) -> UnixControlServer:
        with self._state_lock:
            if not self._started or self._server is None:
                raise ResearchdError("researchd is not started")
            return self._server

    def _require_ledger(self) -> JobLedger:
        if not self._started or self._ledger is None:
            raise ResearchdError("researchd ledger is unavailable")
        return self._ledger

    def _require_fence_ledger(self) -> _CheckpointFenceLedger:
        if not self._started or self._fence_ledger is None:
            raise ResearchdError("researchd fence adapter is unavailable")
        return self._fence_ledger

    def _require_coordinator(self) -> OfflineExecutionCoordinator:
        if not self._started or self._coordinator is None:
            raise ResearchdError("researchd coordinator is unavailable")
        return self._coordinator

    def _close_components(self) -> None:
        server = self._server
        self._server = None
        self._started = False
        if server is not None:
            server.close()

        ledger = self._ledger
        self._ledger = None
        if ledger is not None:
            ledger.close()

        self._coordinator = None
        self._fence_ledger = None
        self._input_store = None
        self._checkpoint_store = None
        self._artifact_store = None

        lock_fd = self._lock_fd
        self._lock_fd = None
        if lock_fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

        root_fd = self._root_fd
        self._root_fd = None
        self._root_identity = None
        if root_fd is not None:
            os.close(root_fd)

    def __enter__(self) -> ResearchDaemon:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _open_runtime_root(root: Path) -> tuple[int, tuple[int, int]]:
    _validate_private_directory(root, "runtime root")
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ResearchdError("platform cannot enforce runtime root ownership")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise ResearchdError("runtime root cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(root)
        identity = (opened.st_dev, opened.st_ino)
        if identity != (current.st_dev, current.st_ino):
            raise ResearchdError("runtime root identity changed during open")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != _ROOT_MODE
            or opened.st_uid != os.geteuid()
        ):
            raise ResearchdError("runtime root ownership or mode is invalid")
        return descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def _verify_runtime_root(
    root: Path,
    descriptor: int,
    identity: tuple[int, int],
) -> None:
    opened = os.fstat(descriptor)
    current = os.lstat(root)
    if (
        (opened.st_dev, opened.st_ino) != identity
        or (current.st_dev, current.st_ino) != identity
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or stat.S_IMODE(current.st_mode) != _ROOT_MODE
        or current.st_uid != os.geteuid()
    ):
        raise ResearchdError("runtime root changed before socket bind")


def _acquire_runtime_lock(root: Path) -> int:
    if fcntl is None or not hasattr(os, "O_NOFOLLOW"):
        raise ResearchdError("platform cannot enforce the runtime lock")
    path = root / ".researchd.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, _LOCK_MODE)
    except OSError as exc:
        raise ResearchdError("runtime lock cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or identity != (current.st_dev, current.st_ino)
            or stat.S_IMODE(opened.st_mode) != _LOCK_MODE
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
        ):
            raise ResearchdError("runtime lock ownership or mode is invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ResearchdError("runtime root already has an active writer") from exc
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=_ROOT_MODE, exist_ok=True)
    except OSError as exc:
        raise ResearchdError("private runtime directory cannot be initialized") from exc
    _validate_private_directory(path, "private runtime directory")


def _validate_private_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ResearchdError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != _ROOT_MODE
        or metadata.st_uid != os.geteuid()
    ):
        raise ResearchdError(f"{label} ownership or mode is invalid")


def _mapping_member(
    value: Mapping[str, object],
    name: str,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ResearchdError(f"{label} must be an object")
    member = value.get(name)
    if not isinstance(member, Mapping):
        raise ResearchdError(f"{label}.{name} must be an object")
    return member


def _text(label: str, value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ResearchdError(f"{label} must be normalized non-empty text")
    return value


def _json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_copy(item) for item in value]
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            _json_copy(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ResearchdError("receipt is not canonical JSON data") from exc


def _service_arguments(argv: Sequence[str] | None) -> _ServiceConfig:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--config":
        raise _ServiceConfigError("exactly one config path is required")
    return _service_config_from_path(arguments[1])


def _service_config_from_path(config_path: str) -> _ServiceConfig:
    if not isinstance(config_path, str) or not config_path or "\x00" in config_path:
        raise _ServiceConfigError("config path is invalid")
    raw = _read_owner_only_config(config_path)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _ServiceConfigError("config is not utf-8") from exc
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_strict_config_object,
            parse_constant=_reject_config_constant,
        )
    except (json.JSONDecodeError, _ServiceConfigError) as exc:
        raise _ServiceConfigError("config is not strict json") from exc
    _ensure_finite_json(decoded)
    if not isinstance(decoded, dict):
        raise _ServiceConfigError("config must be an object")
    _expect_config_keys(decoded, _CONFIG_KEYS, "config")
    return _service_config_from_mapping(decoded)


def _read_owner_only_config(config_path: str) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _ServiceConfigError("platform cannot safely open config")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(config_path, flags)
    except OSError as exc:
        raise _ServiceConfigError("config cannot be opened safely") from exc
    try:
        identity = _verify_config_descriptor(config_path, descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, _MAX_CONFIG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_CONFIG_BYTES:
                raise _ServiceConfigError("config is too large")
        if total == 0:
            raise _ServiceConfigError("config is empty")
        if _verify_config_descriptor(config_path, descriptor) != identity:
            raise _ServiceConfigError("config identity changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_config_descriptor(config_path: str, descriptor: int) -> tuple[int, int]:
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(config_path)
    except OSError as exc:
        raise _ServiceConfigError("config metadata is unavailable") from exc
    identity = (opened.st_dev, opened.st_ino)
    if (
        identity != (current.st_dev, current.st_ino)
        or not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or stat.S_IMODE(opened.st_mode) != _CONFIG_MODE
        or opened.st_uid != os.geteuid()
        or opened.st_nlink != 1
    ):
        raise _ServiceConfigError("config ownership or mode is invalid")
    return identity


def _strict_config_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _ServiceConfigError("config contains a duplicate key")
        result[key] = value
    return result


def _reject_config_constant(value: str) -> object:
    raise _ServiceConfigError("config contains a non-finite number")


def _ensure_finite_json(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise _ServiceConfigError("config contains a non-finite number")
    if isinstance(value, list):
        for item in value:
            _ensure_finite_json(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _ServiceConfigError("config object key is not text")
            _ensure_finite_json(item)


def _service_config_from_mapping(config: Mapping[str, object]) -> _ServiceConfig:
    if config.get("schema_id") != _SERVICE_SCHEMA_ID:
        raise _ServiceConfigError("config schema id is invalid")
    if config.get("schema_version") != _SERVICE_SCHEMA_VERSION:
        raise _ServiceConfigError("config schema version is invalid")

    runtime_root = _config_text(config.get("runtime_root"), "runtime_root", maximum=4096)
    runner_identity = _config_text(
        config.get("runner_identity"), "runner_identity", maximum=256
    )
    allowed_uids = _allowed_uids(config.get("allowed_uids"))
    input_quota_bytes = _quota_bytes(config.get("input_quota_bytes"))
    checkpoint_quota_bytes = _quota_bytes(config.get("checkpoint_quota_bytes"))
    artifact_quota_bytes = _quota_bytes(config.get("artifact_quota_bytes"))
    maximum_input_bytes = _quota_bytes(config.get("maximum_input_bytes"))
    if maximum_input_bytes > input_quota_bytes:
        raise _ServiceConfigError("maximum input exceeds input quota")
    deadline_seconds = _deadline_seconds(config.get("deadline_seconds"))
    authority = _authority_from_config(config)

    return _ServiceConfig(
        runtime_root=runtime_root,
        authority=authority,
        allowed_uids=allowed_uids,
        runner_identity=runner_identity,
        input_quota_bytes=input_quota_bytes,
        checkpoint_quota_bytes=checkpoint_quota_bytes,
        artifact_quota_bytes=artifact_quota_bytes,
        maximum_input_bytes=maximum_input_bytes,
        deadline_seconds=deadline_seconds,
    )


def _allowed_uids(value: object) -> tuple[int, ...]:
    if not isinstance(value, list) or len(value) != 1:
        raise _ServiceConfigError("allowed uid set is invalid")
    uid = value[0]
    if type(uid) is not int or uid != os.geteuid():
        raise _ServiceConfigError("allowed uid set is invalid")
    return (uid,)


def _quota_bytes(value: object) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_CONFIG_QUOTA_BYTES:
        raise _ServiceConfigError("quota is invalid")
    return value


def _deadline_seconds(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _ServiceConfigError("deadline is invalid")
    deadline = float(value)
    if not math.isfinite(deadline) or not 0 < deadline <= 5:
        raise _ServiceConfigError("deadline is invalid")
    return deadline


def _authority_from_config(config: Mapping[str, object]) -> PinnedOfflineAuthority:
    trusted = _trusted_issuers(config.get("trusted_issuers"))
    policies = _authority_document_map(
        config.get("policy_snapshots"),
        schema_id="PolicySnapshot",
        sha256_keys=True,
    )
    approvals = _authority_document_map(
        config.get("approval_receipts"),
        schema_id="ApprovalReceipt",
        sha256_keys=False,
    )
    try:
        return PinnedOfflineAuthority(
            trusted_issuers=trusted,
            policy_snapshots=policies,
            approval_receipts=approvals,
        )
    except Exception as exc:
        raise _ServiceConfigError("authority config is invalid") from exc


def _trusted_issuers(value: object) -> dict[str, TrustedIssuer]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("trusted issuers must be an object")
    _expect_config_keys(value, _TRUSTED_SCHEMAS, "trusted_issuers")
    trusted: dict[str, TrustedIssuer] = {}
    for schema_id in sorted(_TRUSTED_SCHEMAS):
        record = value[schema_id]
        if not isinstance(record, dict):
            raise _ServiceConfigError("trusted issuer record is invalid")
        _expect_config_keys(record, _TRUSTED_ISSUER_KEYS, "trusted_issuer")
        trusted[schema_id] = TrustedIssuer(
            _config_text(record.get("issuer_id"), "issuer_id", maximum=256),
            _config_text(
                record.get("authority_class"), "authority_class", maximum=256
            ),
        )
    return trusted


def _authority_document_map(
    value: object,
    *,
    schema_id: str,
    sha256_keys: bool,
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("authority resolver must be an object")
    result: dict[str, Mapping[str, Any]] = {}
    for key, document in value.items():
        text_key = _config_text(key, "authority resolver key", maximum=256)
        if sha256_keys and not _is_sha256(text_key):
            raise _ServiceConfigError("authority resolver key is invalid")
        result[text_key] = _authority_document(document, schema_id=schema_id)
    return result


def _authority_document(value: object, *, schema_id: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("authority document must be an object")
    _reject_private_classification(value)
    _expect_config_keys(value, _AUTHORITY_COMMON_KEYS, "authority_document")
    if value.get("schema_id") != schema_id or value.get("schema_version") != "1.0.0":
        raise _ServiceConfigError("authority document schema is invalid")
    _config_text(value.get("object_id"), "authority object_id", maximum=256)
    _config_text(value.get("issued_at"), "authority issued_at", maximum=64)
    issuer = value.get("issuer")
    if not isinstance(issuer, dict):
        raise _ServiceConfigError("authority issuer is invalid")
    _expect_config_keys(issuer, _AUTHORITY_ISSUER_KEYS, "authority_issuer")
    _config_text(issuer.get("id"), "authority issuer id", maximum=256)
    _config_text(issuer.get("authority_class"), "authority class", maximum=256)
    _config_text(value.get("contour"), "authority contour", maximum=64)
    if value.get("classification") not in _PUBLIC_AUTHORITY_CLASSES:
        raise _ServiceConfigError("authority classification is invalid")
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise _ServiceConfigError("authority payload is invalid")
    if schema_id == "PolicySnapshot":
        _policy_payload(payload)
    elif schema_id == "ApprovalReceipt":
        _approval_payload(payload)
    integrity = value.get("integrity")
    if not isinstance(integrity, dict):
        raise _ServiceConfigError("authority integrity is invalid")
    _expect_config_keys(integrity, _AUTHORITY_INTEGRITY_KEYS, "authority_integrity")
    if not _is_sha256(integrity.get("payload_sha256")):
        raise _ServiceConfigError("authority payload digest is invalid")
    parent_refs = integrity.get("parent_refs")
    if not isinstance(parent_refs, list):
        raise _ServiceConfigError("authority parent refs are invalid")
    for parent_ref in parent_refs:
        _config_text(parent_ref, "authority parent ref", maximum=256)
    return value


def _policy_payload(value: Mapping[str, object]) -> None:
    _expect_config_keys(value, _POLICY_PAYLOAD_KEYS, "policy_payload")
    for name in ("source_repo", "commit_sha", "valid_from", "valid_until"):
        _config_text(value.get(name), name, maximum=256)
    if not _is_sha256(value.get("aggregate_sha256")):
        raise _ServiceConfigError("policy aggregate digest is invalid")
    _text_list(value.get("covered_action_classes"), "covered action class")
    for name in ("allow_rules", "deny_rules"):
        if not isinstance(value.get(name), list):
            raise _ServiceConfigError("policy rule list is invalid")


def _approval_payload(value: Mapping[str, object]) -> None:
    _expect_config_keys(value, _APPROVAL_PAYLOAD_KEYS, "approval_payload")
    _config_text(value.get("action_class"), "approval action class", maximum=256)
    for name in ("job_spec_sha256", "protocol_sha256", "policy_sha256"):
        if not _is_sha256(value.get(name)):
            raise _ServiceConfigError("approval digest is invalid")
    if not isinstance(value.get("quotas"), dict):
        raise _ServiceConfigError("approval quotas are invalid")
    if not isinstance(value.get("stop_conditions"), list):
        raise _ServiceConfigError("approval stop conditions are invalid")
    _config_text(value.get("expires_at"), "approval expiration", maximum=64)
    _config_text(value.get("nonce"), "approval nonce", maximum=256)
    if type(value.get("revoked")) is not bool:
        raise _ServiceConfigError("approval revoked flag is invalid")


def _reject_private_classification(value: object) -> None:
    if isinstance(value, dict):
        if (
            "classification" in value
            and value.get("classification") not in _PUBLIC_AUTHORITY_CLASSES
        ):
            raise _ServiceConfigError("authority classification is invalid")
        for item in value.values():
            _reject_private_classification(item)
    elif isinstance(value, list):
        for item in value:
            _reject_private_classification(item)


def _text_list(value: object, label: str) -> None:
    if not isinstance(value, list):
        raise _ServiceConfigError("text list is invalid")
    for item in value:
        _config_text(item, label, maximum=256)


def _expect_config_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    label: str,
) -> None:
    if set(value) != expected:
        raise _ServiceConfigError(f"{label} shape is invalid")


def _config_text(value: object, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise _ServiceConfigError(f"{label} must be normalized text")
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX_DIGITS for character in value)
    )


def _write_generic_error(stream: TextIO, line: str) -> None:
    stream.write(line)
    stream.flush()


def run(argv: Sequence[str] | None = None, *, stderr: TextIO | None = None) -> int:
    """Run ``ResearchDaemon`` from one owner-only service configuration."""

    error_stream = sys.stderr if stderr is None else stderr
    try:
        service = _service_arguments(argv)
        daemon = ResearchDaemon(
            service.runtime_root,
            authority=service.authority,
            allowed_uids=service.allowed_uids,
            runner_identity=service.runner_identity,
            input_quota_bytes=service.input_quota_bytes,
            checkpoint_quota_bytes=service.checkpoint_quota_bytes,
            artifact_quota_bytes=service.artifact_quota_bytes,
            maximum_input_bytes=service.maximum_input_bytes,
            deadline_seconds=service.deadline_seconds,
        )
    except Exception:
        _write_generic_error(error_stream, _CONFIG_ERROR_LINE)
        return 2

    stopping = False
    prior_handlers: dict[int, Any] = {}

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        nonlocal stopping
        stopping = True
        daemon.close()

    try:
        prior_handlers[signal.SIGTERM] = signal.getsignal(signal.SIGTERM)
        prior_handlers[signal.SIGINT] = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        daemon.start()
        try:
            daemon.serve_forever()
        except Exception:
            if stopping:
                return 0
            raise
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        if stopping:
            return 0
        _write_generic_error(error_stream, _RUNTIME_ERROR_LINE)
        return 3
    finally:
        for signum, handler in prior_handlers.items():
            try:
                signal.signal(signum, handler)
            except Exception:
                pass
        daemon.close()


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()


__all__ = ["ResearchdError", "ResearchDaemon", "run", "main"]
