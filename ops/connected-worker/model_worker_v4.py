#!/usr/bin/env python3
"""One-shot connected model worker with private response durability.

The worker has no ledger or database access.  It may reach one provider only
after researchd has durably acknowledged SENT over its authenticated AF_UNIX
socket.  A restarted worker never repeats a call whose state is already SENT.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
from typing import Callable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from research_bridge.ipc import decode_message, encode_message  # noqa: E402
from research_bridge.model_broker import KnownProviderFailure  # noqa: E402
from tools.model_provider_shadow_v4 import (  # noqa: E402
    ADVISOR_PROFILE_PATH,
    ConnectedShadowProfile,
    CredentialResolver,
    HTTPRawAdapter,
    HTTPResponseParser,
    ShadowProviderError,
    build_request_bytes,
)


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_CALL_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+._:/-]{0,511}$")
_POLICY_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "policy_id",
        "worker_uid",
        "worker_gid",
        "control_socket",
        "private_store_root",
        "ai_off_path",
        "credential_file",
        "max_dispatch_bytes",
        "max_completion_bytes",
        "max_extracted_output_bytes",
        "max_provider_output_tokens",
        "provider_input_token_margin",
        "minimum_output_bytes",
        "retention_seconds",
        "root_mode",
        "file_mode",
        "storage_encryption",
        "credential_locators",
        "allowed_classifications",
        "automatic_retry",
        "replay_completion_only",
        "worker_ipc_extension_sha256",
        "shadow_profile_sha256",
        "shadow_tool_sha256",
    }
)
_DISPATCH_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "call_id",
        "dispatch_token",
        "request_body",
        "model_binding",
        "classification",
        "max_tokens",
        "expires_at",
        "worker_ipc_extension_sha256",
    }
)
_RECORD_KEYS_V1 = frozenset(
    {
        "schema_id",
        "schema_version",
        "call_id",
        "dispatch_token",
        "outcome",
        "response_ref",
        "raw_response_ref",
        "actual_tokens",
        "actual_cost_units",
        "provider_receipt_ref",
        "failure_code",
        "created_at",
    }
)
_RECORD_KEYS = _RECORD_KEYS_V1 | frozenset({"attempts", "network_calls"})
_ATTEMPT_KEYS = frozenset(
    {
        "attempt_number",
        "attempt_id",
        "call_id",
        "provider_binding",
        "request_sha256",
        "request_bytes_sent",
        "provider_request_id_or_null",
        "failure_phase",
        "failure_code",
        "network_call_performed",
        "started_at",
        "completed_at",
    }
)
_TERMINAL_STATES = frozenset(
    {"SUCCEEDED", "FAILED_KNOWN", "UNKNOWN", "RECONCILED"}
)
# Versioned provider quality envelope for the exact-bound v4 profile. The
# connected worker applies these role-specific transport settings immediately
# before a call. Synthetic token/cost-unit reservations remain unchanged and
# are not USD provider budgets.
_PROVIDER_TIMEOUT_SECONDS = {
    "deepseek-v4-flash": 300,
    "deepseek-v4-pro": 1800,
    "glm-5.2-max": 1200,
    "claude-fable-5": 1200,
}

# Per-binding maximum output tokens (provider capability, not historical ceiling)
_PROVIDER_MAX_OUTPUT_TOKENS = {
    "deepseek-v4-flash": 4096,
    "deepseek-v4-pro": 4096,
    "glm-5.2-max": 4096,
    "claude-fable-5": 4096,
    "gpt-5.6-sol-xhigh": 4096,
    "gpt-5.6-sol-max": 4096,
}

# Safe retry: at most one additional attempt for UNKNOWN/FAILED_KNOWN with
# transient failure codes.  The worker is oneshot; retry is achieved by a
# subsequent timer invocation discovering the existing record and re-dispatching.
_RETRYABLE_FAILURE_CODES = frozenset({
    "HTTP_429",
    "HTTP_502",
    "HTTP_503",
    "HTTP_504",
    "DNS_FAILURE",
    "CONNECT_FAILURE",
})
_MAX_PROVIDER_ATTEMPTS = 2


def _provider_quality_binding(
    name: str,
    binding: Mapping[str, object],
) -> dict[str, object]:
    result = dict(binding)
    options = dict(result.get("request_options") or {})
    if name == "deepseek-v4-flash":
        options.update({"thinking": {"type": "disabled"}, "reasoning_effort": "max"})
    elif name == "deepseek-v4-pro":
        options.update({"thinking": {"type": "enabled"}, "reasoning_effort": "max"})
    elif name == "glm-5.2-max":
        options.update({"thinking": {"type": "enabled"}, "reasoning_effort": "max"})
    result["request_options"] = options
    return result


def _provider_timeout_seconds(name: str, profile: ConnectedShadowProfile) -> int:
    return _PROVIDER_TIMEOUT_SECONDS.get(name, profile.timeout_seconds)


def _classify_transport_failure(exc: BaseException) -> tuple[str | None, object, str]:
    """Return code, bytes-sent truth, and phase without guessing post-send state."""
    import urllib.error

    reason: BaseException = exc
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
        reason = exc.reason
    if isinstance(reason, socket.gaierror):
        return "DNS_FAILURE", False, "connect"
    if isinstance(reason, ConnectionRefusedError):
        return "CONNECT_FAILURE", False, "connect"
    if isinstance(reason, OSError) and reason.errno in {
        errno.ECONNREFUSED,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
    }:
        return "CONNECT_FAILURE", False, "connect"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "AMBIGUOUS_TIMEOUT", "unknown", "unknown_post_send"
    if isinstance(reason, ConnectionResetError):
        return "CONNECTION_RESET", "unknown", "unknown_post_send"
    return None, "unknown", "unknown_post_send"


class ConnectedWorkerError(RuntimeError):
    """The worker failed closed without exposing private details."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConnectedWorkerError("worker data is not canonical JSON") from exc


def _strict_object(raw: bytes, *, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ConnectedWorkerError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    def constant(_value: str) -> object:
        raise ConnectedWorkerError(f"{label} contains a non-finite number")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectedWorkerError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ConnectedWorkerError(f"{label} must be an object")
    return value


def _timestamp(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ConnectedWorkerError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ConnectedWorkerError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ConnectedWorkerError(f"{label} is invalid")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ConnectedWorkerError("bound worker dependency is unavailable") from exc


def _regular_owner_file(path: Path, *, maximum: int, mode: int = 0o600) -> bytes:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ConnectedWorkerError("owner-only input is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise ConnectedWorkerError("owner-only input identity or mode is invalid")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConnectedWorkerError("owner-only input cannot be read") from exc
    if len(raw) != metadata.st_size:
        raise ConnectedWorkerError("owner-only input changed during read")
    return raw


@dataclass(frozen=True, slots=True)
class RuntimePolicy:
    control_socket: Path
    private_store_root: Path
    ai_off_path: Path
    credential_file: Path
    max_dispatch_bytes: int
    max_completion_bytes: int
    max_extracted_output_bytes: int
    max_provider_output_tokens: int
    provider_input_token_margin: int
    minimum_output_bytes: int
    retention_seconds: int
    worker_uid: int
    worker_gid: int
    worker_ipc_extension_sha256: str
    shadow_profile_sha256: str
    shadow_tool_sha256: str
    allowed_classifications: frozenset[str]
    automatic_retry: bool

    @classmethod
    def load(cls, path: Path) -> "RuntimePolicy":
        try:
            value = _strict_object(path.read_bytes(), label="runtime policy")
        except OSError as exc:
            raise ConnectedWorkerError("runtime policy is unavailable") from exc
        if set(value) != _POLICY_KEYS:
            raise ConnectedWorkerError("runtime policy shape drifted")
        if (
            value["schema_id"] != "ConnectedWorkerRuntimePolicy"
            or value["schema_version"] != "1.0.0"
            or value["policy_id"]
            != "r09a-dual-contour-openrouter-advisors-v1"
            or value["root_mode"] != "0700"
            or value["file_mode"] != "0600"
            or value["storage_encryption"] != "EXTERNAL_VOLUME_REQUIRED"
            or value["credential_locators"]
            != [
                "ENVIRONMENT",
                "MACOS_KEYCHAIN_OPENROUTER",
                "OWNER_ONLY_ENV_FILE_VPS",
            ]
            or value["allowed_classifications"] != ["D0", "D1"]
            or value["automatic_retry"] is not True
            or value["replay_completion_only"] is not True
        ):
            raise ConnectedWorkerError("runtime policy semantics drifted")
        integers: dict[str, int] = {}
        for name, maximum in (
            ("worker_uid", 2_147_483_647),
            ("worker_gid", 2_147_483_647),
            ("max_dispatch_bytes", 1_048_576),
            ("max_completion_bytes", 1_048_576),
            ("max_extracted_output_bytes", 1_048_576),
            ("max_provider_output_tokens", 4096),
            ("provider_input_token_margin", 4096),
            ("minimum_output_bytes", 65_536),
            ("retention_seconds", 31_536_000),
        ):
            raw = value[name]
            if type(raw) is not int or not 1 <= raw <= maximum:
                raise ConnectedWorkerError("runtime policy limit is invalid")
            integers[name] = raw
        if integers["worker_uid"] != 10004 or integers["worker_gid"] != 10001:
            raise ConnectedWorkerError("worker identity drifted")
        paths: dict[str, Path] = {}
        for name in (
            "control_socket",
            "private_store_root",
            "ai_off_path",
            "credential_file",
        ):
            raw = value[name]
            if (
                not isinstance(raw, str)
                or not raw.startswith("/")
                or len(raw) > 4096
                or "\x00" in raw
            ):
                raise ConnectedWorkerError("runtime policy path is invalid")
            paths[name] = Path(raw)
        digests: dict[str, str] = {}
        for name in (
            "worker_ipc_extension_sha256",
            "shadow_profile_sha256",
            "shadow_tool_sha256",
        ):
            raw = value[name]
            if not isinstance(raw, str) or not _SHA256_RE.fullmatch(raw):
                raise ConnectedWorkerError("runtime policy digest is invalid")
            digests[name] = raw
        if (
            _sha256_file(
                REPOSITORY_ROOT
                / "provenance"
                / "model-worker-ipc-extension-v1.json"
            )
            != digests["worker_ipc_extension_sha256"]
        ):
            raise ConnectedWorkerError("runtime policy dependency binding is stale")
        profile_paths = {_sha256_file(ADVISOR_PROFILE_PATH): ADVISOR_PROFILE_PATH}
        profile_path = profile_paths.get(digests["shadow_profile_sha256"])
        if profile_path is None:
            raise ConnectedWorkerError("runtime policy dependency binding is stale")
        expected_tool_sha256 = _sha256_file(
            REPOSITORY_ROOT / "tools" / "model_provider_shadow_v4.py"
        )
        if digests["shadow_tool_sha256"] != expected_tool_sha256:
            raise ConnectedWorkerError("runtime policy dependency binding is stale")
        return cls(
            control_socket=paths["control_socket"],
            private_store_root=paths["private_store_root"],
            ai_off_path=paths["ai_off_path"],
            credential_file=paths["credential_file"],
            max_dispatch_bytes=integers["max_dispatch_bytes"],
            max_completion_bytes=integers["max_completion_bytes"],
            max_extracted_output_bytes=integers["max_extracted_output_bytes"],
            max_provider_output_tokens=integers["max_provider_output_tokens"],
            provider_input_token_margin=integers["provider_input_token_margin"],
            minimum_output_bytes=integers["minimum_output_bytes"],
            retention_seconds=integers["retention_seconds"],
            worker_uid=integers["worker_uid"],
            worker_gid=integers["worker_gid"],
            worker_ipc_extension_sha256=digests["worker_ipc_extension_sha256"],
            shadow_profile_sha256=digests["shadow_profile_sha256"],
            shadow_tool_sha256=digests["shadow_tool_sha256"],
            allowed_classifications=frozenset(value["allowed_classifications"]),  # type: ignore[arg-type]
            automatic_retry=bool(value["automatic_retry"]),
        )


@dataclass(frozen=True, slots=True)
class Dispatch:
    call_id: str
    dispatch_token: str
    request_body: str
    model_binding: str
    classification: str
    max_tokens: int
    expires_at: str

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        policy: RuntimePolicy,
        profile: ConnectedShadowProfile,
    ) -> "Dispatch":
        value = _strict_object(
            _regular_owner_file(path, maximum=policy.max_dispatch_bytes),
            label="worker dispatch",
        )
        if set(value) != _DISPATCH_KEYS:
            raise ConnectedWorkerError("worker dispatch shape drifted")
        if (
            value["schema_id"] != "ModelWorkerDispatch"
            or value["schema_version"] != "1.0.0"
            or value["worker_ipc_extension_sha256"]
            != policy.worker_ipc_extension_sha256
        ):
            raise ConnectedWorkerError("worker dispatch identity drifted")
        call_id = value["call_id"]
        token = value["dispatch_token"]
        request_body = value["request_body"]
        binding = value["model_binding"]
        classification = value["classification"]
        max_tokens = value["max_tokens"]
        if not isinstance(call_id, str) or not _CALL_ID_RE.fullmatch(call_id):
            raise ConnectedWorkerError("worker call identity is invalid")
        if not isinstance(token, str) or not _SHA256_RE.fullmatch(token):
            raise ConnectedWorkerError("worker dispatch token is invalid")
        if (
            not isinstance(request_body, str)
            or not request_body
            or len(request_body.encode("utf-8")) > 32_768
            or "\x00" in request_body
        ):
            raise ConnectedWorkerError("worker request body is invalid")
        if not isinstance(binding, str) or binding not in profile.bindings:
            raise ConnectedWorkerError("worker model binding is invalid")
        if classification not in policy.allowed_classifications:
            raise ConnectedWorkerError("worker classification is invalid")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 4096:
            raise ConnectedWorkerError("worker token bound is invalid")
        expires_at = _timestamp(value["expires_at"], label="dispatch expiry")
        return cls(
            call_id=call_id,
            dispatch_token=token,
            request_body=request_body,
            model_binding=binding,
            classification=str(classification),
            max_tokens=max_tokens,
            expires_at=expires_at,
        )


class UnixIPCClient:
    """One-request AF_UNIX client for the researchd worker role."""

    def __init__(self, path: Path, *, timeout: float = 5.0) -> None:
        self._path = path
        self._timeout = timeout

    def request(
        self,
        command: str,
        payload: Mapping[str, object],
        *,
        idempotency_key: str,
    ) -> dict[str, object]:
        request_id = "worker:" + hashlib.sha256(
            (command + ":" + idempotency_key).encode("utf-8")
        ).hexdigest()
        frame = encode_message(
            {
                "version": "1.2",
                "request_id": request_id,
                "idempotency_key": idempotency_key,
                "command": command,
                "payload": dict(payload),
            }
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self._timeout)
        try:
            client.connect(str(self._path))
            client.sendall(frame)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = client.recv(65_536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 262_144:
                    raise ConnectedWorkerError("control response exceeds bound")
        except (OSError, TimeoutError) as exc:
            raise ConnectedWorkerError("control IPC failed closed") from exc
        finally:
            client.close()
        response = decode_message(b"".join(chunks), maximum_bytes=262_144)
        if set(response) != {"version", "request_id", "ok", "command", "result"}:
            raise ConnectedWorkerError("control response shape drifted")
        if (
            response["version"] != "1.2"
            or response["request_id"] != request_id
            or response["ok"] is not True
            or response["command"] != command
            or not isinstance(response["result"], dict)
        ):
            raise ConnectedWorkerError("control response identity drifted")
        return response["result"]  # type: ignore[return-value]


class PrivateResponseStore:
    """Owner-only CAS plus replay records on an externally encrypted volume."""

    def __init__(
        self,
        root: Path,
        *,
        encryption_attested: bool,
        maximum_record_bytes: int,
    ) -> None:
        if encryption_attested is not True:
            raise ConnectedWorkerError("private storage encryption is not attested")
        self.root = self._outside_repository(root)
        self.maximum_record_bytes = maximum_record_bytes
        self.raw_root = self.root / "objects" / "raw"
        self.output_root = self.root / "objects" / "output"
        self.record_root = self.root / "records"
        for path in (
            self.root,
            self.root / "objects",
            self.raw_root,
            self.output_root,
            self.record_root,
        ):
            self._private_directory(path)

    @staticmethod
    def _outside_repository(path: Path) -> Path:
        resolved = path.resolve()
        try:
            resolved.relative_to(REPOSITORY_ROOT.resolve())
        except ValueError:
            return resolved
        raise ConnectedWorkerError("private storage must remain outside the repository")

    @staticmethod
    def _private_directory(path: Path) -> None:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = os.lstat(path)
        except OSError as exc:
            raise ConnectedWorkerError("private directory is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ConnectedWorkerError("private directory identity or mode is invalid")

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _atomic_write(self, path: Path, raw: bytes) -> None:
        if path.exists():
            observed = _regular_owner_file(
                path,
                maximum=max(len(raw), self.maximum_record_bytes),
            )
            if observed != raw:
                raise ConnectedWorkerError("private immutable object conflict")
            return
        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=".worker-", dir=path.parent)
            temporary = Path(name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            temporary = None
            self._sync_directory(path.parent)
            _regular_owner_file(
                path,
                maximum=max(len(raw), self.maximum_record_bytes),
            )
        except OSError as exc:
            raise ConnectedWorkerError("private object commit failed closed") from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def commit_raw(self, raw: bytes) -> str:
        if not isinstance(raw, bytes) or not raw:
            raise ConnectedWorkerError("raw response is invalid")
        digest = hashlib.sha256(raw).hexdigest()
        self._atomic_write(self.raw_root / digest, raw)
        return "private-cas:sha256:" + digest

    def commit_output(self, raw: bytes, *, maximum: int) -> str:
        if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
            raise ConnectedWorkerError("extracted output is invalid")
        digest = hashlib.sha256(raw).hexdigest()
        self._atomic_write(self.output_root / digest, raw)
        return "cas:sha256:" + digest

    def _record_path(self, call_id: str) -> Path:
        return self.record_root / hashlib.sha256(call_id.encode("utf-8")).hexdigest()

    def write_record(self, record: Mapping[str, object]) -> None:
        if set(record) != _RECORD_KEYS:
            raise ConnectedWorkerError("completion record shape is invalid")
        raw = _canonical_bytes(dict(record))
        if len(raw) > self.maximum_record_bytes:
            raise ConnectedWorkerError("completion record exceeds bound")
        self._atomic_write(self._record_path(str(record["call_id"])), raw)

    def load_record(self, call_id: str) -> dict[str, object] | None:
        path = self._record_path(call_id)
        if not path.exists():
            return None
        value = _strict_object(
            _regular_owner_file(path, maximum=self.maximum_record_bytes),
            label="completion record",
        )
        if (
            set(value) not in {_RECORD_KEYS, _RECORD_KEYS_V1}
            or value.get("call_id") != call_id
        ):
            raise ConnectedWorkerError("completion record identity drifted")
        return value

    def delete_ref(self, reference: str) -> bool:
        if not isinstance(reference, str):
            raise ConnectedWorkerError("private reference is invalid")
        if reference.startswith("private-cas:sha256:"):
            root = self.raw_root
            digest = reference.removeprefix("private-cas:sha256:")
        elif reference.startswith("cas:sha256:"):
            root = self.output_root
            digest = reference.removeprefix("cas:sha256:")
        else:
            raise ConnectedWorkerError("private reference is invalid")
        if not _SHA256_RE.fullmatch(digest):
            raise ConnectedWorkerError("private reference digest is invalid")
        path = root / digest
        if not path.exists():
            return False
        _regular_owner_file(path, maximum=16_777_216)
        path.unlink()
        self._sync_directory(root)
        return True

    def purge(self, *, now_epoch: float, retention_seconds: int) -> int:
        removed = 0
        cutoff = now_epoch - retention_seconds
        for root in (self.raw_root, self.output_root, self.record_root):
            for path in sorted(root.iterdir()):
                metadata = os.lstat(path)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise ConnectedWorkerError("private store entry is invalid")
                if metadata.st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            self._sync_directory(root)
        return removed

    def backup(self, destination: Path) -> None:
        target = self._outside_repository(destination)
        self._private_directory(target.parent)
        entries: list[dict[str, str]] = []
        for kind, root in (
            ("raw", self.raw_root),
            ("output", self.output_root),
            ("record", self.record_root),
        ):
            for path in sorted(root.iterdir()):
                raw = _regular_owner_file(path, maximum=16_777_216)
                entries.append(
                    {
                        "kind": kind,
                        "name": path.name,
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "body_base64": base64.b64encode(raw).decode("ascii"),
                    }
                )
        document = {
            "schema_id": "ConnectedWorkerPrivateBackup",
            "schema_version": "1.0.0",
            "entries": entries,
        }
        self._atomic_write(target, _canonical_bytes(document))

    def restore(self, source: Path) -> int:
        document = _strict_object(
            _regular_owner_file(source, maximum=64 * 1024 * 1024),
            label="private backup",
        )
        if (
            set(document) != {"schema_id", "schema_version", "entries"}
            or document["schema_id"] != "ConnectedWorkerPrivateBackup"
            or document["schema_version"] != "1.0.0"
            or not isinstance(document["entries"], list)
        ):
            raise ConnectedWorkerError("private backup identity drifted")
        restored = 0
        for entry in document["entries"]:
            if not isinstance(entry, dict) or set(entry) != {
                "kind",
                "name",
                "sha256",
                "body_base64",
            }:
                raise ConnectedWorkerError("private backup entry is invalid")
            kind = entry["kind"]
            name = entry["name"]
            digest = entry["sha256"]
            body = entry["body_base64"]
            if (
                kind not in {"raw", "output", "record"}
                or not isinstance(name, str)
                or not _SHA256_RE.fullmatch(name)
                or not isinstance(digest, str)
                or not _SHA256_RE.fullmatch(digest)
                or not isinstance(body, str)
            ):
                raise ConnectedWorkerError("private backup entry is invalid")
            try:
                raw = base64.b64decode(body, validate=True)
            except (ValueError, TypeError) as exc:
                raise ConnectedWorkerError("private backup entry is invalid") from exc
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ConnectedWorkerError("private backup entry digest mismatch")
            if kind in {"raw", "output"} and name != digest:
                raise ConnectedWorkerError("private backup CAS name mismatch")
            root = {
                "raw": self.raw_root,
                "output": self.output_root,
                "record": self.record_root,
            }[kind]
            self._atomic_write(root / name, raw)
            restored += 1
        return restored


def _extract_output(raw_response: bytes, *, protocol: str) -> bytes:
    envelope = _strict_object(raw_response, label="provider envelope")
    if set(envelope) != {"binding", "protocol", "http_status", "headers", "body_base64"}:
        raise ConnectedWorkerError("provider envelope shape is invalid")
    body_encoded = envelope["body_base64"]
    if not isinstance(body_encoded, str):
        raise ConnectedWorkerError("provider body encoding is invalid")
    try:
        body = base64.b64decode(body_encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ConnectedWorkerError("provider body encoding is invalid") from exc
    value = _strict_object(body, label="provider body")
    output: object
    if protocol == "OPENAI_CHAT_COMPLETIONS":
        choices = value.get("choices")
        if (
            not isinstance(choices, list)
            or not choices
            or not isinstance(choices[0], dict)
            or not isinstance(choices[0].get("message"), dict)
        ):
            raise ConnectedWorkerError("provider output shape is invalid")
        output = choices[0]["message"].get("content")
    elif protocol == "OPENAI_RESPONSES":
        items = value.get("output")
        texts: list[str] = []
        if not isinstance(items, list):
            raise ConnectedWorkerError("provider output shape is invalid")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("content"), list):
                continue
            for content in item["content"]:
                if (
                    isinstance(content, dict)
                    and content.get("type") == "output_text"
                    and isinstance(content.get("text"), str)
                ):
                    texts.append(content["text"])
        output = "".join(texts)
    else:
        raise ConnectedWorkerError("provider output protocol is invalid")
    if not isinstance(output, str) or not output or "\x00" in output:
        raise ConnectedWorkerError("provider output text is invalid")
    return output.encode("utf-8")


def _credential_environment(path: Path) -> dict[str, str]:
    """Load an optional owner-only VPS locator without logging its values."""

    if not os.path.lexists(path):
        return {}
    raw = _regular_owner_file(path, maximum=65_536)
    allowed = {
        "DEEPSEEK_API_KEY",
        "ZHIPU_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
    }
    result: dict[str, str] = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ConnectedWorkerError("credential locator is invalid") from exc
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConnectedWorkerError("credential locator is invalid")
        name, value = line.split("=", 1)
        if name not in allowed or name in result or not value:
            raise ConnectedWorkerError("credential locator is invalid")
        result[name] = value
    return result


def _record(
    dispatch: Dispatch,
    *,
    outcome: str,
    response_ref: str | None,
    raw_response_ref: str | None,
    actual_tokens: int | None,
    actual_cost_units: int | None,
    provider_receipt_ref: str | None,
    failure_code: str | None,
    created_at: str,
    attempts: tuple[Mapping[str, object], ...] = (),
    network_calls: int = 0,
) -> dict[str, object]:
    return {
        "schema_id": "ConnectedWorkerCompletion",
        "schema_version": "1.1.0",
        "call_id": dispatch.call_id,
        "dispatch_token": dispatch.dispatch_token,
        "outcome": outcome,
        "response_ref": response_ref,
        "raw_response_ref": raw_response_ref,
        "actual_tokens": actual_tokens,
        "actual_cost_units": actual_cost_units,
        "provider_receipt_ref": provider_receipt_ref,
        "failure_code": failure_code,
        "created_at": created_at,
        "attempts": [dict(attempt) for attempt in attempts],
        "network_calls": network_calls,
    }


def _attempt_record(
    dispatch: Dispatch,
    *,
    attempt_number: int,
    request_sha256: str,
    request_bytes_sent: object,
    provider_request_id: str | None,
    failure_phase: str | None,
    failure_code: str | None,
    network_call_performed: bool,
    started_at: str,
    completed_at: str,
) -> dict[str, object]:
    attempt_id = hashlib.sha256(
        f"{dispatch.call_id}:{attempt_number}:{request_sha256}".encode("utf-8")
    ).hexdigest()
    record = {
        "attempt_number": attempt_number,
        "attempt_id": attempt_id,
        "call_id": dispatch.call_id,
        "provider_binding": dispatch.model_binding,
        "request_sha256": request_sha256,
        "request_bytes_sent": request_bytes_sent,
        "provider_request_id_or_null": provider_request_id,
        "failure_phase": failure_phase,
        "failure_code": failure_code,
        "network_call_performed": network_call_performed,
        "started_at": started_at,
        "completed_at": completed_at,
    }
    if set(record) != _ATTEMPT_KEYS:
        raise ConnectedWorkerError("provider attempt record shape drifted")
    return record


def _provider_request_id(raw: bytes) -> str | None:
    try:
        envelope = _strict_object(raw, label="provider envelope")
        headers = envelope.get("headers")
        if not isinstance(headers, dict):
            return None
        for name in ("x-request-id", "request-id", "openai-request-id"):
            value = headers.get(name)
            if (
                isinstance(value, str)
                and 0 < len(value) <= 512
                and "\x00" not in value
            ):
                return value
    except ConnectedWorkerError:
        return None
    return None


def _completion_payload(record: Mapping[str, object]) -> dict[str, object]:
    return {
        "call_id": record["call_id"],
        "dispatch_token": record["dispatch_token"],
        "outcome": record["outcome"],
        "response_ref": record["response_ref"],
        "actual_tokens": record["actual_tokens"],
        "actual_cost_units": record["actual_cost_units"],
        "provider_receipt_ref": record["provider_receipt_ref"],
        "failure_code": record["failure_code"],
    }


def _validate_lookup(dispatch: Dispatch, state: Mapping[str, object]) -> None:
    expected = {
        "call_id": dispatch.call_id,
        "request_sha256": hashlib.sha256(dispatch.request_body.encode("utf-8")).hexdigest(),
        "model_binding": dispatch.model_binding,
        "classification": dispatch.classification,
        "max_tokens": dispatch.max_tokens,
        "expires_at": dispatch.expires_at,
    }
    if any(state.get(name) != value for name, value in expected.items()):
        raise ConnectedWorkerError("durable model call differs from dispatch")


AdapterFactory = Callable[[str, Mapping[str, object], str, ConnectedShadowProfile], object]


def _bounded_provider_request(
    binding: Mapping[str, object],
    prompt: bytes,
    *,
    total_token_budget: int,
    policy: RuntimePolicy,
) -> tuple[bytes, int]:
    """Derive a provider output limit below the total durable reservation.

    Canonical request bytes are a conservative upper bound for visible input
    tokens.  The policy margin covers protocol/provider framing that is not
    represented in that request.  The calculation is repeated after encoding
    the chosen output limit so the final request itself is the bound subject.
    """

    output_limit = 1
    for _ in range(2):
        request = build_request_bytes(binding, prompt, output_limit)
        available = (
            total_token_budget
            - len(request)
            - policy.provider_input_token_margin
        )
        output_limit = min(policy.max_provider_output_tokens, available)
        if output_limit < 1:
            raise ConnectedWorkerError(
                "total token reservation cannot cover the provider request"
            )
    request = build_request_bytes(binding, prompt, output_limit)
    if (
        len(request)
        + policy.provider_input_token_margin
        + output_limit
        > total_token_budget
    ):
        raise ConnectedWorkerError("provider token allowance exceeds reservation")
    return request, output_limit


def run_dispatch(
    *,
    policy_path: Path,
    dispatch_path: Path,
    encryption_attested: bool,
    ipc_client: object | None = None,
    credential_resolver: CredentialResolver | None = None,
    adapter_factory: AdapterFactory | None = None,
    event_at: str | None = None,
) -> dict[str, object]:
    """Run or safely recover one exact dispatch without automatic repetition."""

    policy = RuntimePolicy.load(policy_path)
    profile_paths = {_sha256_file(ADVISOR_PROFILE_PATH): ADVISOR_PROFILE_PATH}
    profile_path = profile_paths.get(policy.shadow_profile_sha256)
    if profile_path is None:
        raise ConnectedWorkerError("provider profile binding is stale")
    profile = ConnectedShadowProfile(profile_path)
    if profile.sha256 != policy.shadow_profile_sha256:
        raise ConnectedWorkerError("provider profile binding is stale")
    dispatch = Dispatch.load(dispatch_path, policy=policy, profile=profile)
    if os.path.lexists(policy.ai_off_path):
        return {"status": "AI_OFF", "call_id": dispatch.call_id, "network_calls": 0}
    binding = _provider_quality_binding(
        dispatch.model_binding,
        profile.binding(dispatch.model_binding),
    )
    if credential_resolver is None:
        environment = dict(os.environ)
        for name, value in _credential_environment(policy.credential_file).items():
            environment.setdefault(name, value)
        resolver = CredentialResolver(environment)
    else:
        resolver = credential_resolver
    credential = resolver.resolve(str(binding["credential_env"]))
    if not credential:
        return {
            "status": "WAIT_CREDENTIAL",
            "call_id": dispatch.call_id,
            "network_calls": 0,
        }
    provider_request, provider_output_tokens = _bounded_provider_request(
        binding,
        dispatch.request_body.encode("utf-8"),
        total_token_budget=dispatch.max_tokens,
        policy=policy,
    )
    if len(provider_request) > profile.max_request_bytes:
        raise ConnectedWorkerError("provider request exceeds the frozen bound")
    now_value = _now() if event_at is None else _timestamp(event_at, label="event time")
    if datetime.fromisoformat(now_value[:-1] + "+00:00") >= datetime.fromisoformat(
        dispatch.expires_at[:-1] + "+00:00"
    ):
        return {"status": "WAIT_EXPIRED", "call_id": dispatch.call_id, "network_calls": 0}
    client = UnixIPCClient(policy.control_socket) if ipc_client is None else ipc_client
    if not callable(getattr(client, "request", None)):
        raise ConnectedWorkerError("control IPC client is invalid")
    key_base = hashlib.sha256(dispatch.call_id.encode("utf-8")).hexdigest()
    state = client.request(  # type: ignore[attr-defined]
        "lookup_model_call",
        {"call_id": dispatch.call_id},
        idempotency_key="worker:lookup:" + key_base,
    )
    if not isinstance(state, Mapping):
        raise ConnectedWorkerError("model call lookup is invalid")
    _validate_lookup(dispatch, state)
    store = PrivateResponseStore(
        policy.private_store_root,
        encryption_attested=encryption_attested,
        maximum_record_bytes=policy.max_completion_bytes,
    )
    existing = store.load_record(dispatch.call_id)
    current_state = state.get("state")
    if current_state in _TERMINAL_STATES:
        return {
            "status": "ALREADY_TERMINAL",
            "call_id": dispatch.call_id,
            "state": current_state,
            "network_calls": 0,
        }
    if existing is not None:
        if current_state != "SENT":
            return {
                "status": "WAIT_RECONCILIATION",
                "call_id": dispatch.call_id,
                "state": current_state,
                "network_calls": 0,
            }
        completed = client.request(  # type: ignore[attr-defined]
            "complete_model_call",
            _completion_payload(existing),
            idempotency_key="worker:complete:" + key_base,
        )
        return {
            "status": "COMPLETION_REPLAYED",
            "call_id": dispatch.call_id,
            "state": completed.get("state"),
            "network_calls": 0,
        }
    if current_state == "SENT":
        uncertain = _record(
            dispatch,
            outcome="UNKNOWN",
            response_ref=None,
            raw_response_ref=None,
            actual_tokens=None,
            actual_cost_units=None,
            provider_receipt_ref=None,
            failure_code=None,
            created_at=now_value,
        )
        store.write_record(uncertain)
        completed = client.request(  # type: ignore[attr-defined]
            "complete_model_call",
            _completion_payload(uncertain),
            idempotency_key="worker:complete:" + key_base,
        )
        return {
            "status": "RECOVERED_UNKNOWN",
            "call_id": dispatch.call_id,
            "state": completed.get("state"),
            "network_calls": 0,
        }
    if current_state != "RESERVED":
        raise ConnectedWorkerError("model call is not dispatchable")
    began = client.request(  # type: ignore[attr-defined]
        "begin_model_call",
        {
            "call_id": dispatch.call_id,
            "dispatch_token": dispatch.dispatch_token,
            "request_body": dispatch.request_body,
        },
        idempotency_key="worker:begin:" + key_base,
    )
    if began.get("state") != "SENT" or began.get("egress_authorized") is not True:
        raise ConnectedWorkerError("durable SENT acknowledgement is invalid")
    factory = adapter_factory
    if factory is None:
        factory = lambda name, item, key, bound_profile: HTTPRawAdapter(
            name,
            item,
            key,
            timeout=_provider_timeout_seconds(name, bound_profile),
            maximum=bound_profile.max_response_bytes,
        )
    adapter = factory(dispatch.model_binding, binding, credential, profile)
    if not callable(getattr(adapter, "invoke_raw", None)):
        raise ConnectedWorkerError("provider adapter is invalid")
    raw_ref: str | None = None
    attempts: list[Mapping[str, object]] = []
    network_calls = 0
    request_sha256 = hashlib.sha256(provider_request).hexdigest()
    attempt = 0
    while True:
        attempt += 1
        attempt_started = now_value if event_at is not None else _now()
        raw: bytes | None = None
        try:
            network_calls += 1
            raw = adapter.invoke_raw(  # type: ignore[attr-defined]
                call_id=dispatch.call_id,
                request_bytes=provider_request,
                max_tokens=provider_output_tokens,
            )
            if (
                not isinstance(raw, bytes)
                or not raw
                or len(raw) > profile.max_response_bytes
            ):
                raise ConnectedWorkerError("provider response exceeds the frozen bound")
            raw_ref = store.commit_raw(raw)
            provider_request_id = _provider_request_id(raw)
            parser = HTTPResponseParser(dispatch.model_binding, str(binding["protocol"]))
            accounting = parser.parse_response(
                raw_response=raw,
                response_ref=raw_ref,
                max_tokens=dispatch.max_tokens,
            )
            if (
                accounting.actual_tokens is None
                or accounting.actual_tokens > dispatch.max_tokens
            ):
                raise KnownProviderFailure(
                    "TOTAL_TOKEN_LIMIT_EXCEEDED",
                    actual_tokens=accounting.actual_tokens,
                    actual_cost_units=accounting.actual_cost_units,
                    provider_receipt_ref=accounting.provider_receipt_ref,
                )
            output = _extract_output(raw, protocol=str(binding["protocol"]))
            if len(output.strip()) < policy.minimum_output_bytes:
                raise KnownProviderFailure(
                    "VACUOUS_OUTPUT",
                    actual_tokens=accounting.actual_tokens,
                    actual_cost_units=accounting.actual_cost_units,
                    provider_receipt_ref=accounting.provider_receipt_ref,
                )
            output_ref = store.commit_output(
                output, maximum=policy.max_extracted_output_bytes
            )
            attempts.append(
                _attempt_record(
                    dispatch,
                    attempt_number=attempt,
                    request_sha256=request_sha256,
                    request_bytes_sent=True,
                    provider_request_id=provider_request_id,
                    failure_phase=None,
                    failure_code=None,
                    network_call_performed=True,
                    started_at=attempt_started,
                    completed_at=now_value if event_at is not None else _now(),
                )
            )
            completion = _record(
                dispatch,
                outcome="SUCCEEDED",
                response_ref=output_ref,
                raw_response_ref=raw_ref,
                actual_tokens=accounting.actual_tokens,
                actual_cost_units=accounting.actual_cost_units,
                provider_receipt_ref=accounting.provider_receipt_ref,
                failure_code=None,
                created_at=now_value,
                attempts=tuple(attempts),
                network_calls=network_calls,
            )
            break
        except KnownProviderFailure as exc:
            attempts.append(
                _attempt_record(
                    dispatch,
                    attempt_number=attempt,
                    request_sha256=request_sha256,
                    request_bytes_sent=True,
                    provider_request_id=(
                        _provider_request_id(raw) if isinstance(raw, bytes) else None
                    ),
                    failure_phase="provider_response",
                    failure_code=exc.code,
                    network_call_performed=True,
                    started_at=attempt_started,
                    completed_at=now_value if event_at is not None else _now(),
                )
            )
            if (
                policy.automatic_retry
                and attempt < _MAX_PROVIDER_ATTEMPTS
                and exc.code in _RETRYABLE_FAILURE_CODES
            ):
                raw_ref = None
                continue
            completion = _record(
                dispatch,
                outcome="FAILED_KNOWN",
                response_ref=None,
                raw_response_ref=raw_ref,
                actual_tokens=exc.actual_tokens,
                actual_cost_units=exc.actual_cost_units,
                provider_receipt_ref=exc.provider_receipt_ref,
                failure_code=exc.code,
                created_at=now_value,
                attempts=tuple(attempts),
                network_calls=network_calls,
            )
            break
        except Exception as exc:
            failure_code, request_bytes_sent, failure_phase = (
                _classify_transport_failure(exc)
            )
            if raw_ref is not None:
                request_bytes_sent = True
                failure_phase = "response_parse"
                if failure_code is None:
                    failure_code = "MALFORMED_RESPONSE"
            attempts.append(
                _attempt_record(
                    dispatch,
                    attempt_number=attempt,
                    request_sha256=request_sha256,
                    request_bytes_sent=request_bytes_sent,
                    provider_request_id=(
                        _provider_request_id(raw) if isinstance(raw, bytes) else None
                    ),
                    failure_phase=failure_phase,
                    failure_code=failure_code,
                    network_call_performed=True,
                    started_at=attempt_started,
                    completed_at=now_value if event_at is not None else _now(),
                )
            )
            if (
                policy.automatic_retry
                and attempt < _MAX_PROVIDER_ATTEMPTS
                and failure_code in _RETRYABLE_FAILURE_CODES
                and request_bytes_sent is False
            ):
                raw_ref = None
                continue
            completion = _record(
                dispatch,
                outcome="UNKNOWN",
                response_ref=None,
                raw_response_ref=raw_ref,
                actual_tokens=None,
                actual_cost_units=None,
                provider_receipt_ref=None,
                failure_code=failure_code,
                created_at=now_value,
                attempts=tuple(attempts),
                network_calls=network_calls,
            )
            break
    store.write_record(completion)
    completed = client.request(  # type: ignore[attr-defined]
        "complete_model_call",
        _completion_payload(completion),
        idempotency_key="worker:complete:" + key_base,
    )
    return {
        "status": "COMPLETED",
        "call_id": dispatch.call_id,
        "state": completed.get("state"),
        "network_calls": network_calls,
        "attempt_ids": tuple(attempt["attempt_id"] for attempt in attempts),
    }


def _store_from_arguments(args: argparse.Namespace) -> tuple[RuntimePolicy, PrivateResponseStore]:
    policy = RuntimePolicy.load(Path(args.policy))
    store = PrivateResponseStore(
        policy.private_store_root,
        encryption_attested=args.storage_encryption_attested,
        maximum_record_bytes=policy.max_completion_bytes,
    )
    return policy, store


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--policy", required=True)
    run.add_argument("--dispatch", required=True)
    backup = subparsers.add_parser("backup")
    backup.add_argument("--policy", required=True)
    backup.add_argument("--destination", required=True)
    restore = subparsers.add_parser("restore")
    restore.add_argument("--policy", required=True)
    restore.add_argument("--backup", required=True)
    delete = subparsers.add_parser("delete")
    delete.add_argument("--policy", required=True)
    delete.add_argument("--ref", required=True)
    purge = subparsers.add_parser("purge")
    purge.add_argument("--policy", required=True)
    for command in (run, backup, restore, delete, purge):
        command.add_argument(
            "--storage-encryption-attested",
            action="store_true",
            help="Confirm the private store is on the required encrypted volume.",
        )
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = run_dispatch(
                policy_path=Path(args.policy),
                dispatch_path=Path(args.dispatch),
                encryption_attested=args.storage_encryption_attested,
            )
        else:
            policy, store = _store_from_arguments(args)
            if args.command == "backup":
                store.backup(Path(args.destination))
                result = {"status": "BACKUP_COMPLETE", "private_bytes_printed": False}
            elif args.command == "restore":
                restored = store.restore(Path(args.backup))
                result = {
                    "status": "RESTORE_COMPLETE",
                    "objects_restored": restored,
                    "private_bytes_printed": False,
                }
            elif args.command == "delete":
                deleted = store.delete_ref(args.ref)
                result = {"status": "DELETE_COMPLETE", "deleted": deleted}
            elif args.command == "purge":
                removed = store.purge(
                    now_epoch=datetime.now(timezone.utc).timestamp(),
                    retention_seconds=policy.retention_seconds,
                )
                result = {"status": "PURGE_COMPLETE", "objects_removed": removed}
            else:
                raise ConnectedWorkerError("worker command is invalid")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result.get("status") not in {"WAIT_CREDENTIAL", "WAIT_EXPIRED"} else 20
    except (ConnectedWorkerError, ShadowProviderError, OSError, RuntimeError):
        print(
            json.dumps(
                {
                    "status": "CONNECTED_WORKER_FAILED_CLOSED",
                    "private_bytes_printed": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 30


if __name__ == "__main__":
    raise SystemExit(main())
