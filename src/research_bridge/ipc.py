"""Size-bounded, deadline-bounded AF_UNIX control transport.

This module is a local front door only.  It creates no network listener and
derives caller identity exclusively from operating-system peer credentials.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import stat
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .control import ControlRequest, ControlResponse, ControlRouter


_MAX_REQUEST_BYTES = 65_536
_MAX_DEADLINE_SECONDS = 5.0
_SOCKET_MODE = 0o660


class IPCError(RuntimeError):
    """A fail-closed local IPC framing, identity, or transport error."""


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """Credentials returned by an operating-system local-peer API."""

    uid: int
    gid: int
    pid: int | None = None

    def __post_init__(self) -> None:
        for name, value in (("uid", self.uid), ("gid", self.gid)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise IPCError(f"peer {name} must be a non-negative integer")
        if self.pid is not None and (
            isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid < 0
        ):
            raise IPCError("peer pid must be a non-negative integer or None")


def resolve_peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Resolve a connected AF_UNIX peer with SO_PEERCRED or getpeereid."""

    if getattr(connection, "family", None) != socket.AF_UNIX:
        raise IPCError("peer credentials require an AF_UNIX connection")

    linux_error: Exception | None = None
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        credential_size = struct.calcsize("3i")
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, so_peercred, credential_size)
            if not isinstance(raw, bytes) or len(raw) != credential_size:
                raise IPCError("SO_PEERCRED returned an invalid credential record")
            pid, uid, gid = struct.unpack("3i", raw)
            return PeerCredentials(uid=uid, gid=gid, pid=pid)
        except (AttributeError, OSError, struct.error, IPCError) as exc:
            linux_error = exc

    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        try:
            uid, gid = getpeereid()
            return PeerCredentials(uid=uid, gid=gid, pid=None)
        except (OSError, TypeError, ValueError, IPCError) as exc:
            raise IPCError("getpeereid could not verify the local peer") from exc

    libc_credentials = _libc_getpeereid(connection)
    if libc_credentials is not None:
        return libc_credentials

    if linux_error is not None:
        raise IPCError("SO_PEERCRED could not verify the local peer") from linux_error
    raise IPCError("this platform exposes no supported local peer credential API")


def encode_message(message: ControlResponse | Mapping[str, object]) -> bytes:
    """Encode one canonical JSON object followed by exactly one newline."""

    if isinstance(message, ControlResponse):
        value: object = message.to_mapping()
    elif isinstance(message, Mapping):
        value = dict(message)
    else:
        raise IPCError("IPC message must be an object")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IPCError("IPC message is not canonical JSON data") from exc
    if len(encoded) > _MAX_REQUEST_BYTES:
        raise IPCError("IPC message exceeds 65536 bytes")
    return encoded


def decode_message(data: bytes) -> dict[str, object]:
    """Strictly decode one size-bounded newline-terminated JSON object."""

    if not isinstance(data, bytes):
        raise IPCError("IPC frame must be bytes")
    if not data or len(data) > _MAX_REQUEST_BYTES:
        raise IPCError("IPC frame size is invalid")
    if not data.endswith(b"\n") or b"\n" in data[:-1] or b"\r" in data:
        raise IPCError("IPC frame must contain exactly one trailing newline")
    if len(data) == 1:
        raise IPCError("IPC frame payload is empty")
    try:
        text = data[:-1].decode("utf-8", errors="strict")
        decoded = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, IPCError) as exc:
        raise IPCError("IPC frame is not strict JSON") from exc
    if not isinstance(decoded, dict):
        raise IPCError("IPC message must be a JSON object")
    return decoded


class UnixControlServer:
    """A single-request local Unix-socket server for typed control messages."""

    def __init__(
        self,
        socket_path: str | Path,
        router: ControlRouter,
        *,
        allowed_uids: Iterable[int],
        deadline_seconds: float = 5.0,
        credential_resolver: Callable[[socket.socket], PeerCredentials] = resolve_peer_credentials,
    ) -> None:
        if isinstance(socket_path, bytes) or not isinstance(socket_path, (str, Path)):
            raise IPCError("socket_path must be a filesystem path")
        normalized_path = str(socket_path)
        if not normalized_path or "\x00" in normalized_path:
            raise IPCError("socket_path must name a filesystem Unix socket")
        if not callable(getattr(router, "dispatch", None)):
            raise IPCError("router must expose dispatch")
        if (
            isinstance(deadline_seconds, bool)
            or not isinstance(deadline_seconds, (int, float))
            or not 0 < float(deadline_seconds) <= _MAX_DEADLINE_SECONDS
        ):
            raise IPCError("deadline_seconds must be greater than zero and at most five")
        if not callable(credential_resolver):
            raise IPCError("credential_resolver must be callable")
        try:
            allowed = frozenset(allowed_uids)
        except TypeError as exc:
            raise IPCError("allowed_uids must be an iterable of integers") from exc
        if any(
            isinstance(uid, bool) or not isinstance(uid, int) or uid < 0
            for uid in allowed
        ):
            raise IPCError("allowed_uids must contain only non-negative integers")

        self._socket_path = normalized_path
        self._router = router
        self._allowed_uids = allowed
        self._deadline_seconds = float(deadline_seconds)
        self._credential_resolver = credential_resolver
        self._listener: socket.socket | None = None
        self._bound_identity: tuple[int, int] | None = None

    def start(self) -> None:
        """Bind one AF_UNIX listener with an exact mode of 0660."""

        if self._listener is not None:
            raise IPCError("Unix control server is already started")
        if os.path.lexists(self._socket_path):
            raise IPCError("socket_path already exists")

        listener: socket.socket | None = None
        try:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if listener.family != socket.AF_UNIX:
                raise IPCError("could not create an AF_UNIX listener")
            listener.bind(self._socket_path)
            socket_stat = os.lstat(self._socket_path)
            if not stat.S_ISSOCK(socket_stat.st_mode):
                raise IPCError("bound control path is not a Unix socket")
            self._bound_identity = (socket_stat.st_dev, socket_stat.st_ino)
            os.chmod(self._socket_path, _SOCKET_MODE)
            socket_stat = os.lstat(self._socket_path)
            if (socket_stat.st_dev, socket_stat.st_ino) != self._bound_identity:
                raise IPCError("bound Unix socket identity changed")
            if stat.S_IMODE(socket_stat.st_mode) != _SOCKET_MODE:
                raise IPCError("Unix control socket mode is not 0660")
            listener.listen(8)
            self._listener = listener
        except (OSError, IPCError) as exc:
            if listener is not None:
                listener.close()
            self._remove_owned_socket()
            if isinstance(exc, IPCError):
                raise
            raise IPCError("could not start Unix control server") from exc

    def serve_once(self) -> ControlResponse:
        """Accept, authenticate, process, and answer one local connection."""

        if self._listener is None:
            raise IPCError("Unix control server is not started")
        try:
            connection, _ = self._listener.accept()
        except OSError as exc:
            raise IPCError("could not accept Unix control connection") from exc
        with connection:
            return self.handle_connection(connection)

    def handle_connection(self, connection: socket.socket) -> ControlResponse:
        """Authenticate before parsing and dispatch exactly one request."""

        if getattr(connection, "family", None) != socket.AF_UNIX:
            raise IPCError("control connection must use AF_UNIX")
        deadline = time.monotonic() + self._deadline_seconds
        self._set_remaining_timeout(connection, deadline)
        try:
            credentials = self._credential_resolver(connection)
        except IPCError:
            raise
        except Exception as exc:
            raise IPCError("peer credential resolution failed") from exc
        if not isinstance(credentials, PeerCredentials):
            raise IPCError("peer credential resolver returned an invalid value")
        if credentials.uid not in self._allowed_uids:
            raise IPCError("peer UID is not allowed")

        frame = self._receive_frame(connection, deadline)
        decoded = decode_message(frame)
        request = ControlRequest.from_mapping(decoded)
        response = self._router.dispatch(request, peer_uid=credentials.uid)
        encoded = encode_message(response)
        self._set_remaining_timeout(connection, deadline)
        try:
            connection.sendall(encoded)
        except (OSError, TimeoutError) as exc:
            raise IPCError("could not send control response before deadline") from exc
        return response

    def close(self) -> None:
        """Close the listener and unlink only the socket inode this server bound."""

        listener = self._listener
        self._listener = None
        if listener is not None:
            listener.close()
        self._remove_owned_socket()

    def __enter__(self) -> UnixControlServer:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _set_remaining_timeout(connection: socket.socket, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IPCError("control request deadline expired")
        try:
            connection.settimeout(remaining)
        except OSError as exc:
            raise IPCError("could not set control request deadline") from exc

    @staticmethod
    def _receive_frame(connection: socket.socket, deadline: float) -> bytes:
        frame = bytearray()
        while True:
            UnixControlServer._set_remaining_timeout(connection, deadline)
            remaining_capacity = _MAX_REQUEST_BYTES + 1 - len(frame)
            if remaining_capacity <= 0:
                raise IPCError("IPC request exceeds 65536 bytes")
            try:
                chunk = connection.recv(min(4096, remaining_capacity))
            except (OSError, TimeoutError) as exc:
                raise IPCError("could not receive control request before deadline") from exc
            if not chunk:
                raise IPCError("control connection closed before a complete request")
            frame.extend(chunk)
            if len(frame) > _MAX_REQUEST_BYTES:
                raise IPCError("IPC request exceeds 65536 bytes")
            if b"\n" in chunk:
                return bytes(frame)

    def _remove_owned_socket(self) -> None:
        identity = self._bound_identity
        self._bound_identity = None
        if identity is None:
            return
        try:
            socket_stat = os.lstat(self._socket_path)
        except FileNotFoundError:
            return
        except OSError:
            return
        if (
            stat.S_ISSOCK(socket_stat.st_mode)
            and (socket_stat.st_dev, socket_stat.st_ino) == identity
        ):
            try:
                os.unlink(self._socket_path)
            except FileNotFoundError:
                pass


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IPCError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise IPCError(f"non-finite JSON constant is forbidden: {value}")


def _libc_getpeereid(connection: socket.socket) -> PeerCredentials | None:
    """Call getpeereid from the platform C library when Python omits a wrapper."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.getpeereid
    except (AttributeError, OSError):
        return None
    function.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    function.restype = ctypes.c_int
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    if function(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        error_number = ctypes.get_errno()
        raise IPCError("getpeereid could not verify the local peer") from OSError(
            error_number, os.strerror(error_number)
        )
    return PeerCredentials(uid=uid.value, gid=gid.value, pid=None)


__all__ = [
    "IPCError",
    "PeerCredentials",
    "UnixControlServer",
    "encode_message",
    "decode_message",
    "resolve_peer_credentials",
]
