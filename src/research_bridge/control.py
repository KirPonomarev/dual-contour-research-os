"""Typed, fail-closed local control routing for the offline bridge.

The router deliberately exposes only persistent safety-state inspection,
global pause, and approval-bound global resume.  Peer identity is supplied by
the local IPC boundary after operating-system credential verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from .authority import (
    AuthorityError,
    PinnedOfflineAuthority,
    require_pinned_authority,
)


_PROTOCOL_VERSION = "1.0"
_REQUEST_KEYS = frozenset(
    {"version", "request_id", "idempotency_key", "command", "payload"}
)
_COMMAND_PAYLOAD_KEYS = {
    "status": frozenset(),
    "pause_global": frozenset({"reason", "authority_ref"}),
    "resume_global": frozenset({"approval_ref"}),
}


class ControlError(RuntimeError):
    """A malformed, unauthorized, or failed local control operation."""


class _ControlBackend(Protocol):
    def pause_snapshot(self) -> Mapping[str, object]: ...

    def pause_global(
        self,
        *,
        actor: str,
        reason: str,
        authority_ref: str,
        idempotency_key: str,
        event_at: str | None = None,
    ) -> object: ...

    def resume_global(
        self,
        *,
        actor: str,
        approval_ref: str,
        idempotency_key: str,
        event_at: str | None = None,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ControlRequest:
    """One strictly shaped versioned control request."""

    version: str
    request_id: str
    idempotency_key: str
    command: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.version != _PROTOCOL_VERSION:
            raise ControlError("unsupported control protocol version")
        _normalized_text("request_id", self.request_id, maximum=256)
        _normalized_text("idempotency_key", self.idempotency_key, maximum=256)
        if not isinstance(self.command, str) or self.command not in _COMMAND_PAYLOAD_KEYS:
            raise ControlError("unsupported control command")
        if not isinstance(self.payload, Mapping):
            raise ControlError("payload must be an object")

        copied_payload = dict(self.payload)
        if set(copied_payload) != _COMMAND_PAYLOAD_KEYS[self.command]:
            raise ControlError("payload keys do not match the control command")
        if self.command == "pause_global":
            _normalized_text("reason", copied_payload["reason"], maximum=1024)
            _normalized_text(
                "authority_ref", copied_payload["authority_ref"], maximum=512
            )
        elif self.command == "resume_global":
            _normalized_text(
                "approval_ref", copied_payload["approval_ref"], maximum=512
            )
        object.__setattr__(self, "payload", MappingProxyType(copied_payload))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> ControlRequest:
        """Build a request only when its top-level shape is exact."""

        if not isinstance(value, Mapping) or set(value) != _REQUEST_KEYS:
            raise ControlError("control request keys do not match the protocol")
        return cls(
            version=value["version"],  # type: ignore[arg-type]
            request_id=value["request_id"],  # type: ignore[arg-type]
            idempotency_key=value["idempotency_key"],  # type: ignore[arg-type]
            command=value["command"],  # type: ignore[arg-type]
            payload=value["payload"],  # type: ignore[arg-type]
        )

    def to_mapping(self) -> dict[str, object]:
        """Return a JSON-ready copy of the request."""

        return {
            "version": self.version,
            "request_id": self.request_id,
            "idempotency_key": self.idempotency_key,
            "command": self.command,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True, slots=True)
class ControlResponse:
    """A successful response from the local control router."""

    version: str
    request_id: str
    command: str
    result: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.version != _PROTOCOL_VERSION:
            raise ControlError("unsupported control response version")
        _normalized_text("request_id", self.request_id, maximum=256)
        if self.command not in _COMMAND_PAYLOAD_KEYS:
            raise ControlError("unsupported control response command")
        if not isinstance(self.result, Mapping):
            raise ControlError("control backend result must be an object")
        copied_result = dict(self.result)
        if not all(isinstance(key, str) for key in copied_result):
            raise ControlError("control backend result keys must be text")
        object.__setattr__(self, "result", MappingProxyType(copied_result))

    @property
    def ok(self) -> bool:
        return True

    def to_mapping(self) -> dict[str, object]:
        """Return the strict success envelope sent over local IPC."""

        return {
            "version": self.version,
            "request_id": self.request_id,
            "ok": True,
            "command": self.command,
            "result": dict(self.result),
        }


class ControlRouter:
    """Route validated local requests to the single pause-state backend."""

    def __init__(
        self,
        backend: _ControlBackend,
        *,
        authority: PinnedOfflineAuthority | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if backend is None:
            raise ControlError("control backend is required")
        if clock is not None and not callable(clock):
            raise ControlError("clock must be callable")
        try:
            self._authority = require_pinned_authority(authority)
        except AuthorityError as exc:
            raise ControlError("pinned authority verifier is required") from exc
        self._backend = backend
        self._clock = clock if clock is not None else lambda: datetime.now(timezone.utc)

    def dispatch(self, request: ControlRequest, *, peer_uid: int) -> ControlResponse:
        """Dispatch one request using only an OS-verified numeric peer UID."""

        if not isinstance(request, ControlRequest):
            raise ControlError("router accepts only typed ControlRequest values")
        if isinstance(peer_uid, bool) or not isinstance(peer_uid, int) or peer_uid < 0:
            raise ControlError("verified peer UID must be a non-negative integer")

        actor = f"uid:{peer_uid}"
        try:
            if request.command == "status":
                result = self._backend.pause_snapshot()
            elif request.command == "pause_global":
                self._backend.pause_global(
                    actor=actor,
                    reason=request.payload["reason"],  # type: ignore[arg-type]
                    authority_ref=request.payload["authority_ref"],  # type: ignore[arg-type]
                    idempotency_key=request.idempotency_key,
                    event_at=self._event_at(),
                )
                result = self._backend.pause_snapshot()
            elif request.command == "resume_global":
                event_at = self._event_at()
                try:
                    self._authority.verify_resume(
                        request.payload["approval_ref"],  # type: ignore[arg-type]
                        now=event_at,
                    )
                except AuthorityError as exc:
                    raise ControlError("resume approval verification failed") from exc
                self._backend.resume_global(
                    actor=actor,
                    approval_ref=request.payload["approval_ref"],  # type: ignore[arg-type]
                    idempotency_key=request.idempotency_key,
                    event_at=event_at,
                )
                result = self._backend.pause_snapshot()
            else:  # pragma: no cover - ControlRequest enforces the closed command set.
                raise ControlError("unsupported control command")
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("control backend operation failed") from exc

        return ControlResponse(
            version=request.version,
            request_id=request.request_id,
            command=request.command,
            result=result,
        )

    def _event_at(self) -> str:
        try:
            current = self._clock()
        except Exception as exc:
            raise ControlError("UTC clock failed") from exc
        if not isinstance(current, datetime):
            raise ControlError("UTC clock must return datetime")
        if current.tzinfo is None or current.utcoffset() is None:
            raise ControlError("UTC clock must return an aware datetime")
        if current.utcoffset() != timezone.utc.utcoffset(current):
            raise ControlError("UTC clock must return UTC")
        return current.isoformat().replace("+00:00", "Z")


def _normalized_text(name: str, value: object, *, maximum: int) -> str:
    if isinstance(value, bytes) or not isinstance(value, str):
        raise ControlError(f"{name} must be text")
    if (
        not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ControlError(f"{name} must be normalized non-empty text")
    return value


__all__ = ["ControlError", "ControlRequest", "ControlResponse", "ControlRouter"]
