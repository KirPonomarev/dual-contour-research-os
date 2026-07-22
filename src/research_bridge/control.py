"""Typed, fail-closed local control routing for the offline bridge.

The router exposes one closed offline protocol for persistent safety control,
bounded L0 submission, and zero-write terminal receipt lookup.  Peer identity
is supplied by the local IPC boundary after operating-system credential
verification.
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


_LEGACY_PROTOCOL_VERSION = "1.1"
_SUPPORTED_PROTOCOL_VERSIONS = frozenset({"1.1", "1.2", "1.3"})
_REQUEST_KEYS = frozenset(
    {"version", "request_id", "idempotency_key", "command", "payload"}
)
_LEGACY_REQUEST_KEYS = frozenset(
    {"request_id", "idempotency_key", "command", "payload"}
)
_COMMAND_PAYLOAD_KEYS = {
    "status": frozenset(),
    "pause_global": frozenset({"reason", "authority_ref"}),
    "resume_global": frozenset({"approval_ref"}),
    "submit": frozenset({"job_spec", "permit", "lease"}),
    "lookup": frozenset({"job_spec_ref"}),
    "submit_source_trigger": frozenset({"source_trigger"}),
    "queue_research_mission": frozenset(
        {
            "mission_envelope",
            "action_envelope",
            "material_event_refs",
            "artifact_body",
            "expected_host_fingerprint",
        }
    ),
    "advance_research_missions": frozenset(),
    "research_mission_status": frozenset({"mission_sha256"}),
    "claim_next_proposal": frozenset(),
    "claim_proposal": frozenset({"material_event_ref"}),
    "submit_proposal": frozenset({"proposal_envelope"}),
    "ack_proposal": frozenset({"material_event_ref", "claim_token"}),
    "reserve_model_call": frozenset(
        {
            "role",
            "role_assignment_ref",
            "classification",
            "request_body",
            "max_tokens",
            "max_cost_units",
            "expires_at",
        }
    ),
    "begin_model_call": frozenset(
        {"call_id", "dispatch_token", "request_body"}
    ),
    "complete_model_call": frozenset(
        {
            "call_id",
            "dispatch_token",
            "outcome",
            "response_ref",
            "actual_tokens",
            "actual_cost_units",
            "provider_receipt_ref",
            "failure_code",
        }
    ),
    "complete_research_model_call": frozenset(
        {
            "call_id",
            "dispatch_token",
            "outcome",
            "response_ref",
            "response_body",
            "actual_tokens",
            "actual_cost_units",
            "provider_receipt_ref",
            "failure_code",
        }
    ),
    "reconcile_model_call": frozenset(
        {
            "call_id",
            "actual_tokens",
            "actual_cost_units",
            "provider_receipt_ref",
        }
    ),
    "lookup_model_call": frozenset({"call_id"}),
    "list_reserved_model_calls": frozenset({"maximum"}),
}
_RESEARCH_PROTOCOL_COMMANDS = frozenset(
    {
        "queue_research_mission",
        "advance_research_missions",
        "research_mission_status",
        "complete_research_model_call",
    }
)
_OPERATOR_COMMANDS = frozenset(
    {
        "status",
        "pause_global",
        "resume_global",
        "submit",
        "lookup",
        "reconcile_model_call",
    }
)
_COLLECTOR_COMMANDS = frozenset({"submit_source_trigger", "queue_research_mission"})
_SCOUT_COMMANDS = frozenset(
    {
        "claim_next_proposal",
        "claim_proposal",
        "submit_proposal",
        "ack_proposal",
        "reserve_model_call",
        "lookup_model_call",
        "advance_research_missions",
        "research_mission_status",
    }
)
_CONNECTED_WORKER_COMMANDS = frozenset(
    {
        "begin_model_call",
        "complete_model_call",
        "complete_research_model_call",
        "lookup_model_call",
        "list_reserved_model_calls",
    }
)
_ROLE_COMMANDS = {
    "operator": _OPERATOR_COMMANDS,
    "collector": _COLLECTOR_COMMANDS,
    "scout": _SCOUT_COMMANDS,
    "connected_worker": _CONNECTED_WORKER_COMMANDS,
}
_ROLE_VERSIONS = {
    "operator": frozenset({"1.1", "1.2", "1.3"}),
    "collector": frozenset({"1.2", "1.3"}),
    "scout": frozenset({"1.2", "1.3"}),
    "connected_worker": frozenset({"1.2", "1.3"}),
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

    def submit(
        self,
        *,
        job_spec: Mapping[str, object],
        permit: Mapping[str, object],
        lease: Mapping[str, object],
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def lookup(self, *, job_spec_ref: str) -> Mapping[str, object]: ...


class _A1ControlBackend(Protocol):
    def submit_source_trigger(
        self,
        *,
        source_trigger: Mapping[str, object],
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def claim_proposal(
        self,
        *,
        material_event_ref: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def claim_next_proposal(
        self,
        *,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def submit_proposal(
        self,
        *,
        proposal_envelope: Mapping[str, object],
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def ack_proposal(
        self,
        *,
        material_event_ref: str,
        claim_token: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...


class _ModelControlBackend(Protocol):
    def queue_research_mission(
        self,
        *,
        mission_envelope: Mapping[str, object],
        action_envelope: Mapping[str, object],
        material_event_refs: object,
        artifact_body: str,
        expected_host_fingerprint: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def advance_research_missions(
        self,
        *,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def research_mission_status(
        self,
        *,
        mission_sha256: str,
        actor: str,
    ) -> Mapping[str, object]: ...

    def reserve_model_call(
        self,
        *,
        role: str,
        role_assignment_ref: str,
        classification: str,
        request_body: str,
        max_tokens: int,
        max_cost_units: int,
        expires_at: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def begin_model_call(
        self,
        *,
        call_id: str,
        dispatch_token: str,
        request_body: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def complete_model_call(
        self,
        *,
        call_id: str,
        dispatch_token: str,
        outcome: str,
        response_ref: str | None,
        actual_tokens: int | None,
        actual_cost_units: int | None,
        provider_receipt_ref: str | None,
        failure_code: str | None,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def complete_research_model_call(
        self,
        *,
        call_id: str,
        dispatch_token: str,
        outcome: str,
        response_ref: str | None,
        response_body: str | None,
        actual_tokens: int | None,
        actual_cost_units: int | None,
        provider_receipt_ref: str | None,
        failure_code: str | None,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def lookup_model_call(
        self,
        *,
        call_id: str,
        actor: str,
    ) -> Mapping[str, object]: ...

    def list_reserved_model_calls(
        self,
        *,
        actor: str,
        maximum: int,
    ) -> Mapping[str, object]: ...

    def reconcile_model_call(
        self,
        *,
        call_id: str,
        actual_tokens: int,
        actual_cost_units: int,
        provider_receipt_ref: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]: ...

    def validate_proposal_envelope(
        self, proposal_envelope: Mapping[str, object]
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ControlRequest:
    """One strictly shaped versioned control request."""

    version: str
    request_id: str
    idempotency_key: str
    command: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.version not in _SUPPORTED_PROTOCOL_VERSIONS:
            raise ControlError("unsupported control protocol version")
        _normalized_text("request_id", self.request_id, maximum=256)
        _normalized_text("idempotency_key", self.idempotency_key, maximum=256)
        if not isinstance(self.command, str) or self.command not in _COMMAND_PAYLOAD_KEYS:
            raise ControlError("unsupported control command")
        if self.version == _LEGACY_PROTOCOL_VERSION and self.command not in _OPERATOR_COMMANDS:
            raise ControlError("protocol 1.1 supports operator commands only")
        if (
            self.version == _LEGACY_PROTOCOL_VERSION
            and self.command == "reconcile_model_call"
        ):
            raise ControlError("model reconciliation requires protocol 1.2")
        if self.command in _RESEARCH_PROTOCOL_COMMANDS and self.version != "1.3":
            raise ControlError("research mission commands require protocol 1.3")
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
        elif self.command == "submit":
            for name in ("job_spec", "permit", "lease"):
                value = copied_payload[name]
                if not isinstance(value, Mapping):
                    raise ControlError(f"{name} must be an object")
                copied_payload[name] = _json_copy(value)
        elif self.command == "lookup":
            _normalized_text(
                "job_spec_ref", copied_payload["job_spec_ref"], maximum=256
            )
        elif self.command == "submit_source_trigger":
            value = copied_payload["source_trigger"]
            if not isinstance(value, Mapping):
                raise ControlError("source_trigger must be an object")
            copied_payload["source_trigger"] = _json_copy(value)
        elif self.command == "queue_research_mission":
            for name in ("mission_envelope", "action_envelope"):
                value = copied_payload[name]
                if not isinstance(value, Mapping):
                    raise ControlError(f"{name} must be an object")
                copied_payload[name] = _json_copy(value)
            refs = copied_payload["material_event_refs"]
            if (
                not isinstance(refs, (list, tuple))
                or len(refs) != 2
                or len(set(refs)) != 2
            ):
                raise ControlError("material_event_refs must contain exactly two unique refs")
            copied_payload["material_event_refs"] = [
                _normalized_text("material_event_ref", item, maximum=256)
                for item in refs
            ]
            _model_request_body(copied_payload["artifact_body"])
            _sha256_text(
                "expected_host_fingerprint",
                copied_payload["expected_host_fingerprint"],
            )
        elif self.command == "advance_research_missions":
            pass
        elif self.command == "research_mission_status":
            _sha256_text("mission_sha256", copied_payload["mission_sha256"])
        elif self.command == "claim_next_proposal":
            pass
        elif self.command == "claim_proposal":
            _normalized_text(
                "material_event_ref",
                copied_payload["material_event_ref"],
                maximum=512,
            )
        elif self.command == "submit_proposal":
            value = copied_payload["proposal_envelope"]
            if not isinstance(value, Mapping):
                raise ControlError("proposal_envelope must be an object")
            copied_payload["proposal_envelope"] = _json_copy(value)
        elif self.command == "ack_proposal":
            _normalized_text(
                "material_event_ref",
                copied_payload["material_event_ref"],
                maximum=512,
            )
            _normalized_text(
                "claim_token", copied_payload["claim_token"], maximum=512
            )
        elif self.command == "reserve_model_call":
            _normalized_text("role", copied_payload["role"], maximum=128)
            _normalized_text(
                "role_assignment_ref",
                copied_payload["role_assignment_ref"],
                maximum=512,
            )
            if copied_payload["classification"] not in {"D0", "D1"}:
                raise ControlError("model call classification must be D0 or D1")
            _model_request_body(copied_payload["request_body"])
            _positive_integer("max_tokens", copied_payload["max_tokens"])
            _positive_integer("max_cost_units", copied_payload["max_cost_units"])
            _normalized_text(
                "expires_at", copied_payload["expires_at"], maximum=64
            )
        elif self.command == "begin_model_call":
            _normalized_text("call_id", copied_payload["call_id"], maximum=128)
            _sha256_text("dispatch_token", copied_payload["dispatch_token"])
            _model_request_body(copied_payload["request_body"])
        elif self.command in {"complete_model_call", "complete_research_model_call"}:
            _normalized_text("call_id", copied_payload["call_id"], maximum=128)
            _sha256_text("dispatch_token", copied_payload["dispatch_token"])
            if copied_payload["outcome"] not in {
                "SUCCEEDED",
                "FAILED_KNOWN",
                "UNKNOWN",
            }:
                raise ControlError("model call outcome is unsupported")
            for name in ("response_ref", "provider_receipt_ref", "failure_code"):
                value = copied_payload[name]
                if value is not None:
                    _normalized_text(name, value, maximum=512)
            for name in ("actual_tokens", "actual_cost_units"):
                _optional_nonnegative_integer(name, copied_payload[name])
            if self.command == "complete_research_model_call":
                response_body = copied_payload["response_body"]
                if response_body is not None:
                    _model_request_body(response_body)
                if (copied_payload["outcome"] == "SUCCEEDED") != (
                    response_body is not None
                ):
                    raise ControlError(
                        "research response_body is required only for SUCCEEDED"
                    )
        elif self.command == "reconcile_model_call":
            _normalized_text("call_id", copied_payload["call_id"], maximum=128)
            _nonnegative_integer(
                "actual_tokens", copied_payload["actual_tokens"]
            )
            _nonnegative_integer(
                "actual_cost_units", copied_payload["actual_cost_units"]
            )
            _normalized_text(
                "provider_receipt_ref",
                copied_payload["provider_receipt_ref"],
                maximum=512,
            )
        elif self.command == "lookup_model_call":
            _normalized_text("call_id", copied_payload["call_id"], maximum=128)
        elif self.command == "list_reserved_model_calls":
            if copied_payload["maximum"] != 1:
                raise ControlError("production reserved-call maximum must be 1")
        object.__setattr__(self, "payload", MappingProxyType(copied_payload))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> ControlRequest:
        """Build a request only when its top-level shape is exact."""

        if not isinstance(value, Mapping):
            raise ControlError("control request keys do not match the protocol")
        keys = set(value)
        if keys == _REQUEST_KEYS:
            version = value["version"]
        elif keys == _LEGACY_REQUEST_KEYS:
            version = _LEGACY_PROTOCOL_VERSION
        else:
            raise ControlError("control request keys do not match the protocol")
        return cls(
            version=version,  # type: ignore[arg-type]
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
            "payload": _json_copy(self.payload),
        }


@dataclass(frozen=True, slots=True)
class ControlResponse:
    """A successful response from the local control router."""

    version: str
    request_id: str
    command: str
    result: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.version not in _SUPPORTED_PROTOCOL_VERSIONS:
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
            "result": _json_copy(self.result),
        }


class ControlRouter:
    """Route validated local requests to the single pause-state backend."""

    def __init__(
        self,
        backend: _ControlBackend,
        *,
        a1_backend: _A1ControlBackend | None = None,
        model_backend: _ModelControlBackend | None = None,
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
        self._a1_backend = a1_backend
        self._model_backend = model_backend
        self._clock = clock if clock is not None else lambda: datetime.now(timezone.utc)

    def dispatch(
        self,
        request: ControlRequest,
        *,
        peer_uid: int,
        peer_role: str = "operator",
    ) -> ControlResponse:
        """Dispatch one request using only an OS-verified numeric peer UID."""

        if not isinstance(request, ControlRequest):
            raise ControlError("router accepts only typed ControlRequest values")
        if isinstance(peer_uid, bool) or not isinstance(peer_uid, int) or peer_uid < 0:
            raise ControlError("verified peer UID must be a non-negative integer")
        if peer_role not in _ROLE_COMMANDS:
            raise ControlError("verified peer role is unsupported")
        if request.version not in _ROLE_VERSIONS[peer_role]:
            raise ControlError("verified peer role cannot use this protocol version")
        if request.command not in _ROLE_COMMANDS[peer_role]:
            raise ControlError("verified peer role cannot use this command")

        actor = (
            f"uid:{peer_uid}"
            if peer_role == "operator"
            else f"{peer_role}:uid:{peer_uid}"
        )
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
            elif request.command == "submit":
                result = self._backend.submit(
                    job_spec=request.payload["job_spec"],  # type: ignore[arg-type]
                    permit=request.payload["permit"],  # type: ignore[arg-type]
                    lease=request.payload["lease"],  # type: ignore[arg-type]
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "lookup":
                result = self._backend.lookup(
                    job_spec_ref=request.payload["job_spec_ref"],  # type: ignore[arg-type]
                )
            elif request.command == "submit_source_trigger":
                result = self._require_a1_backend().submit_source_trigger(
                    source_trigger=request.payload["source_trigger"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "queue_research_mission":
                result = self._require_model_backend().queue_research_mission(
                    mission_envelope=request.payload["mission_envelope"],  # type: ignore[arg-type]
                    action_envelope=request.payload["action_envelope"],  # type: ignore[arg-type]
                    material_event_refs=request.payload["material_event_refs"],
                    artifact_body=request.payload["artifact_body"],  # type: ignore[arg-type]
                    expected_host_fingerprint=request.payload["expected_host_fingerprint"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "advance_research_missions":
                result = self._require_model_backend().advance_research_missions(
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "research_mission_status":
                result = self._require_model_backend().research_mission_status(
                    mission_sha256=request.payload["mission_sha256"],  # type: ignore[arg-type]
                    actor=actor,
                )
            elif request.command == "claim_proposal":
                result = self._require_a1_backend().claim_proposal(
                    material_event_ref=request.payload["material_event_ref"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "claim_next_proposal":
                result = self._require_a1_backend().claim_next_proposal(
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "submit_proposal":
                model_backend = self._model_backend
                if model_backend is not None:
                    model_backend.validate_proposal_envelope(
                        request.payload["proposal_envelope"]  # type: ignore[arg-type]
                    )
                result = self._require_a1_backend().submit_proposal(
                    proposal_envelope=request.payload["proposal_envelope"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "reserve_model_call":
                result = self._require_model_backend().reserve_model_call(
                    role=request.payload["role"],  # type: ignore[arg-type]
                    role_assignment_ref=request.payload["role_assignment_ref"],  # type: ignore[arg-type]
                    classification=request.payload["classification"],  # type: ignore[arg-type]
                    request_body=request.payload["request_body"],  # type: ignore[arg-type]
                    max_tokens=request.payload["max_tokens"],  # type: ignore[arg-type]
                    max_cost_units=request.payload["max_cost_units"],  # type: ignore[arg-type]
                    expires_at=request.payload["expires_at"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "begin_model_call":
                result = self._require_model_backend().begin_model_call(
                    call_id=request.payload["call_id"],  # type: ignore[arg-type]
                    dispatch_token=request.payload["dispatch_token"],  # type: ignore[arg-type]
                    request_body=request.payload["request_body"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "complete_model_call":
                result = self._require_model_backend().complete_model_call(
                    call_id=request.payload["call_id"],  # type: ignore[arg-type]
                    dispatch_token=request.payload["dispatch_token"],  # type: ignore[arg-type]
                    outcome=request.payload["outcome"],  # type: ignore[arg-type]
                    response_ref=request.payload["response_ref"],  # type: ignore[arg-type]
                    actual_tokens=request.payload["actual_tokens"],  # type: ignore[arg-type]
                    actual_cost_units=request.payload["actual_cost_units"],  # type: ignore[arg-type]
                    provider_receipt_ref=request.payload["provider_receipt_ref"],  # type: ignore[arg-type]
                    failure_code=request.payload["failure_code"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "complete_research_model_call":
                result = self._require_model_backend().complete_research_model_call(
                    call_id=request.payload["call_id"],  # type: ignore[arg-type]
                    dispatch_token=request.payload["dispatch_token"],  # type: ignore[arg-type]
                    outcome=request.payload["outcome"],  # type: ignore[arg-type]
                    response_ref=request.payload["response_ref"],  # type: ignore[arg-type]
                    response_body=request.payload["response_body"],  # type: ignore[arg-type]
                    actual_tokens=request.payload["actual_tokens"],  # type: ignore[arg-type]
                    actual_cost_units=request.payload["actual_cost_units"],  # type: ignore[arg-type]
                    provider_receipt_ref=request.payload["provider_receipt_ref"],  # type: ignore[arg-type]
                    failure_code=request.payload["failure_code"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "reconcile_model_call":
                result = self._require_model_backend().reconcile_model_call(
                    call_id=request.payload["call_id"],  # type: ignore[arg-type]
                    actual_tokens=request.payload["actual_tokens"],  # type: ignore[arg-type]
                    actual_cost_units=request.payload["actual_cost_units"],  # type: ignore[arg-type]
                    provider_receipt_ref=request.payload["provider_receipt_ref"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
            elif request.command == "lookup_model_call":
                result = self._require_model_backend().lookup_model_call(
                    call_id=request.payload["call_id"],  # type: ignore[arg-type]
                    actor=actor,
                )
            elif request.command == "list_reserved_model_calls":
                raw_max = request.payload.get("maximum", 1)
                result = self._require_model_backend().list_reserved_model_calls(
                    actor=actor,
                    maximum=raw_max if type(raw_max) is int else 1,  # type: ignore[arg-type]
                )
            elif request.command == "ack_proposal":
                result = self._require_a1_backend().ack_proposal(
                    material_event_ref=request.payload["material_event_ref"],  # type: ignore[arg-type]
                    claim_token=request.payload["claim_token"],  # type: ignore[arg-type]
                    actor=actor,
                    idempotency_key=request.idempotency_key,
                    now=self._event_at(),
                )
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

    def _require_a1_backend(self) -> _A1ControlBackend:
        if self._a1_backend is None:
            raise ControlError("A1 control backend is unavailable")
        return self._a1_backend

    def _require_model_backend(self) -> _ModelControlBackend:
        if self._model_backend is None:
            raise ControlError("model control backend is unavailable")
        return self._model_backend

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


def _model_request_body(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ControlError("request_body must be non-empty UTF-8 text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ControlError("request_body must be non-empty UTF-8 text") from exc
    if len(encoded) > 1_048_576:
        raise ControlError("request_body exceeds the local byte limit")
    return value


def _positive_integer(name: str, value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ControlError(f"{name} must be a positive integer")
    return value


def _nonnegative_integer(name: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise ControlError(f"{name} must be a non-negative integer")
    return value


def _optional_nonnegative_integer(name: str, value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ControlError(f"{name} must be a non-negative integer or null")
    return value


def _sha256_text(name: str, value: object) -> str:
    normalized = _normalized_text(name, value, maximum=64)
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ControlError(f"{name} must be a lowercase sha256 digest")
    return normalized


def _json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_copy(item) for item in value]
    return value


__all__ = ["ControlError", "ControlRequest", "ControlResponse", "ControlRouter"]
