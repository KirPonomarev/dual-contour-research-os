"""Provider-neutral model roles and conservative durable call orchestration.

The module contains no HTTP client, credential reader, scheduler, queue or
scientific authority. Provider adapters remain untrusted egress mechanisms.
Every call is bound to the frozen A1 role profile, D0/D1 privacy, a durable
budget reservation and the existing Bridge global event order.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping, Protocol

from .ledger import JobLedger, LedgerError, ModelCallTransitionRecord


__all__ = [
    "KnownProviderFailure",
    "ModelBrokerError",
    "ModelBudgetPolicy",
    "ModelCallBroker",
    "ModelCallHandle",
    "ModelCallSpec",
    "ModelProviderAdapter",
    "ModelRoleRegistry",
    "ModelRoute",
    "ProviderResult",
    "ResponseCommitter",
]


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_BUDGET_POLICY_RE = re.compile(r"^budget-policy:sha256:[a-f0-9]{64}$")
_BUDGET_SCOPE_RE = re.compile(r"^budget-scope:sha256:[a-f0-9]{64}$")
_PORTABLE_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s\\]{1,511}$")
_CALL_STATES = (
    "PROPOSED", "RESERVED", "SENT", "SUCCEEDED", "FAILED_KNOWN", "UNKNOWN", "RECONCILED"
)
_ROLE_PROFILE_KEYS = frozenset(
    {"profile_id", "schema_version", "status", "routing_mode", "roles", "invariants", "call_state_machine"}
)
_ROLE_KEYS = frozenset(
    {"purpose", "initial_binding", "risk_class", "required_independent_review"}
)
_INVARIANT_KEYS = frozenset(
    {
        "model_outputs_are_untrusted", "models_cannot_self_assign_roles",
        "models_cannot_admit_candidates", "models_cannot_reserve_or_release_budget",
        "models_cannot_issue_permits", "models_cannot_mutate_canonical_state",
        "consensus_is_not_evidence", "same_family_effort_levels_are_correlated",
        "bindings_are_replaceable_after_shadow_evaluation", "allowed_input_classes",
        "forbidden_input_classes",
    }
)
_MAX_REQUEST_BYTES = 1_048_576
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class ModelBrokerError(RuntimeError):
    """A registry, privacy, budget, durability or provider boundary failed closed."""


class KnownProviderFailure(RuntimeError):
    """A provider explicitly reported failure with optional exact usage."""

    def __init__(
        self,
        code: str,
        *,
        actual_tokens: int | None = None,
        actual_cost_units: int | None = None,
        provider_receipt_ref: str | None = None,
    ) -> None:
        super().__init__(_text("known provider failure code", code, maximum=256))
        self.code = code
        self.actual_tokens = _optional_nonnegative("actual_tokens", actual_tokens)
        self.actual_cost_units = _optional_nonnegative(
            "actual_cost_units", actual_cost_units
        )
        self.provider_receipt_ref = _optional_ref(
            "provider_receipt_ref", provider_receipt_ref
        )


@dataclass(frozen=True, slots=True)
class ModelRoute:
    role: str
    model_binding: str
    risk_class: str
    required_independent_review: bool
    binding_revision: str
    registry_sha256: str


@dataclass(frozen=True, slots=True)
class ModelBudgetPolicy:
    policy_ref: str
    scope_ref: str
    max_active_calls: int
    max_reserved_tokens: int
    max_reserved_cost_units: int

    def __post_init__(self) -> None:
        _pattern("policy_ref", self.policy_ref, _BUDGET_POLICY_RE)
        _pattern("scope_ref", self.scope_ref, _BUDGET_SCOPE_RE)
        _positive("max_active_calls", self.max_active_calls)
        _positive("max_reserved_tokens", self.max_reserved_tokens)
        _positive("max_reserved_cost_units", self.max_reserved_cost_units)


@dataclass(frozen=True, slots=True)
class ModelCallSpec:
    role: str
    role_assignment_ref: str
    classification: str
    request_bytes: bytes
    max_tokens: int
    max_cost_units: int
    expires_at: str
    idempotency_key: str

    def __post_init__(self) -> None:
        _text("role", self.role, maximum=128)
        _portable_ref("role_assignment_ref", self.role_assignment_ref)
        if self.classification not in {"D0", "D1"}:
            raise ModelBrokerError("model calls accept D0 or D1 only")
        if not isinstance(self.request_bytes, bytes) or not self.request_bytes:
            raise ModelBrokerError("request_bytes must be non-empty bytes")
        if len(self.request_bytes) > _MAX_REQUEST_BYTES:
            raise ModelBrokerError("request_bytes exceeds the local bound")
        _positive("max_tokens", self.max_tokens)
        _positive("max_cost_units", self.max_cost_units)
        _timestamp("expires_at", self.expires_at)
        _text("idempotency_key", self.idempotency_key, maximum=256)


@dataclass(frozen=True, slots=True)
class ProviderResult:
    raw_response: bytes
    actual_tokens: int | None
    actual_cost_units: int | None
    provider_receipt_ref: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.raw_response, bytes) or not self.raw_response:
            raise ModelBrokerError("provider raw_response must be non-empty bytes")
        _optional_nonnegative("actual_tokens", self.actual_tokens)
        _optional_nonnegative("actual_cost_units", self.actual_cost_units)
        _optional_ref("provider_receipt_ref", self.provider_receipt_ref)


@dataclass(frozen=True, slots=True)
class ModelCallHandle:
    call_id: str
    state: str
    event_sequence: int
    registry_sha256: str
    model_binding: str


class ModelProviderAdapter(Protocol):
    model_binding: str

    def invoke(
        self,
        *,
        call_id: str,
        request_bytes: bytes,
        max_tokens: int,
    ) -> ProviderResult: ...


class ResponseCommitter(Protocol):
    def commit_response(self, raw_response: bytes) -> str: ...


class ModelRoleRegistry:
    """Exact frozen profile plus a versioned, replaceable binding overlay."""

    def __init__(
        self,
        profile_path: str | Path,
        *,
        expected_profile_sha256: str,
        binding_revision: str,
        binding_overrides: Mapping[str, str | None] | None = None,
    ) -> None:
        expected = _sha256("expected_profile_sha256", expected_profile_sha256)
        revision = _text("binding_revision", binding_revision, maximum=128)
        path = Path(profile_path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ModelBrokerError("model role profile is unavailable") from exc
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ModelBrokerError("model role profile digest mismatch")
        try:
            profile = json.loads(raw, object_pairs_hook=_strict_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ModelBrokerError) as exc:
            raise ModelBrokerError("model role profile is not strict JSON") from exc
        value = _exact(profile, _ROLE_PROFILE_KEYS, "model role profile")
        if (
            value["profile_id"] != "model-role-registry-v1"
            or value["schema_version"] != "1.0.0"
            or value["status"] != "frozen"
            or value["routing_mode"] != "provider-neutral-role-binding"
            or value["call_state_machine"] != list(_CALL_STATES)
        ):
            raise ModelBrokerError("model role profile identity or FSM mismatch")
        invariants = _exact(value["invariants"], _INVARIANT_KEYS, "model role invariants")
        boolean_invariants = set(_INVARIANT_KEYS) - {
            "allowed_input_classes", "forbidden_input_classes"
        }
        if any(invariants[name] is not True for name in boolean_invariants):
            raise ModelBrokerError("model role authority invariants must remain true")
        if invariants["allowed_input_classes"] != ["D0", "D1"] or invariants[
            "forbidden_input_classes"
        ] != ["D2", "D3", "sealed-holdout"]:
            raise ModelBrokerError("model role privacy matrix drifted")
        roles = value["roles"]
        if not isinstance(roles, Mapping) or not roles:
            raise ModelBrokerError("model role registry is empty")
        normalized: dict[str, dict[str, object]] = {}
        for role, definition in roles.items():
            role_name = _text("model role", role, maximum=128)
            entry = _exact(definition, _ROLE_KEYS, f"role.{role_name}")
            _text(f"role.{role_name}.purpose", entry["purpose"], maximum=512)
            _text(f"role.{role_name}.risk_class", entry["risk_class"], maximum=128)
            if entry["initial_binding"] is not None:
                _text(
                    f"role.{role_name}.initial_binding",
                    entry["initial_binding"],
                    maximum=256,
                )
            if type(entry["required_independent_review"]) is not bool:
                raise ModelBrokerError("required_independent_review must be boolean")
            normalized[role_name] = entry
        overrides = dict(binding_overrides or {})
        if set(overrides) - set(normalized):
            raise ModelBrokerError("binding overlay contains an unknown role")
        if normalized.get("ARBITER_RESERVE", {}).get("initial_binding") is None and overrides.get(
            "ARBITER_RESERVE"
        ) is not None:
            raise ModelBrokerError("reserved arbiter cannot activate before evaluation")
        bindings: dict[str, str | None] = {}
        for role, entry in normalized.items():
            binding = overrides.get(role, entry["initial_binding"])
            if binding is not None:
                binding = _text(f"binding.{role}", binding, maximum=256)
            bindings[role] = binding
        material = {
            "profile_sha256": actual,
            "binding_revision": revision,
            "bindings": bindings,
            "roles": normalized,
            "privacy": {"allowed": ["D0", "D1"], "forbidden": ["D2", "D3", "sealed-holdout"]},
            "authority": "UNTRUSTED_OUTPUT_ONLY",
        }
        self._profile_sha256 = actual
        self._binding_revision = revision
        self._roles = MappingProxyType(normalized)
        self._bindings = MappingProxyType(bindings)
        self._registry_sha256 = _canonical_sha256(material)

    @property
    def profile_sha256(self) -> str:
        return self._profile_sha256

    @property
    def binding_revision(self) -> str:
        return self._binding_revision

    @property
    def registry_sha256(self) -> str:
        return self._registry_sha256

    def route(self, role: str, classification: str) -> ModelRoute:
        name = _text("role", role, maximum=128)
        if classification not in {"D0", "D1"}:
            raise ModelBrokerError("model role privacy matrix denies this classification")
        definition = self._roles.get(name)
        if definition is None:
            raise ModelBrokerError("model role is not registered")
        binding = self._bindings[name]
        if binding is None:
            raise ModelBrokerError("model role is disabled")
        return ModelRoute(
            role=name,
            model_binding=binding,
            risk_class=definition["risk_class"],  # type: ignore[arg-type]
            required_independent_review=definition["required_independent_review"],  # type: ignore[arg-type]
            binding_revision=self._binding_revision,
            registry_sha256=self._registry_sha256,
        )


class ModelCallBroker:
    """Orchestrate one bounded model call with conservative ambiguity semantics."""

    def __init__(
        self,
        *,
        registry: ModelRoleRegistry,
        ledger: JobLedger,
        budget_policy: ModelBudgetPolicy,
    ) -> None:
        if not isinstance(registry, ModelRoleRegistry):
            raise ModelBrokerError("registry must be ModelRoleRegistry")
        if not isinstance(ledger, JobLedger):
            raise ModelBrokerError("ledger must be JobLedger")
        if not isinstance(budget_policy, ModelBudgetPolicy):
            raise ModelBrokerError("budget_policy must be ModelBudgetPolicy")
        self._registry = registry
        self._ledger = ledger
        self._budget = budget_policy

    def prepare(self, spec: ModelCallSpec, *, event_at: str) -> ModelCallHandle:
        if not isinstance(spec, ModelCallSpec):
            raise ModelBrokerError("spec must be ModelCallSpec")
        timestamp = _timestamp("event_at", event_at)
        route = self._registry.route(spec.role, spec.classification)
        if spec.max_tokens > self._budget.max_reserved_tokens or spec.max_cost_units > self._budget.max_reserved_cost_units:
            raise ModelBrokerError("model call request exceeds its budget scope")
        request_sha256 = hashlib.sha256(spec.request_bytes).hexdigest()
        call_id = "model-call:" + _canonical_sha256(
            {
                "binding_revision": route.binding_revision,
                "budget_scope_ref": self._budget.scope_ref,
                "idempotency_key": spec.idempotency_key,
                "registry_sha256": route.registry_sha256,
                "request_sha256": request_sha256,
                "role": route.role,
                "role_assignment_ref": spec.role_assignment_ref,
            }
        )
        proposed = self._initial_snapshot(
            call_id=call_id,
            route=route,
            spec=spec,
            request_sha256=request_sha256,
            event_at=timestamp,
        )
        self._append(
            proposed,
            idempotency_key=f"{spec.idempotency_key}:proposed",
            event_at=timestamp,
        )
        reserved = {**proposed, "previous_state": "PROPOSED", "state": "RESERVED", "reserved_at": timestamp}
        record = self._append(
            reserved,
            idempotency_key=f"{spec.idempotency_key}:reserved",
            event_at=timestamp,
        )
        return _handle(record)

    def execute(
        self,
        call_id: str,
        *,
        request_bytes: bytes,
        adapter: ModelProviderAdapter,
        response_committer: ResponseCommitter,
        event_at: str,
    ) -> ModelCallHandle:
        timestamp = _timestamp("event_at", event_at)
        current = self._state(call_id)
        if current["state"] != "RESERVED":
            raise ModelBrokerError("only a RESERVED model call may be sent")
        if not isinstance(request_bytes, bytes) or hashlib.sha256(request_bytes).hexdigest() != current["request_sha256"]:
            raise ModelBrokerError("model request bytes differ from the reservation")
        if current["registry_sha256"] != self._registry.registry_sha256:
            raise ModelBrokerError("model registry drifted after reservation")
        route = self._registry.route(current["role"], current["classification"])
        if route.model_binding != current["model_binding"] or route.binding_revision != current["binding_revision"]:
            raise ModelBrokerError("model route drifted after reservation")
        if getattr(adapter, "model_binding", None) != current["model_binding"]:
            raise ModelBrokerError("provider adapter binding differs from the reservation")

        sent = self._transition(current, state="SENT", event_at=timestamp)
        sent_record = self._append(
            sent, idempotency_key=f"{call_id}:sent", event_at=timestamp
        )
        try:
            result = adapter.invoke(
                call_id=call_id,
                request_bytes=request_bytes,
                max_tokens=current["max_tokens"],
            )
            if not isinstance(result, ProviderResult):
                raise ModelBrokerError("provider adapter returned an invalid result")
        except KnownProviderFailure as exc:
            failed = self._terminal(
                sent_record.snapshot,
                state="FAILED_KNOWN",
                event_at=timestamp,
                actual_tokens=exc.actual_tokens,
                actual_cost_units=exc.actual_cost_units,
                provider_receipt_ref=exc.provider_receipt_ref,
                failure_code=exc.code,
            )
            return _handle(
                self._append(
                    failed,
                    idempotency_key=f"{call_id}:failed-known",
                    event_at=timestamp,
                )
            )
        except Exception:
            return self._mark_unknown(sent_record.snapshot, event_at=timestamp)

        try:
            response_ref = response_committer.commit_response(result.raw_response)
            expected_ref = "cas:sha256:" + hashlib.sha256(result.raw_response).hexdigest()
            if response_ref != expected_ref:
                raise ModelBrokerError("response committer returned a mismatched CAS ref")
            succeeded = self._terminal(
                sent_record.snapshot,
                state="SUCCEEDED",
                event_at=timestamp,
                response_ref=response_ref,
                actual_tokens=result.actual_tokens,
                actual_cost_units=result.actual_cost_units,
                provider_receipt_ref=result.provider_receipt_ref,
            )
            return _handle(
                self._append(
                    succeeded,
                    idempotency_key=f"{call_id}:succeeded",
                    event_at=timestamp,
                )
            )
        except (LedgerError, ModelBrokerError, OSError, RuntimeError):
            return self._mark_unknown(sent_record.snapshot, event_at=timestamp)

    def recover_sent(self, call_id: str, *, event_at: str) -> ModelCallHandle:
        current = self._state(call_id)
        if current["state"] != "SENT":
            raise ModelBrokerError("only SENT may be conservatively recovered as UNKNOWN")
        return self._mark_unknown(current, event_at=_timestamp("event_at", event_at))

    def reconcile(
        self,
        call_id: str,
        *,
        actual_tokens: int,
        actual_cost_units: int,
        provider_receipt_ref: str,
        event_at: str,
        idempotency_key: str,
    ) -> ModelCallHandle:
        timestamp = _timestamp("event_at", event_at)
        current = self._state(call_id)
        if current["state"] == "RECONCILED":
            if (
                current["actual_tokens"] != _nonnegative("actual_tokens", actual_tokens)
                or current["actual_cost_units"]
                != _nonnegative("actual_cost_units", actual_cost_units)
                or current["provider_receipt_ref"]
                != _portable_ref("provider_receipt_ref", provider_receipt_ref)
                or current["reconciled_at"] != timestamp
            ):
                raise ModelBrokerError("reconciliation replay differs from durable state")
            return _handle(
                self._append(
                    current,
                    idempotency_key=_text(
                        "idempotency_key", idempotency_key, maximum=256
                    ),
                    event_at=timestamp,
                )
            )
        if current["state"] not in {"SUCCEEDED", "FAILED_KNOWN", "UNKNOWN"}:
            raise ModelBrokerError("model call is not ready for reconciliation")
        reconciled = {
            **current,
            "previous_state": current["state"],
            "state": "RECONCILED",
            "actual_tokens": _nonnegative("actual_tokens", actual_tokens),
            "actual_cost_units": _nonnegative("actual_cost_units", actual_cost_units),
            "provider_receipt_ref": _portable_ref(
                "provider_receipt_ref", provider_receipt_ref
            ),
            "ambiguous_usage": False,
            "budget_released": True,
            "reconciled_at": timestamp,
        }
        return _handle(
            self._append(
                reconciled,
                idempotency_key=_text(
                    "idempotency_key", idempotency_key, maximum=256
                ),
                event_at=timestamp,
            )
        )

    def state(self, call_id: str) -> ModelCallHandle:
        return _handle(self._ledger.model_call_state(call_id))

    def _initial_snapshot(
        self,
        *,
        call_id: str,
        route: ModelRoute,
        spec: ModelCallSpec,
        request_sha256: str,
        event_at: str,
    ) -> dict[str, object]:
        return {
            "call_id": call_id,
            "previous_state": None,
            "state": "PROPOSED",
            "request_sha256": request_sha256,
            "registry_sha256": route.registry_sha256,
            "binding_revision": route.binding_revision,
            "role": route.role,
            "model_binding": route.model_binding,
            "classification": spec.classification,
            "budget_policy_ref": self._budget.policy_ref,
            "budget_scope_ref": self._budget.scope_ref,
            "max_active_calls": self._budget.max_active_calls,
            "max_tokens": spec.max_tokens,
            "max_cost_units": spec.max_cost_units,
            "max_reserved_tokens": self._budget.max_reserved_tokens,
            "max_reserved_cost_units": self._budget.max_reserved_cost_units,
            "expires_at": spec.expires_at,
            "proposed_at": event_at,
            "reserved_at": None,
            "sent_at": None,
            "terminal_at": None,
            "reconciled_at": None,
            "response_ref": None,
            "actual_tokens": None,
            "actual_cost_units": None,
            "provider_receipt_ref": None,
            "failure_code": None,
            "ambiguous_usage": False,
            "budget_released": False,
            "auto_retry": False,
        }

    @staticmethod
    def _transition(
        current: Mapping[str, object], *, state: str, event_at: str
    ) -> dict[str, object]:
        return {
            **dict(current),
            "previous_state": current["state"],
            "state": state,
            "sent_at": event_at,
        }

    @staticmethod
    def _terminal(
        current: Mapping[str, object],
        *,
        state: str,
        event_at: str,
        response_ref: str | None = None,
        actual_tokens: int | None = None,
        actual_cost_units: int | None = None,
        provider_receipt_ref: str | None = None,
        failure_code: str | None = None,
    ) -> dict[str, object]:
        ambiguous = actual_tokens is None or actual_cost_units is None
        return {
            **dict(current),
            "previous_state": current["state"],
            "state": state,
            "terminal_at": event_at,
            "response_ref": response_ref,
            "actual_tokens": actual_tokens,
            "actual_cost_units": actual_cost_units,
            "provider_receipt_ref": provider_receipt_ref,
            "failure_code": failure_code,
            "ambiguous_usage": ambiguous,
            "budget_released": False,
        }

    def _mark_unknown(
        self, current: Mapping[str, object], *, event_at: str
    ) -> ModelCallHandle:
        unknown = self._terminal(
            current,
            state="UNKNOWN",
            event_at=event_at,
            failure_code="AMBIGUOUS_PROVIDER_OUTCOME",
        )
        return _handle(
            self._append(
                unknown,
                idempotency_key=f"{current['call_id']}:unknown",
                event_at=event_at,
            )
        )

    def _state(self, call_id: str) -> Mapping[str, object]:
        try:
            return self._ledger.model_call_state(call_id).snapshot
        except LedgerError as exc:
            raise ModelBrokerError("model call state is unavailable") from exc

    def _append(
        self,
        snapshot: Mapping[str, object],
        *,
        idempotency_key: str,
        event_at: str,
    ) -> ModelCallTransitionRecord:
        try:
            return self._ledger.append_model_call_transition(
                snapshot=snapshot,
                idempotency_key=idempotency_key,
                event_at=event_at,
            )
        except LedgerError as exc:
            raise ModelBrokerError("durable model-call transition failed") from exc


def _handle(record: ModelCallTransitionRecord) -> ModelCallHandle:
    return ModelCallHandle(
        call_id=record.snapshot["call_id"],  # type: ignore[arg-type]
        state=record.snapshot["state"],  # type: ignore[arg-type]
        event_sequence=record.event.sequence,
        registry_sha256=record.snapshot["registry_sha256"],  # type: ignore[arg-type]
        model_binding=record.snapshot["model_binding"],  # type: ignore[arg-type]
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ModelBrokerError("duplicate JSON key")
        result[key] = value
    return result


def _exact(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ModelBrokerError(f"{label} shape mismatch")
    return dict(value)


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ModelBrokerError("registry material is not canonical JSON data") from exc
    return hashlib.sha256(encoded).hexdigest()


def _text(name: str, value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ModelBrokerError(f"{name} must be normalized non-empty text")
    return value


def _pattern(name: str, value: object, pattern: re.Pattern[str]) -> str:
    normalized = _text(name, value, maximum=512)
    if pattern.fullmatch(normalized) is None:
        raise ModelBrokerError(f"{name} has an invalid format")
    return normalized


def _sha256(name: str, value: object) -> str:
    return _pattern(name, value, _SHA256_RE)


def _portable_ref(name: str, value: object) -> str:
    normalized = _pattern(name, value, _PORTABLE_REF_RE)
    if normalized.lower().startswith(("file:", "host:")):
        raise ModelBrokerError(f"{name} must be a portable non-file reference")
    return normalized


def _optional_ref(name: str, value: object) -> str | None:
    return None if value is None else _portable_ref(name, value)


def _positive(name: str, value: object) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_SAFE_INTEGER:
        raise ModelBrokerError(f"{name} must be a positive safe integer")
    return value


def _nonnegative(name: str, value: object) -> int:
    if type(value) is not int or value < 0 or value > _MAX_SAFE_INTEGER:
        raise ModelBrokerError(f"{name} must be a non-negative safe integer")
    return value


def _optional_nonnegative(name: str, value: object) -> int | None:
    return None if value is None else _nonnegative(name, value)


def _timestamp(name: str, value: object) -> str:
    normalized = _text(name, value, maximum=64)
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelBrokerError(f"{name} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ModelBrokerError(f"{name} must include an offset")
    return normalized
