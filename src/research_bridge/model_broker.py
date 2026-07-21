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
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping, Protocol

from .ledger import JobLedger, LedgerError, ModelCallTransitionRecord


__all__ = [
    "KnownProviderFailure",
    "FixtureProviderAdapter",
    "ModelBrokerError",
    "ModelBinding",
    "ModelBudgetPolicy",
    "ModelCallBroker",
    "ModelCallHandle",
    "ModelCallSpec",
    "ModelCorrelationSnapshot",
    "ModelCouncilPlan",
    "ModelCouncilCandidate",
    "ModelCouncilEvaluation",
    "ModelCouncilScore",
    "ModelCouncilTournament",
    "ModelCouncilTournamentResult",
    "ModelErrorObservation",
    "RawModelProviderAdapter",
    "ModelProviderAdapter",
    "ProviderAccounting",
    "ProviderResponseParser",
    "ModelProviderRouting",
    "ModelRoleRegistry",
    "ModelRoute",
    "ModelRouteDecision",
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
_MAX_RAW_RESPONSE_BYTES = 16_777_216
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_FROZEN_MODEL_ROLES = frozenset(
    {
        "SCOUT_FAST",
        "RESEARCH_WORKER",
        "CRITIC_PRIMARY",
        "CRITIC_DEEP",
        "CHIEF_SCIENTIST",
        "ARBITER_RESERVE",
    }
)
_ROUTING_PROFILE_KEYS = frozenset(
    {
        "profile_id",
        "schema_version",
        "status",
        "routing_mode",
        "api_identifiers",
        "privacy",
        "council",
        "bindings",
        "roles",
        "invariants",
    }
)
_ROUTING_PRIVACY_KEYS = frozenset(
    {"allowed_input_classes", "forbidden_input_classes"}
)
_ROUTING_COUNCIL_KEYS = frozenset({"max_calls", "tiers"})
_ROUTING_BINDING_KEYS = frozenset(
    {
        "provider_slot",
        "family",
        "provenance_group",
        "candidate_api_identifier",
        "api_identifier_status",
        "effort_class",
        "fixture_eval_status",
        "fixture_eval_ref",
        "allowed_input_classes",
        "availability",
    }
)
_ROUTING_ROLE_KEYS = frozenset({"primary", "fallbacks", "unavailable_action"})
_ROUTING_INVARIANT_KEYS = frozenset(
    {
        "model_outputs_are_untrusted",
        "routing_is_deterministic",
        "caller_cannot_select_binding",
        "fallback_cannot_widen_privacy_or_authority",
        "every_routed_binding_has_fixture_eval",
        "same_family_efforts_share_provenance_group",
        "consensus_is_not_evidence",
        "cross_family_independence_is_not_claimed",
        "real_provider_calls",
        "credentials_or_endpoints_present",
    }
)
_TOURNAMENT_PROFILE_KEYS = frozenset(
    {
        "profile_id", "schema_version", "status", "max_candidates",
        "max_total_model_calls", "proposer_role", "evaluator_roles",
        "rubric", "invariants",
    }
)
_TOURNAMENT_RUBRIC_KEYS = frozenset(
    {"score_min", "score_max", "criteria", "verdicts"}
)
_TOURNAMENT_CRITERION_KEYS = frozenset({"name", "weight"})
_TOURNAMENT_INVARIANT_KEYS = frozenset(
    {
        "routing_plan_assigns_evaluators",
        "proposer_cannot_select_or_act_as_evaluator",
        "one_evaluator_call_scores_all_candidates",
        "missing_assigned_evaluation_prevents_ranking",
        "dissent_is_preserved",
        "consensus_is_not_evidence",
        "advisory_ranking_is_not_evidence",
        "model_outputs_are_untrusted",
        "independence_is_not_inferred_from_agreement",
        "council_cannot_admit_promote_issue_permit_or_mutate_canonical_state",
        "allowed_input_classes",
        "forbidden_input_classes",
    }
)
_TOURNAMENT_CRITERIA = (
    ("falsifiability", 35),
    ("evidence_quality", 30),
    ("novelty", 15),
    ("cost_risk_fit", 20),
)
_TOURNAMENT_VERDICTS = frozenset({"SUPPORT", "REJECT", "UNCERTAIN"})


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
class ModelBinding:
    name: str
    provider_slot: str
    family: str
    provenance_group: str
    candidate_api_identifier: str | None
    api_identifier_status: str
    effort_class: str
    fixture_eval_status: str
    fixture_eval_ref: str | None
    allowed_input_classes: tuple[str, ...]
    availability: str

    def __post_init__(self) -> None:
        _text("binding.name", self.name, maximum=256)
        _text("binding.provider_slot", self.provider_slot, maximum=128)
        _text("binding.family", self.family, maximum=128)
        _portable_ref("binding.provenance_group", self.provenance_group)
        if self.candidate_api_identifier is not None:
            candidate = _text(
                "binding.candidate_api_identifier",
                self.candidate_api_identifier,
                maximum=256,
            )
            if "://" in candidate:
                raise ModelBrokerError("candidate API identifier cannot be an endpoint")
        _text("binding.api_identifier_status", self.api_identifier_status, maximum=64)
        _text("binding.effort_class", self.effort_class, maximum=64)
        _text("binding.fixture_eval_status", self.fixture_eval_status, maximum=64)
        if self.fixture_eval_ref is not None:
            _portable_ref("binding.fixture_eval_ref", self.fixture_eval_ref)
        if self.allowed_input_classes != ("D0", "D1"):
            raise ModelBrokerError("provider binding privacy scope must remain D0/D1")
        _text("binding.availability", self.availability, maximum=64)


@dataclass(frozen=True, slots=True)
class ModelRouteDecision:
    role: str
    status: str
    binding: str | None
    provider_slot: str | None
    family: str | None
    provenance_group: str | None
    used_fallback: bool
    profile_sha256: str


@dataclass(frozen=True, slots=True)
class ModelCouncilPlan:
    tier: str
    status: str
    decisions: tuple[ModelRouteDecision, ...]
    call_count: int
    max_calls: int
    provenance_groups: tuple[str, ...]
    independence_status: str
    consensus_is_evidence: bool


@dataclass(frozen=True, slots=True)
class ModelCouncilCandidate:
    candidate_id: str
    proposal_ref: str
    proposer_role: str

    def __post_init__(self) -> None:
        _portable_ref("council candidate_id", self.candidate_id)
        _portable_ref("council proposal_ref", self.proposal_ref)
        _text("council proposer_role", self.proposer_role, maximum=128)


@dataclass(frozen=True, slots=True)
class ModelCouncilScore:
    candidate_id: str
    criterion_scores: tuple[tuple[str, int], ...]
    verdict: str

    def __post_init__(self) -> None:
        _portable_ref("council score candidate_id", self.candidate_id)
        if not isinstance(self.criterion_scores, tuple) or any(
            not isinstance(item, tuple) or len(item) != 2
            for item in self.criterion_scores
        ):
            raise ModelBrokerError("council criterion scores must be exact tuples")
        _text("council verdict", self.verdict, maximum=32)


@dataclass(frozen=True, slots=True)
class ModelCouncilEvaluation:
    evaluator_role: str
    model_binding: str
    response_ref: str
    scores: tuple[ModelCouncilScore, ...]

    def __post_init__(self) -> None:
        _text("council evaluator_role", self.evaluator_role, maximum=128)
        _text("council evaluator binding", self.model_binding, maximum=256)
        _portable_ref("council response_ref", self.response_ref)
        if not isinstance(self.scores, tuple) or any(
            not isinstance(item, ModelCouncilScore) for item in self.scores
        ):
            raise ModelBrokerError("council evaluation scores must be a tuple")


@dataclass(frozen=True, slots=True)
class ModelCouncilTournamentResult:
    status: str
    tier: str
    candidate_order: tuple[str, ...]
    weighted_scores: tuple[tuple[str, int], ...]
    evaluator_roles: tuple[str, ...]
    missing_evaluator_roles: tuple[str, ...]
    dissent_candidate_ids: tuple[str, ...]
    unanimous_candidate_ids: tuple[str, ...]
    planned_call_count: int
    evaluation_call_count: int
    max_total_model_calls: int
    independence_status: str
    consensus_is_evidence: bool
    ranking_is_evidence: bool
    grants_authority: bool
    profile_sha256: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelErrorObservation:
    case_id: str
    binding: str
    failed: bool

    def __post_init__(self) -> None:
        _text("observation.case_id", self.case_id, maximum=256)
        _text("observation.binding", self.binding, maximum=256)
        if type(self.failed) is not bool:
            raise ModelBrokerError("observation.failed must be boolean")


@dataclass(frozen=True, slots=True)
class ModelCorrelationSnapshot:
    left_provenance_group: str
    right_provenance_group: str
    sample_size: int
    left_errors: int
    right_errors: int
    joint_errors: int
    joint_error_rate_ppm: int
    uncertainty_low_ppm: int
    uncertainty_high_ppm: int
    independence_status: str
    profile_sha256: str


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
class ProviderAccounting:
    """Parsed accounting emitted only after raw response durability."""

    actual_tokens: int | None
    actual_cost_units: int | None
    provider_receipt_ref: str | None

    def __post_init__(self) -> None:
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


class RawModelProviderAdapter(Protocol):
    """Receive opaque bounded bytes without parsing provider content."""

    model_binding: str

    def invoke_raw(
        self,
        *,
        call_id: str,
        request_bytes: bytes,
        max_tokens: int,
    ) -> bytes: ...


class ProviderResponseParser(Protocol):
    """Parse bytes that the broker has already committed to immutable CAS."""

    model_binding: str

    def parse_response(
        self,
        *,
        raw_response: bytes,
        response_ref: str,
        max_tokens: int,
    ) -> ProviderAccounting: ...


class ResponseCommitter(Protocol):
    def commit_response(self, raw_response: bytes) -> str: ...


class FixtureProviderAdapter:
    """A strict zero-network adapter for pre-registered public test responses."""

    def __init__(
        self,
        binding: ModelBinding,
        responses_by_request_sha256: Mapping[str, ProviderResult],
    ) -> None:
        if not isinstance(binding, ModelBinding):
            raise ModelBrokerError("fixture adapter requires a ModelBinding")
        if (
            binding.fixture_eval_status != "PASS"
            or binding.availability != "FIXTURE_ONLY"
        ):
            raise ModelBrokerError("fixture adapter binding is not fixture-evaluated")
        responses: dict[str, ProviderResult] = {}
        for request_sha256, result in responses_by_request_sha256.items():
            digest = _sha256("fixture request_sha256", request_sha256)
            if not isinstance(result, ProviderResult):
                raise ModelBrokerError("fixture response must be ProviderResult")
            responses[digest] = result
        self.model_binding = binding.name
        self.provider_slot = binding.provider_slot
        self._responses = MappingProxyType(responses)

    def invoke(
        self,
        *,
        call_id: str,
        request_bytes: bytes,
        max_tokens: int,
    ) -> ProviderResult:
        normalized_call_id = _text("call_id", call_id, maximum=128)
        if not normalized_call_id.startswith("model-call:"):
            raise ModelBrokerError("fixture call_id is invalid")
        _sha256("call_id digest", normalized_call_id.removeprefix("model-call:"))
        if not isinstance(request_bytes, bytes) or not request_bytes:
            raise ModelBrokerError("fixture request must be non-empty bytes")
        _positive("max_tokens", max_tokens)
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        result = self._responses.get(request_sha256)
        if result is None:
            raise KnownProviderFailure(
                "FIXTURE_CASE_NOT_REGISTERED",
                actual_tokens=0,
                actual_cost_units=0,
                provider_receipt_ref=(
                    "fixture:sha256:"
                    + hashlib.sha256(
                        f"{self.model_binding}:{request_sha256}".encode("utf-8")
                    ).hexdigest()
                ),
            )
        if result.actual_tokens is not None and result.actual_tokens > max_tokens:
            raise KnownProviderFailure(
                "FIXTURE_TOKEN_LIMIT_EXCEEDED",
                actual_tokens=result.actual_tokens,
                actual_cost_units=result.actual_cost_units,
                provider_receipt_ref=result.provider_receipt_ref,
            )
        return result


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


class ModelProviderRouting:
    """Strict fixture-evaluated routing without transport or provider authority."""

    def __init__(
        self,
        profile_path: str | Path,
        *,
        expected_profile_sha256: str,
        role_registry: ModelRoleRegistry,
    ) -> None:
        if not isinstance(role_registry, ModelRoleRegistry):
            raise ModelBrokerError("routing requires ModelRoleRegistry")
        expected = _sha256(
            "expected routing profile sha256", expected_profile_sha256
        )
        try:
            raw = Path(profile_path).read_bytes()
        except OSError as exc:
            raise ModelBrokerError("provider routing profile is unavailable") from exc
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ModelBrokerError("provider routing profile digest mismatch")
        try:
            profile = json.loads(raw, object_pairs_hook=_strict_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ModelBrokerError) as exc:
            raise ModelBrokerError("provider routing profile is not strict JSON") from exc
        value = _exact(profile, _ROUTING_PROFILE_KEYS, "provider routing profile")
        profile_identity = (value["profile_id"], value["schema_version"])
        if (
            profile_identity
            not in {
                ("model-provider-routing-v1", "1.0.0"),
                ("model-provider-routing-v2", "2.0.0"),
            }
            or value["status"] != "fixture-evaluated"
            or value["routing_mode"]
            != "deterministic-role-to-evaluated-binding"
            or value["api_identifiers"]
            != "UNVERIFIED_UNTIL_REAL_PROVIDER_SHADOW"
        ):
            raise ModelBrokerError("provider routing profile identity mismatch")

        privacy = _exact(
            value["privacy"], _ROUTING_PRIVACY_KEYS, "provider routing privacy"
        )
        if privacy != {
            "allowed_input_classes": ["D0", "D1"],
            "forbidden_input_classes": ["D2", "D3", "sealed-holdout"],
        }:
            raise ModelBrokerError("provider routing privacy scope drifted")
        invariants = _exact(
            value["invariants"],
            _ROUTING_INVARIANT_KEYS,
            "provider routing invariants",
        )
        true_invariants = set(_ROUTING_INVARIANT_KEYS) - {
            "real_provider_calls",
            "credentials_or_endpoints_present",
        }
        if any(invariants[name] is not True for name in true_invariants) or any(
            invariants[name] is not False
            for name in {"real_provider_calls", "credentials_or_endpoints_present"}
        ):
            raise ModelBrokerError("provider routing invariants drifted")

        raw_bindings = value["bindings"]
        if not isinstance(raw_bindings, Mapping) or not raw_bindings:
            raise ModelBrokerError("provider routing bindings are empty")
        bindings: dict[str, ModelBinding] = {}
        family_groups: dict[str, str] = {}
        for raw_name, raw_definition in raw_bindings.items():
            name = _text("provider binding name", raw_name, maximum=256)
            definition = _exact(
                raw_definition,
                _ROUTING_BINDING_KEYS,
                f"provider binding.{name}",
            )
            allowed = definition["allowed_input_classes"]
            if allowed != ["D0", "D1"]:
                raise ModelBrokerError("provider binding privacy scope drifted")
            candidate = definition["candidate_api_identifier"]
            eval_ref = definition["fixture_eval_ref"]
            binding = ModelBinding(
                name=name,
                provider_slot=_text(
                    f"binding.{name}.provider_slot",
                    definition["provider_slot"],
                    maximum=128,
                ),
                family=_text(
                    f"binding.{name}.family", definition["family"], maximum=128
                ),
                provenance_group=_portable_ref(
                    f"binding.{name}.provenance_group",
                    definition["provenance_group"],
                ),
                candidate_api_identifier=(
                    None
                    if candidate is None
                    else _text(
                        f"binding.{name}.candidate_api_identifier",
                        candidate,
                        maximum=256,
                    )
                ),
                api_identifier_status=_text(
                    f"binding.{name}.api_identifier_status",
                    definition["api_identifier_status"],
                    maximum=64,
                ),
                effort_class=_text(
                    f"binding.{name}.effort_class",
                    definition["effort_class"],
                    maximum=64,
                ),
                fixture_eval_status=_text(
                    f"binding.{name}.fixture_eval_status",
                    definition["fixture_eval_status"],
                    maximum=64,
                ),
                fixture_eval_ref=(
                    None
                    if eval_ref is None
                    else _portable_ref(f"binding.{name}.fixture_eval_ref", eval_ref)
                ),
                allowed_input_classes=tuple(allowed),
                availability=_text(
                    f"binding.{name}.availability",
                    definition["availability"],
                    maximum=64,
                ),
            )
            if binding.availability == "FIXTURE_ONLY":
                if (
                    binding.fixture_eval_status != "PASS"
                    or binding.fixture_eval_ref is None
                    or binding.api_identifier_status != "UNVERIFIED"
                    or binding.candidate_api_identifier is None
                ):
                    raise ModelBrokerError(
                        "routable fixture binding lacks exact evaluation state"
                    )
            elif binding.availability == "DISABLED_UNEVALUATED":
                if (
                    binding.fixture_eval_status != "NOT_RUN"
                    or binding.fixture_eval_ref is not None
                    or binding.api_identifier_status != "UNSELECTED"
                    or binding.candidate_api_identifier is not None
                ):
                    raise ModelBrokerError("disabled reserve binding is not inert")
            else:
                raise ModelBrokerError("provider binding availability is unsupported")
            previous_group = family_groups.setdefault(
                binding.family, binding.provenance_group
            )
            if previous_group != binding.provenance_group:
                raise ModelBrokerError(
                    "same provider family must share one provenance group"
                )
            bindings[name] = binding

        raw_roles = value["roles"]
        if not isinstance(raw_roles, Mapping) or set(raw_roles) != _FROZEN_MODEL_ROLES:
            raise ModelBrokerError("provider routing roles differ from frozen roles")
        roles: dict[str, tuple[str | None, tuple[str, ...], str]] = {}
        binding_overrides: dict[str, str] = {}
        routed_bindings: set[str] = set()
        for role in sorted(_FROZEN_MODEL_ROLES):
            definition = _exact(
                raw_roles[role], _ROUTING_ROLE_KEYS, f"provider route.{role}"
            )
            primary = definition["primary"]
            if primary is not None:
                primary = _text(f"route.{role}.primary", primary, maximum=256)
            raw_fallbacks = definition["fallbacks"]
            if not isinstance(raw_fallbacks, list):
                raise ModelBrokerError("provider route fallbacks must be a list")
            fallbacks = tuple(
                _text(f"route.{role}.fallback", item, maximum=256)
                for item in raw_fallbacks
            )
            if len(set(fallbacks)) != len(fallbacks) or primary in fallbacks:
                raise ModelBrokerError("provider route contains duplicate bindings")
            action = _text(
                f"route.{role}.unavailable_action",
                definition["unavailable_action"],
                maximum=64,
            )
            if action not in {"PARKED", "WAIT_PROVIDER"}:
                raise ModelBrokerError("provider unavailable action is unsupported")
            candidates = (() if primary is None else (primary,)) + fallbacks
            if any(candidate not in bindings for candidate in candidates):
                raise ModelBrokerError("provider route references an unknown binding")
            if any(
                bindings[candidate].availability != "FIXTURE_ONLY"
                or bindings[candidate].fixture_eval_status != "PASS"
                for candidate in candidates
            ):
                raise ModelBrokerError("provider route references an unevaluated binding")
            if role == "ARBITER_RESERVE":
                if primary is not None or fallbacks:
                    raise ModelBrokerError("reserve arbiter must remain disabled")
                try:
                    role_registry.route(role, "D0")
                except ModelBrokerError:
                    pass
                else:
                    raise ModelBrokerError("reserve arbiter registry binding is active")
            else:
                if primary is None:
                    raise ModelBrokerError("active model role lacks a primary binding")
                registry_binding = role_registry.route(role, "D0").model_binding
                if registry_binding not in candidates:
                    raise ModelBrokerError(
                        "role registry binding is outside provider route candidates"
                    )
                if registry_binding != primary:
                    binding_overrides[role] = registry_binding
            routed_bindings.update(candidates)
            roles[role] = (primary, fallbacks, action)

        council = _exact(
            value["council"], _ROUTING_COUNCIL_KEYS, "provider council"
        )
        max_calls = _positive("provider council max_calls", council["max_calls"])
        raw_tiers = council["tiers"]
        expected_tiers = {
            "STANDARD": ("RESEARCH_WORKER", "CRITIC_PRIMARY"),
            "MATERIAL": (
                "RESEARCH_WORKER",
                "CRITIC_PRIMARY",
                "CRITIC_DEEP",
            ),
            "CRITICAL": (
                "RESEARCH_WORKER",
                "CRITIC_PRIMARY",
                "CRITIC_DEEP",
                "CHIEF_SCIENTIST",
            ),
        }
        if not isinstance(raw_tiers, Mapping) or set(raw_tiers) != set(
            expected_tiers
        ):
            raise ModelBrokerError("provider council tiers differ from frozen scope")
        tiers: dict[str, tuple[str, ...]] = {}
        for tier, expected_roles in expected_tiers.items():
            configured = raw_tiers[tier]
            if not isinstance(configured, list) or tuple(configured) != expected_roles:
                raise ModelBrokerError("provider council tier role order drifted")
            if len(configured) > max_calls:
                raise ModelBrokerError("provider council tier exceeds call cap")
            tiers[tier] = expected_roles
        if max_calls != 4:
            raise ModelBrokerError("provider council call cap drifted")
        if set(bindings) - routed_bindings != {"qwen-reserve-slot"}:
            raise ModelBrokerError("unexpected unrouted provider binding")

        self._profile_sha256 = actual
        self._bindings = MappingProxyType(bindings)
        self._roles = MappingProxyType(roles)
        self._binding_overrides = MappingProxyType(binding_overrides)
        self._tiers = MappingProxyType(tiers)
        self._max_calls = max_calls

    @property
    def profile_sha256(self) -> str:
        return self._profile_sha256

    def binding(self, name: str) -> ModelBinding:
        normalized = _text("provider binding", name, maximum=256)
        binding = self._bindings.get(normalized)
        if binding is None:
            raise ModelBrokerError("provider binding is not registered")
        return binding

    def route(
        self,
        role: str,
        classification: str,
        *,
        available_bindings: frozenset[str],
    ) -> ModelRouteDecision:
        name = _text("provider route role", role, maximum=128)
        if name not in self._roles:
            raise ModelBrokerError("provider route role is unknown")
        if classification not in {"D0", "D1"}:
            raise ModelBrokerError("provider routing privacy matrix denies input")
        available = self._available(available_bindings)
        primary, fallbacks, unavailable_action = self._roles[name]
        override = self._binding_overrides.get(name)
        candidates = (
            (override,)
            if override is not None
            else (() if primary is None else (primary,)) + fallbacks
        )
        for index, candidate in enumerate(candidates):
            if candidate not in available:
                continue
            binding = self._bindings[candidate]
            if classification not in binding.allowed_input_classes:
                raise ModelBrokerError("provider fallback would widen privacy")
            return ModelRouteDecision(
                role=name,
                status="ROUTED",
                binding=binding.name,
                provider_slot=binding.provider_slot,
                family=binding.family,
                provenance_group=binding.provenance_group,
                used_fallback=candidate != primary,
                profile_sha256=self._profile_sha256,
            )
        return ModelRouteDecision(
            role=name,
            status=unavailable_action,
            binding=None,
            provider_slot=None,
            family=None,
            provenance_group=None,
            used_fallback=False,
            profile_sha256=self._profile_sha256,
        )

    def plan_council(
        self,
        tier: str,
        classification: str,
        *,
        available_bindings: frozenset[str],
    ) -> ModelCouncilPlan:
        normalized = _text("provider council tier", tier, maximum=64)
        roles = self._tiers.get(normalized)
        if roles is None:
            raise ModelBrokerError("provider council tier is unknown")
        decisions = tuple(
            self.route(
                role,
                classification,
                available_bindings=available_bindings,
            )
            for role in roles
        )
        if len(decisions) > self._max_calls:
            raise ModelBrokerError("provider council call cap exceeded")
        statuses = {decision.status for decision in decisions}
        if statuses == {"ROUTED"}:
            status = "ROUTED"
        elif "WAIT_PROVIDER" in statuses:
            status = "WAIT_PROVIDER"
        else:
            status = "PARKED"
        groups = tuple(
            sorted(
                {
                    decision.provenance_group
                    for decision in decisions
                    if decision.provenance_group is not None
                }
            )
        )
        return ModelCouncilPlan(
            tier=normalized,
            status=status,
            decisions=decisions,
            call_count=sum(decision.status == "ROUTED" for decision in decisions),
            max_calls=self._max_calls,
            provenance_groups=groups,
            independence_status="INDEPENDENCE_NOT_ESTABLISHED",
            consensus_is_evidence=False,
        )

    def correlation_snapshot(
        self,
        left_binding: str,
        right_binding: str,
        observations: tuple[ModelErrorObservation, ...],
    ) -> ModelCorrelationSnapshot:
        left = self.binding(left_binding)
        right = self.binding(right_binding)
        if left.name == right.name:
            raise ModelBrokerError("correlation requires two distinct bindings")
        if left.availability != "FIXTURE_ONLY" or right.availability != "FIXTURE_ONLY":
            raise ModelBrokerError("correlation requires evaluated fixture bindings")
        if not isinstance(observations, tuple) or any(
            not isinstance(item, ModelErrorObservation) for item in observations
        ):
            raise ModelBrokerError("correlation observations must be a tuple")
        allowed = {left.name, right.name}
        by_case: dict[str, dict[str, bool]] = {}
        for observation in observations:
            if observation.binding not in allowed:
                raise ModelBrokerError("correlation observation binding is unrelated")
            case = by_case.setdefault(observation.case_id, {})
            if observation.binding in case:
                raise ModelBrokerError("duplicate correlation observation")
            case[observation.binding] = observation.failed
        paired = [case for case in by_case.values() if set(case) == allowed]
        sample_size = len(paired)
        left_errors = sum(case[left.name] for case in paired)
        right_errors = sum(case[right.name] for case in paired)
        joint_errors = sum(case[left.name] and case[right.name] for case in paired)
        rate = 0 if sample_size == 0 else round(joint_errors * 1_000_000 / sample_size)
        low, high = _wilson_ppm(joint_errors, sample_size)
        status = (
            "CORRELATED_SAME_PROVENANCE_GROUP"
            if left.provenance_group == right.provenance_group
            else "INDEPENDENCE_NOT_ESTABLISHED"
        )
        return ModelCorrelationSnapshot(
            left_provenance_group=left.provenance_group,
            right_provenance_group=right.provenance_group,
            sample_size=sample_size,
            left_errors=left_errors,
            right_errors=right_errors,
            joint_errors=joint_errors,
            joint_error_rate_ppm=rate,
            uncertainty_low_ppm=low,
            uncertainty_high_ppm=high,
            independence_status=status,
            profile_sha256=self._profile_sha256,
        )

    def _available(self, values: frozenset[str]) -> frozenset[str]:
        if not isinstance(values, frozenset) or any(
            not isinstance(value, str) for value in values
        ):
            raise ModelBrokerError("available bindings must be a frozenset of names")
        unknown = values - set(self._bindings)
        if unknown:
            raise ModelBrokerError("availability contains an unknown provider binding")
        if any(
            self._bindings[name].availability != "FIXTURE_ONLY" for name in values
        ):
            raise ModelBrokerError("disabled provider binding cannot become available")
        return values


class ModelCouncilTournament:
    """Deterministically aggregate policy-assigned critiques as advice only."""

    def __init__(
        self,
        profile_path: str | Path,
        *,
        expected_profile_sha256: str,
    ) -> None:
        expected = _sha256(
            "expected council tournament profile sha256",
            expected_profile_sha256,
        )
        try:
            raw = Path(profile_path).read_bytes()
        except OSError as exc:
            raise ModelBrokerError("council tournament profile is unavailable") from exc
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ModelBrokerError("council tournament profile digest mismatch")
        try:
            profile = json.loads(raw, object_pairs_hook=_strict_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ModelBrokerError) as exc:
            raise ModelBrokerError("council tournament profile is not strict JSON") from exc
        value = _exact(profile, _TOURNAMENT_PROFILE_KEYS, "council tournament profile")
        if (
            value["profile_id"] != "model-council-tournament-v1"
            or value["schema_version"] != "1.0.0"
            or value["status"] != "frozen-advisory-only"
            or value["max_candidates"] != 4
            or value["max_total_model_calls"] != 4
            or value["proposer_role"] != "RESEARCH_WORKER"
            or value["evaluator_roles"]
            != ["CRITIC_PRIMARY", "CRITIC_DEEP", "CHIEF_SCIENTIST"]
        ):
            raise ModelBrokerError("council tournament profile identity drifted")
        rubric = _exact(
            value["rubric"], _TOURNAMENT_RUBRIC_KEYS, "council tournament rubric"
        )
        criteria = rubric["criteria"]
        if not isinstance(criteria, list):
            raise ModelBrokerError("council tournament criteria must be a list")
        normalized_criteria = tuple(
            (
                _text(
                    "council tournament criterion name",
                    _exact(item, _TOURNAMENT_CRITERION_KEYS, "council criterion")["name"],
                    maximum=64,
                ),
                _positive(
                    "council tournament criterion weight",
                    _exact(item, _TOURNAMENT_CRITERION_KEYS, "council criterion")["weight"],
                ),
            )
            for item in criteria
        )
        if (
            rubric["score_min"] != 0
            or rubric["score_max"] != 100
            or normalized_criteria != _TOURNAMENT_CRITERIA
            or sum(weight for _, weight in normalized_criteria) != 100
            or rubric["verdicts"] != ["SUPPORT", "REJECT", "UNCERTAIN"]
        ):
            raise ModelBrokerError("council tournament rubric drifted")
        invariants = _exact(
            value["invariants"],
            _TOURNAMENT_INVARIANT_KEYS,
            "council tournament invariants",
        )
        if (
            invariants["allowed_input_classes"] != ["D0", "D1"]
            or invariants["forbidden_input_classes"]
            != ["D2", "D3", "sealed-holdout"]
            or any(
                invariants[name] is not True
                for name in _TOURNAMENT_INVARIANT_KEYS
                - {"allowed_input_classes", "forbidden_input_classes"}
            )
        ):
            raise ModelBrokerError("council tournament invariant drifted")
        self._profile_sha256 = actual
        self._max_candidates = 4
        self._max_calls = 4
        self._proposer_role = "RESEARCH_WORKER"
        self._evaluator_roles = (
            "CRITIC_PRIMARY",
            "CRITIC_DEEP",
            "CHIEF_SCIENTIST",
        )
        self._criteria = _TOURNAMENT_CRITERIA

    @property
    def profile_sha256(self) -> str:
        return self._profile_sha256

    def evaluate(
        self,
        plan: ModelCouncilPlan,
        candidates: tuple[ModelCouncilCandidate, ...],
        evaluations: tuple[ModelCouncilEvaluation, ...],
    ) -> ModelCouncilTournamentResult:
        if not isinstance(plan, ModelCouncilPlan):
            raise ModelBrokerError("council tournament requires ModelCouncilPlan")
        if (
            plan.max_calls != self._max_calls
            or plan.call_count > self._max_calls
            or plan.consensus_is_evidence
            or plan.independence_status != "INDEPENDENCE_NOT_ESTABLISHED"
        ):
            raise ModelBrokerError("council plan widens frozen tournament semantics")
        if not isinstance(candidates, tuple) or any(
            not isinstance(candidate, ModelCouncilCandidate) for candidate in candidates
        ):
            raise ModelBrokerError("council candidates must be a tuple")
        if not candidates or len(candidates) > self._max_candidates:
            raise ModelBrokerError("council candidate cap violated")
        candidate_ids = tuple(candidate.candidate_id for candidate in candidates)
        if len(set(candidate_ids)) != len(candidate_ids):
            raise ModelBrokerError("council candidates contain duplicate identity")
        if any(
            candidate.proposer_role != self._proposer_role for candidate in candidates
        ):
            raise ModelBrokerError("council candidate proposer role is not policy-assigned")
        if not isinstance(evaluations, tuple) or any(
            not isinstance(evaluation, ModelCouncilEvaluation)
            for evaluation in evaluations
        ):
            raise ModelBrokerError("council evaluations must be a tuple")
        if not plan.decisions or plan.decisions[0].role != self._proposer_role:
            raise ModelBrokerError("council plan proposer role drifted")
        evaluator_decisions = plan.decisions[1:]
        if any(
            decision.role not in self._evaluator_roles
            for decision in evaluator_decisions
        ):
            raise ModelBrokerError("council plan contains an unapproved evaluator")
        expected_roles = tuple(decision.role for decision in evaluator_decisions)
        if len(set(expected_roles)) != len(expected_roles):
            raise ModelBrokerError("council plan duplicates an evaluator role")

        if plan.status != "ROUTED":
            if evaluations:
                raise ModelBrokerError(
                    "unroutable council cannot accept evaluator output"
                )
            missing = tuple(
                decision.role
                for decision in evaluator_decisions
                if decision.status != "ROUTED"
            )
            return self._result(
                status=plan.status,
                plan=plan,
                candidate_order=(),
                weighted_scores=(),
                evaluator_roles=expected_roles,
                missing_evaluator_roles=missing,
                dissent_candidate_ids=(),
                unanimous_candidate_ids=(),
                evaluation_call_count=0,
                reason_codes=(
                    "MISSING_ASSIGNED_CRITIC",
                    "CONSENSUS_NOT_EVIDENCE",
                    "INDEPENDENCE_NOT_ESTABLISHED",
                ),
            )
        if any(
            decision.status != "ROUTED" or decision.binding is None
            for decision in plan.decisions
        ):
            raise ModelBrokerError("ROUTED council contains an unrouted decision")

        by_role: dict[str, ModelCouncilEvaluation] = {}
        for evaluation in evaluations:
            role = evaluation.evaluator_role
            if role == self._proposer_role:
                raise ModelBrokerError("council proposer cannot act as evaluator")
            if role not in expected_roles:
                raise ModelBrokerError("council evaluator was not assigned by policy")
            if role in by_role:
                raise ModelBrokerError("council evaluator output is duplicated")
            decision = next(item for item in evaluator_decisions if item.role == role)
            if evaluation.model_binding != decision.binding:
                raise ModelBrokerError("council evaluator binding differs from policy route")
            self._validated_scores(evaluation, frozenset(candidate_ids))
            by_role[role] = evaluation
        missing_roles = tuple(role for role in expected_roles if role not in by_role)
        if missing_roles:
            return self._result(
                status="INCOMPLETE",
                plan=plan,
                candidate_order=(),
                weighted_scores=(),
                evaluator_roles=expected_roles,
                missing_evaluator_roles=missing_roles,
                dissent_candidate_ids=(),
                unanimous_candidate_ids=(),
                evaluation_call_count=len(by_role),
                reason_codes=(
                    "MISSING_ASSIGNED_EVALUATION",
                    "RANKING_WITHHELD",
                    "CONSENSUS_NOT_EVIDENCE",
                ),
            )

        weighted_totals = {candidate_id: 0 for candidate_id in candidate_ids}
        verdicts = {candidate_id: set() for candidate_id in candidate_ids}
        for role in expected_roles:
            evaluation = by_role[role]
            score_by_candidate = {
                score.candidate_id: score for score in evaluation.scores
            }
            for candidate_id in candidate_ids:
                score = score_by_candidate[candidate_id]
                weighted_totals[candidate_id] += sum(
                    value * weight
                    for (name, value), (expected_name, weight) in zip(
                        score.criterion_scores, self._criteria, strict=True
                    )
                    if name == expected_name
                )
                verdicts[candidate_id].add(score.verdict)
        normalized_scores = {
            candidate_id: weighted_totals[candidate_id] // len(expected_roles)
            for candidate_id in candidate_ids
        }
        candidate_order = tuple(
            sorted(candidate_ids, key=lambda item: (-normalized_scores[item], item))
        )
        weighted_scores = tuple(
            (candidate_id, normalized_scores[candidate_id])
            for candidate_id in candidate_order
        )
        dissent = tuple(
            sorted(candidate_id for candidate_id, values in verdicts.items() if len(values) > 1)
        )
        unanimous = tuple(
            sorted(candidate_id for candidate_id, values in verdicts.items() if len(values) == 1)
        )
        reasons = ["ADVISORY_RANKING_NOT_EVIDENCE", "INDEPENDENCE_NOT_ESTABLISHED"]
        reasons.append("DISSENT_PRESERVED" if dissent else "UNANIMOUS_NOT_EVIDENCE")
        return self._result(
            status="COMPLETE_ADVISORY",
            plan=plan,
            candidate_order=candidate_order,
            weighted_scores=weighted_scores,
            evaluator_roles=expected_roles,
            missing_evaluator_roles=(),
            dissent_candidate_ids=dissent,
            unanimous_candidate_ids=unanimous,
            evaluation_call_count=len(by_role),
            reason_codes=tuple(reasons),
        )

    def _validated_scores(
        self,
        evaluation: ModelCouncilEvaluation,
        candidate_ids: frozenset[str],
    ) -> None:
        score_ids = tuple(score.candidate_id for score in evaluation.scores)
        if len(set(score_ids)) != len(score_ids) or frozenset(score_ids) != candidate_ids:
            raise ModelBrokerError("one evaluator call must score every candidate once")
        for score in evaluation.scores:
            if tuple(name for name, _ in score.criterion_scores) != tuple(
                name for name, _ in self._criteria
            ):
                raise ModelBrokerError("council evaluation rubric keys or order drifted")
            for _, value in score.criterion_scores:
                if type(value) is not int or not 0 <= value <= 100:
                    raise ModelBrokerError("council evaluation score is outside frozen bounds")
            if score.verdict not in _TOURNAMENT_VERDICTS:
                raise ModelBrokerError("council evaluation verdict is unsupported")

    def _result(
        self,
        *,
        status: str,
        plan: ModelCouncilPlan,
        candidate_order: tuple[str, ...],
        weighted_scores: tuple[tuple[str, int], ...],
        evaluator_roles: tuple[str, ...],
        missing_evaluator_roles: tuple[str, ...],
        dissent_candidate_ids: tuple[str, ...],
        unanimous_candidate_ids: tuple[str, ...],
        evaluation_call_count: int,
        reason_codes: tuple[str, ...],
    ) -> ModelCouncilTournamentResult:
        return ModelCouncilTournamentResult(
            status=status,
            tier=plan.tier,
            candidate_order=candidate_order,
            weighted_scores=weighted_scores,
            evaluator_roles=evaluator_roles,
            missing_evaluator_roles=missing_evaluator_roles,
            dissent_candidate_ids=dissent_candidate_ids,
            unanimous_candidate_ids=unanimous_candidate_ids,
            planned_call_count=plan.call_count,
            evaluation_call_count=evaluation_call_count,
            max_total_model_calls=self._max_calls,
            independence_status="INDEPENDENCE_NOT_ESTABLISHED",
            consensus_is_evidence=False,
            ranking_is_evidence=False,
            grants_authority=False,
            profile_sha256=self._profile_sha256,
            reason_codes=reason_codes,
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
        existing: ModelCallTransitionRecord | None = None
        try:
            existing = self._ledger.model_call_state(call_id)
        except LedgerError:
            try:
                self._append(
                    proposed,
                    idempotency_key=f"{spec.idempotency_key}:proposed",
                    event_at=timestamp,
                )
            except ModelBrokerError:
                # A concurrent identical prepare may have durably won after
                # our state read. Re-read and prove equivalence below.
                try:
                    existing = self._ledger.model_call_state(call_id)
                except LedgerError as exc:
                    raise ModelBrokerError(
                        "durable model-call preparation is unavailable"
                    ) from exc
        if existing is not None:
            self._assert_same_preparation(existing.snapshot, proposed)
            if existing.snapshot["state"] != "PROPOSED":
                return _handle(existing)
            proposed = dict(existing.snapshot)
        reserved = {**proposed, "previous_state": "PROPOSED", "state": "RESERVED", "reserved_at": timestamp}
        record = self._append(
            reserved,
            idempotency_key=f"{spec.idempotency_key}:reserved",
            event_at=timestamp,
        )
        return _handle(record)

    @staticmethod
    def _assert_same_preparation(
        current: Mapping[str, object], proposed: Mapping[str, object]
    ) -> None:
        immutable_fields = {
            "call_id", "request_sha256", "registry_sha256", "binding_revision",
            "role", "model_binding", "classification", "budget_policy_ref",
            "budget_scope_ref", "max_active_calls", "max_tokens",
            "max_cost_units", "max_reserved_tokens", "max_reserved_cost_units",
            "expires_at", "auto_retry",
        }
        if any(current[field] != proposed[field] for field in immutable_fields):
            raise ModelBrokerError(
                "model call idempotency key was reused with different preparation"
            )

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

    def begin_external(
        self,
        call_id: str,
        *,
        request_bytes: bytes,
        event_at: str,
    ) -> ModelCallHandle:
        """Durably mark one reserved IPC dispatch SENT before worker egress.

        A repeated begin is rejected instead of authorizing a second external
        attempt.  Restart recovery converts a stranded SENT state to UNKNOWN.
        """

        timestamp = _timestamp("event_at", event_at)
        current = self._state(call_id)
        if current["state"] != "RESERVED":
            raise ModelBrokerError("only a fresh RESERVED model call may begin")
        if (
            not isinstance(request_bytes, bytes)
            or hashlib.sha256(request_bytes).hexdigest()
            != current["request_sha256"]
        ):
            raise ModelBrokerError("model request bytes differ from the reservation")
        if current["registry_sha256"] != self._registry.registry_sha256:
            raise ModelBrokerError("model registry drifted after reservation")
        route = self._registry.route(current["role"], current["classification"])
        if (
            route.model_binding != current["model_binding"]
            or route.binding_revision != current["binding_revision"]
        ):
            raise ModelBrokerError("model route drifted after reservation")
        sent = self._transition(current, state="SENT", event_at=timestamp)
        return _handle(
            self._append(
                sent,
                idempotency_key=f"{call_id}:external-sent",
                event_at=timestamp,
            )
        )

    def complete_external(
        self,
        call_id: str,
        *,
        outcome: str,
        response_ref: str | None,
        actual_tokens: int | None,
        actual_cost_units: int | None,
        provider_receipt_ref: str | None,
        failure_code: str | None,
        event_at: str,
    ) -> ModelCallHandle:
        """Record untrusted worker completion metadata in the one ledger.

        Raw response bytes never cross this boundary.  The response reference
        remains non-authoritative evidence until later physical-worker proof.
        """

        timestamp = _timestamp("event_at", event_at)
        state = _text("outcome", outcome, maximum=64)
        if state not in {"SUCCEEDED", "FAILED_KNOWN", "UNKNOWN"}:
            raise ModelBrokerError("external model-call outcome is unsupported")
        response = (
            None
            if response_ref is None
            else _portable_ref("response_ref", response_ref)
        )
        tokens = _optional_nonnegative("actual_tokens", actual_tokens)
        cost = _optional_nonnegative("actual_cost_units", actual_cost_units)
        receipt = _optional_ref("provider_receipt_ref", provider_receipt_ref)
        failure = (
            None
            if failure_code is None
            else _text("failure_code", failure_code, maximum=512)
        )
        if state == "SUCCEEDED":
            if response is None or failure is not None:
                raise ModelBrokerError("successful external completion shape is invalid")
        elif state == "FAILED_KNOWN":
            if response is not None or failure is None:
                raise ModelBrokerError("known external failure shape is invalid")
        elif any(value is not None for value in (tokens, cost, receipt, failure)):
            raise ModelBrokerError("UNKNOWN external completion cannot assert accounting")

        current = self._state(call_id)
        durable_origin = (
            current["previous_state"]
            if current["state"] == "RECONCILED"
            else current["state"]
        )
        if durable_origin in {"SUCCEEDED", "FAILED_KNOWN", "UNKNOWN"}:
            expected_failure = (
                "AMBIGUOUS_PROVIDER_OUTCOME" if state == "UNKNOWN" else failure
            )
            if (
                durable_origin != state
                or current["response_ref"] != response
                or current["actual_tokens"] != tokens
                or current["actual_cost_units"] != cost
                or current["provider_receipt_ref"] != receipt
                or current["failure_code"] != expected_failure
            ):
                raise ModelBrokerError(
                    "external completion replay differs from durable state"
                )
            return ModelCallHandle(
                call_id=current["call_id"],  # type: ignore[arg-type]
                state=current["state"],  # type: ignore[arg-type]
                event_sequence=self._ledger.model_call_state(call_id).event.sequence,
                registry_sha256=current["registry_sha256"],  # type: ignore[arg-type]
                model_binding=current["model_binding"],  # type: ignore[arg-type]
            )
        if current["state"] != "SENT":
            raise ModelBrokerError("only SENT may accept external completion")
        if state == "UNKNOWN":
            return self._mark_unknown(
                current,
                event_at=timestamp,
                response_ref=response,
            )
        terminal = self._terminal(
            current,
            state=state,
            event_at=timestamp,
            response_ref=response,
            actual_tokens=tokens,
            actual_cost_units=cost,
            provider_receipt_ref=receipt,
            failure_code=failure,
        )
        return _handle(
            self._append(
                terminal,
                idempotency_key=f"{call_id}:external-{state.lower()}",
                event_at=timestamp,
            )
        )

    def execute_raw(
        self,
        call_id: str,
        *,
        request_bytes: bytes,
        adapter: RawModelProviderAdapter,
        response_committer: ResponseCommitter,
        response_parser: ProviderResponseParser,
        event_at: str,
    ) -> ModelCallHandle:
        """Execute connected-style egress with commit-before-parse ordering.

        Once ``SENT`` is durable, every uncertain transport, commit, or parse
        outcome becomes ``UNKNOWN``. The method never retries and never
        releases the reservation. A response-bearing known provider failure is
        parsed only after its raw bytes have an exact immutable CAS reference.
        """

        timestamp = _timestamp("event_at", event_at)
        current = self._state(call_id)
        if current["state"] != "RESERVED":
            raise ModelBrokerError("only a RESERVED model call may be sent")
        if (
            not isinstance(request_bytes, bytes)
            or hashlib.sha256(request_bytes).hexdigest()
            != current["request_sha256"]
        ):
            raise ModelBrokerError("model request bytes differ from the reservation")
        if current["registry_sha256"] != self._registry.registry_sha256:
            raise ModelBrokerError("model registry drifted after reservation")
        route = self._registry.route(current["role"], current["classification"])
        if (
            route.model_binding != current["model_binding"]
            or route.binding_revision != current["binding_revision"]
        ):
            raise ModelBrokerError("model route drifted after reservation")
        if getattr(adapter, "model_binding", None) != current["model_binding"]:
            raise ModelBrokerError(
                "raw provider adapter binding differs from the reservation"
            )
        if getattr(response_parser, "model_binding", None) != current["model_binding"]:
            raise ModelBrokerError(
                "provider response parser binding differs from the reservation"
            )

        sent = self._transition(current, state="SENT", event_at=timestamp)
        sent_record = self._append(
            sent, idempotency_key=f"{call_id}:sent", event_at=timestamp
        )
        try:
            raw_response = adapter.invoke_raw(
                call_id=call_id,
                request_bytes=request_bytes,
                max_tokens=current["max_tokens"],
            )
            if not isinstance(raw_response, bytes) or not raw_response:
                raise ModelBrokerError("raw provider adapter returned invalid bytes")
            if len(raw_response) > _MAX_RAW_RESPONSE_BYTES:
                raise ModelBrokerError("raw provider response exceeds the local bound")
        except Exception:
            return self._mark_unknown(sent_record.snapshot, event_at=timestamp)

        try:
            response_ref = response_committer.commit_response(raw_response)
            expected_ref = "cas:sha256:" + hashlib.sha256(raw_response).hexdigest()
            if response_ref != expected_ref:
                raise ModelBrokerError(
                    "response committer returned a mismatched CAS ref"
                )
        except (LedgerError, ModelBrokerError, OSError, RuntimeError):
            return self._mark_unknown(sent_record.snapshot, event_at=timestamp)

        try:
            accounting = response_parser.parse_response(
                raw_response=raw_response,
                response_ref=response_ref,
                max_tokens=current["max_tokens"],
            )
            if not isinstance(accounting, ProviderAccounting):
                raise ModelBrokerError("provider parser returned invalid accounting")
        except KnownProviderFailure:
            # The frozen ledger shape cannot attach a response reference to
            # FAILED_KNOWN. Conservatively retain the committed evidence as
            # UNKNOWN for later provider reconciliation instead of creating an
            # unreferenced CAS object or weakening that durable invariant.
            return self._mark_unknown(
                sent_record.snapshot,
                event_at=timestamp,
                response_ref=response_ref,
            )
        except Exception:
            return self._mark_unknown(
                sent_record.snapshot,
                event_at=timestamp,
                response_ref=response_ref,
            )

        succeeded = self._terminal(
            sent_record.snapshot,
            state="SUCCEEDED",
            event_at=timestamp,
            response_ref=response_ref,
            actual_tokens=accounting.actual_tokens,
            actual_cost_units=accounting.actual_cost_units,
            provider_receipt_ref=accounting.provider_receipt_ref,
        )
        try:
            return _handle(
                self._append(
                    succeeded,
                    idempotency_key=f"{call_id}:succeeded",
                    event_at=timestamp,
                )
            )
        except (LedgerError, ModelBrokerError, OSError, RuntimeError):
            return self._mark_unknown(
                sent_record.snapshot,
                event_at=timestamp,
                response_ref=response_ref,
            )

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

    def snapshot(self, call_id: str) -> Mapping[str, object]:
        """Return an immutable copy of one replay-validated durable state."""

        return MappingProxyType(dict(self._state(call_id)))

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
        self,
        current: Mapping[str, object],
        *,
        event_at: str,
        response_ref: str | None = None,
    ) -> ModelCallHandle:
        unknown = self._terminal(
            current,
            state="UNKNOWN",
            event_at=event_at,
            response_ref=response_ref,
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


def _wilson_ppm(errors: int, sample_size: int) -> tuple[int, int]:
    if sample_size == 0:
        return 0, 1_000_000
    proportion = errors / sample_size
    z = 1.959963984540054
    denominator = 1 + z * z / sample_size
    center = (proportion + z * z / (2 * sample_size)) / denominator
    radius = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / sample_size
            + z * z / (4 * sample_size * sample_size)
        )
        / denominator
    )
    low = max(0, min(1_000_000, round((center - radius) * 1_000_000)))
    high = max(0, min(1_000_000, round((center + radius) * 1_000_000)))
    return low, high


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
