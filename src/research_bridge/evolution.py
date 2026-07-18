"""Pure bounded evolution planning over non-authoritative operational memory."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping, Sequence

from .ledger import FeedbackReplayReport, KnowledgeFabricReport


_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s\\]{1,511}$")
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_MAX_AGENDA_ITEMS = 256
_MAX_PORTFOLIO_SLOTS = 32
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_SHA_REF_RE = re.compile(r"^agenda-item:sha256:[a-f0-9]{64}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_REPLICATION_DIMENSIONS = ("data", "code", "environment", "temporal", "model")


class EvolutionError(RuntimeError):
    """A bounded evolution input or invariant failed closed."""


@dataclass(frozen=True, slots=True)
class AgendaProposal:
    debt_ref: str
    root_event_ref: str
    outcome_ref: str
    next_event_ref: str
    diversity_key: str
    value_units: int
    cost_units: int
    risk_units: int
    created_sequence: int
    safe_to_run: bool

    def __post_init__(self) -> None:
        for name in ("debt_ref", "root_event_ref", "outcome_ref", "next_event_ref"):
            _reference(getattr(self, name), name)
        _token(self.diversity_key, "diversity_key")
        _nonnegative(self.value_units, "value_units")
        _positive(self.cost_units, "cost_units")
        _nonnegative(self.risk_units, "risk_units")
        _nonnegative(self.created_sequence, "created_sequence")
        if type(self.safe_to_run) is not bool:
            raise EvolutionError("safe_to_run must be boolean")


@dataclass(frozen=True, slots=True)
class AgendaItem:
    item_id: str
    debt_ref: str
    root_event_ref: str
    outcome_ref: str
    next_event_ref: str
    diversity_key: str
    value_units: int
    cost_units: int
    risk_units: int
    created_sequence: int
    remaining_energy: int
    shadow_taint: str
    safe_to_run: bool
    provenance_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.item_id, str) or _SHA_REF_RE.fullmatch(self.item_id) is None:
            raise EvolutionError("agenda item identity is invalid")
        for name in ("debt_ref", "root_event_ref", "outcome_ref", "next_event_ref"):
            _reference(getattr(self, name), name)
        _token(self.diversity_key, "diversity_key")
        _nonnegative(self.value_units, "value_units")
        _positive(self.cost_units, "cost_units")
        _nonnegative(self.risk_units, "risk_units")
        _nonnegative(self.created_sequence, "created_sequence")
        _nonnegative(self.remaining_energy, "remaining_energy")
        if self.shadow_taint not in {"NONE", "SHADOW_UNAPPLIED"}:
            raise EvolutionError("agenda item shadow_taint is invalid")
        if type(self.safe_to_run) is not bool:
            raise EvolutionError("agenda item safe_to_run must be boolean")
        _references(self.provenance_refs, "agenda item provenance_refs")
        identity_material = {
            key: value
            for key, value in _agenda_item_material(self).items()
            if key != "item_id"
        }
        if self.item_id != "agenda-item:sha256:" + _sha(identity_material):
            raise EvolutionError("agenda item identity does not match its payload")


@dataclass(frozen=True, slots=True)
class AgendaSnapshot:
    agenda_version: str
    knowledge_fabric_sha256: str
    items: tuple[AgendaItem, ...]
    unassessed_debt_refs: tuple[str, ...]
    agenda_sha256: str
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class PortfolioPolicy:
    policy_id: str
    max_slots: int
    max_total_cost_units: int
    max_total_risk_units: int
    max_per_diversity_key: int
    value_weight: int
    cost_weight: int
    risk_weight: int
    diversity_bonus: int
    starvation_after_sequences: int
    starvation_bonus: int

    def __post_init__(self) -> None:
        _reference(self.policy_id, "policy_id")
        if not 1 <= _positive(self.max_slots, "max_slots") <= _MAX_PORTFOLIO_SLOTS:
            raise EvolutionError("max_slots exceeds the frozen bound")
        _positive(self.max_total_cost_units, "max_total_cost_units")
        _nonnegative(self.max_total_risk_units, "max_total_risk_units")
        if not 1 <= _positive(self.max_per_diversity_key, "max_per_diversity_key") <= self.max_slots:
            raise EvolutionError("max_per_diversity_key is outside slot bounds")
        for name in (
            "value_weight", "cost_weight", "risk_weight", "diversity_bonus",
            "starvation_after_sequences", "starvation_bonus",
        ):
            _nonnegative(getattr(self, name), name)

    @property
    def sha256(self) -> str:
        return _sha(_policy_material(self))


@dataclass(frozen=True, slots=True)
class PortfolioEntry:
    item_id: str
    outcome_ref: str
    score: int
    status: str
    reason_code: str
    selected_rank: int | None
    next_trigger: Mapping[str, object] | None


@dataclass(frozen=True, slots=True)
class PortfolioSnapshot:
    portfolio_version: str
    agenda_sha256: str
    policy_sha256: str
    current_sequence: int
    entries: tuple[PortfolioEntry, ...]
    selected_item_ids: tuple[str, ...]
    used_cost_units: int
    used_risk_units: int
    portfolio_sha256: str
    side_effects: bool = False
    grants_authority: bool = False


class ReplicationPolicy:
    """Digest-bound S26 metadata and evaluator-exposure policy."""

    def __init__(
        self,
        profile_path: str | Path,
        *,
        expected_profile_sha256: str,
        exposure_profile_path: str | Path,
        expected_exposure_sha256: str,
    ) -> None:
        profile = _load_exact_json(profile_path, expected_profile_sha256, "replication profile")
        expected_keys = {
            "profile_id", "schema_version", "status", "allowed_classifications",
            "forbidden_classifications", "dimensions", "dimension_statuses",
            "overall_statuses", "limits", "evaluator_exposure_profile_sha256",
            "declassification", "invariants",
        }
        if set(profile) != expected_keys:
            raise EvolutionError("replication profile keys drifted")
        if (
            profile["profile_id"] != "evidence-replication-matrix-v1"
            or profile["schema_version"] != "1.0.0"
            or profile["status"] != "frozen-control-plane-metadata-only"
            or profile["allowed_classifications"] != ["D0_PUBLIC"]
            or profile["forbidden_classifications"]
            != ["D1_INTERNAL_SANITIZED", "D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"]
            or tuple(profile["dimensions"]) != _REPLICATION_DIMENSIONS
            or profile["dimension_statuses"] != [
                "CORRELATED_SAME_GROUP", "DISTINCT_DECLARED_CORRELATED_SOURCE",
                "DISTINCT_FOR_FROZEN_SCOPE",
            ]
            or profile["overall_statuses"] != [
                "CORRELATED", "INDEPENDENCE_NOT_ESTABLISHED",
                "MULTIDIMENSIONAL_PASS_FOR_FROZEN_SCOPE",
            ]
        ):
            raise EvolutionError("replication profile identity or privacy drifted")
        limits = profile["limits"]
        if limits != {
            "max_evidence_items": 64, "max_replication_pairs": 32,
            "max_islands": 8, "max_metadata_labels": 16,
        }:
            raise EvolutionError("replication limits drifted")
        if profile["evaluator_exposure_profile_sha256"] != expected_exposure_sha256:
            raise EvolutionError("replication exposure binding drifted")
        declassification = profile["declassification"]
        if (
            not isinstance(declassification, Mapping)
            or declassification.get("mode") != "dry-run-only"
            or declassification.get("true_holdout_queries") != 0
            or any(declassification.get(name) != 0 for name in ("network_calls", "bytes_exported", "canonical_writes"))
        ):
            raise EvolutionError("declassification boundary drifted")
        invariants = profile["invariants"]
        if not isinstance(invariants, Mapping) or set(invariants) != {
            "sidecars_contain_refs_hashes_groups_and_labels_only", "raw_evidence_payloads_are_forbidden",
            "dimension_groups_must_be_bound_to_sidecar_evidence", "distinct_groups_require_distinct_source_groups",
            "correlated_sources_are_not_independent", "dimension_independence_is_scoped_not_absolute",
            "linear_replication_level_is_forbidden", "research_islands_have_disjoint_namespaces_and_trial_ownership",
            "evaluator_exposure_is_lineage_family_day_bound", "true_holdout_autonomous_queries_are_zero",
            "declassification_is_no-write-no-export-no-authority", "domain_replication_receipts_remain_domain_writer_owned",
        } or any(value is not True for value in invariants.values()):
            raise EvolutionError("replication invariants drifted")
        exposure = _load_exact_json(
            exposure_profile_path, expected_exposure_sha256, "evaluator exposure profile"
        )
        if (
            exposure.get("profile_id") != "evaluator-exposure-v1"
            or exposure.get("budgets") != {
                "per_candidate_max_queries": 3,
                "per_trial_family_max_queries": 12,
                "per_day_max_queries": 50,
                "true_holdout_queries_autonomous_a1": 0,
            }
            or exposure.get("feedback_classes") != {
                "binary-pass-fail": 1, "coarse-reason-class": 2,
                "metric-vector": 5, "row-level-diagnostic": 100,
            }
            or exposure.get("on_exhaustion") != "PARK"
        ):
            raise EvolutionError("evaluator exposure profile drifted")
        self.profile_sha256 = expected_profile_sha256
        self.exposure_profile_sha256 = expected_exposure_sha256
        self.max_evidence_items = 64
        self.max_replication_pairs = 32
        self.max_islands = 8
        self.max_metadata_labels = 16
        self.feedback_weights = MappingProxyType(dict(exposure["feedback_classes"]))


@dataclass(frozen=True, slots=True)
class EvidenceDescriptor:
    evidence_ref: str
    classification: str
    content_sha256: str
    source_group: str
    dimension_groups: tuple[tuple[str, str], ...]
    synthetic: bool
    shadow_taint: str

    def __post_init__(self) -> None:
        _reference(self.evidence_ref, "evidence_ref")
        _digest(self.content_sha256, "content_sha256")
        _reference(self.source_group, "source_group")
        if self.classification != "D0_PUBLIC":
            raise EvolutionError("evidence sidecar accepts D0_PUBLIC only")
        if type(self.synthetic) is not bool:
            raise EvolutionError("evidence synthetic flag must be boolean")
        if self.shadow_taint not in {"NONE", "SHADOW_UNAPPLIED"}:
            raise EvolutionError("evidence shadow taint is invalid")
        if not isinstance(self.dimension_groups, tuple) or tuple(
            name for name, _ in self.dimension_groups
        ) != _REPLICATION_DIMENSIONS:
            raise EvolutionError("evidence dimension groups must be exact and ordered")
        for _, group in self.dimension_groups:
            _reference(group, "dimension_group")


@dataclass(frozen=True, slots=True)
class EvidenceSidecar:
    version: str
    descriptors: tuple[EvidenceDescriptor, ...]
    sidecar_sha256: str
    raw_payloads_present: bool = False
    side_effects: bool = False
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class ReplicationDimensionClaim:
    dimension: str
    parent_group: str
    child_group: str
    verification_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.dimension not in _REPLICATION_DIMENSIONS:
            raise EvolutionError("replication dimension is unknown")
        _reference(self.parent_group, "parent_group")
        _reference(self.child_group, "child_group")
        _references(self.verification_refs, "verification_refs")


@dataclass(frozen=True, slots=True)
class ReplicationPairClaim:
    parent_trial_ref: str
    child_trial_ref: str
    original_outcome_ref: str
    replication_outcome_ref: str
    dimensions: tuple[ReplicationDimensionClaim, ...]

    def __post_init__(self) -> None:
        for name in ("parent_trial_ref", "child_trial_ref", "original_outcome_ref", "replication_outcome_ref"):
            _reference(getattr(self, name), name)
        if self.parent_trial_ref == self.child_trial_ref:
            raise EvolutionError("replication trials must differ")
        if not isinstance(self.dimensions, tuple) or tuple(item.dimension for item in self.dimensions) != _REPLICATION_DIMENSIONS:
            raise EvolutionError("replication claim requires five ordered dimensions")


@dataclass(frozen=True, slots=True)
class ReplicationDimensionResult:
    dimension: str
    parent_group: str
    child_group: str
    verification_refs: tuple[str, ...]
    status: str


@dataclass(frozen=True, slots=True)
class ReplicationPairResult:
    parent_trial_ref: str
    child_trial_ref: str
    original_outcome_ref: str
    replication_outcome_ref: str
    dimensions: tuple[ReplicationDimensionResult, ...]
    overall_status: str
    pair_sha256: str


@dataclass(frozen=True, slots=True)
class ReplicationMatrixSnapshot:
    version: str
    evidence_sidecar_sha256: str
    pairs: tuple[ReplicationPairResult, ...]
    matrix_sha256: str
    absolute_independence_claimed: bool = False
    linear_replication_level: str | None = None
    side_effects: bool = False
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class EvaluatorExposureRecord:
    evaluator_ref: str
    candidate_lineage: str
    trial_family_ref: str
    day_bucket: str
    feedback_class: str
    query_count: int
    true_holdout: bool

    def __post_init__(self) -> None:
        for name in ("evaluator_ref", "candidate_lineage", "trial_family_ref"):
            _reference(getattr(self, name), name)
        if not isinstance(self.day_bucket, str) or _DAY_RE.fullmatch(self.day_bucket) is None:
            raise EvolutionError("exposure day bucket is invalid")
        _token(self.feedback_class, "feedback_class")
        _positive(self.query_count, "query_count")
        if type(self.true_holdout) is not bool:
            raise EvolutionError("true_holdout must be boolean")


@dataclass(frozen=True, slots=True)
class ResearchIslandSpec:
    island_id: str
    workspace_namespace_ref: str
    model_context_ref: str
    classification: str
    trial_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    exposures: tuple[EvaluatorExposureRecord, ...]
    network_enabled: bool = False
    canonical_write_enabled: bool = False

    def __post_init__(self) -> None:
        for name in ("island_id", "workspace_namespace_ref", "model_context_ref"):
            _reference(getattr(self, name), name)
        _references(self.trial_refs, "island trial_refs")
        _references(self.evidence_refs, "island evidence_refs")
        if self.classification != "D0_PUBLIC":
            raise EvolutionError("research islands accept D0_PUBLIC only")
        if not isinstance(self.exposures, tuple) or any(not isinstance(item, EvaluatorExposureRecord) for item in self.exposures):
            raise EvolutionError("island exposures must be typed tuples")
        if self.network_enabled or self.canonical_write_enabled:
            raise EvolutionError("research island cannot enable network or canonical writes")


@dataclass(frozen=True, slots=True)
class ResearchIslandSnapshot:
    version: str
    evidence_sidecar_sha256: str
    islands: tuple[ResearchIslandSpec, ...]
    status: str
    reason_codes: tuple[str, ...]
    weighted_exposure_units: int
    snapshot_sha256: str
    side_effects: bool = False
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class DeclassificationCandidate:
    candidate_ref: str
    source_island_id: str
    classification: str
    public_manifest_sha256: str
    evidence_refs: tuple[str, ...]
    replication_matrix_ref: str
    metadata_labels: tuple[str, ...]

    def __post_init__(self) -> None:
        _reference(self.candidate_ref, "declassification candidate_ref")
        _reference(self.source_island_id, "declassification source_island_id")
        _digest(self.public_manifest_sha256, "public_manifest_sha256")
        _references(self.evidence_refs, "declassification evidence_refs")
        _reference(self.replication_matrix_ref, "replication_matrix_ref")
        if self.classification not in {"D0_PUBLIC", "D1_INTERNAL_SANITIZED", "D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"}:
            raise EvolutionError("declassification classification is invalid")
        if not isinstance(self.metadata_labels, tuple) or any(_token(item, "metadata_label") != item for item in self.metadata_labels):
            raise EvolutionError("declassification metadata labels are invalid")
        if len(set(self.metadata_labels)) != len(self.metadata_labels):
            raise EvolutionError("declassification metadata labels are duplicated")


@dataclass(frozen=True, slots=True)
class DeclassificationDryRunResult:
    status: str
    candidate_ref: str
    reason_codes: tuple[str, ...]
    forbidden_bytes_or_metadata_detected: bool
    bytes_exported: int
    network_calls: int
    canonical_writes: int
    grants_authority: bool
    result_sha256: str


class MemoryEvaluationPolicy:
    """Digest-bound S27 shadow measurement and capacity policy."""

    def __init__(self, profile_path: str | Path, *, expected_profile_sha256: str) -> None:
        profile = _load_exact_json(
            profile_path, expected_profile_sha256, "memory evaluation profile"
        )
        if set(profile) != {
            "profile_id", "schema_version", "status", "allowed_classifications",
            "measurement_statuses", "paired_metric", "uncertainty", "false_learn",
            "calibration", "capacity", "replay", "invariants",
        }:
            raise EvolutionError("memory evaluation profile keys drifted")
        if (
            profile["profile_id"] != "memory-uplift-replay-capacity-v1"
            or profile["schema_version"] != "1.0.0"
            or profile["status"] != "frozen-shadow-evaluation-only"
            or profile["allowed_classifications"] != ["D0_PUBLIC"]
            or profile["measurement_statuses"] != [
                "MEMORY_UPLIFT_MEASURED_SCOPED", "NOT_ESTABLISHED", "PARKED_CAPACITY"
            ]
            or profile["paired_metric"] != {
                "outcomes": ["SUCCESS", "FAILURE"],
                "uplift_unit": "parts-per-million-of-paired-success-delta",
                "information_value_unit": "bounded-integer-units",
                "research_debt_unit": "bounded-integer-units",
            }
        ):
            raise EvolutionError("memory evaluation profile identity drifted")
        uncertainty = profile["uncertainty"]
        false_learn = profile["false_learn"]
        calibration = profile["calibration"]
        capacity = profile["capacity"]
        replay = profile["replay"]
        if uncertainty != {
            "method": "paired-hoeffding-conservative-integer-bound",
            "confidence_floor_ppm": 950000,
            "radius_numerator_ppm": 1358102,
            "minimum_sample_pairs": 16,
            "zero_observation_interval_ppm": [-1000000, 1000000],
        }:
            raise EvolutionError("memory evaluation uncertainty drifted")
        if false_learn != {
            "upper_bound_method": "observed-rate-plus-paired-hoeffding-radius",
            "zero_observation_upper_bound_ppm": 1000000,
            "required_for_positive_claim": 0,
        }:
            raise EvolutionError("memory evaluation false-learn policy drifted")
        if calibration != {
            "collection_only": True,
            "confidence_bin_width_ppm": 100000,
            "minimum_observations_for_scoped_summary": 100,
            "calibrated_claimed": False,
        }:
            raise EvolutionError("memory evaluation calibration policy drifted")
        if capacity != {
            "max_memory_twin_pairs": 256,
            "max_calibration_observations": 512,
            "max_information_value_units_per_observation": 1000000,
            "max_research_debt_units_per_observation": 1000000,
            "overload_status": "PARKED_CAPACITY",
            "backpressure_reason_code": "MEMORY_EVALUATION_CAPACITY_EXHAUSTED",
            "infrastructure_scale_claimed": False,
        }:
            raise EvolutionError("memory evaluation capacity drifted")
        if replay != {
            "requires_two_equal_full_feedback_replays": True,
            "requires_rebuilt_equals_stored": True,
            "requires_memory_fabrics_bound_to_replay": True,
            "side_effects": False,
        }:
            raise EvolutionError("memory evaluation replay policy drifted")
        invariants = profile["invariants"]
        if not isinstance(invariants, Mapping) or set(invariants) != {
            "same_case_fixture_protocol_and_base_for_each_twin",
            "memory_off_and_memory_on_observations_are_both_required",
            "underpowered_or_uncertain_results_are_not_established",
            "positive_claim_requires_strictly_positive_lower_bound",
            "positive_claim_requires_zero_observed_false_learn_and_nonincreasing_debt",
            "calibration_collection_never_claims_calibrated",
            "full_replay_is_read_only_and_digest_bound",
            "capacity_is_frozen_and_overload_parks",
            "scientific_truth_claimed", "grants_authority",
        }:
            raise EvolutionError("memory evaluation invariants drifted")
        required_true = set(invariants) - {"scientific_truth_claimed", "grants_authority"}
        if any(invariants[name] is not True for name in required_true) or any(
            invariants[name] is not False for name in ("scientific_truth_claimed", "grants_authority")
        ):
            raise EvolutionError("memory evaluation invariants widened")
        self.profile_sha256 = expected_profile_sha256
        self.minimum_sample_pairs = 16
        self.uncertainty_radius_numerator_ppm = 1_358_102
        self.max_memory_twin_pairs = 256
        self.max_calibration_observations = 512
        self.max_information_value_units = 1_000_000
        self.max_research_debt_units = 1_000_000
        self.calibration_bin_width_ppm = 100_000
        self.minimum_calibration_observations = 100


@dataclass(frozen=True, slots=True)
class MemoryTwinPair:
    pair_id: str
    case_ref: str
    fixture_sha256: str
    protocol_sha256: str
    base_sha256: str
    memory_off_success: bool
    memory_on_success: bool
    memory_off_false_learn: bool
    memory_on_false_learn: bool
    memory_off_information_value_units: int
    memory_on_information_value_units: int
    memory_off_research_debt_units: int
    memory_on_research_debt_units: int

    def __post_init__(self) -> None:
        _reference(self.pair_id, "memory twin pair_id")
        _reference(self.case_ref, "memory twin case_ref")
        for name in ("fixture_sha256", "protocol_sha256", "base_sha256"):
            _digest(getattr(self, name), name)
        for name in (
            "memory_off_success", "memory_on_success",
            "memory_off_false_learn", "memory_on_false_learn",
        ):
            if type(getattr(self, name)) is not bool:
                raise EvolutionError(f"{name} must be boolean")
        for name in (
            "memory_off_information_value_units", "memory_on_information_value_units",
            "memory_off_research_debt_units", "memory_on_research_debt_units",
        ):
            _nonnegative(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class CalibrationObservation:
    observation_ref: str
    confidence_ppm: int
    correct: bool
    memory_enabled: bool

    def __post_init__(self) -> None:
        _reference(self.observation_ref, "calibration observation_ref")
        value = _nonnegative(self.confidence_ppm, "confidence_ppm")
        if value > 1_000_000:
            raise EvolutionError("confidence_ppm exceeds one million")
        if type(self.correct) is not bool or type(self.memory_enabled) is not bool:
            raise EvolutionError("calibration flags must be boolean")


@dataclass(frozen=True, slots=True)
class CalibrationBinSnapshot:
    lower_ppm: int
    upper_ppm: int
    observation_count: int
    mean_confidence_ppm: int | None
    observed_accuracy_ppm: int | None


@dataclass(frozen=True, slots=True)
class MemoryUpliftSnapshot:
    version: str
    policy_sha256: str
    full_replay_sha256: str
    memory_off_fabric_sha256: str
    memory_on_fabric_sha256: str
    status: str
    reason_codes: tuple[str, ...]
    sample_pairs: int
    uplift_ppm: int
    uncertainty_low_ppm: int
    uncertainty_high_ppm: int
    memory_on_false_learn_rate_ppm: int
    false_learn_upper_bound_ppm: int
    information_value_delta_units: int
    research_debt_delta_units: int
    calibration_observations: int
    calibration_status: str
    calibration_brier_ppm: int | None
    calibration_bins: tuple[CalibrationBinSnapshot, ...]
    capacity_envelope: Mapping[str, object]
    snapshot_sha256: str
    learned_claimed: bool = False
    calibrated_claimed: bool = False
    claims_scientific_truth: bool = False
    side_effects: bool = False
    grants_authority: bool = False


class EvolutionGenomePolicy:
    """Digest-bound S29 proposal-only genome policy."""

    def __init__(self, profile_path: str | Path, *, expected_profile_sha256: str) -> None:
        profile = _load_exact_json(profile_path, expected_profile_sha256, "genome profile")
        if set(profile) != {
            "profile_id", "schema_version", "status", "allowed_classifications",
            "allowed_mutation_kinds", "forbidden_mutation_kinds",
            "required_deny_invariants", "limits", "proposal_states", "invariants",
        }:
            raise EvolutionError("genome profile keys drifted")
        allowed = (
            "OBSERVABILITY_ADDITION", "PARAMETER_TIGHTENING", "REPLAY_HARDENING",
            "TEST_ADDITION", "VALIDATOR_HARDENING",
        )
        forbidden = (
            "AUTHORITY_EXPANSION", "CANONICAL_WRITE", "DEPLOYMENT",
            "GENERATED_CODE_EXECUTION", "POLICY_RELAXATION", "PUBLICATION",
            "LIVE_SECURITY_EXECUTION", "LIVE_TRADING",
        )
        denies = (
            "authority-expansion-denied", "canonical-mutation-denied",
            "d2-d3-private-data-denied", "deployment-denied",
            "generated-code-execution-denied", "live-security-execution-denied",
            "live-trading-denied", "policy-relaxation-denied", "publication-denied",
        )
        if (
            profile["profile_id"] != "evolution-genome-gap-miner-v1"
            or profile["schema_version"] != "1.0.0"
            or profile["status"] != "frozen-proposal-only"
            or profile["allowed_classifications"] != ["D0_PUBLIC"]
            or tuple(profile["allowed_mutation_kinds"]) != allowed
            or tuple(profile["forbidden_mutation_kinds"]) != forbidden
            or tuple(profile["required_deny_invariants"]) != denies
            or profile["limits"] != {
                "max_components": 128, "max_dependencies_per_component": 16,
                "max_gap_signals": 256, "max_evidence_refs_per_gap": 16,
                "max_blast_radius_components": 64, "max_added_deny_invariants": 16,
                "max_archive_candidates": 256,
            }
            or profile["proposal_states"] != [
                "RESEARCH_CANDIDATE", "PARKED_FORBIDDEN", "PARKED_CAPACITY",
                "WAIT_AUTHORITY",
            ]
        ):
            raise EvolutionError("genome profile semantics drifted")
        invariants = profile["invariants"]
        expected_invariants = {
            "genome_is_versioned_and_digest_bound": True,
            "blast_radius_is_transitive_reverse_dependency_closure": True,
            "all_required_deny_invariants_are_retained": True,
            "deny_invariants_may_only_grow": True,
            "policy_and_authority_may_not_expand": True,
            "mutation_payload_is_descriptive_not_executable": True,
            "candidate_archive_is_deterministic_and_provenance_bound": True,
            "mutation_applied": False, "generated_code_executed": False,
            "canonical_writes": 0, "grants_authority": False,
        }
        if invariants != expected_invariants:
            raise EvolutionError("genome invariants drifted")
        self.profile_sha256 = expected_profile_sha256
        self.allowed_mutation_kinds = frozenset(allowed)
        self.forbidden_mutation_kinds = frozenset(forbidden)
        self.required_deny_invariants = frozenset(denies)
        self.max_components = 128
        self.max_dependencies_per_component = 16
        self.max_gap_signals = 256
        self.max_evidence_refs_per_gap = 16
        self.max_blast_radius_components = 64
        self.max_added_deny_invariants = 16
        self.max_archive_candidates = 256


@dataclass(frozen=True, slots=True)
class GenomeComponent:
    component_ref: str
    version: str
    content_sha256: str
    dependency_refs: tuple[str, ...]
    deny_invariants: tuple[str, ...]

    def __post_init__(self) -> None:
        _reference(self.component_ref, "genome component_ref")
        _reference(self.version, "genome component version")
        _digest(self.content_sha256, "genome component content_sha256")
        _optional_references(self.dependency_refs, "genome dependency_refs")
        _deny_invariants(self.deny_invariants, "genome deny_invariants")


@dataclass(frozen=True, slots=True)
class GenomeSnapshot:
    version: str
    subject_ref: str
    policy_sha256: str
    components: tuple[GenomeComponent, ...]
    genome_sha256: str
    mutation_authority: bool = False


@dataclass(frozen=True, slots=True)
class OperationalGapSignal:
    gap_ref: str
    target_component_ref: str
    reason_code: str
    objective_code: str
    requested_mutation_kind: str
    evidence_refs: tuple[str, ...]
    added_deny_invariants: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _reference(self.gap_ref, "gap_ref")
        _reference(self.target_component_ref, "target_component_ref")
        _token(self.reason_code, "gap reason_code")
        _token(self.objective_code, "gap objective_code")
        if not isinstance(self.requested_mutation_kind, str) or re.fullmatch(
            r"[A-Z][A-Z0-9_]{1,63}", self.requested_mutation_kind
        ) is None:
            raise EvolutionError("requested mutation kind is invalid")
        _references(self.evidence_refs, "gap evidence_refs")
        _deny_invariants(self.added_deny_invariants, "added deny_invariants", allow_empty=True)


@dataclass(frozen=True, slots=True)
class ImprovementOpportunity:
    opportunity_ref: str
    gap_ref: str
    genome_ref: str
    target_component_ref: str
    reason_code: str
    objective_code: str
    evidence_refs: tuple[str, ...]
    blast_radius_refs: tuple[str, ...]
    status: str
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class MutationProposal:
    proposal_ref: str
    opportunity_ref: str
    genome_ref: str
    target_component_ref: str
    mutation_kind: str
    objective_code: str
    blast_radius_refs: tuple[str, ...]
    retained_deny_invariants: tuple[str, ...]
    added_deny_invariants: tuple[str, ...]
    state: str
    executable_payload_present: bool = False
    mutation_applied: bool = False
    generated_code_executed: bool = False
    canonical_writes: int = 0
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class MutationCandidateArchive:
    version: str
    genome_sha256: str
    policy_sha256: str
    opportunities: tuple[ImprovementOpportunity, ...]
    proposals: tuple[MutationProposal, ...]
    parked_gap_refs: tuple[str, ...]
    provenance_refs: tuple[str, ...]
    archive_sha256: str
    applied_count: int = 0
    side_effects: bool = False
    grants_authority: bool = False


class ChallengerEvaluationPolicy:
    """Digest-bound S30 frozen Pareto evaluator policy."""

    def __init__(self, profile_path: str | Path, *, expected_profile_sha256: str) -> None:
        profile = _load_exact_json(profile_path, expected_profile_sha256, "challenger profile")
        if set(profile) != {"profile_id","schema_version","status","allowed_classifications","dimensions","statuses","limits","acceptance","invariants"}:
            raise EvolutionError("challenger profile keys drifted")
        if (
            profile["profile_id"] != "champion-challenger-evaluation-v1"
            or profile["schema_version"] != "1.0.0"
            or profile["status"] != "frozen-shadow-evaluator"
            or profile["allowed_classifications"] != ["D0_PUBLIC"]
            or profile["dimensions"] != {"quality_units":"maximize","information_value_units":"maximize","cost_units":"minimize","latency_units":"minimize","safety_violations":"zero-tolerance"}
            or profile["statuses"] != ["CHAMPION_CHALLENGER_PASS","NOT_ESTABLISHED","REJECTED_SAFETY","PARKED_CAPACITY"]
            or profile["limits"] != {"min_benchmark_cases":8,"max_benchmark_cases":64,"min_adversarial_cases":2,"min_known_invalid_cases":2,"max_retained_candidates":32,"max_metric_units":1000000}
            or profile["acceptance"] != {"requires_pareto_dominance":True,"requires_strict_benefit":True,"allowed_safety_violations":0,"single_scalar_score":False,"promotion":False}
        ):
            raise EvolutionError("challenger profile semantics drifted")
        expected = {"benchmark_identity_is_frozen":True,"champion_and_challenger_use_exact_counterfactual_twins":True,"adversarial_and_known_invalid_cases_are_mandatory":True,"evaluator_identity_is_immutable":True,"all_dimensions_remain_visible":True,"tradeoffs_are_not_collapsed_to_one_score":True,"candidate_diversity_is_retained":True,"holdout_queries":0,"winner_promoted":False,"mutation_applied":False,"grants_authority":False}
        if profile["invariants"] != expected:
            raise EvolutionError("challenger invariants drifted")
        self.profile_sha256=expected_profile_sha256
        self.min_cases=8; self.max_cases=64; self.min_adversarial=2
        self.min_known_invalid=2; self.max_retained=32; self.max_metric=1_000_000


class ShadowCanaryPolicy:
    """Digest-bound S31 proposal-only shadow/canary policy."""

    def __init__(self, profile_path: str | Path, *, expected_profile_sha256: str) -> None:
        profile = _load_exact_json(profile_path, expected_profile_sha256, "shadow canary profile")
        if set(profile) != {
            "profile_id", "schema_version", "status", "allowed_classifications",
            "statuses", "limits", "regression_policy", "acceptance", "invariants",
        }:
            raise EvolutionError("shadow canary profile keys drifted")
        if (
            profile["profile_id"] != "shadow-canary-evolution-loop-v1"
            or profile["schema_version"] != "1.0.0"
            or profile["status"] != "frozen-proposal-only-shadow-canary"
            or profile["allowed_classifications"] != ["D0_PUBLIC"]
            or profile["statuses"] != [
                "MUTATION_PROPOSAL_LOOP_PASS", "EVOLUTION_LOOP_SHADOW_PASS",
                "META_EVOLUTION_PROPOSAL_ONLY", "NOT_ESTABLISHED",
                "REGRESSION_DETECTED", "PARKED_CAPACITY", "WAIT_AUTHORITY",
            ]
            or profile["limits"] != {
                "min_observations": 8, "max_observations": 64,
                "min_unique_cases": 4, "max_regression_signals": 32,
                "max_metric_units": 1_000_000,
            }
            or profile["regression_policy"] != {
                "safety_violations_allowed": 0, "unexpected_failures_allowed": 0,
                "quality_regression_units_allowed": 0,
                "information_regression_units_allowed": 0,
                "cost_regression_units_allowed": 0,
                "latency_regression_units_allowed": 0,
            }
            or profile["acceptance"] != {
                "requires_champion_challenger_pass": True,
                "requires_calibration_maturity": True,
                "requires_zero_regressions": True,
                "promotion_state": "WAIT_AUTHORITY",
                "automatic_promotion": False,
                "rollback_application": False,
            }
        ):
            raise EvolutionError("shadow canary profile semantics drifted")
        expected_invariants = {
            "scope_is_digest_bound": True,
            "observations_are_precomputed_D0_metadata": True,
            "shadow_has_no_network_or_filesystem_writes": True,
            "canary_never_executes_code": True,
            "regression_creates_descriptive_rollback_proposal": True,
            "rollback_proposal_requires_authority": True,
            "meta_evolution_is_proposal_only": True,
            "production_promotion": False,
            "policy_application": False,
            "canonical_writes": 0,
            "holdout_queries": 0,
            "grants_authority": False,
        }
        if profile["invariants"] != expected_invariants:
            raise EvolutionError("shadow canary invariants drifted")
        self.profile_sha256 = expected_profile_sha256
        self.min_observations = 8
        self.max_observations = 64
        self.min_unique_cases = 4
        self.max_regression_signals = 32
        self.max_metric_units = 1_000_000


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    case_ref: str
    fixture_sha256: str
    protocol_sha256: str
    adversarial: bool
    known_invalid: bool
    classification: str = "D0_PUBLIC"
    def __post_init__(self) -> None:
        _reference(self.case_ref,"benchmark case_ref"); _digest(self.fixture_sha256,"fixture_sha256"); _digest(self.protocol_sha256,"protocol_sha256")
        if type(self.adversarial) is not bool or type(self.known_invalid) is not bool or self.classification != "D0_PUBLIC":
            raise EvolutionError("benchmark case boundary is invalid")


@dataclass(frozen=True, slots=True)
class BenchmarkSnapshot:
    version: str
    evaluator_ref: str
    evaluator_sha256: str
    cases: tuple[BenchmarkCase,...]
    benchmark_sha256: str
    holdout_queries: int = 0
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class CandidateCaseResult:
    candidate_ref: str
    case_ref: str
    benchmark_sha256: str
    quality_units: int
    information_value_units: int
    cost_units: int
    latency_units: int
    safety_violations: int
    invalid_input_rejected: bool
    def __post_init__(self) -> None:
        _reference(self.candidate_ref,"candidate_ref"); _reference(self.case_ref,"result case_ref"); _digest(self.benchmark_sha256,"result benchmark_sha256")
        for name in ("quality_units","information_value_units","cost_units","latency_units","safety_violations"): _nonnegative(getattr(self,name),name)
        if type(self.invalid_input_rejected) is not bool: raise EvolutionError("invalid_input_rejected must be boolean")


@dataclass(frozen=True, slots=True)
class EvaluationDimension:
    name: str
    direction: str
    champion_total: int
    challenger_total: int
    delta_units: int
    challenger_relation: str


@dataclass(frozen=True, slots=True)
class ChampionChallengerReport:
    version: str
    benchmark_sha256: str
    evaluator_ref: str
    champion_ref: str
    challenger_ref: str
    dimensions: tuple[EvaluationDimension,...]
    pareto_relation: str
    status: str
    reason_codes: tuple[str,...]
    retained_candidate_refs: tuple[str,...]
    report_sha256: str
    single_scalar_score: int | None = None
    winner_promoted: bool = False
    mutation_applied: bool = False
    holdout_queries: int = 0
    side_effects: bool = False
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class CanaryScope:
    scope_ref: str
    policy_sha256: str
    archive_sha256: str
    report_sha256: str
    benchmark_sha256: str
    candidate_ref: str
    case_refs: tuple[str, ...]
    max_observations: int
    scope_sha256: str
    classification: str = "D0_PUBLIC"
    network_enabled: bool = False
    filesystem_write_enabled: bool = False
    generated_code_execution_enabled: bool = False
    canonical_write_enabled: bool = False
    promotion_enabled: bool = False
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class ShadowCanaryObservation:
    observation_ref: str
    scope_sha256: str
    candidate_ref: str
    case_ref: str
    quality_regression_units: int
    information_regression_units: int
    cost_regression_units: int
    latency_regression_units: int
    safety_violations: int
    unexpected_failure: bool
    classification: str = "D0_PUBLIC"

    def __post_init__(self) -> None:
        _reference(self.observation_ref, "observation_ref")
        _digest(self.scope_sha256, "observation scope_sha256")
        _reference(self.candidate_ref, "observation candidate_ref")
        _reference(self.case_ref, "observation case_ref")
        for name in (
            "quality_regression_units", "information_regression_units",
            "cost_regression_units", "latency_regression_units", "safety_violations",
        ):
            _nonnegative(getattr(self, name), name)
        if type(self.unexpected_failure) is not bool or self.classification != "D0_PUBLIC":
            raise EvolutionError("shadow observation boundary is invalid")


@dataclass(frozen=True, slots=True)
class RegressionSignal:
    signal_ref: str
    observation_ref: str
    case_ref: str
    regression_kinds: tuple[str, ...]
    signal_sha256: str


@dataclass(frozen=True, slots=True)
class RollbackProposal:
    proposal_ref: str
    candidate_ref: str
    scope_sha256: str
    regression_signal_refs: tuple[str, ...]
    reason_code: str
    state: str = "WAIT_AUTHORITY"
    executable_payload_present: bool = False
    rollback_applied: bool = False
    policy_applied: bool = False
    canonical_writes: int = 0
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class ShadowCanarySnapshot:
    version: str
    policy_sha256: str
    scope_sha256: str
    report_sha256: str
    archive_sha256: str
    candidate_ref: str
    mutation_proposal_loop_status: str
    evolution_loop_shadow_status: str
    meta_evolution_status: str
    calibration_maturity_status: str
    promotion_state: str
    reason_codes: tuple[str, ...]
    observation_count: int
    unique_case_count: int
    regression_signals: tuple[RegressionSignal, ...]
    rollback_proposal: RollbackProposal | None
    snapshot_sha256: str
    network_calls: int = 0
    filesystem_writes: int = 0
    generated_code_executions: int = 0
    canonical_writes: int = 0
    winner_promoted: bool = False
    mutation_applied: bool = False
    policy_applied: bool = False
    rollback_applied: bool = False
    holdout_queries: int = 0
    side_effects: bool = False
    grants_authority: bool = False


def build_genome_snapshot(
    policy: EvolutionGenomePolicy,
    *,
    subject_ref: str,
    components: Sequence[GenomeComponent],
) -> GenomeSnapshot:
    """Freeze a versioned dependency genome with all deny invariants retained."""

    if not isinstance(policy, EvolutionGenomePolicy):
        raise EvolutionError("genome policy is required")
    subject = _reference(subject_ref, "genome subject_ref")
    if not isinstance(components, Sequence) or isinstance(components, (str, bytes)):
        raise EvolutionError("genome components must be a sequence")
    if not components or len(components) > policy.max_components:
        raise EvolutionError("genome component capacity violated")
    if any(not isinstance(item, GenomeComponent) for item in components):
        raise EvolutionError("genome component type is invalid")
    ordered = tuple(sorted(components, key=lambda item: item.component_ref))
    refs = {item.component_ref for item in ordered}
    if len(refs) != len(ordered):
        raise EvolutionError("genome component identity is duplicated")
    for item in ordered:
        if len(item.dependency_refs) > policy.max_dependencies_per_component:
            raise EvolutionError("genome dependency capacity violated")
        if item.component_ref in item.dependency_refs or not set(item.dependency_refs) <= refs:
            raise EvolutionError("genome dependency is self-referential or unknown")
        if not policy.required_deny_invariants <= set(item.deny_invariants):
            raise EvolutionError("genome component omits required deny invariants")
    _assert_acyclic_genome(ordered)
    material = {
        "version": "evolution-genome-v1", "subject_ref": subject,
        "policy_sha256": policy.profile_sha256,
        "components": [_genome_component_material(item) for item in ordered],
        "mutation_authority": False,
    }
    return GenomeSnapshot(
        version="evolution-genome-v1", subject_ref=subject,
        policy_sha256=policy.profile_sha256, components=ordered,
        genome_sha256=_sha(material), mutation_authority=False,
    )


def mine_mutation_candidates(
    policy: EvolutionGenomePolicy,
    genome: GenomeSnapshot,
    gaps: Sequence[OperationalGapSignal],
) -> MutationCandidateArchive:
    """Create descriptive opportunities and proposals without applying mutations."""

    _validate_genome_snapshot(policy, genome)
    if not isinstance(gaps, Sequence) or isinstance(gaps, (str, bytes)):
        raise EvolutionError("gap signals must be a sequence")
    if len(gaps) > policy.max_gap_signals:
        raise EvolutionError("gap signal capacity violated")
    if any(not isinstance(item, OperationalGapSignal) for item in gaps):
        raise EvolutionError("gap signal type is invalid")
    ordered = tuple(sorted(gaps, key=lambda item: item.gap_ref))
    if len({item.gap_ref for item in ordered}) != len(ordered):
        raise EvolutionError("gap signal identity is duplicated")
    components = {item.component_ref: item for item in genome.components}
    genome_ref = "genome:sha256:" + genome.genome_sha256
    opportunities: list[ImprovementOpportunity] = []
    proposals: list[MutationProposal] = []
    parked: list[str] = []
    provenance: set[str] = {genome_ref}
    for gap in ordered:
        if gap.target_component_ref not in components:
            raise EvolutionError("gap target is outside the frozen genome")
        if len(gap.evidence_refs) > policy.max_evidence_refs_per_gap:
            raise EvolutionError("gap evidence capacity violated")
        if len(gap.added_deny_invariants) > policy.max_added_deny_invariants:
            raise EvolutionError("added deny invariant capacity violated")
        blast = _blast_radius(genome.components, gap.target_component_ref)
        if len(blast) > policy.max_blast_radius_components:
            raise EvolutionError("mutation blast radius capacity violated")
        allowed = gap.requested_mutation_kind in policy.allowed_mutation_kinds
        status = "RESEARCH_CANDIDATE" if allowed else "PARKED_FORBIDDEN"
        opportunity_material = {
            "gap_ref": gap.gap_ref, "genome_ref": genome_ref,
            "target_component_ref": gap.target_component_ref,
            "reason_code": gap.reason_code, "objective_code": gap.objective_code,
            "evidence_refs": tuple(sorted(gap.evidence_refs)),
            "blast_radius_refs": blast, "status": status,
            "grants_authority": False,
        }
        opportunity = ImprovementOpportunity(
            opportunity_ref="improvement-opportunity:sha256:" + _sha(opportunity_material),
            **opportunity_material,
        )
        opportunities.append(opportunity)
        provenance.update(gap.evidence_refs)
        if not allowed:
            parked.append(gap.gap_ref)
            continue
        retained = tuple(sorted(set().union(
            *(set(components[ref].deny_invariants) for ref in blast),
            policy.required_deny_invariants,
            gap.added_deny_invariants,
        )))
        proposal_material = {
            "opportunity_ref": opportunity.opportunity_ref, "genome_ref": genome_ref,
            "target_component_ref": gap.target_component_ref,
            "mutation_kind": gap.requested_mutation_kind,
            "objective_code": gap.objective_code, "blast_radius_refs": blast,
            "retained_deny_invariants": retained,
            "added_deny_invariants": tuple(sorted(gap.added_deny_invariants)),
            "state": "RESEARCH_CANDIDATE", "executable_payload_present": False,
            "mutation_applied": False, "generated_code_executed": False,
            "canonical_writes": 0, "grants_authority": False,
        }
        proposals.append(MutationProposal(
            proposal_ref="mutation-proposal:sha256:" + _sha(proposal_material),
            **proposal_material,
        ))
    if len(proposals) > policy.max_archive_candidates:
        raise EvolutionError("mutation archive capacity violated")
    archive_material = {
        "version": "mutation-candidate-archive-v1",
        "genome_sha256": genome.genome_sha256,
        "policy_sha256": policy.profile_sha256,
        "opportunities": [_opportunity_material(item) for item in opportunities],
        "proposals": [_proposal_material(item) for item in proposals],
        "parked_gap_refs": tuple(parked),
        "provenance_refs": tuple(sorted(provenance)),
        "applied_count": 0, "side_effects": False, "grants_authority": False,
    }
    return MutationCandidateArchive(
        version="mutation-candidate-archive-v1",
        genome_sha256=genome.genome_sha256,
        policy_sha256=policy.profile_sha256,
        opportunities=tuple(opportunities), proposals=tuple(proposals),
        parked_gap_refs=tuple(parked), provenance_refs=tuple(sorted(provenance)),
        archive_sha256=_sha(archive_material), applied_count=0,
        side_effects=False, grants_authority=False,
    )


def build_benchmark_snapshot(
    policy: ChallengerEvaluationPolicy,
    *, evaluator_ref: str,
    evaluator_sha256: str,
    cases: Sequence[BenchmarkCase],
) -> BenchmarkSnapshot:
    if not isinstance(policy,ChallengerEvaluationPolicy): raise EvolutionError("challenger policy is required")
    evaluator=_reference(evaluator_ref,"evaluator_ref"); digest=_digest(evaluator_sha256,"evaluator_sha256")
    if not isinstance(cases,Sequence) or isinstance(cases,(str,bytes)) or any(not isinstance(x,BenchmarkCase) for x in cases):
        raise EvolutionError("benchmark cases must be typed")
    if not policy.min_cases <= len(cases) <= policy.max_cases: raise EvolutionError("benchmark case capacity or maturity violated")
    ordered=tuple(sorted(cases,key=lambda x:x.case_ref))
    if len({x.case_ref for x in ordered}) != len(ordered): raise EvolutionError("benchmark case duplicated")
    if sum(x.adversarial for x in ordered) < policy.min_adversarial or sum(x.known_invalid for x in ordered) < policy.min_known_invalid:
        raise EvolutionError("benchmark hostile coverage is incomplete")
    material={"version":"champion-challenger-benchmark-v1","evaluator_ref":evaluator,"evaluator_sha256":digest,"cases":[_benchmark_case_material(x) for x in ordered],"holdout_queries":0,"grants_authority":False}
    return BenchmarkSnapshot("champion-challenger-benchmark-v1",evaluator,digest,ordered,_sha(material),0,False)


def evaluate_challenger(
    policy: ChallengerEvaluationPolicy,
    benchmark: BenchmarkSnapshot,
    archive: MutationCandidateArchive,
    *, champion_ref: str,
    challenger_ref: str,
    champion_results: Sequence[CandidateCaseResult],
    challenger_results: Sequence[CandidateCaseResult],
) -> ChampionChallengerReport:
    _validate_benchmark(policy,benchmark); _validate_mutation_archive(archive)
    champion=_reference(champion_ref,"champion_ref"); challenger=_reference(challenger_ref,"challenger_ref")
    if champion==challenger: raise EvolutionError("champion and challenger must differ")
    archive_refs={x.proposal_ref for x in archive.proposals}
    if challenger not in archive_refs: raise EvolutionError("challenger is outside candidate archive")
    c=_result_map(policy,benchmark,champion,champion_results); h=_result_map(policy,benchmark,challenger,challenger_results)
    dimensions=[]
    specs=(("quality_units","maximize"),("information_value_units","maximize"),("cost_units","minimize"),("latency_units","minimize"),("safety_violations","minimize"))
    nonworse=True; strict=False
    for name,direction in specs:
        cv=sum(getattr(x,name) for x in c.values()); hv=sum(getattr(x,name) for x in h.values()); delta=hv-cv
        better=delta>0 if direction=="maximize" else delta<0; equal=delta==0; nonworse_here=better or equal
        nonworse &= nonworse_here; strict |= better
        dimensions.append(EvaluationDimension(name,direction,cv,hv,delta,"BETTER" if better else "EQUAL" if equal else "WORSE"))
    cases={x.case_ref:x for x in benchmark.cases}
    invalid_failure=any(cases[ref].known_invalid and not result.invalid_input_rejected for ref,result in h.items())
    safety=sum(x.safety_violations for x in h.values())
    reasons=set()
    if safety or invalid_failure:
        status="REJECTED_SAFETY"; relation="REGRESSION"; reasons.add("SAFETY_REGRESSION")
        if invalid_failure: reasons.add("KNOWN_INVALID_NOT_REJECTED")
    elif nonworse and strict:
        status="CHAMPION_CHALLENGER_PASS"; relation="CHALLENGER_PARETO_DOMINATES"; reasons.add("PASS_FOR_FROZEN_BENCHMARK")
    else:
        status="NOT_ESTABLISHED"; relation="TRADEOFF_OR_NO_STRICT_BENEFIT"; reasons.add("PARETO_DOMINANCE_NOT_ESTABLISHED")
    retained=tuple(sorted(archive_refs))
    if len(retained)>policy.max_retained: raise EvolutionError("retained candidate capacity violated")
    material={"version":"champion-challenger-report-v1","benchmark_sha256":benchmark.benchmark_sha256,"evaluator_ref":benchmark.evaluator_ref,"champion_ref":champion,"challenger_ref":challenger,"dimensions":[_evaluation_dimension_material(x) for x in dimensions],"pareto_relation":relation,"status":status,"reason_codes":tuple(sorted(reasons)),"retained_candidate_refs":retained,"single_scalar_score":None,"winner_promoted":False,"mutation_applied":False,"holdout_queries":0,"side_effects":False,"grants_authority":False}
    return ChampionChallengerReport(
        version="champion-challenger-report-v1",
        benchmark_sha256=benchmark.benchmark_sha256,
        evaluator_ref=benchmark.evaluator_ref,
        champion_ref=champion,
        challenger_ref=challenger,
        dimensions=tuple(dimensions),
        pareto_relation=relation,
        status=status,
        reason_codes=tuple(sorted(reasons)),
        retained_candidate_refs=retained,
        report_sha256=_sha(material),
        single_scalar_score=None,
        winner_promoted=False,
        mutation_applied=False,
        holdout_queries=0,
        side_effects=False,
        grants_authority=False,
    )


def build_canary_scope(
    policy: ShadowCanaryPolicy,
    report: ChampionChallengerReport,
    archive: MutationCandidateArchive,
    *,
    scope_ref: str,
    case_refs: Sequence[str],
    max_observations: int,
) -> CanaryScope:
    """Freeze a D0 metadata-only scope for one S30-passing challenger."""

    if not isinstance(policy, ShadowCanaryPolicy):
        raise EvolutionError("shadow canary policy is required")
    _validate_mutation_archive(archive)
    _validate_challenger_report(report)
    if report.status != "CHAMPION_CHALLENGER_PASS":
        raise EvolutionError("only a frozen benchmark pass can enter shadow canary")
    if report.challenger_ref not in {item.proposal_ref for item in archive.proposals}:
        raise EvolutionError("shadow candidate is outside the mutation archive")
    scope = _reference(scope_ref, "canary scope_ref")
    cases = _references(case_refs, "canary case_refs")
    if len(cases) < policy.min_unique_cases:
        raise EvolutionError("canary case scope is immature")
    maximum = _positive(max_observations, "canary max_observations")
    if not policy.min_observations <= maximum <= policy.max_observations:
        raise EvolutionError("canary observation scope exceeds frozen bounds")
    material = {
        "scope_ref": scope, "policy_sha256": policy.profile_sha256,
        "archive_sha256": archive.archive_sha256,
        "report_sha256": report.report_sha256,
        "benchmark_sha256": report.benchmark_sha256,
        "candidate_ref": report.challenger_ref,
        "case_refs": tuple(sorted(cases)), "max_observations": maximum,
        "classification": "D0_PUBLIC", "network_enabled": False,
        "filesystem_write_enabled": False,
        "generated_code_execution_enabled": False,
        "canonical_write_enabled": False, "promotion_enabled": False,
        "grants_authority": False,
    }
    return CanaryScope(**material, scope_sha256=_sha(material))


def run_shadow_canary(
    policy: ShadowCanaryPolicy,
    scope: CanaryScope,
    report: ChampionChallengerReport,
    archive: MutationCandidateArchive,
    observations: Sequence[ShadowCanaryObservation],
) -> ShadowCanarySnapshot:
    """Reduce precomputed D0 observations; never execute or apply a mutation."""

    if not isinstance(policy, ShadowCanaryPolicy):
        raise EvolutionError("shadow canary policy is required")
    _validate_mutation_archive(archive)
    _validate_challenger_report(report)
    _validate_canary_scope(policy, scope, report, archive)
    if not isinstance(observations, Sequence) or isinstance(observations, (str, bytes)):
        raise EvolutionError("shadow observations must be a sequence")
    if any(not isinstance(item, ShadowCanaryObservation) for item in observations):
        raise EvolutionError("shadow observations must be typed")
    ordered = tuple(sorted(observations, key=lambda item: item.observation_ref))
    if len({item.observation_ref for item in ordered}) != len(ordered):
        raise EvolutionError("shadow observation identity is duplicated")
    for item in ordered:
        if (
            item.scope_sha256 != scope.scope_sha256
            or item.candidate_ref != scope.candidate_ref
            or item.case_ref not in scope.case_refs
        ):
            raise EvolutionError("shadow observation binding is invalid")
        for name in (
            "quality_regression_units", "information_regression_units",
            "cost_regression_units", "latency_regression_units", "safety_violations",
        ):
            if getattr(item, name) > policy.max_metric_units:
                raise EvolutionError("shadow observation metric exceeds frozen bound")

    overloaded = len(ordered) > scope.max_observations or len(ordered) > policy.max_observations
    unique_cases = len({item.case_ref for item in ordered})
    regression_signals: tuple[RegressionSignal, ...] = ()
    rollback: RollbackProposal | None = None
    reasons: set[str] = set()
    if overloaded:
        shadow_status = "PARKED_CAPACITY"
        maturity = "NOT_ESTABLISHED"
        reasons.add("SHADOW_CANARY_CAPACITY_EXCEEDED")
    else:
        built_signals = tuple(
            signal for signal in (_regression_signal(item) for item in ordered)
            if signal is not None
        )
        if len(built_signals) > policy.max_regression_signals:
            shadow_status = "PARKED_CAPACITY"
            maturity = "NOT_ESTABLISHED"
            reasons.add("REGRESSION_SIGNAL_CAPACITY_EXCEEDED")
        else:
            regression_signals = built_signals
            mature = (
                len(ordered) >= policy.min_observations
                and unique_cases >= policy.min_unique_cases
                and set(scope.case_refs) <= {item.case_ref for item in ordered}
            )
            maturity = "MATURE_FOR_FROZEN_SCOPE" if mature else "NOT_ESTABLISHED"
            if regression_signals:
                shadow_status = "REGRESSION_DETECTED"
                reasons.add("SHADOW_CANARY_REGRESSION_DETECTED")
                rollback = _rollback_proposal(scope, regression_signals)
            elif mature:
                shadow_status = "EVOLUTION_LOOP_SHADOW_PASS"
                reasons.add("PASS_FOR_FROZEN_SHADOW_SCOPE")
            else:
                shadow_status = "NOT_ESTABLISHED"
                reasons.add("CALIBRATION_MATURITY_NOT_ESTABLISHED")

    material = {
        "version": "shadow-canary-snapshot-v1",
        "policy_sha256": policy.profile_sha256,
        "scope_sha256": scope.scope_sha256,
        "report_sha256": report.report_sha256,
        "archive_sha256": archive.archive_sha256,
        "candidate_ref": scope.candidate_ref,
        "mutation_proposal_loop_status": "MUTATION_PROPOSAL_LOOP_PASS",
        "evolution_loop_shadow_status": shadow_status,
        "meta_evolution_status": "META_EVOLUTION_PROPOSAL_ONLY",
        "calibration_maturity_status": maturity,
        "promotion_state": "WAIT_AUTHORITY",
        "reason_codes": tuple(sorted(reasons)),
        "observation_count": len(ordered), "unique_case_count": unique_cases,
        "regression_signals": [_regression_signal_material(item) for item in regression_signals],
        "rollback_proposal": None if rollback is None else _rollback_proposal_material(rollback),
        "network_calls": 0, "filesystem_writes": 0,
        "generated_code_executions": 0, "canonical_writes": 0,
        "winner_promoted": False, "mutation_applied": False,
        "policy_applied": False, "rollback_applied": False,
        "holdout_queries": 0, "side_effects": False, "grants_authority": False,
    }
    return ShadowCanarySnapshot(**material, snapshot_sha256=_sha(material))


def build_research_agenda(
    knowledge: KnowledgeFabricReport,
    proposals: Sequence[AgendaProposal],
) -> AgendaSnapshot:
    """Bind scored proposals to exact S23 debt and root-energy evidence."""

    if not isinstance(knowledge, KnowledgeFabricReport):
        raise EvolutionError("knowledge must be a KnowledgeFabricReport")
    if (
        knowledge.fabric_version != "research-knowledge-fabric-v1"
        or knowledge.memory_enabled is not True
        or knowledge.side_effects is not False
        or knowledge.claims_scientific_truth is not False
        or knowledge.grants_authority is not False
    ):
        raise EvolutionError("knowledge fabric is not safe for agenda construction")
    expected_knowledge_sha = _sha(
        {
            "fabric_version": knowledge.fabric_version,
            "ledger_sequence_last": knowledge.ledger_sequence_last,
            "memory_enabled": knowledge.memory_enabled,
            "query_root_event_ref": knowledge.query_root_event_ref,
            "idea_nodes": knowledge.idea_nodes,
            "failure_memory": knowledge.failure_memory,
            "conflict_candidates": knowledge.conflict_candidates,
            "root_event_energy": knowledge.root_event_energy,
            "research_debt": knowledge.research_debt,
            "retrieval_trace": knowledge.retrieval_trace,
            "side_effects": knowledge.side_effects,
            "claims_scientific_truth": knowledge.claims_scientific_truth,
            "grants_authority": knowledge.grants_authority,
        }
    )
    if knowledge.fabric_sha256 != expected_knowledge_sha:
        raise EvolutionError("knowledge fabric integrity mismatch")
    if not isinstance(proposals, Sequence) or isinstance(proposals, (str, bytes)):
        raise EvolutionError("proposals must be a sequence")
    if len(proposals) > _MAX_AGENDA_ITEMS:
        raise EvolutionError("agenda item bound exceeded")
    if any(not isinstance(item, AgendaProposal) for item in proposals):
        raise EvolutionError("agenda proposal type is invalid")

    debt = {str(item["subject_ref"]): item for item in knowledge.research_debt}
    energy = {str(item["root_event_ref"]): item for item in knowledge.root_event_energy}
    if len(debt) != len(knowledge.research_debt) or len(energy) != len(knowledge.root_event_energy):
        raise EvolutionError("knowledge debt or energy identity is duplicated")
    seen_debt: set[str] = set()
    seen_outcomes: set[str] = set()
    items: list[AgendaItem] = []
    for proposal in proposals:
        if proposal.debt_ref in seen_debt:
            raise EvolutionError("agenda debt is proposed more than once")
        if proposal.outcome_ref in seen_outcomes:
            raise EvolutionError("outcome has more than one next-event proposal")
        seen_debt.add(proposal.debt_ref)
        seen_outcomes.add(proposal.outcome_ref)
        debt_item = debt.get(proposal.debt_ref)
        energy_item = energy.get(proposal.root_event_ref)
        if debt_item is None or energy_item is None:
            raise EvolutionError("agenda proposal lacks exact debt or root-energy evidence")
        if energy_item.get("source_outcome_ref") != proposal.outcome_ref:
            raise EvolutionError("agenda outcome is not bound to root-energy evidence")
        debt_taint = debt_item.get("shadow_taint")
        if debt_taint not in {"NONE", "SHADOW_UNAPPLIED"} or energy_item.get("shadow_taint") != debt_taint:
            raise EvolutionError("agenda taint inheritance is inconsistent")
        observed = energy_item.get("observed_remaining_energy")
        remaining = 0 if observed is None else _nonnegative(observed, "observed_remaining_energy")
        provenance = tuple(
            sorted(
                {
                    *(_references(debt_item.get("provenance_refs"), "debt provenance_refs")),
                    *(_references(energy_item.get("provenance_refs"), "energy provenance_refs")),
                    f"knowledge-fabric:sha256:{knowledge.fabric_sha256}",
                }
            )
        )
        material = {
            "debt_ref": proposal.debt_ref,
            "root_event_ref": proposal.root_event_ref,
            "outcome_ref": proposal.outcome_ref,
            "next_event_ref": proposal.next_event_ref,
            "diversity_key": proposal.diversity_key,
            "value_units": proposal.value_units,
            "cost_units": proposal.cost_units,
            "risk_units": proposal.risk_units,
            "created_sequence": proposal.created_sequence,
            "remaining_energy": remaining,
            "shadow_taint": debt_taint,
            "safe_to_run": proposal.safe_to_run,
            "provenance_refs": provenance,
        }
        items.append(AgendaItem(item_id="agenda-item:sha256:" + _sha(material), **material))
    items.sort(key=lambda item: item.item_id)
    unassessed = tuple(sorted(set(debt) - seen_debt))
    snapshot_material = {
        "agenda_version": "research-agenda-v1",
        "knowledge_fabric_sha256": knowledge.fabric_sha256,
        "items": [_agenda_item_material(item) for item in items],
        "unassessed_debt_refs": unassessed,
        "grants_authority": False,
    }
    return AgendaSnapshot(
        agenda_version="research-agenda-v1",
        knowledge_fabric_sha256=knowledge.fabric_sha256,
        items=tuple(items),
        unassessed_debt_refs=unassessed,
        agenda_sha256=_sha(snapshot_material),
        grants_authority=False,
    )


def select_portfolio(
    agenda: AgendaSnapshot,
    policy: PortfolioPolicy,
    *,
    current_sequence: int,
) -> PortfolioSnapshot:
    """Greedily select a deterministic bounded portfolio without side effects."""

    if not isinstance(agenda, AgendaSnapshot) or not isinstance(policy, PortfolioPolicy):
        raise EvolutionError("agenda and policy types are invalid")
    sequence = _nonnegative(current_sequence, "current_sequence")
    if agenda.grants_authority is not False or len(agenda.items) > _MAX_AGENDA_ITEMS:
        raise EvolutionError("agenda authority or capacity is invalid")
    expected_agenda = _sha(
        {
            "agenda_version": agenda.agenda_version,
            "knowledge_fabric_sha256": agenda.knowledge_fabric_sha256,
            "items": [_agenda_item_material(item) for item in agenda.items],
            "unassessed_debt_refs": agenda.unassessed_debt_refs,
            "grants_authority": False,
        }
    )
    if agenda.agenda_version != "research-agenda-v1" or agenda.agenda_sha256 != expected_agenda:
        raise EvolutionError("agenda snapshot integrity mismatch")
    if len({item.item_id for item in agenda.items}) != len(agenda.items):
        raise EvolutionError("agenda item identity is duplicated")
    if len({item.outcome_ref for item in agenda.items}) != len(agenda.items):
        raise EvolutionError("agenda contains multiple next events for one outcome")

    remaining = list(agenda.items)
    entries: list[PortfolioEntry] = []
    selected: list[AgendaItem] = []
    diversity_counts: dict[str, int] = {}
    used_cost = 0
    used_risk = 0
    while remaining:
        scored = [
            (_score(item, policy, sequence, diversity_counts), item)
            for item in remaining
        ]
        score, item = min(scored, key=lambda pair: (-pair[0], pair[1].created_sequence, pair[1].item_id))
        remaining.remove(item)
        status = "SELECTED"
        reason = "SELECTED_WITHIN_BOUNDS"
        rank: int | None = None
        trigger: Mapping[str, object] | None = None
        if not item.safe_to_run:
            status, reason = "PARKED", "UNSAFE_POLICY_DENIED"
        elif item.remaining_energy <= 0:
            status, reason = "PARKED", "ROOT_ENERGY_EXHAUSTED"
        elif item.value_units == 0:
            status, reason = "REJECTED", "NO_RESEARCH_VALUE"
        elif len(selected) >= policy.max_slots:
            status, reason = "PARKED", "SLOT_CAPACITY_EXHAUSTED"
        elif diversity_counts.get(item.diversity_key, 0) >= policy.max_per_diversity_key:
            status, reason = "PARKED", "DIVERSITY_CAP_REACHED"
        elif used_cost + item.cost_units > policy.max_total_cost_units:
            status, reason = "PARKED", "COST_BUDGET_EXHAUSTED"
        elif used_risk + item.risk_units > policy.max_total_risk_units:
            status, reason = "PARKED", "RISK_BUDGET_EXHAUSTED"
        else:
            selected.append(item)
            used_cost += item.cost_units
            used_risk += item.risk_units
            diversity_counts[item.diversity_key] = diversity_counts.get(item.diversity_key, 0) + 1
            rank = len(selected)
            trigger_material = {
                "source": "bounded-portfolio-selector-v1",
                "agenda_item_ref": item.item_id,
                "outcome_ref": item.outcome_ref,
                "root_event_ref": item.root_event_ref,
                "next_event_ref": item.next_event_ref,
                "remaining_energy": item.remaining_energy - 1,
                "shadow_taint": item.shadow_taint,
                "grants_authority": False,
            }
            trigger = MappingProxyType(
                {"trigger_id": "portfolio-trigger:sha256:" + _sha(trigger_material), **trigger_material}
            )
        entries.append(
            PortfolioEntry(
                item_id=item.item_id,
                outcome_ref=item.outcome_ref,
                score=score,
                status=status,
                reason_code=reason,
                selected_rank=rank,
                next_trigger=trigger,
            )
        )
    entries.sort(key=lambda item: (item.selected_rank is None, item.selected_rank or 0, item.item_id))
    selected_ids = tuple(item.item_id for item in selected)
    material = {
        "portfolio_version": "bounded-portfolio-v1",
        "agenda_sha256": agenda.agenda_sha256,
        "policy_sha256": policy.sha256,
        "current_sequence": sequence,
        "entries": [_portfolio_entry_material(item) for item in entries],
        "selected_item_ids": selected_ids,
        "used_cost_units": used_cost,
        "used_risk_units": used_risk,
        "side_effects": False,
        "grants_authority": False,
    }
    return PortfolioSnapshot(
        portfolio_version="bounded-portfolio-v1",
        agenda_sha256=agenda.agenda_sha256,
        policy_sha256=policy.sha256,
        current_sequence=sequence,
        entries=tuple(entries),
        selected_item_ids=selected_ids,
        used_cost_units=used_cost,
        used_risk_units=used_risk,
        portfolio_sha256=_sha(material),
        side_effects=False,
        grants_authority=False,
    )


def build_evidence_sidecar(
    policy: ReplicationPolicy,
    descriptors: Sequence[EvidenceDescriptor],
) -> EvidenceSidecar:
    if not isinstance(policy, ReplicationPolicy):
        raise EvolutionError("replication policy is required")
    if not isinstance(descriptors, Sequence) or isinstance(descriptors, (str, bytes)):
        raise EvolutionError("evidence descriptors must be a sequence")
    if not descriptors or len(descriptors) > policy.max_evidence_items:
        raise EvolutionError("evidence sidecar capacity violated")
    if any(not isinstance(item, EvidenceDescriptor) for item in descriptors):
        raise EvolutionError("evidence descriptor type is invalid")
    ordered = tuple(sorted(descriptors, key=lambda item: item.evidence_ref))
    if len({item.evidence_ref for item in ordered}) != len(ordered):
        raise EvolutionError("evidence reference is duplicated")
    material = {
        "version": "evidence-sidecar-v1",
        "descriptors": [_evidence_material(item) for item in ordered],
        "raw_payloads_present": False,
        "side_effects": False,
        "grants_authority": False,
    }
    return EvidenceSidecar(
        version="evidence-sidecar-v1",
        descriptors=ordered,
        sidecar_sha256=_sha(material),
        raw_payloads_present=False,
        side_effects=False,
        grants_authority=False,
    )


def build_replication_matrix(
    policy: ReplicationPolicy,
    sidecar: EvidenceSidecar,
    claims: Sequence[ReplicationPairClaim],
) -> ReplicationMatrixSnapshot:
    _validate_sidecar(policy, sidecar)
    if not isinstance(claims, Sequence) or isinstance(claims, (str, bytes)):
        raise EvolutionError("replication claims must be a sequence")
    if not claims or len(claims) > policy.max_replication_pairs:
        raise EvolutionError("replication pair capacity violated")
    if any(not isinstance(item, ReplicationPairClaim) for item in claims):
        raise EvolutionError("replication claim type is invalid")
    descriptors = {item.evidence_ref: item for item in sidecar.descriptors}
    results: list[ReplicationPairResult] = []
    seen_pairs: set[tuple[str, str]] = set()
    for claim in claims:
        pair_key = (claim.parent_trial_ref, claim.child_trial_ref)
        if pair_key in seen_pairs:
            raise EvolutionError("replication trial pair is duplicated")
        seen_pairs.add(pair_key)
        dimensions: list[ReplicationDimensionResult] = []
        for dimension in claim.dimensions:
            selected: list[EvidenceDescriptor] = []
            for reference in dimension.verification_refs:
                descriptor = descriptors.get(reference)
                if descriptor is None:
                    raise EvolutionError("replication verification reference is outside sidecar")
                selected.append(descriptor)
            parent = [item for item in selected if dict(item.dimension_groups)[dimension.dimension] == dimension.parent_group]
            child = [item for item in selected if dict(item.dimension_groups)[dimension.dimension] == dimension.child_group]
            if not parent or not child:
                raise EvolutionError("replication dimension groups lack sidecar evidence")
            if dimension.parent_group == dimension.child_group:
                status = "CORRELATED_SAME_GROUP"
            elif {item.source_group for item in parent} & {item.source_group for item in child}:
                status = "DISTINCT_DECLARED_CORRELATED_SOURCE"
            else:
                status = "DISTINCT_FOR_FROZEN_SCOPE"
            dimensions.append(
                ReplicationDimensionResult(
                    dimension=dimension.dimension,
                    parent_group=dimension.parent_group,
                    child_group=dimension.child_group,
                    verification_refs=tuple(sorted(dimension.verification_refs)),
                    status=status,
                )
            )
        statuses = {item.status for item in dimensions}
        if "CORRELATED_SAME_GROUP" in statuses:
            overall = "CORRELATED"
        elif statuses == {"DISTINCT_FOR_FROZEN_SCOPE"}:
            overall = "MULTIDIMENSIONAL_PASS_FOR_FROZEN_SCOPE"
        else:
            overall = "INDEPENDENCE_NOT_ESTABLISHED"
        pair_material = {
            "parent_trial_ref": claim.parent_trial_ref,
            "child_trial_ref": claim.child_trial_ref,
            "original_outcome_ref": claim.original_outcome_ref,
            "replication_outcome_ref": claim.replication_outcome_ref,
            "dimensions": [_dimension_result_material(item) for item in dimensions],
            "overall_status": overall,
        }
        results.append(
            ReplicationPairResult(
                parent_trial_ref=claim.parent_trial_ref,
                child_trial_ref=claim.child_trial_ref,
                original_outcome_ref=claim.original_outcome_ref,
                replication_outcome_ref=claim.replication_outcome_ref,
                dimensions=tuple(dimensions),
                overall_status=overall,
                pair_sha256=_sha(pair_material),
            )
        )
    results.sort(key=lambda item: (item.parent_trial_ref, item.child_trial_ref))
    material = {
        "version": "replication-matrix-v1",
        "evidence_sidecar_sha256": sidecar.sidecar_sha256,
        "pairs": [_pair_result_material(item) for item in results],
        "absolute_independence_claimed": False,
        "linear_replication_level": None,
        "side_effects": False,
        "grants_authority": False,
    }
    return ReplicationMatrixSnapshot(
        version="replication-matrix-v1",
        evidence_sidecar_sha256=sidecar.sidecar_sha256,
        pairs=tuple(results),
        matrix_sha256=_sha(material),
        absolute_independence_claimed=False,
        linear_replication_level=None,
        side_effects=False,
        grants_authority=False,
    )


def build_research_islands(
    policy: ReplicationPolicy,
    sidecar: EvidenceSidecar,
    islands: Sequence[ResearchIslandSpec],
) -> ResearchIslandSnapshot:
    _validate_sidecar(policy, sidecar)
    if not isinstance(islands, Sequence) or isinstance(islands, (str, bytes)):
        raise EvolutionError("research islands must be a sequence")
    if not islands or len(islands) > policy.max_islands:
        raise EvolutionError("research island capacity violated")
    if any(not isinstance(item, ResearchIslandSpec) for item in islands):
        raise EvolutionError("research island type is invalid")
    ordered = tuple(sorted(islands, key=lambda item: item.island_id))
    for attribute in ("island_id", "workspace_namespace_ref", "model_context_ref"):
        values = [getattr(item, attribute) for item in ordered]
        if len(values) != len(set(values)):
            raise EvolutionError(f"research island {attribute} is duplicated")
    all_trials = [reference for item in ordered for reference in item.trial_refs]
    if len(all_trials) != len(set(all_trials)):
        raise EvolutionError("research island trial ownership overlaps")
    available_evidence = {item.evidence_ref for item in sidecar.descriptors}
    if any(reference not in available_evidence for item in ordered for reference in item.evidence_refs):
        raise EvolutionError("research island evidence is outside sidecar")
    reasons: set[str] = set()
    candidate_units: dict[str, int] = {}
    family_units: dict[str, int] = {}
    day_units: dict[str, int] = {}
    total_units = 0
    for island in ordered:
        for exposure in island.exposures:
            weight = policy.feedback_weights.get(exposure.feedback_class)
            if weight is None:
                raise EvolutionError("evaluator feedback class is unsupported")
            units = exposure.query_count * int(weight)
            total_units += units
            candidate_units[exposure.candidate_lineage] = candidate_units.get(exposure.candidate_lineage, 0) + units
            family_units[exposure.trial_family_ref] = family_units.get(exposure.trial_family_ref, 0) + units
            day_units[exposure.day_bucket] = day_units.get(exposure.day_bucket, 0) + units
            if exposure.true_holdout:
                reasons.add("TRUE_HOLDOUT_AUTONOMOUS_DENIED")
    if any(value > 3 for value in candidate_units.values()):
        reasons.add("CANDIDATE_EXPOSURE_BUDGET_EXHAUSTED")
    if any(value > 12 for value in family_units.values()):
        reasons.add("TRIAL_FAMILY_EXPOSURE_BUDGET_EXHAUSTED")
    if any(value > 50 for value in day_units.values()):
        reasons.add("DAILY_EXPOSURE_BUDGET_EXHAUSTED")
    status = "READY_METADATA_ONLY" if not reasons else "PARKED_EXPOSURE"
    material = {
        "version": "research-islands-v1",
        "evidence_sidecar_sha256": sidecar.sidecar_sha256,
        "islands": [_island_material(item) for item in ordered],
        "status": status,
        "reason_codes": tuple(sorted(reasons)),
        "weighted_exposure_units": total_units,
        "side_effects": False,
        "grants_authority": False,
    }
    return ResearchIslandSnapshot(
        version="research-islands-v1",
        evidence_sidecar_sha256=sidecar.sidecar_sha256,
        islands=ordered,
        status=status,
        reason_codes=tuple(sorted(reasons)),
        weighted_exposure_units=total_units,
        snapshot_sha256=_sha(material),
        side_effects=False,
        grants_authority=False,
    )


def declassification_dry_run(
    policy: ReplicationPolicy,
    candidate: DeclassificationCandidate,
    islands: ResearchIslandSnapshot,
    matrix: ReplicationMatrixSnapshot,
) -> DeclassificationDryRunResult:
    if not isinstance(policy, ReplicationPolicy) or not isinstance(candidate, DeclassificationCandidate):
        raise EvolutionError("typed declassification inputs are required")
    if not isinstance(islands, ResearchIslandSnapshot) or not isinstance(matrix, ReplicationMatrixSnapshot):
        raise EvolutionError("declassification snapshots are invalid")
    _validate_island_snapshot(policy, islands)
    _validate_matrix_snapshot(policy, matrix)
    if islands.evidence_sidecar_sha256 != matrix.evidence_sidecar_sha256:
        raise EvolutionError("declassification snapshots bind different evidence sidecars")
    reasons: list[str] = []
    forbidden = False
    if candidate.classification != "D0_PUBLIC":
        reasons.append("CLASSIFICATION_NOT_PUBLIC")
        forbidden = True
    if len(candidate.metadata_labels) > policy.max_metadata_labels:
        reasons.append("METADATA_LABEL_CAP_EXCEEDED")
        forbidden = True
    source = next((item for item in islands.islands if item.island_id == candidate.source_island_id), None)
    if source is None:
        reasons.append("SOURCE_ISLAND_NOT_FOUND")
    elif not set(candidate.evidence_refs).issubset(source.evidence_refs):
        reasons.append("EVIDENCE_OUTSIDE_SOURCE_ISLAND")
        forbidden = True
    if islands.status != "READY_METADATA_ONLY":
        reasons.append("ISLAND_EXPOSURE_NOT_READY")
    expected_matrix_ref = "replication-matrix:sha256:" + matrix.matrix_sha256
    if candidate.replication_matrix_ref != expected_matrix_ref:
        reasons.append("REPLICATION_MATRIX_BINDING_MISMATCH")
    status = "PASS_DRY_RUN_NO_AUTHORITY" if not reasons else "DENIED"
    material = {
        "status": status,
        "candidate_ref": candidate.candidate_ref,
        "reason_codes": tuple(sorted(reasons)),
        "forbidden_bytes_or_metadata_detected": forbidden,
        "bytes_exported": 0,
        "network_calls": 0,
        "canonical_writes": 0,
        "grants_authority": False,
    }
    return DeclassificationDryRunResult(**material, result_sha256=_sha(material))


def measure_memory_uplift(
    policy: MemoryEvaluationPolicy,
    first_replay: FeedbackReplayReport,
    second_replay: FeedbackReplayReport,
    memory_off: KnowledgeFabricReport,
    memory_on: KnowledgeFabricReport,
    twins: Sequence[MemoryTwinPair],
    calibration: Sequence[CalibrationObservation] = (),
) -> MemoryUpliftSnapshot:
    """Measure a bounded paired shadow uplift without learning or mutation."""

    if not isinstance(policy, MemoryEvaluationPolicy):
        raise EvolutionError("memory evaluation policy is required")
    _validate_full_replay(first_replay)
    _validate_full_replay(second_replay)
    if first_replay != second_replay:
        raise EvolutionError("full feedback replay is not deterministic")
    _validate_memory_fabric(memory_off, expected_enabled=False, replay=first_replay)
    _validate_memory_fabric(memory_on, expected_enabled=True, replay=first_replay)
    if (
        memory_off.ledger_sequence_last != memory_on.ledger_sequence_last
        or memory_off.query_root_event_ref != memory_on.query_root_event_ref
    ):
        raise EvolutionError("memory twins do not share the same ledger and query scope")
    if not isinstance(twins, Sequence) or isinstance(twins, (str, bytes)):
        raise EvolutionError("memory twins must be a sequence")
    if not isinstance(calibration, Sequence) or isinstance(calibration, (str, bytes)):
        raise EvolutionError("calibration observations must be a sequence")
    if any(not isinstance(item, MemoryTwinPair) for item in twins):
        raise EvolutionError("memory twin type is invalid")
    if any(not isinstance(item, CalibrationObservation) for item in calibration):
        raise EvolutionError("calibration observation type is invalid")
    ordered_twins = tuple(sorted(twins, key=lambda item: item.pair_id))
    ordered_calibration = tuple(sorted(calibration, key=lambda item: item.observation_ref))
    if len({item.pair_id for item in ordered_twins}) != len(ordered_twins):
        raise EvolutionError("memory twin identity is duplicated")
    if len({item.case_ref for item in ordered_twins}) != len(ordered_twins):
        raise EvolutionError("memory twin case is duplicated")
    if len({item.observation_ref for item in ordered_calibration}) != len(ordered_calibration):
        raise EvolutionError("calibration observation identity is duplicated")
    for item in ordered_twins:
        if (
            item.memory_off_information_value_units > policy.max_information_value_units
            or item.memory_on_information_value_units > policy.max_information_value_units
            or item.memory_off_research_debt_units > policy.max_research_debt_units
            or item.memory_on_research_debt_units > policy.max_research_debt_units
        ):
            raise EvolutionError("memory twin bounded metric exceeds frozen capacity")

    capacity_overloaded = (
        len(ordered_twins) > policy.max_memory_twin_pairs
        or len(ordered_calibration) > policy.max_calibration_observations
    )
    sample_size = len(ordered_twins)
    if capacity_overloaded:
        status = "PARKED_CAPACITY"
        reasons = ("MEMORY_EVALUATION_CAPACITY_EXHAUSTED",)
        uplift = 0
        low, high = -1_000_000, 1_000_000
        false_rate = 0
        false_upper = 1_000_000
        information_delta = 0
        debt_delta = 0
        calibration_status = "NOT_ESTABLISHED"
        brier = None
        bins: tuple[CalibrationBinSnapshot, ...] = ()
    else:
        deltas = [int(item.memory_on_success) - int(item.memory_off_success) for item in ordered_twins]
        uplift = _signed_mean(deltas, scale=1_000_000)
        radius = _paired_uncertainty_radius(policy, sample_size)
        low = max(-1_000_000, uplift - radius)
        high = min(1_000_000, uplift + radius)
        false_count = sum(item.memory_on_false_learn for item in ordered_twins)
        false_rate = _signed_mean([int(item.memory_on_false_learn) for item in ordered_twins], scale=1_000_000)
        false_upper = 1_000_000 if sample_size == 0 else min(1_000_000, false_rate + radius)
        information_delta = _signed_mean(
            [
                item.memory_on_information_value_units
                - item.memory_off_information_value_units
                for item in ordered_twins
            ]
        )
        debt_delta = _signed_mean(
            [
                item.memory_on_research_debt_units
                - item.memory_off_research_debt_units
                for item in ordered_twins
            ]
        )
        reasons_set: set[str] = set()
        if sample_size == 0:
            reasons_set.add("NO_MEMORY_TWIN_OBSERVATIONS")
        if sample_size < policy.minimum_sample_pairs:
            reasons_set.add("MEMORY_UPLIFT_UNDERPOWERED")
        if low <= 0:
            reasons_set.add("MEMORY_UPLIFT_LOWER_BOUND_NOT_POSITIVE")
        if false_count:
            reasons_set.add("MEMORY_FALSE_LEARN_OBSERVED")
        if debt_delta > 0:
            reasons_set.add("MEMORY_RESEARCH_DEBT_INCREASED")
        if not reasons_set:
            status = "MEMORY_UPLIFT_MEASURED_SCOPED"
            reasons_set.add("PASS_FOR_FROZEN_SHADOW_SCOPE")
        else:
            status = "NOT_ESTABLISHED"
        reasons = tuple(sorted(reasons_set))
        bins, brier = _calibration_summary(policy, ordered_calibration)
        calibration_status = (
            "COLLECTED_SCOPED"
            if len(ordered_calibration) >= policy.minimum_calibration_observations
            else "NOT_ESTABLISHED"
        )

    capacity = MappingProxyType(
        {
            "scope": "single-process-pure-shadow-evaluation-v1",
            "max_memory_twin_pairs": policy.max_memory_twin_pairs,
            "max_calibration_observations": policy.max_calibration_observations,
            "observed_memory_twin_pairs": sample_size,
            "observed_calibration_observations": len(ordered_calibration),
            "remaining_memory_twin_pairs": max(0, policy.max_memory_twin_pairs - sample_size),
            "remaining_calibration_observations": max(
                0, policy.max_calibration_observations - len(ordered_calibration)
            ),
            "overloaded": capacity_overloaded,
            "backpressure": capacity_overloaded,
            "infrastructure_scale_claimed": False,
        }
    )
    material = {
        "version": "memory-uplift-snapshot-v1",
        "policy_sha256": policy.profile_sha256,
        "full_replay_sha256": first_replay.replay_sha256,
        "memory_off_fabric_sha256": memory_off.fabric_sha256,
        "memory_on_fabric_sha256": memory_on.fabric_sha256,
        "status": status,
        "reason_codes": reasons,
        "sample_pairs": sample_size,
        "uplift_ppm": uplift,
        "uncertainty_low_ppm": low,
        "uncertainty_high_ppm": high,
        "memory_on_false_learn_rate_ppm": false_rate,
        "false_learn_upper_bound_ppm": false_upper,
        "information_value_delta_units": information_delta,
        "research_debt_delta_units": debt_delta,
        "calibration_observations": len(ordered_calibration),
        "calibration_status": calibration_status,
        "calibration_brier_ppm": brier,
        "calibration_bins": [_calibration_bin_material(item) for item in bins],
        "capacity_envelope": capacity,
        "learned_claimed": False,
        "calibrated_claimed": False,
        "claims_scientific_truth": False,
        "side_effects": False,
        "grants_authority": False,
    }
    return MemoryUpliftSnapshot(
        version="memory-uplift-snapshot-v1",
        policy_sha256=policy.profile_sha256,
        full_replay_sha256=first_replay.replay_sha256,
        memory_off_fabric_sha256=memory_off.fabric_sha256,
        memory_on_fabric_sha256=memory_on.fabric_sha256,
        status=status,
        reason_codes=reasons,
        sample_pairs=sample_size,
        uplift_ppm=uplift,
        uncertainty_low_ppm=low,
        uncertainty_high_ppm=high,
        memory_on_false_learn_rate_ppm=false_rate,
        false_learn_upper_bound_ppm=false_upper,
        information_value_delta_units=information_delta,
        research_debt_delta_units=debt_delta,
        calibration_observations=len(ordered_calibration),
        calibration_status=calibration_status,
        calibration_brier_ppm=brier,
        calibration_bins=bins,
        capacity_envelope=capacity,
        snapshot_sha256=_sha(material),
        learned_claimed=False,
        calibrated_claimed=False,
        claims_scientific_truth=False,
        side_effects=False,
        grants_authority=False,
    )


def _validate_full_replay(report: FeedbackReplayReport) -> None:
    if not isinstance(report, FeedbackReplayReport) or report.side_effects:
        raise EvolutionError("full feedback replay is not a read-only typed report")
    sequence_last = _nonnegative(report.ledger_sequence_last, "replay ledger_sequence_last")
    bundle_count = _nonnegative(report.feedback_bundle_count, "replay feedback_bundle_count")
    if bundle_count == 0:
        if report.first_feedback_sequence is not None or report.last_feedback_sequence is not None:
            raise EvolutionError("empty feedback replay has sequence bounds")
    else:
        first = _positive(report.first_feedback_sequence, "first_feedback_sequence")
        last = _positive(report.last_feedback_sequence, "last_feedback_sequence")
        if not first <= last <= sequence_last:
            raise EvolutionError("feedback replay sequence bounds are invalid")
    rebuilt = dict(report.rebuilt_projection_sha256)
    stored = dict(report.stored_projection_sha256)
    if rebuilt != stored:
        raise EvolutionError("full feedback replay differs from stored projections")
    for name, digest in rebuilt.items():
        _token(name.replace("_", "-"), "replay projection name")
        _digest(digest, "replay projection sha256")
    capacity = report.capacity_envelope
    if not isinstance(capacity, Mapping):
        raise EvolutionError("feedback replay capacity is invalid")
    if (
        capacity.get("writer_count") != 1
        or capacity.get("second_writer_authorized") is not False
        or capacity.get("distributed_scale_claimed") is not False
    ):
        raise EvolutionError("feedback replay capacity boundary widened")
    material = {
        "ledger_sequence_last": sequence_last,
        "feedback_bundle_count": bundle_count,
        "first_feedback_sequence": report.first_feedback_sequence,
        "last_feedback_sequence": report.last_feedback_sequence,
        "rebuilt_projection_sha256": rebuilt,
        "stored_projection_sha256": stored,
        "capacity_envelope": capacity,
        "side_effects": False,
    }
    if report.replay_sha256 != _sha(material):
        raise EvolutionError("full feedback replay integrity mismatch")


def _validate_memory_fabric(
    fabric: KnowledgeFabricReport,
    *,
    expected_enabled: bool,
    replay: FeedbackReplayReport,
) -> None:
    if not isinstance(fabric, KnowledgeFabricReport):
        raise EvolutionError("memory fabric must be a typed report")
    if (
        fabric.fabric_version != "research-knowledge-fabric-v1"
        or fabric.memory_enabled is not expected_enabled
        or fabric.ledger_sequence_last != replay.ledger_sequence_last
        or fabric.side_effects
        or fabric.claims_scientific_truth
        or fabric.grants_authority
    ):
        raise EvolutionError("memory fabric boundary widened")
    trace = fabric.retrieval_trace
    if (
        not isinstance(trace, Mapping)
        or trace.get("trace_type") != "KnowledgeRetrievalTrace"
        or trace.get("memory_enabled") is not expected_enabled
        or trace.get("source_replay_sha256") != replay.replay_sha256
        or trace.get("side_effects") is not False
    ):
        raise EvolutionError("memory fabric is not bound to full replay")
    if not expected_enabled and (
        fabric.idea_nodes
        or fabric.failure_memory
        or fabric.conflict_candidates
        or fabric.root_event_energy
        or fabric.research_debt
        or trace.get("selected_records") != 0
    ):
        raise EvolutionError("memory-off fabric contains retrieved memory")
    material = {
        "fabric_version": fabric.fabric_version,
        "ledger_sequence_last": fabric.ledger_sequence_last,
        "memory_enabled": fabric.memory_enabled,
        "query_root_event_ref": fabric.query_root_event_ref,
        "idea_nodes": fabric.idea_nodes,
        "failure_memory": fabric.failure_memory,
        "conflict_candidates": fabric.conflict_candidates,
        "root_event_energy": fabric.root_event_energy,
        "research_debt": fabric.research_debt,
        "retrieval_trace": fabric.retrieval_trace,
        "side_effects": False,
        "claims_scientific_truth": False,
        "grants_authority": False,
    }
    if fabric.fabric_sha256 != _sha(material):
        raise EvolutionError("memory fabric integrity mismatch")


def _paired_uncertainty_radius(policy: MemoryEvaluationPolicy, sample_size: int) -> int:
    if sample_size == 0:
        return 1_000_000
    root = max(1, math.isqrt(sample_size))
    return min(
        1_000_000,
        (policy.uncertainty_radius_numerator_ppm + root - 1) // root,
    )


def _signed_mean(values: Sequence[int], *, scale: int = 1) -> int:
    if not values:
        return 0
    total = sum(values) * scale
    sign = -1 if total < 0 else 1
    magnitude = abs(total)
    return sign * ((magnitude + len(values) // 2) // len(values))


def _calibration_summary(
    policy: MemoryEvaluationPolicy,
    observations: Sequence[CalibrationObservation],
) -> tuple[tuple[CalibrationBinSnapshot, ...], int | None]:
    if not observations:
        return (), None
    width = policy.calibration_bin_width_ppm
    grouped: list[list[CalibrationObservation]] = [[] for _ in range(1_000_000 // width)]
    squared_error = 0
    for item in observations:
        grouped[min(len(grouped) - 1, item.confidence_ppm // width)].append(item)
        target = 1_000_000 if item.correct else 0
        squared_error += (item.confidence_ppm - target) ** 2
    bins: list[CalibrationBinSnapshot] = []
    for index, items in enumerate(grouped):
        lower = index * width
        upper = 1_000_000 if index == len(grouped) - 1 else (index + 1) * width - 1
        bins.append(
            CalibrationBinSnapshot(
                lower_ppm=lower,
                upper_ppm=upper,
                observation_count=len(items),
                mean_confidence_ppm=(
                    None
                    if not items
                    else _signed_mean([item.confidence_ppm for item in items])
                ),
                observed_accuracy_ppm=(
                    None
                    if not items
                    else _signed_mean([int(item.correct) for item in items], scale=1_000_000)
                ),
            )
        )
    denominator = len(observations) * 1_000_000
    brier_ppm = (squared_error + denominator // 2) // denominator
    return tuple(bins), brier_ppm


def _calibration_bin_material(item: CalibrationBinSnapshot) -> dict[str, object]:
    return {
        "lower_ppm": item.lower_ppm,
        "upper_ppm": item.upper_ppm,
        "observation_count": item.observation_count,
        "mean_confidence_ppm": item.mean_confidence_ppm,
        "observed_accuracy_ppm": item.observed_accuracy_ppm,
    }


def _genome_component_material(item: GenomeComponent) -> dict[str, object]:
    return {
        "component_ref": item.component_ref, "version": item.version,
        "content_sha256": item.content_sha256,
        "dependency_refs": item.dependency_refs,
        "deny_invariants": item.deny_invariants,
    }


def _benchmark_case_material(item: BenchmarkCase) -> dict[str, object]:
    return {"case_ref":item.case_ref,"fixture_sha256":item.fixture_sha256,"protocol_sha256":item.protocol_sha256,"adversarial":item.adversarial,"known_invalid":item.known_invalid,"classification":"D0_PUBLIC"}


def _evaluation_dimension_material(item: EvaluationDimension) -> dict[str, object]:
    return {"name":item.name,"direction":item.direction,"champion_total":item.champion_total,"challenger_total":item.challenger_total,"delta_units":item.delta_units,"challenger_relation":item.challenger_relation}


def _validate_benchmark(policy: ChallengerEvaluationPolicy, benchmark: BenchmarkSnapshot) -> None:
    if not isinstance(policy,ChallengerEvaluationPolicy) or not isinstance(benchmark,BenchmarkSnapshot) or benchmark.holdout_queries or benchmark.grants_authority:
        raise EvolutionError("benchmark boundary widened")
    rebuilt=build_benchmark_snapshot(policy,evaluator_ref=benchmark.evaluator_ref,evaluator_sha256=benchmark.evaluator_sha256,cases=benchmark.cases)
    if rebuilt != benchmark: raise EvolutionError("benchmark integrity mismatch")


def _validate_mutation_archive(archive: MutationCandidateArchive) -> None:
    if not isinstance(archive,MutationCandidateArchive) or archive.applied_count or archive.side_effects or archive.grants_authority:
        raise EvolutionError("candidate archive boundary widened")
    for x in archive.proposals:
        if x.executable_payload_present or x.mutation_applied or x.generated_code_executed or x.canonical_writes or x.grants_authority:
            raise EvolutionError("candidate proposal boundary widened")
    material={"version":archive.version,"genome_sha256":archive.genome_sha256,"policy_sha256":archive.policy_sha256,"opportunities":[_opportunity_material(x) for x in archive.opportunities],"proposals":[_proposal_material(x) for x in archive.proposals],"parked_gap_refs":archive.parked_gap_refs,"provenance_refs":archive.provenance_refs,"applied_count":0,"side_effects":False,"grants_authority":False}
    if archive.version!="mutation-candidate-archive-v1" or archive.archive_sha256 != _sha(material): raise EvolutionError("candidate archive integrity mismatch")


def _result_map(policy: ChallengerEvaluationPolicy, benchmark: BenchmarkSnapshot, candidate_ref: str, results: Sequence[CandidateCaseResult]) -> dict[str,CandidateCaseResult]:
    if not isinstance(results,Sequence) or isinstance(results,(str,bytes)) or any(not isinstance(x,CandidateCaseResult) for x in results): raise EvolutionError("candidate results must be typed")
    mapped={x.case_ref:x for x in results}
    expected={x.case_ref for x in benchmark.cases}
    if len(mapped)!=len(results) or set(mapped)!=expected: raise EvolutionError("counterfactual twins do not cover exact benchmark cases")
    for x in mapped.values():
        if x.candidate_ref!=candidate_ref or x.benchmark_sha256!=benchmark.benchmark_sha256: raise EvolutionError("candidate result binding mismatch")
        if any(getattr(x,name)>policy.max_metric for name in ("quality_units","information_value_units","cost_units","latency_units","safety_violations")): raise EvolutionError("candidate metric exceeds frozen bound")
    return mapped


def _validate_challenger_report(report: ChampionChallengerReport) -> None:
    if not isinstance(report, ChampionChallengerReport):
        raise EvolutionError("typed champion/challenger report is required")
    if (
        report.version != "champion-challenger-report-v1"
        or report.status not in {
            "CHAMPION_CHALLENGER_PASS", "NOT_ESTABLISHED", "REJECTED_SAFETY"
        }
        or report.single_scalar_score is not None
        or report.winner_promoted
        or report.mutation_applied
        or report.holdout_queries
        or report.side_effects
        or report.grants_authority
    ):
        raise EvolutionError("champion/challenger report boundary widened")
    if tuple(item.name for item in report.dimensions) != (
        "quality_units", "information_value_units", "cost_units",
        "latency_units", "safety_violations",
    ):
        raise EvolutionError("champion/challenger dimensions drifted")
    material = {
        "version": report.version,
        "benchmark_sha256": report.benchmark_sha256,
        "evaluator_ref": report.evaluator_ref,
        "champion_ref": report.champion_ref,
        "challenger_ref": report.challenger_ref,
        "dimensions": [_evaluation_dimension_material(item) for item in report.dimensions],
        "pareto_relation": report.pareto_relation,
        "status": report.status,
        "reason_codes": report.reason_codes,
        "retained_candidate_refs": report.retained_candidate_refs,
        "single_scalar_score": None,
        "winner_promoted": False,
        "mutation_applied": False,
        "holdout_queries": 0,
        "side_effects": False,
        "grants_authority": False,
    }
    if report.report_sha256 != _sha(material):
        raise EvolutionError("champion/challenger report integrity mismatch")


def _validate_canary_scope(
    policy: ShadowCanaryPolicy,
    scope: CanaryScope,
    report: ChampionChallengerReport,
    archive: MutationCandidateArchive,
) -> None:
    if not isinstance(scope, CanaryScope):
        raise EvolutionError("typed canary scope is required")
    if (
        report.status != "CHAMPION_CHALLENGER_PASS"
        or scope.policy_sha256 != policy.profile_sha256
        or scope.archive_sha256 != archive.archive_sha256
        or scope.report_sha256 != report.report_sha256
        or scope.benchmark_sha256 != report.benchmark_sha256
        or scope.candidate_ref != report.challenger_ref
        or scope.candidate_ref not in {item.proposal_ref for item in archive.proposals}
        or scope.classification != "D0_PUBLIC"
        or scope.network_enabled
        or scope.filesystem_write_enabled
        or scope.generated_code_execution_enabled
        or scope.canonical_write_enabled
        or scope.promotion_enabled
        or scope.grants_authority
    ):
        raise EvolutionError("canary scope boundary widened")
    _reference(scope.scope_ref, "canary scope_ref")
    cases = _references(scope.case_refs, "canary case_refs")
    if tuple(sorted(cases)) != scope.case_refs or len(cases) < policy.min_unique_cases:
        raise EvolutionError("canary case scope is not canonical or mature")
    if not policy.min_observations <= scope.max_observations <= policy.max_observations:
        raise EvolutionError("canary observation scope exceeds frozen bounds")
    material = {
        "scope_ref": scope.scope_ref, "policy_sha256": scope.policy_sha256,
        "archive_sha256": scope.archive_sha256,
        "report_sha256": scope.report_sha256,
        "benchmark_sha256": scope.benchmark_sha256,
        "candidate_ref": scope.candidate_ref, "case_refs": scope.case_refs,
        "max_observations": scope.max_observations,
        "classification": "D0_PUBLIC", "network_enabled": False,
        "filesystem_write_enabled": False,
        "generated_code_execution_enabled": False,
        "canonical_write_enabled": False, "promotion_enabled": False,
        "grants_authority": False,
    }
    if scope.scope_sha256 != _sha(material):
        raise EvolutionError("canary scope integrity mismatch")


def _regression_signal(item: ShadowCanaryObservation) -> RegressionSignal | None:
    kinds: list[str] = []
    if item.quality_regression_units:
        kinds.append("quality-regression")
    if item.information_regression_units:
        kinds.append("information-regression")
    if item.cost_regression_units:
        kinds.append("cost-regression")
    if item.latency_regression_units:
        kinds.append("latency-regression")
    if item.safety_violations:
        kinds.append("safety-regression")
    if item.unexpected_failure:
        kinds.append("unexpected-failure")
    if not kinds:
        return None
    material = {
        "observation_ref": item.observation_ref, "case_ref": item.case_ref,
        "regression_kinds": tuple(sorted(kinds)),
    }
    digest = _sha(material)
    return RegressionSignal(
        signal_ref="regression-signal:sha256:" + digest,
        observation_ref=item.observation_ref,
        case_ref=item.case_ref,
        regression_kinds=tuple(sorted(kinds)),
        signal_sha256=digest,
    )


def _regression_signal_material(item: RegressionSignal) -> dict[str, object]:
    return {
        "signal_ref": item.signal_ref, "observation_ref": item.observation_ref,
        "case_ref": item.case_ref, "regression_kinds": item.regression_kinds,
        "signal_sha256": item.signal_sha256,
    }


def _rollback_proposal(
    scope: CanaryScope, signals: Sequence[RegressionSignal]
) -> RollbackProposal:
    signal_refs = tuple(item.signal_ref for item in signals)
    material = {
        "candidate_ref": scope.candidate_ref, "scope_sha256": scope.scope_sha256,
        "regression_signal_refs": signal_refs,
        "reason_code": "SHADOW_CANARY_REGRESSION_DETECTED",
        "state": "WAIT_AUTHORITY", "executable_payload_present": False,
        "rollback_applied": False, "policy_applied": False,
        "canonical_writes": 0, "grants_authority": False,
    }
    return RollbackProposal(
        proposal_ref="rollback-proposal:sha256:" + _sha(material), **material
    )


def _rollback_proposal_material(item: RollbackProposal) -> dict[str, object]:
    return {
        "proposal_ref": item.proposal_ref, "candidate_ref": item.candidate_ref,
        "scope_sha256": item.scope_sha256,
        "regression_signal_refs": item.regression_signal_refs,
        "reason_code": item.reason_code, "state": "WAIT_AUTHORITY",
        "executable_payload_present": False, "rollback_applied": False,
        "policy_applied": False, "canonical_writes": 0,
        "grants_authority": False,
    }


def _opportunity_material(item: ImprovementOpportunity) -> dict[str, object]:
    return {
        "opportunity_ref": item.opportunity_ref, "gap_ref": item.gap_ref,
        "genome_ref": item.genome_ref,
        "target_component_ref": item.target_component_ref,
        "reason_code": item.reason_code, "objective_code": item.objective_code,
        "evidence_refs": item.evidence_refs,
        "blast_radius_refs": item.blast_radius_refs, "status": item.status,
        "grants_authority": False,
    }


def _proposal_material(item: MutationProposal) -> dict[str, object]:
    return {
        "proposal_ref": item.proposal_ref, "opportunity_ref": item.opportunity_ref,
        "genome_ref": item.genome_ref,
        "target_component_ref": item.target_component_ref,
        "mutation_kind": item.mutation_kind, "objective_code": item.objective_code,
        "blast_radius_refs": item.blast_radius_refs,
        "retained_deny_invariants": item.retained_deny_invariants,
        "added_deny_invariants": item.added_deny_invariants,
        "state": item.state, "executable_payload_present": False,
        "mutation_applied": False, "generated_code_executed": False,
        "canonical_writes": 0, "grants_authority": False,
    }


def _assert_acyclic_genome(components: Sequence[GenomeComponent]) -> None:
    graph = {item.component_ref: item.dependency_refs for item in components}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise EvolutionError("genome dependency cycle detected")
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(graph):
        visit(node)


def _blast_radius(
    components: Sequence[GenomeComponent], target: str
) -> tuple[str, ...]:
    reverse: dict[str, set[str]] = {item.component_ref: set() for item in components}
    for item in components:
        for dependency in item.dependency_refs:
            reverse[dependency].add(item.component_ref)
    reached = {target}
    frontier = [target]
    while frontier:
        current = frontier.pop()
        for dependent in sorted(reverse[current]):
            if dependent not in reached:
                reached.add(dependent)
                frontier.append(dependent)
    return tuple(sorted(reached))


def _validate_genome_snapshot(
    policy: EvolutionGenomePolicy, genome: GenomeSnapshot
) -> None:
    if not isinstance(policy, EvolutionGenomePolicy) or not isinstance(genome, GenomeSnapshot):
        raise EvolutionError("typed genome policy and snapshot are required")
    if (
        genome.version != "evolution-genome-v1"
        or genome.policy_sha256 != policy.profile_sha256
        or genome.mutation_authority
        or not genome.components
        or len(genome.components) > policy.max_components
    ):
        raise EvolutionError("genome snapshot boundary widened")
    material = {
        "version": genome.version, "subject_ref": genome.subject_ref,
        "policy_sha256": genome.policy_sha256,
        "components": [_genome_component_material(item) for item in genome.components],
        "mutation_authority": False,
    }
    if genome.genome_sha256 != _sha(material):
        raise EvolutionError("genome snapshot integrity mismatch")
    rebuilt = build_genome_snapshot(
        policy, subject_ref=genome.subject_ref, components=genome.components
    )
    if rebuilt != genome:
        raise EvolutionError("genome snapshot is not canonical")


def _score(
    item: AgendaItem,
    policy: PortfolioPolicy,
    current_sequence: int,
    diversity_counts: Mapping[str, int],
) -> int:
    age = max(0, current_sequence - item.created_sequence)
    return (
        item.value_units * policy.value_weight
        - item.cost_units * policy.cost_weight
        - item.risk_units * policy.risk_weight
        + (policy.diversity_bonus if diversity_counts.get(item.diversity_key, 0) == 0 else 0)
        + (policy.starvation_bonus if age >= policy.starvation_after_sequences else 0)
    )


def _agenda_item_material(item: AgendaItem) -> dict[str, object]:
    return {
        "item_id": item.item_id, "debt_ref": item.debt_ref,
        "root_event_ref": item.root_event_ref, "outcome_ref": item.outcome_ref,
        "next_event_ref": item.next_event_ref, "diversity_key": item.diversity_key,
        "value_units": item.value_units, "cost_units": item.cost_units,
        "risk_units": item.risk_units, "created_sequence": item.created_sequence,
        "remaining_energy": item.remaining_energy, "shadow_taint": item.shadow_taint,
        "safe_to_run": item.safe_to_run, "provenance_refs": item.provenance_refs,
    }


def _portfolio_entry_material(item: PortfolioEntry) -> dict[str, object]:
    return {
        "item_id": item.item_id, "outcome_ref": item.outcome_ref, "score": item.score,
        "status": item.status, "reason_code": item.reason_code,
        "selected_rank": item.selected_rank,
        "next_trigger": None if item.next_trigger is None else dict(item.next_trigger),
    }


def _evidence_material(item: EvidenceDescriptor) -> dict[str, object]:
    return {
        "evidence_ref": item.evidence_ref,
        "classification": item.classification,
        "content_sha256": item.content_sha256,
        "source_group": item.source_group,
        "dimension_groups": item.dimension_groups,
        "synthetic": item.synthetic,
        "shadow_taint": item.shadow_taint,
    }


def _dimension_result_material(item: ReplicationDimensionResult) -> dict[str, object]:
    return {
        "dimension": item.dimension,
        "parent_group": item.parent_group,
        "child_group": item.child_group,
        "verification_refs": item.verification_refs,
        "status": item.status,
    }


def _pair_result_material(item: ReplicationPairResult) -> dict[str, object]:
    return {
        "parent_trial_ref": item.parent_trial_ref,
        "child_trial_ref": item.child_trial_ref,
        "original_outcome_ref": item.original_outcome_ref,
        "replication_outcome_ref": item.replication_outcome_ref,
        "dimensions": [_dimension_result_material(value) for value in item.dimensions],
        "overall_status": item.overall_status,
        "pair_sha256": item.pair_sha256,
    }


def _island_material(item: ResearchIslandSpec) -> dict[str, object]:
    return {
        "island_id": item.island_id,
        "workspace_namespace_ref": item.workspace_namespace_ref,
        "model_context_ref": item.model_context_ref,
        "classification": item.classification,
        "trial_refs": item.trial_refs,
        "evidence_refs": item.evidence_refs,
        "exposures": [
            {
                "evaluator_ref": value.evaluator_ref,
                "candidate_lineage": value.candidate_lineage,
                "trial_family_ref": value.trial_family_ref,
                "day_bucket": value.day_bucket,
                "feedback_class": value.feedback_class,
                "query_count": value.query_count,
                "true_holdout": value.true_holdout,
            }
            for value in item.exposures
        ],
        "network_enabled": False,
        "canonical_write_enabled": False,
    }


def _validate_sidecar(policy: ReplicationPolicy, sidecar: EvidenceSidecar) -> None:
    if not isinstance(policy, ReplicationPolicy) or not isinstance(sidecar, EvidenceSidecar):
        raise EvolutionError("typed replication policy and evidence sidecar are required")
    if (
        sidecar.version != "evidence-sidecar-v1"
        or sidecar.raw_payloads_present
        or sidecar.side_effects
        or sidecar.grants_authority
        or len(sidecar.descriptors) > policy.max_evidence_items
    ):
        raise EvolutionError("evidence sidecar boundary widened")
    material = {
        "version": sidecar.version,
        "descriptors": [_evidence_material(item) for item in sidecar.descriptors],
        "raw_payloads_present": False,
        "side_effects": False,
        "grants_authority": False,
    }
    if sidecar.sidecar_sha256 != _sha(material):
        raise EvolutionError("evidence sidecar integrity mismatch")


def _validate_matrix_snapshot(policy: ReplicationPolicy, matrix: ReplicationMatrixSnapshot) -> None:
    if (
        matrix.version != "replication-matrix-v1"
        or matrix.absolute_independence_claimed
        or matrix.linear_replication_level is not None
        or matrix.side_effects
        or matrix.grants_authority
        or not matrix.pairs
        or len(matrix.pairs) > policy.max_replication_pairs
    ):
        raise EvolutionError("replication matrix boundary widened")
    for pair in matrix.pairs:
        if tuple(item.dimension for item in pair.dimensions) != _REPLICATION_DIMENSIONS:
            raise EvolutionError("replication matrix dimensions drifted")
        pair_material = {
            "parent_trial_ref": pair.parent_trial_ref,
            "child_trial_ref": pair.child_trial_ref,
            "original_outcome_ref": pair.original_outcome_ref,
            "replication_outcome_ref": pair.replication_outcome_ref,
            "dimensions": [_dimension_result_material(item) for item in pair.dimensions],
            "overall_status": pair.overall_status,
        }
        if pair.pair_sha256 != _sha(pair_material):
            raise EvolutionError("replication pair integrity mismatch")
    material = {
        "version": matrix.version,
        "evidence_sidecar_sha256": matrix.evidence_sidecar_sha256,
        "pairs": [_pair_result_material(item) for item in matrix.pairs],
        "absolute_independence_claimed": False,
        "linear_replication_level": None,
        "side_effects": False,
        "grants_authority": False,
    }
    if matrix.matrix_sha256 != _sha(material):
        raise EvolutionError("replication matrix integrity mismatch")


def _validate_island_snapshot(policy: ReplicationPolicy, islands: ResearchIslandSnapshot) -> None:
    if (
        islands.version != "research-islands-v1"
        or islands.side_effects
        or islands.grants_authority
        or not islands.islands
        or len(islands.islands) > policy.max_islands
        or islands.status not in {"READY_METADATA_ONLY", "PARKED_EXPOSURE"}
    ):
        raise EvolutionError("research island snapshot boundary widened")
    material = {
        "version": islands.version,
        "evidence_sidecar_sha256": islands.evidence_sidecar_sha256,
        "islands": [_island_material(item) for item in islands.islands],
        "status": islands.status,
        "reason_codes": islands.reason_codes,
        "weighted_exposure_units": islands.weighted_exposure_units,
        "side_effects": False,
        "grants_authority": False,
    }
    if islands.snapshot_sha256 != _sha(material):
        raise EvolutionError("research island snapshot integrity mismatch")


def _policy_material(policy: PortfolioPolicy) -> dict[str, object]:
    return {
        "policy_id": policy.policy_id, "max_slots": policy.max_slots,
        "max_total_cost_units": policy.max_total_cost_units,
        "max_total_risk_units": policy.max_total_risk_units,
        "max_per_diversity_key": policy.max_per_diversity_key,
        "value_weight": policy.value_weight, "cost_weight": policy.cost_weight,
        "risk_weight": policy.risk_weight, "diversity_bonus": policy.diversity_bonus,
        "starvation_after_sequences": policy.starvation_after_sequences,
        "starvation_bonus": policy.starvation_bonus,
    }


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise EvolutionError(f"{name} must be sha256")
    return value


def _load_exact_json(path: str | Path, expected_sha256: str, label: str) -> dict[str, object]:
    _digest(expected_sha256, f"{label} expected_sha256")
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise EvolutionError(f"{label} is unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise EvolutionError(f"{label} digest mismatch")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvolutionError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvolutionError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise EvolutionError(f"{label} must be an object")
    return value


def _reference(value: object, name: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise EvolutionError(f"{name} must be a portable reference")
    if value.lower().startswith(("file:", "host:")) or value.startswith(("/", "~")):
        raise EvolutionError(f"{name} cannot reference a local path or host")
    return value


def _references(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise EvolutionError(f"{name} must be a non-empty sequence")
    result = tuple(_reference(item, name) for item in value)
    if len(result) != len(set(result)):
        raise EvolutionError(f"{name} must be unique")
    return result


def _optional_references(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise EvolutionError(f"{name} must be a sequence")
    result = tuple(_reference(item, name) for item in value)
    if len(result) != len(set(result)):
        raise EvolutionError(f"{name} must be unique")
    return result


def _deny_invariants(
    value: object, name: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, tuple) or (not allow_empty and not value):
        raise EvolutionError(f"{name} must be a tuple")
    result = tuple(_token(item, name) for item in value)
    if result != tuple(sorted(set(result))):
        raise EvolutionError(f"{name} must be sorted and unique")
    return result


def _token(value: object, name: str) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise EvolutionError(f"{name} is invalid")
    return value


def _nonnegative(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise EvolutionError(f"{name} must be a non-negative safe integer")
    return value


def _positive(value: object, name: str) -> int:
    result = _nonnegative(value, name)
    if result == 0:
        raise EvolutionError(f"{name} must be positive")
    return result


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _json_ready(value), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value
