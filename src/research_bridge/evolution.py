"""Pure bounded evolution planning over non-authoritative operational memory."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping, Sequence

from .ledger import KnowledgeFabricReport


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
