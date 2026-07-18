"""Pure bounded evolution planning over non-authoritative operational memory."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
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
