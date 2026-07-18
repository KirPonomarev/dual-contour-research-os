from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge.evolution import (  # noqa: E402
    AgendaItem,
    AgendaProposal,
    EvolutionError,
    PortfolioPolicy,
    build_research_agenda,
    select_portfolio,
)
from research_bridge.ledger import JobLedger  # noqa: E402
from tests.test_a1_storage_v2 import AT, projection_states  # noqa: E402
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS, feedback_kwargs  # noqa: E402


def policy(**overrides: int) -> PortfolioPolicy:
    values = {
        "max_slots": 3,
        "max_total_cost_units": 10,
        "max_total_risk_units": 5,
        "max_per_diversity_key": 1,
        "value_weight": 4,
        "cost_weight": 1,
        "risk_weight": 2,
        "diversity_bonus": 5,
        "starvation_after_sequences": 10,
        "starvation_bonus": 20,
    }
    values.update(overrides)
    return PortfolioPolicy(policy_id="portfolio-policy:s24-v1", **values)


class AgendaPortfolioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger = JobLedger(Path(self.temporary.name) / "agenda.sqlite3")
        self.addCleanup(self.ledger.close)
        self.ledger.append_a1_bundle(
            objects=BASE_DOCUMENTS,
            projections=projection_states("agenda-base"),
            idempotency_key="agenda-base-bundle",
            event_at=AT,
        )

    def knowledge(self, count: int = 3, *, exhausted: set[int] | None = None):
        exhausted = exhausted or set()
        for index in range(count):
            candidate = {
                "reason_code": "FOLLOW_UP",
                "policy_ref": "policy:agenda-v1",
                "remaining_energy": 0 if index in exhausted else 3,
                "causal_depth": 1,
            }
            self.ledger.append_feedback_bundle(
                **feedback_kwargs(  # type: ignore[arg-type]
                    execution_ref=f"execution:agenda-{index}",
                    validation_ref=f"validation:agenda-{index}",
                    root_event_ref=f"material-event:agenda-root-{index}",
                    parent_event_ref=f"material-event:agenda-parent-{index}",
                    next_event_candidate=candidate,
                    parked_gap_refs=[],
                    idempotency_key=f"agenda-feedback-{index}",
                )
            )
        return self.ledger.research_knowledge_fabric(memory_enabled=True)

    @staticmethod
    def proposals(knowledge, *, values: list[dict[str, object]] | None = None):
        energy = list(knowledge.root_event_energy)
        settings = values or [{} for _ in energy]
        result = []
        for index, (entry, overrides) in enumerate(zip(energy, settings, strict=True)):
            base = {
                "debt_ref": entry["source_outcome_ref"],
                "root_event_ref": entry["root_event_ref"],
                "outcome_ref": entry["source_outcome_ref"],
                "next_event_ref": f"internal-event:agenda-next-{index}",
                "diversity_key": f"lane-{index}",
                "value_units": 10 - index,
                "cost_units": 2,
                "risk_units": 1,
                "created_sequence": index,
                "safe_to_run": True,
            }
            base.update(overrides)
            result.append(AgendaProposal(**base))
        return result

    def test_deterministic_selection_is_order_independent_and_zero_side_effect(self) -> None:
        knowledge = self.knowledge()
        proposals = self.proposals(knowledge)
        changes = self.ledger._connection.total_changes
        agenda_a = build_research_agenda(knowledge, proposals)
        agenda_b = build_research_agenda(knowledge, tuple(reversed(proposals)))
        first = select_portfolio(agenda_a, policy(), current_sequence=20)
        second = select_portfolio(agenda_b, policy(), current_sequence=20)
        self.assertEqual(agenda_a, agenda_b)
        self.assertEqual(first, second)
        self.assertEqual(len(first.selected_item_ids), 3)
        self.assertLessEqual(first.used_cost_units, 10)
        self.assertLessEqual(first.used_risk_units, 5)
        self.assertFalse(first.side_effects)
        self.assertFalse(first.grants_authority)
        self.assertEqual(self.ledger._connection.total_changes, changes)
        self.assertTrue(all(entry.next_trigger["grants_authority"] is False for entry in first.entries))
        self.assertEqual(len({entry.outcome_ref for entry in first.entries}), len(first.entries))
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            first.used_cost_units = 999  # type: ignore[misc]

    def test_budget_slot_risk_diversity_and_value_states_are_explicit(self) -> None:
        knowledge = self.knowledge(6)
        proposals = self.proposals(
            knowledge,
            values=[
                {"diversity_key": "same", "cost_units": 3, "risk_units": 1},
                {"diversity_key": "same", "cost_units": 3, "risk_units": 1},
                {"diversity_key": "risk", "risk_units": 5},
                {"diversity_key": "cost", "cost_units": 9},
                {"diversity_key": "zero", "value_units": 0},
                {"diversity_key": "safe", "safe_to_run": False},
            ],
        )
        snapshot = select_portfolio(
            build_research_agenda(knowledge, proposals),
            policy(max_slots=2, max_total_cost_units=5, max_total_risk_units=2),
            current_sequence=2,
        )
        reasons = {entry.reason_code for entry in snapshot.entries}
        self.assertIn("DIVERSITY_CAP_REACHED", reasons)
        self.assertIn("RISK_BUDGET_EXHAUSTED", reasons)
        self.assertIn("COST_BUDGET_EXHAUSTED", reasons)
        self.assertIn("NO_RESEARCH_VALUE", reasons)
        self.assertIn("UNSAFE_POLICY_DENIED", reasons)
        self.assertLessEqual(len(snapshot.selected_item_ids), 2)
        self.assertLessEqual(snapshot.used_cost_units, 5)
        self.assertLessEqual(snapshot.used_risk_units, 2)

    def test_root_energy_exhaustion_parks_without_trigger(self) -> None:
        knowledge = self.knowledge(2, exhausted={0})
        snapshot = select_portfolio(
            build_research_agenda(knowledge, self.proposals(knowledge)),
            policy(max_slots=2, max_per_diversity_key=2),
            current_sequence=3,
        )
        exhausted = [entry for entry in snapshot.entries if entry.reason_code == "ROOT_ENERGY_EXHAUSTED"]
        self.assertEqual(len(exhausted), 1)
        self.assertIsNone(exhausted[0].next_trigger)
        selected = [entry for entry in snapshot.entries if entry.status == "SELECTED"]
        self.assertEqual(selected[0].next_trigger["remaining_energy"], 1)

    def test_diversity_and_starvation_change_priority_without_changing_budget(self) -> None:
        knowledge = self.knowledge(3)
        proposals = self.proposals(
            knowledge,
            values=[
                {"diversity_key": "hot", "value_units": 12, "created_sequence": 19},
                {"diversity_key": "hot", "value_units": 11, "created_sequence": 18},
                {"diversity_key": "cold", "value_units": 5, "created_sequence": 0},
            ],
        )
        snapshot = select_portfolio(
            build_research_agenda(knowledge, proposals),
            policy(max_slots=2, max_per_diversity_key=1, starvation_bonus=40),
            current_sequence=20,
        )
        selected = [entry for entry in snapshot.entries if entry.status == "SELECTED"]
        self.assertEqual(len(selected), 2)
        selected_items = set(snapshot.selected_item_ids)
        agenda = build_research_agenda(knowledge, proposals)
        lanes = {item.diversity_key for item in agenda.items if item.item_id in selected_items}
        self.assertEqual(lanes, {"hot", "cold"})

    def test_duplicate_outcome_or_debt_is_rejected_before_selection(self) -> None:
        knowledge = self.knowledge(2)
        proposals = self.proposals(knowledge)
        duplicate_outcome = replace(
            proposals[1], outcome_ref=proposals[0].outcome_ref
        )
        with self.assertRaisesRegex(EvolutionError, "more than one next-event"):
            build_research_agenda(knowledge, [proposals[0], duplicate_outcome])
        duplicate_debt = replace(proposals[1], debt_ref=proposals[0].debt_ref)
        with self.assertRaisesRegex(EvolutionError, "debt is proposed more than once"):
            build_research_agenda(knowledge, [proposals[0], duplicate_debt])

    def test_forged_knowledge_agenda_and_unbounded_inputs_fail_closed(self) -> None:
        knowledge = self.knowledge(1)
        proposal = self.proposals(knowledge)[0]
        with self.assertRaisesRegex(EvolutionError, "knowledge fabric integrity"):
            build_research_agenda(replace(knowledge, fabric_sha256="0" * 64), [proposal])
        agenda = build_research_agenda(knowledge, [proposal])
        with self.assertRaisesRegex(EvolutionError, "identity does not match"):
            replace(agenda.items[0], value_units=999)
        with self.assertRaisesRegex(EvolutionError, "agenda item bound"):
            build_research_agenda(knowledge, [proposal] * 257)
        with self.assertRaisesRegex(EvolutionError, "max_slots exceeds"):
            policy(max_slots=33)

    def test_unassessed_debt_is_visible_and_shadow_taint_is_inherited(self) -> None:
        knowledge = self.knowledge(2)
        proposal = self.proposals(knowledge)[0]
        agenda = build_research_agenda(knowledge, [proposal])
        self.assertGreater(len(agenda.unassessed_debt_refs), 0)
        self.assertEqual(agenda.items[0].shadow_taint, "SHADOW_UNAPPLIED")
        snapshot = select_portfolio(agenda, policy(max_slots=1), current_sequence=1)
        trigger = next(entry.next_trigger for entry in snapshot.entries if entry.status == "SELECTED")
        self.assertEqual(trigger["shadow_taint"], "SHADOW_UNAPPLIED")
        self.assertFalse(trigger["grants_authority"])


if __name__ == "__main__":
    unittest.main()
