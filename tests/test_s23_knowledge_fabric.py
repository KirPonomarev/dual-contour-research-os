from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import research_bridge.ledger as ledger_module  # noqa: E402
from research_bridge.ledger import (  # noqa: E402
    FeedbackBundleRecord,
    JobLedger,
    KnowledgeFabricReport,
    LedgerError,
)
from tests.test_a1_storage_v2 import AT, projection_states  # noqa: E402
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS, feedback_kwargs  # noqa: E402


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def thaw(value: object) -> dict[str, object]:
    return json.loads(ledger_module._canonical_json(value))


def reseal(prefix: str, value: dict[str, object]) -> None:
    payload = {key: item for key, item in value.items() if key != "object_id"}
    value["object_id"] = prefix + hashlib.sha256(canonical(payload).encode()).hexdigest()


class KnowledgeFabricTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "knowledge.sqlite3"
        self.ledger = JobLedger(self.database)
        self.addCleanup(self.ledger.close)
        self.ledger.append_a1_bundle(
            objects=BASE_DOCUMENTS,
            projections=projection_states("knowledge-base"),
            idempotency_key="knowledge-base-bundle",
            event_at=AT,
        )

    def test_memory_off_on_is_measurable_deterministic_and_zero_write(self) -> None:
        self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        changes = self.ledger._connection.total_changes
        event_count = self.ledger.event_count()

        disabled = self.ledger.research_knowledge_fabric(memory_enabled=False)
        enabled = self.ledger.research_knowledge_fabric(memory_enabled=True)
        replay = self.ledger.research_knowledge_fabric(memory_enabled=True)

        self.assertIsInstance(enabled, KnowledgeFabricReport)
        self.assertEqual(enabled, replay)
        self.assertNotEqual(disabled.fabric_sha256, enabled.fabric_sha256)
        self.assertEqual(disabled.idea_nodes, ())
        self.assertEqual(disabled.retrieval_trace["selected_records"], 0)
        self.assertEqual(disabled.retrieval_trace["excluded"]["memory_disabled"], 1)
        self.assertEqual(len(enabled.idea_nodes), 1)
        self.assertEqual(enabled.retrieval_trace["selected_records"], 1)
        self.assertFalse(enabled.claims_scientific_truth)
        self.assertFalse(enabled.grants_authority)
        self.assertFalse(enabled.side_effects)
        self.assertEqual(self.ledger._connection.total_changes, changes)
        self.assertEqual(self.ledger.event_count(), event_count)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            enabled.fabric_sha256 = "0" * 64  # type: ignore[misc]

    def test_typed_provenance_failure_energy_debt_and_root_filter(self) -> None:
        failed = self.ledger.append_feedback_bundle(
            **feedback_kwargs(  # type: ignore[arg-type]
                mechanical_axis="MECHANICAL_FAILURE",
                proposed_outcome="PROVIDER_FAILURE",
                blame_axis="PROVIDER",
                next_event_candidate=None,
            )
        )
        report = self.ledger.research_knowledge_fabric(
            memory_enabled=True,
            root_event_ref="material-event:root-synthetic-one",
        )
        self.assertEqual(report.idea_nodes[0]["record_type"], "IdeaNode")
        self.assertEqual(report.idea_nodes[0]["shadow_taint"], "SHADOW_UNAPPLIED")
        self.assertEqual(report.idea_nodes[0]["ledger_sequence"], failed.event.sequence)
        self.assertTrue(str(report.idea_nodes[0]["provenance_refs"][0]).startswith("ledger-event:sha256:"))
        self.assertEqual(report.failure_memory[0]["record_type"], "ReusableFailureMemory")
        self.assertEqual(report.failure_memory[0]["blame_axis"], "PROVIDER")
        self.assertEqual(report.root_event_energy[0]["status"], "NO_RUNNABLE_TRIGGER")
        reasons = {item["reason_code"] for item in report.research_debt}
        self.assertTrue({"SHADOW_REVIEW_REQUIRED", "EPISTEMIC_UNRESOLVED", "WAIT_AUTHORITY"} <= reasons)
        empty = self.ledger.research_knowledge_fabric(
            memory_enabled=True, root_event_ref="material-event:absent"
        )
        self.assertEqual(empty.idea_nodes, ())
        self.assertEqual(empty.retrieval_trace["excluded"]["root_filter"], 1)

    def test_domain_supported_and_refuted_become_candidate_not_truth(self) -> None:
        for index, outcome in enumerate(("SUPPORTED", "REFUTED"), start=1):
            self.ledger.append_feedback_bundle(
                **feedback_kwargs(  # type: ignore[arg-type]
                    execution_ref=f"execution:conflict-{index}",
                    validation_ref=f"validation:conflict-{index}",
                    shadow_taint="NONE",
                    proposed_outcome=outcome,
                    domain_application_ref=f"outcome:domain-conflict-{index}",
                    next_event_candidate=None,
                    parked_gap_refs=[],
                    idempotency_key=f"knowledge-conflict-{index}",
                )
            )
        report = self.ledger.research_knowledge_fabric(memory_enabled=True)
        self.assertEqual(len(report.conflict_candidates), 1)
        conflict = report.conflict_candidates[0]
        self.assertEqual(conflict["axes"], ("REFUTED", "SUPPORTED"))
        self.assertEqual(conflict["status"], "REPLICATION_REQUIRED")
        self.assertFalse(conflict["claims_scientific_truth"])
        self.assertEqual(conflict["shadow_taint"], "NONE")
        self.assertIn(
            "CONFLICT_REPLICATION_REQUIRED",
            {item["reason_code"] for item in report.research_debt},
        )

    def test_energy_and_limit_are_exact_not_unbounded(self) -> None:
        for index in range(3):
            self.ledger.append_feedback_bundle(
                **feedback_kwargs(  # type: ignore[arg-type]
                    execution_ref=f"execution:energy-{index}",
                    validation_ref=f"validation:energy-{index}",
                    root_event_ref=f"material-event:energy-root-{index}",
                    parent_event_ref=f"material-event:energy-parent-{index}",
                    idempotency_key=f"knowledge-energy-{index}",
                )
            )
        report = self.ledger.research_knowledge_fabric(memory_enabled=True, limit=2)
        self.assertEqual(len(report.idea_nodes), 2)
        self.assertEqual(report.retrieval_trace["excluded"]["limit"], 1)
        self.assertEqual(len(report.root_event_energy), 2)
        self.assertTrue(
            all(item["observed_remaining_energy"] == 2 for item in report.root_event_energy)
        )
        with self.assertRaises(LedgerError):
            self.ledger.research_knowledge_fabric(memory_enabled=True, limit=257)

    def test_duplicate_execution_is_denied_before_retrieval(self) -> None:
        self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        with self.assertRaisesRegex(LedgerError, "already has a feedback bundle"):
            self.ledger.append_feedback_bundle(
                **feedback_kwargs(idempotency_key="duplicate-knowledge")  # type: ignore[arg-type]
            )

    def test_resealed_truth_claim_and_shadow_laundering_are_rejected(self) -> None:
        original = self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        for mutation in ("truth", "taint"):
            outcome = thaw(original.outcome_disposition)
            experience = thaw(original.experience_record)
            idea = thaw(original.idea_node)
            outbox = thaw(original.outbox_record)
            if mutation == "truth":
                outcome["claims_scientific_truth"] = True
            else:
                outcome["shadow_taint"] = "NONE"
                outcome["disposition"] = "DOMAIN_APPLIED"
                experience["shadow_taint"] = "NONE"
                idea["shadow_taint"] = "NONE"
                trigger = outbox["internal_event_trigger"]
                trigger["shadow_taint"] = "NONE"
                trigger_payload = {key: value for key, value in trigger.items() if key != "trigger_id"}
                trigger["trigger_id"] = "internal-trigger:" + hashlib.sha256(
                    canonical(trigger_payload).encode()
                ).hexdigest()
            reseal("outcome-disposition:", outcome)
            experience["outcome_ref"] = outcome["object_id"]
            reseal("experience:", experience)
            outbox["outcome_ref"] = outcome["object_id"]
            if outbox["internal_event_trigger"] is not None:
                trigger = outbox["internal_event_trigger"]
                trigger["outcome_ref"] = outcome["object_id"]
                trigger_payload = {key: value for key, value in trigger.items() if key != "trigger_id"}
                trigger["trigger_id"] = "internal-trigger:" + hashlib.sha256(
                    canonical(trigger_payload).encode()
                ).hexdigest()
            reseal("feedback-outbox:", outbox)
            idea["outcome_ref"] = outcome["object_id"]
            idea["experience_ref"] = experience["object_id"]
            idea["outbox_ref"] = outbox["object_id"]
            reseal("idea-node:", idea)
            poisoned = FeedbackBundleRecord(
                event=original.event,
                outcome_disposition=outcome,
                experience_record=experience,
                idea_node=idea,
                outbox_record=outbox,
            )
            with self.assertRaisesRegex(LedgerError, "cannot claim|taint or disposition"):
                ledger_module._validate_feedback_knowledge_material(poisoned)

    def test_restart_preserves_exact_fabric_hash(self) -> None:
        self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        before = self.ledger.research_knowledge_fabric(memory_enabled=True)
        self.ledger.close()
        with JobLedger(self.database) as reopened:
            after = reopened.research_knowledge_fabric(memory_enabled=True)
            self.assertEqual(after, before)
            self.assertTrue(reopened.verify_chain())
            self.assertTrue(reopened.verify_a1_coverage())


if __name__ == "__main__":
    unittest.main()
