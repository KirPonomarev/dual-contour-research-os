from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge.ledger import (  # noqa: E402
    FeedbackBundleRecord,
    JobLedger,
    LedgerError,
)
from tests.test_a1_storage_v2 import (  # noqa: E402
    AT,
    a1_document,
    projection_states,
)


BASE_DOCUMENTS = (
    a1_document("MaterialEvent", "feedback-base"),
    a1_document("CandidateSpecDraft", "feedback-base"),
    a1_document("AdmissionReceipt", "feedback-base"),
    a1_document("CapabilityProofReceipt", "feedback-base"),
)


def feedback_kwargs(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "execution_ref": "execution:receipt-synthetic-one",
        "validation_ref": "validation:receipt-synthetic-one",
        "root_event_ref": "material-event:root-synthetic-one",
        "parent_event_ref": "material-event:parent-synthetic-one",
        "contour": "bridge",
        "classification": "D1",
        "shadow_taint": "SHADOW_UNAPPLIED",
        "mechanical_axis": "MECHANICAL_SUCCESS",
        "proposed_outcome": "REFUTED",
        "blame_axis": "NONE",
        "domain_application_ref": None,
        "next_event_candidate": {
            "reason_code": "FOLLOWUP_FALSIFIER",
            "policy_ref": "policy:synthetic-a1-v1",
            "remaining_energy": 3,
            "causal_depth": 1,
        },
        "parked_gap_refs": ["agenda-gap:synthetic-parked-one"],
        "idempotency_key": "feedback-synthetic-one",
        "event_at": AT,
    }
    values.update(overrides)
    return values


class AtomicFeedbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "feedback.sqlite3"
        self.ledger = JobLedger(self.database)
        self.addCleanup(self.ledger.close)
        self.ledger.append_a1_bundle(
            objects=BASE_DOCUMENTS,
            projections=projection_states("feedback-base"),
            idempotency_key="feedback-base-bundle",
            event_at=AT,
        )

    def test_shadow_feedback_is_atomic_reference_only_and_replay_safe(self) -> None:
        first = self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        retry = self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]

        self.assertIsInstance(first, FeedbackBundleRecord)
        self.assertEqual(first.event.sequence, 2)
        self.assertEqual(retry.event.event_sha256, first.event.event_sha256)
        self.assertEqual(self.ledger.event_count(), 2)
        self.assertEqual(first.outcome_disposition["disposition"], "SHADOW_UNAPPLIED")
        self.assertEqual(first.outcome_disposition["epistemic_axis"], "UNRESOLVED")
        self.assertEqual(first.outcome_disposition["proposed_outcome"], "REFUTED")
        self.assertFalse(first.outcome_disposition["claims_scientific_truth"])
        self.assertEqual(first.experience_record["memory_class"], "INCONCLUSIVE")
        self.assertFalse(first.experience_record["claims_learning"])
        self.assertEqual(first.idea_node["state"], "GENERATING")
        self.assertFalse(first.idea_node["learned"])
        self.assertEqual(first.outbox_record["status"], "RUNNABLE")
        self.assertEqual(first.outbox_record["runnable_count"], 1)
        self.assertFalse(first.outbox_record["material_event_minted"])

        trigger = first.outbox_record["internal_event_trigger"]
        self.assertEqual(trigger["root_event_ref"], "material-event:root-synthetic-one")
        self.assertEqual(trigger["parent_event_ref"], "material-event:parent-synthetic-one")
        self.assertEqual(trigger["shadow_taint"], "SHADOW_UNAPPLIED")
        self.assertEqual(trigger["causal_depth"], 2)
        self.assertEqual(trigger["remaining_energy"], 2)
        self.assertFalse(trigger["grants_authority"])
        self.assertEqual(
            set(self.ledger.feedback_projection_coverage()),
            {"outcome_dispositions", "experiences", "idea_tree", "feedback_outbox"},
        )
        self.assertTrue(self.ledger.verify_chain())
        self.assertTrue(self.ledger.verify_a1_coverage())

        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            first.event = retry.event  # type: ignore[misc]
        with self.assertRaises((TypeError, AttributeError)):
            first.outbox_record["status"] = "LEARNED"  # type: ignore[index]

    def test_domain_application_controls_positive_negative_and_inconclusive_memory(self) -> None:
        expected = {
            "SUPPORTED": ("SUPPORTED", "POSITIVE"),
            "REFUTED": ("REFUTED", "NEGATIVE"),
            "INCONCLUSIVE": ("INCONCLUSIVE", "INCONCLUSIVE"),
        }
        for index, (proposed, axes) in enumerate(expected.items(), start=1):
            with self.subTest(proposed=proposed):
                database = Path(self.temporary.name) / f"domain-{index}.sqlite3"
                with JobLedger(database) as ledger:
                    ledger.append_a1_bundle(
                        objects=BASE_DOCUMENTS,
                        projections=projection_states(f"domain-{index}"),
                        idempotency_key=f"domain-base-{index}",
                        event_at=AT,
                    )
                    record = ledger.append_feedback_bundle(
                        **feedback_kwargs(  # type: ignore[arg-type]
                            execution_ref=f"execution:domain-{index}",
                            validation_ref=f"validation:domain-{index}",
                            shadow_taint="NONE",
                            proposed_outcome=proposed,
                            domain_application_ref=f"outcome:domain-applied-{index}",
                            next_event_candidate=None,
                            parked_gap_refs=[],
                            idempotency_key=f"domain-feedback-{index}",
                        )
                    )
                    self.assertEqual(record.outcome_disposition["disposition"], "DOMAIN_APPLIED")
                    self.assertEqual(record.outcome_disposition["epistemic_axis"], axes[0])
                    self.assertEqual(record.experience_record["memory_class"], axes[1])
                    self.assertEqual(record.idea_node["state"], "WAIT_AUTHORITY")
                    self.assertFalse(record.idea_node["learned"])
                    self.assertEqual(record.outbox_record["runnable_count"], 0)

    def test_failures_never_become_refutation_or_learning(self) -> None:
        record = self.ledger.append_feedback_bundle(
            **feedback_kwargs(  # type: ignore[arg-type]
                mechanical_axis="MECHANICAL_FAILURE",
                proposed_outcome="PROVIDER_FAILURE",
                blame_axis="PROVIDER",
                next_event_candidate=None,
            )
        )
        self.assertEqual(record.outcome_disposition["epistemic_axis"], "UNRESOLVED")
        self.assertEqual(record.experience_record["memory_class"], "INCONCLUSIVE")
        self.assertTrue(record.experience_record["reusable_failure"])
        self.assertFalse(record.idea_node["learned"])
        self.assertNotEqual(record.idea_node["state"], "LEARNED")

    def test_exhausted_energy_parks_candidate_and_waits_for_authority(self) -> None:
        candidate = deepcopy(feedback_kwargs()["next_event_candidate"])
        candidate["remaining_energy"] = 0  # type: ignore[index]
        record = self.ledger.append_feedback_bundle(
            **feedback_kwargs(next_event_candidate=candidate)  # type: ignore[arg-type]
        )
        self.assertEqual(record.outbox_record["status"], "WAIT_AUTHORITY")
        self.assertEqual(record.outbox_record["runnable_count"], 0)
        self.assertIsNone(record.outbox_record["internal_event_trigger"])
        self.assertEqual(len(record.outbox_record["parked_gap_refs"]), 2)

    def test_invalid_authority_epistemic_and_bounds_combinations_fail_closed(self) -> None:
        invalid = (
            {"classification": "D2"},
            {"shadow_taint": "SHADOW_UNAPPLIED", "domain_application_ref": "outcome:forged"},
            {"mechanical_axis": "MECHANICAL_SUCCESS", "blame_axis": "PROVIDER"},
            {"mechanical_axis": "MECHANICAL_FAILURE", "blame_axis": "NONE"},
            {"proposed_outcome": "LEARNED"},
            {"next_event_candidate": {"reason_code": "X", "policy_ref": "file:/tmp/p", "remaining_energy": 1, "causal_depth": 0}},
            {"parked_gap_refs": [f"agenda-gap:{index}" for index in range(17)]},
        )
        for values in invalid:
            with self.subTest(values=values):
                before = self.ledger.event_count()
                with self.assertRaises(LedgerError):
                    self.ledger.append_feedback_bundle(
                        **feedback_kwargs(**values)  # type: ignore[arg-type]
                    )
                self.assertEqual(self.ledger.event_count(), before)

    def test_transaction_fault_rolls_back_event_and_every_projection(self) -> None:
        base_coverage = self.ledger.projection_coverage()
        self.ledger._connection.execute(
            """CREATE TRIGGER synthetic_feedback_fault
            BEFORE INSERT ON bridge_a1_projection_state
            WHEN NEW.projection_name = 'experiences'
            BEGIN SELECT RAISE(ABORT, 'synthetic feedback fault'); END"""
        )
        with self.assertRaisesRegex(LedgerError, "synthetic feedback fault"):
            self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        self.assertEqual(self.ledger.event_count(), 1)
        self.assertEqual(self.ledger.feedback_projection_coverage(), {})
        self.assertEqual(self.ledger.projection_coverage(), base_coverage)
        self.assertTrue(self.ledger.verify_chain())
        self.ledger._connection.execute("DROP TRIGGER synthetic_feedback_fault")

        recovered = self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        self.assertEqual(recovered.event.sequence, 2)

    def test_restart_lookup_and_later_a1_bundle_preserve_feedback_coverage(self) -> None:
        record = self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        self.ledger.close()
        with JobLedger(self.database) as reopened:
            lookup = reopened.feedback_for_execution("execution:receipt-synthetic-one")
            self.assertEqual(lookup.event.event_sha256, record.event.event_sha256)
            self.assertEqual(lookup.idea_node["state"], "GENERATING")
            legacy_retry = reopened.append_a1_bundle(
                objects=BASE_DOCUMENTS,
                projections=projection_states("feedback-base"),
                idempotency_key="feedback-base-bundle",
                event_at=AT,
            )
            self.assertEqual(legacy_retry.event.sequence, 1)
            self.assertEqual(reopened.event_count(), 2)
            reopened.append_a1_bundle(
                objects=[a1_document("MaterialEvent", "after-feedback")],
                projections=projection_states("after-feedback"),
                idempotency_key="after-feedback-bundle",
                event_at=AT,
            )
            self.assertTrue(reopened.verify_a1_coverage())
            coverage = reopened.projection_coverage()
            self.assertEqual(len(coverage), 8)
            self.assertTrue(
                all(value["last_applied_sequence"] == 3 for value in coverage.values())
            )

    def test_idempotency_conflict_and_second_feedback_for_execution_are_denied(self) -> None:
        self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        with self.assertRaisesRegex(LedgerError, "idempotency key was reused"):
            self.ledger.append_feedback_bundle(
                **feedback_kwargs(proposed_outcome="SUPPORTED")  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(LedgerError, "already has a feedback bundle"):
            self.ledger.append_feedback_bundle(
                **feedback_kwargs(idempotency_key="different-feedback-key")  # type: ignore[arg-type]
            )
        self.assertEqual(self.ledger.event_count(), 2)


if __name__ == "__main__":
    unittest.main()
