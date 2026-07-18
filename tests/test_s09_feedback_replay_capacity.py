from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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
    FeedbackReplayReport,
    JobLedger,
    LedgerError,
)
from tests.test_a1_storage_v2 import AT, a1_document, projection_states  # noqa: E402
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS, feedback_kwargs  # noqa: E402


class FeedbackReplayCapacityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "replay.sqlite3"

    def base_ledger(self, database: Path | None = None) -> JobLedger:
        ledger = JobLedger(database or self.database)
        ledger.append_a1_bundle(
            objects=BASE_DOCUMENTS,
            projections=projection_states("replay-base"),
            idempotency_key="replay-base-bundle",
            event_at=AT,
        )
        return ledger

    def populated_ledger(self) -> JobLedger:
        ledger = self.base_ledger()
        ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        ledger.append_a1_bundle(
            objects=[a1_document("MaterialEvent", "replay-middle")],
            projections=projection_states("replay-middle"),
            idempotency_key="replay-middle-bundle",
            event_at=AT,
        )
        ledger.append_feedback_bundle(
            **feedback_kwargs(  # type: ignore[arg-type]
                execution_ref="execution:receipt-synthetic-two",
                validation_ref="validation:receipt-synthetic-two",
                root_event_ref="material-event:root-synthetic-two",
                parent_event_ref="material-event:parent-synthetic-two",
                proposed_outcome="INCONCLUSIVE",
                next_event_candidate=None,
                parked_gap_refs=[],
                idempotency_key="feedback-synthetic-two",
            )
        )
        return ledger

    def test_replay_is_deterministic_zero_write_and_capacity_is_honest(self) -> None:
        ledger = self.populated_ledger()
        self.addCleanup(ledger.close)
        changes = ledger._connection.total_changes
        event_count = ledger.event_count()
        coverage = ledger.projection_coverage()

        first = ledger.replay_feedback()
        second = ledger.replay_feedback()
        self.assertIsInstance(first, FeedbackReplayReport)
        self.assertEqual(first, second)
        self.assertEqual(first.replay_sha256, second.replay_sha256)
        self.assertEqual(first.ledger_sequence_last, 4)
        self.assertEqual(first.feedback_bundle_count, 2)
        self.assertEqual(first.first_feedback_sequence, 2)
        self.assertEqual(first.last_feedback_sequence, 4)
        self.assertEqual(first.rebuilt_projection_sha256, first.stored_projection_sha256)
        self.assertFalse(first.side_effects)
        self.assertEqual(ledger._connection.total_changes, changes)
        self.assertEqual(ledger.event_count(), event_count)
        self.assertEqual(ledger.projection_coverage(), coverage)

        capacity = first.capacity_envelope
        self.assertEqual(capacity["writer_count"], 1)
        self.assertFalse(capacity["second_writer_authorized"])
        self.assertFalse(capacity["distributed_scale_claimed"])
        self.assertEqual(capacity["projection_entry_limit_each"], 256)
        self.assertEqual(capacity["parked_gap_refs_per_outcome_limit"], 16)
        self.assertEqual(capacity["causal_depth_limit"], 16)
        observed = capacity["observed"]
        self.assertEqual(observed["projection_entries"]["outcome_dispositions"], 2)
        self.assertEqual(observed["projection_remaining"]["outcome_dispositions"], 254)
        self.assertEqual(observed["runnable_outbox_records"], 1)
        self.assertEqual(observed["wait_authority_outbox_records"], 1)
        self.assertFalse(capacity["throughput_observation"]["rate_claimed"])
        self.assertEqual(
            capacity["throughput_observation"]["kind"],
            "durable-counts-not-wall-clock-rate",
        )
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            first.replay_sha256 = "0" * 64  # type: ignore[misc]

    def test_restart_replay_preserves_wait_authority_and_exact_report(self) -> None:
        ledger = self.populated_ledger()
        before = ledger.replay_feedback()
        wait_record = ledger.feedback_for_execution("execution:receipt-synthetic-two")
        self.assertEqual(wait_record.idea_node["state"], "WAIT_AUTHORITY")
        ledger.close()

        with JobLedger(self.database) as reopened:
            after = reopened.replay_feedback()
            self.assertEqual(after, before)
            recovered = reopened.feedback_for_execution("execution:receipt-synthetic-two")
            self.assertEqual(recovered.idea_node["state"], "WAIT_AUTHORITY")
            self.assertEqual(recovered.outbox_record["runnable_count"], 0)

    def test_empty_feedback_replay_is_valid_and_makes_no_rate_claim(self) -> None:
        ledger = self.base_ledger()
        self.addCleanup(ledger.close)
        report = ledger.replay_feedback()
        self.assertEqual(report.feedback_bundle_count, 0)
        self.assertEqual(report.rebuilt_projection_sha256, {})
        self.assertEqual(report.stored_projection_sha256, {})
        self.assertEqual(report.capacity_envelope["observed"]["feedback_bundles"], 0)
        self.assertFalse(report.capacity_envelope["throughput_observation"]["rate_claimed"])

    def test_descriptor_tamper_and_sequence_gap_fail_closed(self) -> None:
        tampered_db = Path(self.temporary.name) / "descriptor.sqlite3"
        ledger = self.base_ledger(tampered_db)
        ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        ledger._connection.execute("DROP TRIGGER bridge_job_ledger_no_update")
        row = ledger._connection.execute(
            "SELECT * FROM bridge_job_ledger WHERE sequence = 2"
        ).fetchone()
        payload = json.loads(row["payload_json"])
        for descriptor in payload["projections"]:
            if descriptor["projection_name"] == "experiences":
                descriptor["state_sha256"] = "f" * 64
        material = JobLedger._hash_material(
            sequence=2,
            event_type=row["event_type"],
            job_id=row["job_id"],
            attempt_id=row["attempt_id"],
            fencing_epoch=row["fencing_epoch"],
            event_at=row["event_at"],
            payload=payload,
            previous_sha256=row["previous_sha256"],
        )
        ledger._connection.execute(
            "UPDATE bridge_job_ledger SET payload_json = ?, event_sha256 = ? WHERE sequence = 2",
            (ledger_module._canonical_json(payload), hashlib.sha256(material).hexdigest()),
        )
        with self.assertRaisesRegex(LedgerError, "descriptor digest mismatch"):
            ledger.replay_feedback()
        ledger.close()

        gap_db = Path(self.temporary.name) / "gap.sqlite3"
        gap = self.populated_ledger_for(gap_db)
        gap._connection.execute("DROP TRIGGER bridge_job_ledger_no_delete")
        gap._connection.execute("DELETE FROM bridge_job_ledger WHERE sequence = 2")
        with self.assertRaisesRegex(LedgerError, "sequence gap"):
            gap.replay_feedback()
        gap.close()

    def populated_ledger_for(self, database: Path) -> JobLedger:
        original = self.database
        self.database = database
        try:
            return self.populated_ledger()
        finally:
            self.database = original

    def test_stored_projection_mismatch_is_rejected(self) -> None:
        ledger = self.populated_ledger()
        self.addCleanup(ledger.close)
        ledger._connection.execute("DROP TRIGGER bridge_a1_projection_no_regression")
        row = ledger._connection.execute(
            "SELECT state_json FROM bridge_a1_projection_state WHERE projection_name = 'idea_tree'"
        ).fetchone()
        state = json.loads(row["state_json"])
        state["count"] += 1
        ledger._connection.execute(
            "UPDATE bridge_a1_projection_state SET state_json = ? WHERE projection_name = 'idea_tree'",
            (ledger_module._canonical_json(state),),
        )
        with self.assertRaisesRegex(LedgerError, "stored feedback projection digest mismatch"):
            ledger.replay_feedback()

    def test_fault_at_each_feedback_projection_transition_leaves_no_second_trial(self) -> None:
        for projection in (
            "outcome_dispositions",
            "experiences",
            "idea_tree",
            "feedback_outbox",
        ):
            with self.subTest(projection=projection):
                database = Path(self.temporary.name) / f"fault-{projection}.sqlite3"
                ledger = self.base_ledger(database)
                ledger._connection.execute(
                    f"""CREATE TRIGGER synthetic_fault_{projection}
                    BEFORE INSERT ON bridge_a1_projection_state
                    WHEN NEW.projection_name = '{projection}'
                    BEGIN SELECT RAISE(ABORT, 'synthetic transition fault'); END"""
                )
                with self.assertRaisesRegex(LedgerError, "synthetic transition fault"):
                    ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
                self.assertEqual(ledger.event_count(), 1)
                self.assertEqual(ledger.feedback_projection_coverage(), {})
                ledger.close()

    def test_concurrent_identical_feedback_uses_one_single_writer_append(self) -> None:
        ledger = self.base_ledger()
        self.addCleanup(ledger.close)
        with ThreadPoolExecutor(max_workers=4) as executor:
            records = list(
                executor.map(
                    lambda _: ledger.append_feedback_bundle(**feedback_kwargs()),  # type: ignore[arg-type]
                    range(8),
                )
            )
        self.assertEqual(len({record.event.event_sha256 for record in records}), 1)
        self.assertEqual(ledger.event_count(), 2)
        self.assertEqual(ledger.replay_feedback().feedback_bundle_count, 1)


if __name__ == "__main__":
    unittest.main()
