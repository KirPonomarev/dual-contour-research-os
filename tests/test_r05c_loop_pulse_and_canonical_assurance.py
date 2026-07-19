from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.ledger import JobLedger
from research_bridge.organism import project_organism_state_from_ledger, sample_pulse
from tests import test_r03c_corridor_hostile_assurance as _corridor
from tests.test_a1_storage_v2 import AT, projection_states
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS, feedback_kwargs
from tests.test_s12_state_pulse import ENVIRONMENT, _capability, _manifest, _policy, _state


PROJECTED_AT = "2026-07-19T06:00:01Z"


class LoopPulseCanonicalAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _corridor.CorridorHostileAssuranceTests(methodName="runTest")
        self.harness.setUp()
        self.addCleanup(self.harness.tearDown)

    def _project(self, ledger: JobLedger):
        return project_organism_state_from_ledger(
            ledger,
            _manifest(),
            projected_at=PROJECTED_AT,
            environment_ref=ENVIRONMENT,
            ai_enabled=True,
        )

    def test_invalid_completed_full_loop_is_visible_non_green_and_restart_stable(self) -> None:
        daemon = self.harness._daemon()
        daemon.start()
        empty_ref = self.harness._publish_input(daemon, b"")
        bundle, _ = self.harness._authority_bundle(
            daemon,
            suffix="r05c-invalid-tail",
            evidence_ref=empty_ref,
        )
        self.assertIsInstance(bundle, dict)
        with self.assertRaises(Exception):
            self.harness._submit(daemon, bundle)

        ledger = daemon._ledger
        self.assertIsInstance(ledger, JobLedger)
        changes = ledger._connection.total_changes
        before = self._project(ledger)
        pulse = sample_pulse(
            before, _manifest(), [_capability()], _policy(), sampled_at=PROJECTED_AT
        )
        self.assertEqual(before["payload"]["lifecycle_state"], "PARKED")
        self.assertEqual(before["payload"]["queue"]["parked"], 1)
        self.assertIn(
            "COMPLETED_WITHOUT_VALIDATED_FEEDBACK",
            before["payload"]["reason_codes"],
        )
        self.assertNotEqual(pulse["payload"]["traffic_light"], "GREEN")
        self.assertFalse(pulse["payload"]["side_effects"])
        self.assertFalse(pulse["payload"]["grants_authority"])
        self.assertEqual(ledger._connection.total_changes, changes)

        daemon.close()
        reopened = self.harness._daemon()
        reopened.start()
        reopened_ledger = reopened._ledger
        self.assertIsInstance(reopened_ledger, JobLedger)
        after = self._project(reopened_ledger)
        self.assertEqual(after, before)
        self.assertEqual(after["object_id"], before["object_id"])
        self.assertEqual(reopened_ledger.event_count("complete"), 1)
        self.assertEqual(reopened_ledger.replay_feedback().feedback_bundle_count, 0)

        valid_bundle, _ = self.harness._authority_bundle(
            reopened,
            suffix="r05c-valid-after-invalid",
        )
        self.assertIsInstance(valid_bundle, dict)
        valid = self.harness._submit(reopened, valid_bundle)
        self.assertIsNotNone(valid.result["feedback"])
        still_visible = self._project(reopened_ledger)
        self.assertEqual(still_visible["payload"]["lifecycle_state"], "PARKED")
        self.assertIn(
            "COMPLETED_WITHOUT_VALIDATED_FEEDBACK",
            still_visible["payload"]["reason_codes"],
        )

    def test_duplicate_runnable_producer_is_parked_and_never_green(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with JobLedger(Path(temporary) / "duplicate.sqlite3") as ledger:
                ledger.append_a1_bundle(
                    objects=BASE_DOCUMENTS,
                    projections=projection_states("r05c-duplicate"),
                    idempotency_key="r05c-duplicate-base",
                    event_at=AT,
                )
                ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
                second = deepcopy(feedback_kwargs())
                second.update(
                    execution_ref="execution:receipt-synthetic-two",
                    validation_ref="validation:receipt-synthetic-two",
                    root_event_ref="material-event:root-synthetic-two",
                    parent_event_ref="material-event:parent-synthetic-two",
                    parked_gap_refs=["agenda-gap:synthetic-parked-two"],
                    idempotency_key="feedback-synthetic-two",
                )
                ledger.append_feedback_bundle(**second)  # type: ignore[arg-type]
                changes = ledger._connection.total_changes
                state = self._project(ledger)
                pulse = sample_pulse(
                    state, _manifest(), [_capability()], _policy(), sampled_at=PROJECTED_AT
                )
                self.assertEqual(state["payload"]["lifecycle_state"], "PARKED")
                self.assertIn("MULTIPLE_RUNNABLE_PRODUCERS", state["payload"]["reason_codes"])
                self.assertEqual(state["payload"]["queue"]["runnable"], 2)
                self.assertGreaterEqual(state["payload"]["queue"]["parked"], 1)
                self.assertNotEqual(pulse["payload"]["traffic_light"], "GREEN")
                self.assertEqual(ledger._connection.total_changes, changes)

    def test_stale_source_or_provider_proof_is_red_and_requests_no_action(self) -> None:
        capabilities = [
            _capability(capability_id="SOURCE_INTAKE", status="STALE", critical=True),
            _capability(capability_id="MODEL_PROVIDER", status="FAILED", critical=True),
        ]
        pulse = sample_pulse(
            _state(), _manifest(), capabilities, _policy(), sampled_at="2026-01-02T03:04:06Z"
        )
        self.assertEqual(pulse["payload"]["traffic_light"], "RED")
        self.assertIn("CAPABILITY_NOT_CURRENT", pulse["payload"]["reason_codes"])
        self.assertFalse(pulse["payload"]["side_effects"])
        self.assertFalse(pulse["payload"]["grants_authority"])


if __name__ == "__main__":
    unittest.main()
