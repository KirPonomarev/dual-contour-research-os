from __future__ import annotations

import unittest
from unittest.mock import patch

from tests import test_r03c_corridor_hostile_assurance as _corridor


_canonical = _corridor._canonical
_config = _corridor._config
_plain = _corridor._plain


class FeedbackMemoryNextEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _corridor.CorridorHostileAssuranceTests(methodName="runTest")
        self.harness.setUp()
        self.addCleanup(self.harness.tearDown)

    def test_validated_submit_atomically_closes_memory_and_one_material_event(self) -> None:
        daemon = self.harness._daemon()
        daemon.start()
        bundle, _ = self.harness._authority_bundle(daemon, suffix="r05a-full")
        self.assertIsInstance(bundle, dict)

        submitted = self.harness._submit(daemon, bundle)
        feedback = _plain(submitted.result["feedback"])
        self.assertFalse(feedback["claims_scientific_truth"])
        self.assertFalse(feedback["grants_authority"])
        self.assertEqual(feedback["outcome_disposition"]["epistemic_axis"], "UNRESOLVED")
        self.assertEqual(feedback["experience_record"]["memory_class"], "INCONCLUSIVE")
        self.assertFalse(feedback["experience_record"]["claims_learning"])
        self.assertEqual(feedback["idea_node"]["state"], "GENERATING")
        self.assertEqual(feedback["outbox_record"]["status"], "RUNNABLE")
        self.assertEqual(feedback["outbox_record"]["runnable_count"], 1)
        self.assertTrue(feedback["outbox_record"]["material_event_minted"])

        event = feedback["next_material_event"]
        self.assertEqual(event["schema_id"], "MaterialEvent")
        self.assertEqual(event["payload"]["origin_class"], "ENDOGENOUS")
        self.assertEqual(event["payload"]["event_kind"], "VALIDATED_FEEDBACK")
        self.assertEqual(event["payload"]["causal_depth"], 1)
        self.assertEqual(event["payload"]["shadow_taint"], "SHADOW_UNAPPLIED")
        self.assertEqual(event["payload"]["remaining_energy"]["tokens"], 199_000)
        self.assertEqual(event["payload"]["remaining_energy"]["cost_units"], 98)
        self.assertEqual(
            event["payload"]["materiality_inputs"]["execution_ref"],
            feedback["execution_ref"],
        )

        coverage = daemon._ledger.feedback_projection_coverage()  # type: ignore[union-attr]
        self.assertEqual(set(coverage), {"outcome_dispositions", "experiences", "idea_tree", "feedback_outbox"})
        knowledge = daemon._ledger.research_knowledge_fabric(memory_enabled=True)  # type: ignore[union-attr]
        self.assertEqual(len(knowledge.idea_nodes), 1)
        self.assertEqual(len(knowledge.root_event_energy), 1)
        self.assertTrue(daemon._ledger.verify_chain())  # type: ignore[union-attr]
        self.assertTrue(daemon._ledger.verify_a1_coverage())  # type: ignore[union-attr]

        before_lookup = daemon._ledger.event_count()  # type: ignore[union-attr]
        looked_up = daemon.lookup(job_spec_ref=bundle["job_spec"]["object_id"])
        self.assertEqual(_canonical(looked_up), _canonical(submitted.result))
        self.assertEqual(daemon._ledger.event_count(), before_lookup)  # type: ignore[union-attr]

    def test_restart_recovers_completed_validation_without_reexecuting(self) -> None:
        daemon = self.harness._daemon()
        daemon.start()
        bundle, _ = self.harness._authority_bundle(daemon, suffix="r05a-recover")
        self.assertIsInstance(bundle, dict)
        backend = daemon._a1_backend
        self.assertIsNotNone(backend)
        with patch.object(backend, "close_validated_execution", side_effect=RuntimeError("synthetic tail interruption")):
            with self.assertRaises(Exception):
                self.harness._submit(daemon, bundle)
        completed_count = daemon._ledger.event_count()  # type: ignore[union-attr]
        daemon.close()

        reopened = self.harness._daemon()
        reopened.start()
        after_recovery = reopened._ledger.event_count()  # type: ignore[union-attr]
        self.assertEqual(after_recovery, completed_count + 1)
        result = reopened.lookup(job_spec_ref=bundle["job_spec"]["object_id"])
        self.assertEqual(result["feedback"]["outbox_record"]["runnable_count"], 1)
        self.assertEqual(reopened._ledger.completed_event(bundle["job_spec"]["object_id"]).event_type, "complete")  # type: ignore[union-attr]
        reopened.close()

        second = self.harness._daemon()
        second.start()
        self.assertEqual(second._ledger.event_count(), after_recovery)  # type: ignore[union-attr]

    def test_exhausted_root_energy_yields_exact_wait_authority_and_no_event(self) -> None:
        config = _config(self.harness.runtime)
        cycle = config["a1_limits"]["cycle_limits"]
        cycle["max_tokens"] = 1_000
        cycle["max_cost_units"] = 2
        daemon = self.harness._daemon(config=config)
        daemon.start()
        bundle, _ = self.harness._authority_bundle(daemon, suffix="r05a-exhaust")
        self.assertIsInstance(bundle, dict)

        submitted = self.harness._submit(daemon, bundle)
        feedback = submitted.result["feedback"]
        self.assertEqual(feedback["idea_node"]["state"], "WAIT_AUTHORITY")
        self.assertEqual(feedback["outbox_record"]["status"], "WAIT_AUTHORITY")
        self.assertEqual(feedback["outbox_record"]["runnable_count"], 0)
        self.assertFalse(feedback["outbox_record"]["material_event_minted"])
        self.assertIsNone(feedback["outbox_record"]["internal_event_trigger"])
        self.assertIsNone(feedback["next_material_event"])
        self.assertEqual(len(feedback["outbox_record"]["parked_gap_refs"]), 1)
        states = daemon._a1_backend._states()  # type: ignore[union-attr]
        self.assertEqual(len(states["material_events"]["events"]), 1)


if __name__ == "__main__":
    unittest.main()
