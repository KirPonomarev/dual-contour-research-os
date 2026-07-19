from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge import execution as _execution
from research_bridge.execution import ExecutionError
from research_bridge.researchd import (
    _L0_VALIDATOR_ID,
    _L0_VALIDATOR_SOURCE_SHA256,
)
from tests import test_r03c_corridor_hostile_assurance as _corridor


class IndependentValidationClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _corridor.CorridorHostileAssuranceTests(methodName="runTest")
        self.harness.setUp()
        self.addCleanup(self.harness.tearDown)

    def test_empty_registered_input_never_reaches_validation_or_feedback(self) -> None:
        daemon = self.harness._daemon()
        daemon.start()
        empty_ref = self.harness._publish_input(daemon, b"")
        bundle, _ = self.harness._authority_bundle(
            daemon,
            suffix="r05b-empty",
            evidence_ref=empty_ref,
        )
        self.assertIsInstance(bundle, dict)
        with self.assertRaises(Exception):
            self.harness._submit(daemon, bundle)
        self.assertEqual(daemon._ledger.feedback_projection_coverage(), {})  # type: ignore[union-attr]
        self.assertEqual(
            daemon._ledger.completed_event(bundle["job_spec"]["object_id"]).event_type,  # type: ignore[union-attr]
            "complete",
        )
        daemon.close()

        reopened = self.harness._daemon()
        reopened.start()
        self.assertEqual(reopened._ledger.feedback_projection_coverage(), {})  # type: ignore[union-attr]
        self.assertTrue(reopened._ledger.verify_chain())  # type: ignore[union-attr]
        valid_bundle, _ = self.harness._authority_bundle(
            reopened,
            suffix="r05b-after-invalid",
        )
        valid = self.harness._submit(reopened, valid_bundle)
        self.assertEqual(
            valid.result["validation_receipt"]["payload"]["proposed_outcome"],
            "VALIDATED_MECHANICAL",
        )
        self.assertIsNotNone(valid.result["feedback"])

    def test_valid_nonempty_receipt_is_exact_mechanical_only_and_non_vacuous(self) -> None:
        daemon = self.harness._daemon()
        daemon.start()
        bundle, _ = self.harness._authority_bundle(daemon, suffix="r05b-valid")
        self.assertIsInstance(bundle, dict)
        submitted = self.harness._submit(daemon, bundle)
        validation = submitted.result["validation_receipt"]
        payload = validation["payload"]
        self.assertEqual(payload["holdout_access_ref"], "holdout:none")
        self.assertEqual(payload["proposed_outcome"], "VALIDATED_MECHANICAL")
        self.assertEqual(tuple(payload["reasons"]), ("L0_BYTES_RECOMPUTED",))
        self.assertEqual(payload["reproducibility_class"], "deterministic-offline")
        self.assertEqual(
            payload["tolerances"],
            {"byte_mismatches": 0, "digest_mismatches": 0},
        )
        self.assertTrue(all(value > 0 for value in payload["metrics"].values()))
        self.assertIn(
            "non-vacuous-input-and-chunk-evidence",
            payload["checks_performed"],
        )
        serialized = _corridor._canonical(validation)
        self.assertNotIn(b"model_output", serialized)
        self.assertNotIn(b"critique_output", serialized)
        self.assertNotIn(b"holdout_rows", serialized)

    def test_forged_epistemic_and_vacuity_profiles_fail_at_handoff(self) -> None:
        daemon = self.harness._daemon()
        daemon.start()
        bundle, _ = self.harness._authority_bundle(daemon, suffix="r05b-forged")
        self.assertIsInstance(bundle, dict)
        submitted = self.harness._submit(daemon, bundle)
        execution = _corridor._plain(submitted.result["execution_receipt"])
        original = _corridor._plain(submitted.result["validation_receipt"])
        mutations = {
            "zero-input-bytes": lambda payload: payload["metrics"].update(input_bytes=0),
            "zero-chunks": lambda payload: payload["metrics"].update(chunk_count=0),
            "nonzero-tolerance": lambda payload: payload["tolerances"].update(byte_mismatches=1),
            "holdout": lambda payload: payload.update(holdout_access_ref="holdout:synthetic"),
            "scientific-outcome": lambda payload: payload.update(proposed_outcome="REFUTED"),
            "missing-check": lambda payload: payload["checks_performed"].remove("non-vacuous-input-and-chunk-evidence"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = deepcopy(original)
                mutate(validation["payload"])
                digest = _execution.canonical_json_sha256(validation["payload"])
                validation["integrity"]["payload_sha256"] = digest
                validation["object_id"] = f"validation-receipt-{digest}"
                with self.assertRaises(ExecutionError):
                    _execution._validate_validation_handoff(
                        execution,
                        validation,
                        expected_validator_id=_L0_VALIDATOR_ID,
                        expected_validator_sha256=_L0_VALIDATOR_SOURCE_SHA256,
                        expected_protocol_ref=_corridor.PROTOCOL_REF,
                    )


if __name__ == "__main__":
    unittest.main()
