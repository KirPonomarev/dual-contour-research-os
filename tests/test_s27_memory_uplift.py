from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.evolution import (  # noqa: E402
    CalibrationObservation,
    EvolutionError,
    MemoryEvaluationPolicy,
    MemoryTwinPair,
    measure_memory_uplift,
)
from research_bridge.ledger import JobLedger  # noqa: E402
from tests.test_a1_storage_v2 import AT, projection_states  # noqa: E402
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS, feedback_kwargs  # noqa: E402


PROFILE = ROOT / "provenance" / "memory-uplift-replay-capacity-v1.json"
PROFILE_SHA = "0a02b65ff5db728bcf75c7368244c9d2071e266055d91519437fdc5316825393"


def twin(
    index: int,
    *,
    off_success: bool = False,
    on_success: bool = True,
    on_false_learn: bool = False,
    off_information: int = 0,
    on_information: int = 2,
    off_debt: int = 1,
    on_debt: int = 0,
) -> MemoryTwinPair:
    return MemoryTwinPair(
        pair_id=f"memory-twin:{index}",
        case_ref=f"synthetic-case:{index}",
        fixture_sha256=f"{index + 1:064x}",
        protocol_sha256="a" * 64,
        base_sha256="b" * 64,
        memory_off_success=off_success,
        memory_on_success=on_success,
        memory_off_false_learn=False,
        memory_on_false_learn=on_false_learn,
        memory_off_information_value_units=off_information,
        memory_on_information_value_units=on_information,
        memory_off_research_debt_units=off_debt,
        memory_on_research_debt_units=on_debt,
    )


class MemoryUpliftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger = JobLedger(Path(self.temporary.name) / "memory-uplift.sqlite3")
        self.addCleanup(self.ledger.close)
        self.ledger.append_a1_bundle(
            objects=BASE_DOCUMENTS,
            projections=projection_states("s27-memory-uplift"),
            idempotency_key="s27-memory-uplift-base",
            event_at=AT,
        )
        self.ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        self.replay = self.ledger.replay_feedback()
        self.memory_off = self.ledger.research_knowledge_fabric(memory_enabled=False)
        self.memory_on = self.ledger.research_knowledge_fabric(memory_enabled=True)
        self.policy = MemoryEvaluationPolicy(
            PROFILE, expected_profile_sha256=PROFILE_SHA
        )

    def measure(
        self,
        twins: tuple[MemoryTwinPair, ...],
        calibration: tuple[CalibrationObservation, ...] = (),
    ):
        return measure_memory_uplift(
            self.policy,
            self.replay,
            self.ledger.replay_feedback(),
            self.memory_off,
            self.memory_on,
            twins,
            calibration,
        )

    def test_profile_is_exact_digest_bound_and_rejects_metric_drift(self) -> None:
        self.assertEqual(self.policy.profile_sha256, PROFILE_SHA)
        value = json.loads(PROFILE.read_text())
        value["uncertainty"]["minimum_sample_pairs"] = 1
        mutated = Path(self.temporary.name) / "mutated-profile.json"
        mutated.write_text(json.dumps(value))
        digest = hashlib.sha256(mutated.read_bytes()).hexdigest()
        with self.assertRaisesRegex(EvolutionError, "uncertainty drifted"):
            MemoryEvaluationPolicy(mutated, expected_profile_sha256=digest)

    def test_strong_paired_uplift_is_measured_only_for_frozen_shadow_scope(self) -> None:
        pairs = tuple(twin(index) for index in range(16))
        before_changes = self.ledger._connection.total_changes
        first = self.measure(pairs)
        second = self.measure(tuple(reversed(pairs)))
        self.assertEqual(first, second)
        self.assertEqual(first.status, "MEMORY_UPLIFT_MEASURED_SCOPED")
        self.assertEqual(first.reason_codes, ("PASS_FOR_FROZEN_SHADOW_SCOPE",))
        self.assertEqual(first.uplift_ppm, 1_000_000)
        self.assertGreater(first.uncertainty_low_ppm, 0)
        self.assertEqual(first.information_value_delta_units, 2)
        self.assertEqual(first.research_debt_delta_units, -1)
        self.assertEqual(self.ledger._connection.total_changes, before_changes)
        self.assertFalse(first.learned_claimed)
        self.assertFalse(first.calibrated_claimed)
        self.assertFalse(first.claims_scientific_truth)
        self.assertFalse(first.side_effects)
        self.assertFalse(first.grants_authority)

    def test_zero_and_underpowered_observations_are_not_established(self) -> None:
        empty = self.measure(())
        self.assertEqual(empty.status, "NOT_ESTABLISHED")
        self.assertEqual(
            (empty.uncertainty_low_ppm, empty.uncertainty_high_ppm),
            (-1_000_000, 1_000_000),
        )
        self.assertEqual(empty.false_learn_upper_bound_ppm, 1_000_000)
        self.assertIn("NO_MEMORY_TWIN_OBSERVATIONS", empty.reason_codes)
        underpowered = self.measure(tuple(twin(index) for index in range(15)))
        self.assertEqual(underpowered.status, "NOT_ESTABLISHED")
        self.assertIn("MEMORY_UPLIFT_UNDERPOWERED", underpowered.reason_codes)

    def test_false_learn_or_research_debt_growth_blocks_positive_claim(self) -> None:
        false_learn = tuple(
            twin(index, on_false_learn=index == 0) for index in range(16)
        )
        false_report = self.measure(false_learn)
        self.assertEqual(false_report.status, "NOT_ESTABLISHED")
        self.assertIn("MEMORY_FALSE_LEARN_OBSERVED", false_report.reason_codes)
        self.assertGreater(false_report.false_learn_upper_bound_ppm, 0)

        debt_growth = tuple(twin(index, off_debt=0, on_debt=1) for index in range(16))
        debt_report = self.measure(debt_growth)
        self.assertEqual(debt_report.status, "NOT_ESTABLISHED")
        self.assertIn("MEMORY_RESEARCH_DEBT_INCREASED", debt_report.reason_codes)

    def test_mixed_or_forged_replay_fails_closed(self) -> None:
        forged = replace(self.replay, replay_sha256="0" * 64)
        with self.assertRaisesRegex(EvolutionError, "replay integrity mismatch"):
            measure_memory_uplift(
                self.policy,
                forged,
                forged,
                self.memory_off,
                self.memory_on,
                (),
            )
        different = replace(self.replay, feedback_bundle_count=0)
        with self.assertRaises(EvolutionError):
            measure_memory_uplift(
                self.policy,
                self.replay,
                different,
                self.memory_off,
                self.memory_on,
                (),
            )

    def test_forged_or_misbound_memory_fabric_fails_closed(self) -> None:
        forged_trace = dict(self.memory_on.retrieval_trace)
        forged_trace["source_replay_sha256"] = "0" * 64
        forged = replace(self.memory_on, retrieval_trace=forged_trace)
        with self.assertRaisesRegex(EvolutionError, "not bound to full replay"):
            measure_memory_uplift(
                self.policy,
                self.replay,
                self.replay,
                self.memory_off,
                forged,
                (),
            )
        with self.assertRaises(EvolutionError):
            measure_memory_uplift(
                self.policy,
                self.replay,
                self.replay,
                self.memory_on,
                self.memory_off,
                (),
            )

    def test_capacity_exhaustion_parks_with_backpressure_and_no_scale_claim(self) -> None:
        report = self.measure(tuple(twin(index) for index in range(257)))
        self.assertEqual(report.status, "PARKED_CAPACITY")
        self.assertEqual(
            report.reason_codes, ("MEMORY_EVALUATION_CAPACITY_EXHAUSTED",)
        )
        self.assertTrue(report.capacity_envelope["overloaded"])
        self.assertTrue(report.capacity_envelope["backpressure"])
        self.assertFalse(report.capacity_envelope["infrastructure_scale_claimed"])
        self.assertFalse(report.grants_authority)

    def test_calibration_is_collected_but_never_claimed_calibrated(self) -> None:
        observations = tuple(
            CalibrationObservation(
                observation_ref=f"calibration:{index}",
                confidence_ppm=1_000_000,
                correct=True,
                memory_enabled=True,
            )
            for index in range(100)
        )
        report = self.measure(tuple(twin(index) for index in range(16)), observations)
        self.assertEqual(report.calibration_status, "COLLECTED_SCOPED")
        self.assertEqual(report.calibration_observations, 100)
        self.assertEqual(report.calibration_brier_ppm, 0)
        self.assertEqual(len(report.calibration_bins), 10)
        self.assertFalse(report.calibrated_claimed)

    def test_duplicate_identity_and_metric_bound_fail_closed(self) -> None:
        duplicate = twin(1)
        with self.assertRaisesRegex(EvolutionError, "identity is duplicated"):
            self.measure((duplicate, duplicate))
        overbound = replace(duplicate, memory_on_information_value_units=1_000_001)
        with self.assertRaisesRegex(EvolutionError, "exceeds frozen capacity"):
            self.measure((overbound,))


if __name__ == "__main__":
    unittest.main()
