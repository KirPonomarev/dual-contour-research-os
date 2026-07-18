from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.evolution import (  # noqa: E402
    BenchmarkCase,
    CandidateCaseResult,
    ChallengerEvaluationPolicy,
    EvolutionError,
    EvolutionGenomePolicy,
    GenomeComponent,
    OperationalGapSignal,
    ShadowCanaryObservation,
    ShadowCanaryPolicy,
    build_benchmark_snapshot,
    build_canary_scope,
    build_genome_snapshot,
    evaluate_challenger,
    mine_mutation_candidates,
    run_shadow_canary,
)


GENOME_PROFILE = ROOT / "provenance" / "evolution-genome-gap-miner-v1.json"
GENOME_SHA = "bd35130dc90e252773359973f77e4a8e4cc9cdc5a746c1ff362d1bee8a599c07"
CHALLENGER_PROFILE = ROOT / "provenance" / "champion-challenger-evaluation-v1.json"
CHALLENGER_SHA = "e31e4aa9f946e54ffe5c91ec887e5f26f44db2569c7edf975504aaa3be7831a8"
CANARY_PROFILE = ROOT / "provenance" / "shadow-canary-evolution-loop-v1.json"
CANARY_SHA = "81440253d296d04a42bacca18b259f715236444a7b4c068fda54bd382d6b9c5e"


class ShadowCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        genome_policy = EvolutionGenomePolicy(
            GENOME_PROFILE, expected_profile_sha256=GENOME_SHA
        )
        deny = tuple(sorted(genome_policy.required_deny_invariants))
        genome = build_genome_snapshot(
            genome_policy,
            subject_ref="git:" + "a" * 40,
            components=(GenomeComponent("component:x", "version:v1", "1" * 64, (), deny),),
        )
        self.archive = mine_mutation_candidates(
            genome_policy,
            genome,
            (
                OperationalGapSignal(
                    "gap:one", "component:x", "gap-code", "fix-gap",
                    "TEST_ADDITION", ("evidence:one",),
                ),
            ),
        )
        challenger_policy = ChallengerEvaluationPolicy(
            CHALLENGER_PROFILE, expected_profile_sha256=CHALLENGER_SHA
        )
        self.cases = tuple(
            BenchmarkCase(
                f"case:{index}", f"{index + 1:064x}", "2" * 64,
                index < 2, 2 <= index < 4,
            )
            for index in range(8)
        )
        benchmark = build_benchmark_snapshot(
            challenger_policy,
            evaluator_ref="evaluator:frozen",
            evaluator_sha256="3" * 64,
            cases=self.cases,
        )
        champion_ref = "champion:v1"
        challenger_ref = self.archive.proposals[0].proposal_ref

        def results(candidate_ref: str, *, quality: int, cost: int):
            return tuple(
                CandidateCaseResult(
                    candidate_ref, case.case_ref, benchmark.benchmark_sha256,
                    quality, quality, cost, cost, 0, case.known_invalid,
                )
                for case in self.cases
            )

        self.report = evaluate_challenger(
            challenger_policy,
            benchmark,
            self.archive,
            champion_ref=champion_ref,
            challenger_ref=challenger_ref,
            champion_results=results(champion_ref, quality=10, cost=10),
            challenger_results=results(challenger_ref, quality=11, cost=9),
        )
        self.policy = ShadowCanaryPolicy(
            CANARY_PROFILE, expected_profile_sha256=CANARY_SHA
        )
        self.scope = build_canary_scope(
            self.policy,
            self.report,
            self.archive,
            scope_ref="canary:s31",
            case_refs=tuple(case.case_ref for case in self.cases),
            max_observations=8,
        )

    def observations(self, count: int = 8, **overrides: object):
        values = {
            "quality_regression_units": 0,
            "information_regression_units": 0,
            "cost_regression_units": 0,
            "latency_regression_units": 0,
            "safety_violations": 0,
            "unexpected_failure": False,
        }
        values.update(overrides)
        return tuple(
            ShadowCanaryObservation(
                observation_ref=f"observation:{index}",
                scope_sha256=self.scope.scope_sha256,
                candidate_ref=self.scope.candidate_ref,
                case_ref=self.cases[index % len(self.cases)].case_ref,
                **values,
            )
            for index in range(count)
        )

    def evaluate_shadow(self, observations=None):
        return run_shadow_canary(
            self.policy, self.scope, self.report, self.archive,
            self.observations() if observations is None else observations,
        )

    def test_mature_clean_scope_passes_shadow_but_waits_authority(self) -> None:
        result = self.evaluate_shadow()
        self.assertEqual(result.mutation_proposal_loop_status, "MUTATION_PROPOSAL_LOOP_PASS")
        self.assertEqual(result.evolution_loop_shadow_status, "EVOLUTION_LOOP_SHADOW_PASS")
        self.assertEqual(result.meta_evolution_status, "META_EVOLUTION_PROPOSAL_ONLY")
        self.assertEqual(result.calibration_maturity_status, "MATURE_FOR_FROZEN_SCOPE")
        self.assertEqual(result.promotion_state, "WAIT_AUTHORITY")
        self.assertIsNone(result.rollback_proposal)
        self.assertEqual(
            (
                result.network_calls, result.filesystem_writes,
                result.generated_code_executions, result.canonical_writes,
                result.holdout_queries,
            ),
            (0, 0, 0, 0, 0),
        )
        self.assertFalse(result.winner_promoted)
        self.assertFalse(result.mutation_applied)
        self.assertFalse(result.side_effects)
        self.assertFalse(result.grants_authority)

    def test_immature_observations_are_not_established(self) -> None:
        result = self.evaluate_shadow(self.observations(4))
        self.assertEqual(result.evolution_loop_shadow_status, "NOT_ESTABLISHED")
        self.assertEqual(result.calibration_maturity_status, "NOT_ESTABLISHED")
        self.assertEqual(result.promotion_state, "WAIT_AUTHORITY")

    def test_every_regression_dimension_and_failure_creates_proposal_only_rollback(self) -> None:
        for field in (
            "quality_regression_units", "information_regression_units",
            "cost_regression_units", "latency_regression_units", "safety_violations",
        ):
            with self.subTest(field=field):
                result = self.evaluate_shadow(self.observations(**{field: 1}))
                self.assertEqual(result.evolution_loop_shadow_status, "REGRESSION_DETECTED")
                self.assertIsNotNone(result.rollback_proposal)
                self.assertEqual(result.rollback_proposal.state, "WAIT_AUTHORITY")
                self.assertFalse(result.rollback_proposal.executable_payload_present)
                self.assertFalse(result.rollback_proposal.rollback_applied)
                self.assertFalse(result.rollback_proposal.policy_applied)
                self.assertEqual(result.rollback_proposal.canonical_writes, 0)
                self.assertFalse(result.rollback_proposal.grants_authority)
        failed = self.evaluate_shadow(self.observations(unexpected_failure=True))
        self.assertEqual(failed.evolution_loop_shadow_status, "REGRESSION_DETECTED")

    def test_foreign_candidate_case_or_scope_fails_closed(self) -> None:
        valid = self.observations()
        for changed in (
            replace(valid[0], candidate_ref="proposal:foreign"),
            replace(valid[0], case_ref="case:foreign"),
            replace(valid[0], scope_sha256="0" * 64),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(EvolutionError):
                    self.evaluate_shadow((changed,) + valid[1:])

    def test_scope_capacity_parks_without_hidden_execution(self) -> None:
        result = self.evaluate_shadow(self.observations(9))
        self.assertEqual(result.evolution_loop_shadow_status, "PARKED_CAPACITY")
        self.assertEqual(result.promotion_state, "WAIT_AUTHORITY")
        self.assertIsNone(result.rollback_proposal)
        self.assertFalse(result.side_effects)

    def test_scope_report_and_archive_integrity_fail_closed(self) -> None:
        with self.assertRaises(EvolutionError):
            run_shadow_canary(
                self.policy, replace(self.scope, scope_sha256="0" * 64),
                self.report, self.archive, self.observations(),
            )
        with self.assertRaises(EvolutionError):
            run_shadow_canary(
                self.policy, self.scope, replace(self.report, report_sha256="0" * 64),
                self.archive, self.observations(),
            )
        with self.assertRaises(EvolutionError):
            run_shadow_canary(
                self.policy, self.scope, self.report,
                replace(self.archive, archive_sha256="0" * 64), self.observations(),
            )

    def test_nonpassing_challenger_cannot_enter_canary(self) -> None:
        with self.assertRaises(EvolutionError):
            build_canary_scope(
                self.policy,
                replace(self.report, status="NOT_ESTABLISHED"),
                self.archive,
                scope_ref="canary:bad",
                case_refs=tuple(case.case_ref for case in self.cases),
                max_observations=8,
            )

    def test_profile_digest_and_semantics_are_frozen(self) -> None:
        document = json.loads(CANARY_PROFILE.read_text())
        document["acceptance"]["automatic_promotion"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(document))
            with self.assertRaises(EvolutionError):
                ShadowCanaryPolicy(path, expected_profile_sha256=CANARY_SHA)


if __name__ == "__main__":
    unittest.main()
