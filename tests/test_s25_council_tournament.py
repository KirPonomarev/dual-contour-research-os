from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.model_broker import (  # noqa: E402
    ModelBrokerError,
    ModelCouncilCandidate,
    ModelCouncilEvaluation,
    ModelCouncilScore,
    ModelCouncilTournament,
)
from tests.test_s16_provider_routing import ROUTED, routing  # noqa: E402


PROFILE = ROOT / "provenance" / "model-council-tournament-v1.json"
PROFILE_SHA256 = "e27222fe820912b7dd0abf725bf1c1825115e8f51bfb50ce44666bc8c8f27d81"
CRITERIA = (
    "falsifiability",
    "evidence_quality",
    "novelty",
    "cost_risk_fit",
)


def candidate(index: int) -> ModelCouncilCandidate:
    return ModelCouncilCandidate(
        candidate_id=f"candidate:s25-{index}",
        proposal_ref=f"proposal:sha256:{index:064x}",
        proposer_role="RESEARCH_WORKER",
    )


def score(
    item: ModelCouncilCandidate,
    value: int,
    verdict: str,
    *,
    criteria: tuple[str, ...] = CRITERIA,
) -> ModelCouncilScore:
    return ModelCouncilScore(
        candidate_id=item.candidate_id,
        criterion_scores=tuple((name, value) for name in criteria),
        verdict=verdict,
    )


def evaluation(
    decision,  # type: ignore[no-untyped-def]
    candidates: tuple[ModelCouncilCandidate, ...],
    *,
    values: tuple[int, ...],
    verdicts: tuple[str, ...],
) -> ModelCouncilEvaluation:
    assert decision.binding is not None
    return ModelCouncilEvaluation(
        evaluator_role=decision.role,
        model_binding=decision.binding,
        response_ref=f"fixture:council-{decision.role.lower()}",
        scores=tuple(
            score(item, value, verdict)
            for item, value, verdict in zip(candidates, values, verdicts, strict=True)
        ),
    )


class CouncilTournamentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tournament = ModelCouncilTournament(
            PROFILE, expected_profile_sha256=PROFILE_SHA256
        )
        self.router = routing()

    def test_profile_is_digest_bound_exact_and_advisory_only(self) -> None:
        self.assertEqual(self.tournament.profile_sha256, PROFILE_SHA256)
        value = json.loads(PROFILE.read_text())
        self.assertEqual(value["max_total_model_calls"], 4)
        self.assertEqual(value["max_candidates"], 4)
        self.assertTrue(value["invariants"]["consensus_is_not_evidence"])
        self.assertTrue(value["invariants"]["advisory_ranking_is_not_evidence"])
        for mutation in (
            lambda item: item.__setitem__("max_total_model_calls", 5),
            lambda item: item["rubric"]["criteria"][0].__setitem__("weight", 36),
            lambda item: item["invariants"].__setitem__("dissent_is_preserved", False),
            lambda item: item["evaluator_roles"].reverse(),
        ):
            candidate_profile = json.loads(json.dumps(value))
            mutation(candidate_profile)
            path = self.root / f"mutated-{len(list(self.root.iterdir()))}.json"
            path.write_text(json.dumps(candidate_profile))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(ModelBrokerError):
                ModelCouncilTournament(path, expected_profile_sha256=digest)
        with self.assertRaises(ModelBrokerError):
            ModelCouncilTournament(PROFILE, expected_profile_sha256="0" * 64)

    def test_standard_council_is_capped_and_unanimity_is_not_evidence(self) -> None:
        plan = self.router.plan_council("STANDARD", "D0", available_bindings=ROUTED)
        candidates = (candidate(1), candidate(2))
        critic = evaluation(
            plan.decisions[1],
            candidates,
            values=(90, 40),
            verdicts=("SUPPORT", "REJECT"),
        )
        result = self.tournament.evaluate(plan, candidates, (critic,))
        self.assertEqual(result.status, "COMPLETE_ADVISORY")
        self.assertEqual(result.candidate_order, ("candidate:s25-1", "candidate:s25-2"))
        self.assertEqual(result.planned_call_count, 2)
        self.assertEqual(result.evaluation_call_count, 1)
        self.assertLessEqual(result.planned_call_count, result.max_total_model_calls)
        self.assertEqual(result.dissent_candidate_ids, ())
        self.assertEqual(
            result.unanimous_candidate_ids,
            ("candidate:s25-1", "candidate:s25-2"),
        )
        self.assertIn("UNANIMOUS_NOT_EVIDENCE", result.reason_codes)
        self.assertFalse(result.consensus_is_evidence)
        self.assertFalse(result.ranking_is_evidence)
        self.assertFalse(result.grants_authority)
        self.assertEqual(result.independence_status, "INDEPENDENCE_NOT_ESTABLISHED")

    def test_critical_council_preserves_dissent_and_replays_independent_of_order(self) -> None:
        plan = self.router.plan_council("CRITICAL", "D1", available_bindings=ROUTED)
        candidates = tuple(candidate(index) for index in range(1, 5))
        evaluations = (
            evaluation(
                plan.decisions[1], candidates,
                values=(90, 70, 50, 30),
                verdicts=("SUPPORT", "SUPPORT", "REJECT", "UNCERTAIN"),
            ),
            evaluation(
                plan.decisions[2], candidates,
                values=(80, 60, 40, 20),
                verdicts=("REJECT", "SUPPORT", "REJECT", "UNCERTAIN"),
            ),
            evaluation(
                plan.decisions[3], candidates,
                values=(85, 65, 45, 25),
                verdicts=("UNCERTAIN", "SUPPORT", "REJECT", "SUPPORT"),
            ),
        )
        first = self.tournament.evaluate(plan, candidates, evaluations)
        replay = self.tournament.evaluate(
            plan,
            tuple(reversed(candidates)),
            tuple(reversed(evaluations)),
        )
        self.assertEqual(first, replay)
        self.assertEqual(first.planned_call_count, 4)
        self.assertEqual(first.evaluation_call_count, 3)
        self.assertEqual(
            first.candidate_order,
            tuple(f"candidate:s25-{index}" for index in range(1, 5)),
        )
        self.assertEqual(
            first.dissent_candidate_ids,
            ("candidate:s25-1", "candidate:s25-4"),
        )
        self.assertEqual(
            first.unanimous_candidate_ids,
            ("candidate:s25-2", "candidate:s25-3"),
        )
        self.assertIn("DISSENT_PRESERVED", first.reason_codes)

    def test_missing_mandatory_critic_waits_without_partial_ranking(self) -> None:
        available = ROUTED - {"gpt-5.6-sol-xhigh", "gpt-5.6-sol-max"}
        plan = self.router.plan_council("MATERIAL", "D0", available_bindings=available)
        self.assertEqual(plan.status, "WAIT_PROVIDER")
        result = self.tournament.evaluate(plan, (candidate(1),), ())
        self.assertEqual(result.status, "WAIT_PROVIDER")
        self.assertEqual(result.missing_evaluator_roles, ("CRITIC_DEEP",))
        self.assertEqual(result.candidate_order, ())
        self.assertEqual(result.weighted_scores, ())
        self.assertIn("MISSING_ASSIGNED_CRITIC", result.reason_codes)

    def test_missing_assigned_output_is_incomplete_and_ranking_is_withheld(self) -> None:
        plan = self.router.plan_council("MATERIAL", "D0", available_bindings=ROUTED)
        candidates = (candidate(1), candidate(2))
        only_primary = evaluation(
            plan.decisions[1], candidates,
            values=(80, 20), verdicts=("SUPPORT", "REJECT")
        )
        result = self.tournament.evaluate(plan, candidates, (only_primary,))
        self.assertEqual(result.status, "INCOMPLETE")
        self.assertEqual(result.missing_evaluator_roles, ("CRITIC_DEEP",))
        self.assertEqual(result.candidate_order, ())
        self.assertIn("RANKING_WITHHELD", result.reason_codes)

    def test_proposer_cannot_review_and_caller_cannot_forge_evaluator_or_binding(self) -> None:
        plan = self.router.plan_council("STANDARD", "D0", available_bindings=ROUTED)
        candidates = (candidate(1),)
        valid = evaluation(
            plan.decisions[1], candidates, values=(50,), verdicts=("UNCERTAIN",)
        )
        for forged in (
            replace(valid, evaluator_role="RESEARCH_WORKER"),
            replace(valid, evaluator_role="CRITIC_DEEP"),
            replace(valid, model_binding="gpt-5.6-sol-xhigh"),
        ):
            with self.assertRaises(ModelBrokerError):
                self.tournament.evaluate(plan, candidates, (forged,))
        with self.assertRaises(ModelBrokerError):
            self.tournament.evaluate(plan, candidates, (valid, valid))
        self.assertNotIn(
            "evaluator_role", inspect.signature(ModelCouncilCandidate).parameters
        )

    def test_candidate_score_and_rubric_hostile_inputs_fail_closed(self) -> None:
        plan = self.router.plan_council("STANDARD", "D0", available_bindings=ROUTED)
        candidates = (candidate(1), candidate(2))
        decision = plan.decisions[1]
        assert decision.binding is not None
        cases = (
            (score(candidates[0], 50, "SUPPORT"),),
            (
                score(candidates[0], 50, "SUPPORT"),
                score(candidates[0], 50, "SUPPORT"),
            ),
            (
                score(candidates[0], 50, "SUPPORT", criteria=tuple(reversed(CRITERIA))),
                score(candidates[1], 50, "SUPPORT"),
            ),
            (
                score(candidates[0], 101, "SUPPORT"),
                score(candidates[1], 50, "SUPPORT"),
            ),
            (
                score(candidates[0], 50, "PROMOTE"),
                score(candidates[1], 50, "SUPPORT"),
            ),
        )
        for index, scores in enumerate(cases):
            hostile = ModelCouncilEvaluation(
                evaluator_role=decision.role,
                model_binding=decision.binding,
                response_ref=f"fixture:hostile-{index}",
                scores=scores,
            )
            with self.subTest(index=index):
                with self.assertRaises(ModelBrokerError):
                    self.tournament.evaluate(plan, candidates, (hostile,))

    def test_candidate_caps_identity_and_proposer_role_fail_closed(self) -> None:
        plan = self.router.plan_council("STANDARD", "D0", available_bindings=ROUTED)
        with self.assertRaises(ModelBrokerError):
            self.tournament.evaluate(plan, (), ())
        with self.assertRaises(ModelBrokerError):
            self.tournament.evaluate(
                plan, tuple(candidate(index) for index in range(5)), ()
            )
        duplicate = candidate(1)
        with self.assertRaises(ModelBrokerError):
            self.tournament.evaluate(plan, (duplicate, duplicate), ())
        forged = replace(candidate(1), proposer_role="CHIEF_SCIENTIST")
        with self.assertRaises(ModelBrokerError):
            self.tournament.evaluate(plan, (forged,), ())

    def test_forged_plan_cannot_widen_call_cap_consensus_or_independence(self) -> None:
        plan = self.router.plan_council("STANDARD", "D0", available_bindings=ROUTED)
        for forged in (
            replace(plan, max_calls=5),
            replace(plan, call_count=5),
            replace(plan, consensus_is_evidence=True),
            replace(plan, independence_status="INDEPENDENT"),
        ):
            with self.assertRaises(ModelBrokerError):
                self.tournament.evaluate(forged, (candidate(1),), ())


if __name__ == "__main__":
    unittest.main()
