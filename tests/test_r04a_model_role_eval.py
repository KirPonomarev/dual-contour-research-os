from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import verify_model_role_evaluation as evaluation  # noqa: E402


PROFILE = ROOT / "provenance" / "model-role-evaluation-v2.json"


class ModelRoleEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(PROFILE.read_text(encoding="utf-8"))

    def write_mutation(self, mutator) -> Path:  # type: ignore[no-untyped-def]
        value = copy.deepcopy(self.value)
        mutator(value)
        temporary = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        with temporary:
            json.dump(value, temporary, sort_keys=True, separators=(",", ":"))
        return Path(temporary.name)

    def test_profile_is_exact_versioned_and_waits_for_current_provider_state(self) -> None:
        profile = evaluation.validate_profile(PROFILE)
        self.assertEqual(profile["status"], "WAIT_PROVIDER")
        self.assertEqual(
            hashlib.sha256(PROFILE.read_bytes()).hexdigest(),
            "111a7ac1dc954466b19d5e408debeeefcf65c76b5b025a743a2433be910c1e75",
        )
        self.assertEqual(profile["current_preflight"]["configured_bindings"], [])
        self.assertEqual(profile["budget"]["stage_provider_calls_observed"], 0)
        self.assertFalse(profile["budget"]["new_payment_authority"])

    def test_role_mapping_chief_and_reserve_states_are_explicit(self) -> None:
        profile = evaluation.validate_profile(PROFILE)
        roles = profile["roles"]
        self.assertEqual(roles["SCOUT_FAST"]["primary"], "deepseek-v4-flash")
        self.assertEqual(roles["RESEARCH_WORKER"]["primary"], "deepseek-v4-pro")
        self.assertEqual(roles["CRITIC_PRIMARY"]["primary"], "glm-5.2-max")
        self.assertEqual(roles["CHIEF_SCIENTIST"]["primary"], "gpt-5.6-sol-max")
        reserve = roles["ARBITER_RESERVE"]
        self.assertIsNone(reserve["primary"])
        self.assertEqual(reserve["candidate"], "qwen3.7-max-reserve")
        self.assertIn("WAIT", reserve["evaluation_status"])

    def test_price_privacy_and_family_correlation_are_conservative(self) -> None:
        profile = evaluation.validate_profile(PROFILE)
        self.assertEqual(profile["privacy"]["allowed_connected_input_classes"], ["D0"])
        self.assertEqual(
            set(profile["privacy"]["parked_input_classes"]),
            {"D1", "D2", "D3", "sealed-holdout"},
        )
        self.assertEqual(
            profile["bindings"]["glm-5.2-max"]["pricing"]["status"],
            "UNVERIFIED_CURRENT_PRICE",
        )
        self.assertEqual(
            profile["correlation_groups"]["gpt-5.6-sol"],
            ["gpt-5.6-sol-xhigh", "gpt-5.6-sol-max"],
        )
        self.assertTrue(profile["invariants"]["gateway_is_not_independence_evidence"])

    def test_empty_preflight_is_exact_wait_and_changed_state_requires_reevaluation(self) -> None:
        profile = evaluation.validate_profile(PROFILE)
        waiting = evaluation.evaluate_preflight(profile, frozenset())
        self.assertEqual(waiting["result"], "WAIT_PROVIDER")
        changed = evaluation.evaluate_preflight(
            profile, frozenset({"gpt-5.6-sol-xhigh"})
        )
        self.assertEqual(changed["result"], "REEVALUATION_REQUIRED")
        self.assertEqual(
            changed["binding_states"]["gpt-5.6-sol-xhigh"],
            "CONFIGURED_UNPROVEN",
        )
        with self.assertRaises(evaluation.EvaluationError):
            evaluation.evaluate_preflight(profile, frozenset({"unknown-binding"}))

    def test_route_privacy_budget_reserve_and_currentness_mutations_fail_closed(self) -> None:
        mutations = {
            "route": lambda value: value["roles"]["CHIEF_SCIENTIST"].__setitem__("primary", "deepseek-v4-pro"),
            "privacy": lambda value: value["privacy"]["allowed_connected_input_classes"].append("D1"),
            "budget": lambda value: value["budget"].__setitem__("max_council_calls", 5),
            "reserve": lambda value: value["roles"]["ARBITER_RESERVE"].__setitem__("primary", "qwen3.7-max-reserve"),
            "availability": lambda value: value["bindings"]["deepseek-v4-pro"].__setitem__("connected_evaluation", "PASS_CURRENT"),
            "correlation": lambda value: value["correlation_groups"]["gpt-5.6-sol"].pop(),
            "authority": lambda value: value["invariants"].__setitem__("grants_authority", True),
        }
        for label, mutator in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(evaluation.EvaluationError):
                    evaluation.validate_profile(self.write_mutation(mutator))

    def test_cli_static_and_local_preflight_emit_only_sanitized_state(self) -> None:
        static = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "verify_model_role_evaluation.py"), str(PROFILE)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(static.returncode, 0, static.stderr)
        result = json.loads(static.stdout)
        self.assertEqual(result["static_validation"], "GREEN")
        self.assertEqual(result["status"], "WAIT_PROVIDER")
        self.assertFalse(result["secrets_printed"])
        text = PROFILE.read_text(encoding="utf-8").lower()
        for forbidden in ("credential_value", "bearer ", "api_key", "secret_key", "raw_response_bytes"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
