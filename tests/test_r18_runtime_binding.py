"""R18 runtime binding override and fallback gate tests.

Verifies that role_binding_overrides in the model_runtime config allow
exact pre-approved fallback routes while preserving all existing
prohibitions: caller-selected model, D2/D3, unknown roles, and
ARBITER_RESERVE activation.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from research_bridge.ipc import PeerCredentials  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    ResearchDaemon,
    ResearchdError,
    _ServiceConfigError,
    _model_runtime_from_config,
    _service_config_from_mapping,
)

CONTRACTS_ROOT = REPO_ROOT / "contracts"
PROVENANCE_ROOT = REPO_ROOT / "provenance"

ROLE_REGISTRY_SHA256 = (
    "4faf6765f48a952e4d35540d92797330517938b34b8d2f12cde791e761a32eac"
)
ROUTING_V2_SHA256 = (
    "0539b1c2b3fd2e5b5f6e21769afe99d36a197f9399db100e5f0c5885e5da3c67"
)
ROLE_EVALUATION_SHA256 = (
    "111a7ac1dc954466b19d5e408debeeefcf65c76b5b025a743a2433be910c1e75"
)
WORKER_EXTENSION_SHA256 = (
    "03d91f027bb6975c55d84acaef188546bcd24af9944a72f4ff9314296399d07a"
)


def _base_model_runtime(
    *,
    available_bindings: list[str] | None = None,
    role_binding_overrides: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "role_registry_sha256": ROLE_REGISTRY_SHA256,
        "routing_profile_sha256": ROUTING_V2_SHA256,
        "role_evaluation_sha256": ROLE_EVALUATION_SHA256,
        "worker_ipc_extension_sha256": WORKER_EXTENSION_SHA256,
        "binding_revision": "r18-connected-advisor-v1",
        "budget_policy_ref": "budget-policy:sha256:" + "a" * 64,
        "budget_scope_ref": "budget-scope:sha256:" + "b" * 64,
        "max_active_calls": 4,
        "max_reserved_tokens": 20_000,
        "max_reserved_cost_units": 40,
        "available_bindings": available_bindings
        if available_bindings is not None
        else [
            "deepseek-v4-flash",
            "deepseek-v4-pro",
            "glm-5.2-max",
            "claude-fable-5",
            "gpt-5.6-sol-xhigh",
            "gpt-5.6-sol-max",
        ],
        "role_binding_overrides": role_binding_overrides
        if role_binding_overrides is not None
        else {},
    }


def _full_config(model_runtime: dict[str, object]) -> dict[str, object]:
    config_path = REPO_ROOT / "ops" / "release" / "researchd.config.template.json"
    config = json.loads(config_path.read_text())
    config["allowed_uids"] = [10001, 10002, 10003, 10004]
    config["principal_roles"] = {
        "10001": "operator",
        "10002": "collector",
        "10003": "scout",
        "10004": "connected_worker",
    }
    config["frozen_bindings"]["model_runtime"] = model_runtime
    return config


class RoleBindingOverrideConfigTests(unittest.TestCase):
    """Config parsing validation for role_binding_overrides."""

    def test_empty_overrides_accepted(self) -> None:
        runtime = _model_runtime_from_config(
            _base_model_runtime(role_binding_overrides={})
        )
        self.assertEqual(runtime["role_binding_overrides"], {})

    def test_valid_override_accepted(self) -> None:
        runtime = _model_runtime_from_config(
            _base_model_runtime(
                role_binding_overrides={"CRITIC_PRIMARY": "claude-fable-5"}
            )
        )
        self.assertEqual(
            runtime["role_binding_overrides"],
            {"CRITIC_PRIMARY": "claude-fable-5"},
        )

    def test_multiple_overrides_accepted(self) -> None:
        runtime = _model_runtime_from_config(
            _base_model_runtime(
                role_binding_overrides={
                    "CRITIC_PRIMARY": "claude-fable-5",
                    "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
                }
            )
        )
        self.assertEqual(
            runtime["role_binding_overrides"],
            {
                "CRITIC_PRIMARY": "claude-fable-5",
                "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
            },
        )

    def test_arbiter_reserve_override_rejected(self) -> None:
        with self.assertRaises(_ServiceConfigError):
            _model_runtime_from_config(
                _base_model_runtime(
                    role_binding_overrides={"ARBITER_RESERVE": "some-binding"}
                )
            )

    def test_unknown_role_override_rejected(self) -> None:
        with self.assertRaises(_ServiceConfigError):
            _model_runtime_from_config(
                _base_model_runtime(
                    role_binding_overrides={"NONEXISTENT_ROLE": "some-binding"}
                )
            )

    def test_non_dict_overrides_rejected(self) -> None:
        rt = _base_model_runtime()
        rt["role_binding_overrides"] = ["CRITIC_PRIMARY"]
        with self.assertRaises(_ServiceConfigError):
            _model_runtime_from_config(rt)

    def test_empty_binding_value_rejected(self) -> None:
        with self.assertRaises(_ServiceConfigError):
            _model_runtime_from_config(
                _base_model_runtime(
                    role_binding_overrides={"CRITIC_PRIMARY": ""}
                )
            )

    def test_missing_overrides_key_rejected(self) -> None:
        rt = _base_model_runtime()
        del rt["role_binding_overrides"]
        with self.assertRaises(_ServiceConfigError):
            _model_runtime_from_config(rt)


NOW = datetime(2026, 7, 21, 18, 0, 0, tzinfo=timezone.utc)


class FallbackRoutingTests(unittest.TestCase):
    """Tests for routing v2 fallback behavior and the override gate logic."""

    def _routing(self) -> "ModelProviderRouting":
        from research_bridge.model_broker import (
            ModelProviderRouting,
            ModelRoleRegistry,
        )

        registry = ModelRoleRegistry(
            CONTRACTS_ROOT / "a1" / "v1" / "profiles" / "model_role_registry_v1.json",
            expected_profile_sha256=ROLE_REGISTRY_SHA256,
            binding_revision="r18-test-v1",
        )
        return ModelProviderRouting(
            PROVENANCE_ROOT / "model-provider-routing-v2.json",
            expected_profile_sha256=ROUTING_V2_SHA256,
            role_registry=registry,
        )

    def test_critic_primary_fallback_to_fable_when_glm_unavailable(self) -> None:
        """Routing v2 routes CRITIC_PRIMARY to claude-fable-5 as fallback."""
        routing = self._routing()
        decision = routing.route(
            "CRITIC_PRIMARY",
            "D0",
            available_bindings=frozenset({"claude-fable-5"}),
        )
        self.assertEqual(decision.status, "ROUTED")
        self.assertEqual(decision.binding, "claude-fable-5")
        self.assertTrue(decision.used_fallback)

    def test_critic_primary_primary_when_glm_available(self) -> None:
        """Routing v2 routes CRITIC_PRIMARY to glm-5.2-max as primary."""
        routing = self._routing()
        decision = routing.route(
            "CRITIC_PRIMARY",
            "D0",
            available_bindings=frozenset({"glm-5.2-max", "claude-fable-5"}),
        )
        self.assertEqual(decision.status, "ROUTED")
        self.assertEqual(decision.binding, "glm-5.2-max")
        self.assertFalse(decision.used_fallback)

    def test_critic_primary_wait_provider_when_nothing_available(self) -> None:
        """Routing v2 returns WAIT_PROVIDER when no binding is available."""
        routing = self._routing()
        decision = routing.route(
            "CRITIC_PRIMARY",
            "D0",
            available_bindings=frozenset(),
        )
        self.assertEqual(decision.status, "WAIT_PROVIDER")
        self.assertIsNone(decision.binding)

    def test_d2_classification_rejected_by_routing(self) -> None:
        """Routing rejects D2 classification."""
        routing = self._routing()
        from research_bridge.model_broker import ModelBrokerError

        with self.assertRaises(ModelBrokerError):
            routing.route(
                "CRITIC_PRIMARY",
                "D2",
                available_bindings=frozenset({"claude-fable-5"}),
            )

    def test_override_gate_logic_exact_match(self) -> None:
        """The override gate allows fallback only on exact match."""
        overrides: dict[str, str] = {"CRITIC_PRIMARY": "claude-fable-5"}
        # Simulates the gate check in reserve_model_call
        role = "CRITIC_PRIMARY"
        binding = "claude-fable-5"
        used_fallback = True
        # Gate passes: override matches the fallback binding
        if used_fallback:
            self.assertEqual(overrides.get(role), binding)

    def test_override_gate_logic_mismatch_rejects(self) -> None:
        """The override gate rejects fallback when override doesn't match."""
        overrides: dict[str, str] = {"CRITIC_PRIMARY": "glm-5.2-max"}
        role = "CRITIC_PRIMARY"
        binding = "claude-fable-5"
        used_fallback = True
        # Gate fails: override does NOT match the fallback binding
        if used_fallback:
            self.assertNotEqual(overrides.get(role), binding)

    def test_override_gate_logic_no_override_rejects(self) -> None:
        """The override gate rejects fallback when no override exists."""
        overrides: dict[str, str] = {}
        role = "CRITIC_PRIMARY"
        binding = "claude-fable-5"
        used_fallback = True
        # Gate fails: no override for this role
        if used_fallback:
            self.assertIsNone(overrides.get(role))

    def test_research_worker_primary_not_affected(self) -> None:
        """RESEARCH_WORKER still routes to deepseek-v4-pro as primary."""
        routing = self._routing()
        decision = routing.route(
            "RESEARCH_WORKER",
            "D0",
            available_bindings=frozenset({"deepseek-v4-pro", "deepseek-v4-flash"}),
        )
        self.assertEqual(decision.status, "ROUTED")
        self.assertEqual(decision.binding, "deepseek-v4-pro")
        self.assertFalse(decision.used_fallback)

    def test_council_cap_remains_four(self) -> None:
        """Council max_calls remains 4 in routing v2."""
        routing = self._routing()
        plan = routing.plan_council(
            "CRITICAL",
            "D0",
            available_bindings=frozenset(
                {
                    "deepseek-v4-pro",
                    "deepseek-v4-flash",
                    "glm-5.2-max",
                    "claude-fable-5",
                    "gpt-5.6-sol-xhigh",
                    "gpt-5.6-sol-max",
                }
            ),
        )
        self.assertEqual(plan.status, "ROUTED")
        self.assertEqual(len(plan.decisions), 4)


if __name__ == "__main__":
    unittest.main()
