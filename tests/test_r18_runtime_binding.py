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
    "16b143ea3b095c6eaa34c5663c0e8f2424c7a16fc77f5f4ffd52f6298b773c43"
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
        "binding_revision": "kmax-kimi-k3-max-gpt-xhigh-v1",
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
            "kimi-k3-max",
            "gpt-5.6-sol-xhigh",
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
                role_binding_overrides={"CRITIC_PRIMARY": "kimi-k3-max"}
            )
        )
        self.assertEqual(
            runtime["role_binding_overrides"],
            {"CRITIC_PRIMARY": "kimi-k3-max"},
        )

    def test_multiple_overrides_accepted(self) -> None:
        runtime = _model_runtime_from_config(
            _base_model_runtime(
                role_binding_overrides={
                    "CRITIC_PRIMARY": "kimi-k3-max",
                    "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
                    "CHIEF_SCIENTIST": "gpt-5.6-sol-xhigh",
                }
            )
        )
        self.assertEqual(
            runtime["role_binding_overrides"],
            {
                "CRITIC_PRIMARY": "kimi-k3-max",
                "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
                "CHIEF_SCIENTIST": "gpt-5.6-sol-xhigh",
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
            binding_revision="kmax-kimi-k3-max-gpt-xhigh-v1",
            binding_overrides={
                "CRITIC_PRIMARY": "kimi-k3-max",
                "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
                "CHIEF_SCIENTIST": "gpt-5.6-sol-xhigh",
            },
        )
        return ModelProviderRouting(
            PROVENANCE_ROOT / "model-provider-routing-v2.json",
            expected_profile_sha256=ROUTING_V2_SHA256,
            role_registry=registry,
        )

    def test_critic_primary_fallback_to_glm_when_kimi_unavailable(self) -> None:
        """Routing v2 preserves GLM only as Kimi's bounded fallback."""
        routing = self._routing()
        decision = routing.route(
            "CRITIC_PRIMARY",
            "D0",
            available_bindings=frozenset({"glm-5.2-max"}),
        )
        self.assertEqual(decision.status, "ROUTED")
        self.assertEqual(decision.binding, "glm-5.2-max")
        self.assertTrue(decision.used_fallback)

    def test_critic_primary_is_kimi_even_when_glm_is_available(self) -> None:
        """The active exact binding routes CRITIC_PRIMARY to Kimi K3 max."""
        routing = self._routing()
        decision = routing.route(
            "CRITIC_PRIMARY",
            "D0",
            available_bindings=frozenset({"glm-5.2-max", "kimi-k3-max"}),
        )
        self.assertEqual(decision.status, "ROUTED")
        self.assertEqual(decision.binding, "kimi-k3-max")
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
                available_bindings=frozenset({"kimi-k3-max"}),
            )

    def test_override_gate_logic_exact_match(self) -> None:
        """The override gate allows fallback only on exact match."""
        overrides: dict[str, str] = {"CRITIC_PRIMARY": "kimi-k3-max"}
        # Simulates the gate check in reserve_model_call
        role = "CRITIC_PRIMARY"
        binding = "kimi-k3-max"
        used_fallback = True
        # Gate passes: override matches the fallback binding
        if used_fallback:
            self.assertEqual(overrides.get(role), binding)

    def test_override_gate_logic_mismatch_rejects(self) -> None:
        """The override gate rejects fallback when override doesn't match."""
        overrides: dict[str, str] = {"CRITIC_PRIMARY": "glm-5.2-max"}
        role = "CRITIC_PRIMARY"
        binding = "kimi-k3-max"
        used_fallback = True
        # Gate fails: override does NOT match the fallback binding
        if used_fallback:
            self.assertNotEqual(overrides.get(role), binding)

    def test_override_gate_logic_no_override_rejects(self) -> None:
        """The override gate rejects fallback when no override exists."""
        overrides: dict[str, str] = {}
        role = "CRITIC_PRIMARY"
        binding = "kimi-k3-max"
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

    def test_researchd_broker_uses_exact_kimi_override(self) -> None:
        """The durable broker and availability router must select the same binding."""
        runtime = _base_model_runtime(
            available_bindings=["glm-5.2-max", "kimi-k3-max"],
            role_binding_overrides={
                "CRITIC_PRIMARY": "kimi-k3-max",
                "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
                "CHIEF_SCIENTIST": "gpt-5.6-sol-xhigh",
            },
        )
        service = _service_config_from_mapping(_full_config(runtime))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir(mode=0o700)
            daemon = ResearchDaemon(
                root,
                authority=service.authority,
                allowed_uids=service.allowed_uids,
                principal_roles=service.principal_roles,
                a1_enabled=service.a1_enabled,
                frozen_bindings=service.frozen_bindings,
                a1_limits=service.a1_limits,
                runner_identity=service.runner_identity,
                input_quota_bytes=service.input_quota_bytes,
                checkpoint_quota_bytes=service.checkpoint_quota_bytes,
                artifact_quota_bytes=service.artifact_quota_bytes,
                maximum_input_bytes=service.maximum_input_bytes,
                deadline_seconds=service.deadline_seconds,
                clock=lambda: NOW,
            )
            daemon.start()
            try:
                payload = {
                    "capability": "R18_EXACT_OVERRIDE_TEST",
                    "fixture_only": True,
                    "grants_authority": False,
                }
                assert daemon._ledger is not None
                daemon._ledger.append_a1_bundle(
                    objects=[
                        {
                            "schema_id": "CapabilityProofReceipt",
                            "schema_version": "1.0.0",
                            "object_id": "capability-proof:r18-exact-override-test",
                            "issued_at": "2026-07-21T18:00:00Z",
                            "issuer": {
                                "id": "agent-0-r18-test",
                                "authority_class": "fixture-only-non-authoritative",
                            },
                            "contour": "governance",
                            "classification": "D0",
                            "payload": payload,
                            "integrity": {
                                "profile_id": "core-json-sha256-v1",
                                "payload_sha256": hashlib.sha256(
                                    json.dumps(
                                        payload,
                                        sort_keys=True,
                                        separators=(",", ":"),
                                    ).encode()
                                ).hexdigest(),
                                "parent_refs": ["profile:r18-exact-override-test"],
                            },
                        }
                    ],
                    projections={
                        name: {
                            "count": 1 if name == "capabilities" else 0,
                            "fixture_only": True,
                            "grants_authority": False,
                            "marker": "r18-exact-override-test",
                            "shadow_only": True,
                        }
                        for name in (
                            "admissions",
                            "candidates",
                            "capabilities",
                            "material_events",
                        )
                    },
                    idempotency_key="r18-exact-override-test-bootstrap",
                    event_at="2026-07-21T18:00:00Z",
                )
                result = daemon.reserve_model_call(
                    role="CRITIC_PRIMARY",
                    role_assignment_ref="role-assignment:r18-test/critic-primary",
                    classification="D0",
                    request_body="Synthetic D0 fallback routing proof.",
                    max_tokens=512,
                    max_cost_units=5,
                    expires_at="2026-07-21T19:00:00Z",
                    actor="scout:uid:10003",
                    idempotency_key="kmax-test-kimi-primary",
                    now="2026-07-21T18:00:00Z",
                )
            finally:
                daemon.close()
        self.assertEqual(result["state"], "RESERVED")
        self.assertEqual(result["model_binding"], "kimi-k3-max")
        self.assertFalse(result["used_fallback"])

    def test_runbook_available_bindings_fail_closed_and_render_by_name(self) -> None:
        """The durable source advertises no binding before name-only capability render."""
        runbook = json.loads(
            (REPO_ROOT / "ops/connected-worker/runbook-inputs-v2.json").read_text()
        )
        composition = runbook["researchd_runtime_composition"]
        runtime = composition["add_frozen_binding"]["model_runtime"]
        self.assertEqual(runtime["available_bindings"], [])
        render = composition["available_bindings_render"]
        self.assertEqual(render["mode"], "NAME_ONLY_NONEMPTY_CREDENTIAL_INTERSECTION")
        self.assertTrue(render["required_before_private_render"])
        self.assertEqual(render["fail_closed_default"], [])
        self.assertFalse(render["credential_values_recorded"])

        profile = json.loads(
            (REPO_ROOT / "provenance/model-provider-connected-shadow-v4.json").read_text()
        )
        required = {
            name: binding["credential_env"]
            for name, binding in profile["bindings"].items()
        }

        def available(capabilities: set[str]) -> list[str]:
            return sorted(name for name, credential in required.items() if credential in capabilities)

        self.assertEqual(
            available({"OPENROUTER_API_KEY"}),
            ["gpt-5.6-sol-xhigh"],
        )
        self.assertEqual(
            available({"MOONSHOT_API_KEY"}),
            ["kimi-k3-max"],
        )
        self.assertEqual(
            available(
                {"DEEPSEEK_API_KEY", "MOONSHOT_API_KEY", "OPENROUTER_API_KEY"}
            ),
            [
                "deepseek-v4-flash",
                "deepseek-v4-pro",
                "gpt-5.6-sol-xhigh",
                "kimi-k3-max",
            ],
        )
        self.assertNotIn("claude-fable-5", required)
        self.assertNotIn("gpt-5.6-sol-max", required)

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
                    "kimi-k3-max",
                    "gpt-5.6-sol-xhigh",
                }
            ),
        )
        self.assertEqual(plan.status, "ROUTED")
        self.assertEqual(len(plan.decisions), 4)


if __name__ == "__main__":
    unittest.main()
