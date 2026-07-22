from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from research_bridge.model_broker import (  # noqa: E402
    ModelBrokerError,
    ModelProviderRouting,
    ModelRoleRegistry,
)
from research_bridge.researchd import (  # noqa: E402
    _ServiceConfigError,
    _service_config_from_mapping,
)
from tools import model_provider_shadow_v4 as shadow  # noqa: E402


WORKER_PATH = ROOT / "ops" / "connected-worker" / "model_worker_v4.py"
POLICY_PATH = ROOT / "ops" / "connected-worker" / "runtime-policy-v4.json"
ROUTING_PATH = ROOT / "provenance" / "model-provider-routing-v2.json"
ROLE_PATH = ROOT / "contracts" / "a1" / "v1" / "profiles" / "model_role_registry_v1.json"
CONFIG_PATH = ROOT / "ops" / "release" / "researchd.config.template.json"

worker_spec = importlib.util.spec_from_file_location("r09a_model_worker_v4", WORKER_PATH)
assert worker_spec is not None and worker_spec.loader is not None
worker = importlib.util.module_from_spec(worker_spec)
sys.modules[worker_spec.name] = worker
worker_spec.loader.exec_module(worker)

ROLE_SHA256 = hashlib.sha256(ROLE_PATH.read_bytes()).hexdigest()
ROUTING_SHA256 = hashlib.sha256(ROUTING_PATH.read_bytes()).hexdigest()
ROLE_EVALUATION_SHA256 = (
    "111a7ac1dc954466b19d5e408debeeefcf65c76b5b025a743a2433be910c1e75"
)
WORKER_EXTENSION_SHA256 = (
    "03d91f027bb6975c55d84acaef188546bcd24af9944a72f4ff9314296399d07a"
)


def _registry() -> ModelRoleRegistry:
    return ModelRoleRegistry(
        ROLE_PATH,
        expected_profile_sha256=ROLE_SHA256,
        binding_revision="kmax-kimi-k3-max-gpt-xhigh-v1",
        binding_overrides={
            "CRITIC_PRIMARY": "kimi-k3-max",
            "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
            "CHIEF_SCIENTIST": "gpt-5.6-sol-xhigh",
        },
    )


def _routing() -> ModelProviderRouting:
    return ModelProviderRouting(
        ROUTING_PATH,
        expected_profile_sha256=ROUTING_SHA256,
        role_registry=_registry(),
    )


def _runtime_config(routing_sha256: str = ROUTING_SHA256) -> dict[str, object]:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    worker_uid = 10004
    if worker_uid not in config["allowed_uids"]:
        config["allowed_uids"].append(worker_uid)
    config["principal_roles"][str(worker_uid)] = "connected_worker"
    config["frozen_bindings"]["model_runtime"] = {
        "role_registry_sha256": ROLE_SHA256,
        "routing_profile_sha256": routing_sha256,
        "role_evaluation_sha256": ROLE_EVALUATION_SHA256,
        "worker_ipc_extension_sha256": WORKER_EXTENSION_SHA256,
        "binding_revision": "kmax-kimi-k3-max-gpt-xhigh-v1",
        "budget_policy_ref": "budget-policy:sha256:" + "a" * 64,
        "budget_scope_ref": "budget-scope:sha256:" + "b" * 64,
        "max_active_calls": 4,
        "max_reserved_tokens": 20000,
        "max_reserved_cost_units": 40,
        "available_bindings": [
            "deepseek-v4-pro",
            "kimi-k3-max",
            "gpt-5.6-sol-xhigh",
        ],
        "role_binding_overrides": {
            "CRITIC_PRIMARY": "kimi-k3-max",
            "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
            "CHIEF_SCIENTIST": "gpt-5.6-sol-xhigh",
        },
    }
    return config


class DualContourAdvisorTests(unittest.TestCase):
    def test_v4_profile_policy_and_request_are_exact(self) -> None:
        profile = shadow.ConnectedShadowProfile(shadow.ADVISOR_PROFILE_PATH)
        policy = worker.RuntimePolicy.load(POLICY_PATH)
        self.assertEqual(profile.profile_id, "model-provider-connected-shadow-v4")
        self.assertEqual(policy.shadow_profile_sha256, profile.sha256)
        self.assertEqual(
            policy.shadow_tool_sha256,
            hashlib.sha256((ROOT / "tools/model_provider_shadow_v4.py").read_bytes()).hexdigest(),
        )
        binding = profile.binding("kimi-k3-max")
        self.assertEqual(binding["provider"], "moonshot")
        self.assertEqual(binding["provider_slot"], "MOONSHOT_API")
        self.assertEqual(binding["credential_env"], "MOONSHOT_API_KEY")
        self.assertEqual(binding["api_model"], "kimi-k3")
        request = json.loads(
            shadow.build_request_bytes(binding, b"public synthetic critique", 32)
        )
        self.assertEqual(request["model"], "kimi-k3")
        self.assertEqual(request["reasoning_effort"], "max")
        self.assertNotIn("MOONSHOT_API_KEY", json.dumps(request))
        self.assertEqual(worker._provider_timeout_seconds("kimi-k3-max", profile), 1200)
        sol = profile.binding("gpt-5.6-sol-xhigh")
        self.assertEqual(sol["request_options"], {"reasoning": {"effort": "xhigh"}})

    def test_kimi_alone_receives_the_16384_provider_output_ceiling(self) -> None:
        profile = shadow.ConnectedShadowProfile(shadow.ADVISOR_PROFILE_PATH)
        policy = worker.RuntimePolicy.load(POLICY_PATH)
        kimi = profile.binding("kimi-k3-max")
        request, limit = worker._bounded_provider_request(
            "kimi-k3-max",
            kimi,
            b"public synthetic critique",
            total_token_budget=20_000,
            policy=policy,
        )
        self.assertEqual(limit, 16_384)
        self.assertEqual(json.loads(request)["max_tokens"], 16_384)
        self.assertEqual(json.loads(request)["reasoning_effort"], "max")
        for name in (
            "deepseek-v4-flash",
            "deepseek-v4-pro",
            "glm-5.2-max",
            "gpt-5.6-sol-xhigh",
        ):
            _request, other_limit = worker._bounded_provider_request(
                name,
                profile.binding(name),
                b"public synthetic control",
                total_token_budget=16_384,
                policy=policy,
            )
            self.assertLessEqual(other_limit, 4096, name)
        with self.assertRaises(shadow.ShadowProviderError):
            shadow.build_request_bytes(kimi, b"public synthetic", 16_385)

    def test_provider_input_margin_is_removed_from_the_output_allowance(self) -> None:
        profile = shadow.ConnectedShadowProfile(shadow.ADVISOR_PROFILE_PATH)
        policy = worker.RuntimePolicy.load(POLICY_PATH)
        kimi = profile.binding("kimi-k3-max")
        request, limit = worker._bounded_provider_request(
            "kimi-k3-max",
            kimi,
            b"public synthetic bounded proof",
            total_token_budget=768,
            policy=policy,
        )
        self.assertEqual(policy.provider_input_token_margin, 256)
        self.assertEqual(limit, 512)
        self.assertEqual(json.loads(request)["max_tokens"], 512)
        with self.assertRaisesRegex(
            worker.ConnectedWorkerError,
            "total token reservation cannot cover the provider input margin",
        ):
            worker._bounded_provider_request(
                "kimi-k3-max",
                kimi,
                b"public synthetic bounded proof",
                total_token_budget=256,
                policy=policy,
            )

    def test_kimi_is_deterministic_critic_and_precedes_xhigh(self) -> None:
        router = _routing()
        primary = router.route(
            "CRITIC_PRIMARY",
            "D0",
            available_bindings=frozenset({"glm-5.2-max", "kimi-k3-max"}),
        )
        self.assertEqual(primary.binding, "kimi-k3-max")
        self.assertFalse(primary.used_fallback)
        deep = router.route(
            "CRITIC_DEEP",
            "D1",
            available_bindings=frozenset({"gpt-5.6-sol-xhigh"}),
        )
        self.assertEqual(deep.binding, "gpt-5.6-sol-xhigh")
        self.assertFalse(deep.used_fallback)
        with self.assertRaises(ModelBrokerError):
            router.route(
                "CRITIC_PRIMARY",
                "D2",
                available_bindings=frozenset({"kimi-k3-max"}),
            )
        council = router.plan_council(
            "STANDARD",
            "D0",
            available_bindings=frozenset(
                {"deepseek-v4-pro", "kimi-k3-max"}
            ),
        )
        self.assertEqual(council.status, "ROUTED")
        self.assertEqual(council.call_count, 2)
        self.assertEqual(council.decisions[1].binding, "kimi-k3-max")
        self.assertFalse(council.consensus_is_evidence)

    def test_researchd_accepts_only_exact_additive_routing_digest(self) -> None:
        service = _service_config_from_mapping(_runtime_config())
        runtime = service.frozen_bindings["model_runtime"]
        self.assertEqual(runtime["routing_profile_sha256"], ROUTING_SHA256)
        self.assertIn("kimi-k3-max", runtime["available_bindings"])
        self.assertNotIn("claude-fable-5", runtime["available_bindings"])
        with self.assertRaises(_ServiceConfigError):
            _service_config_from_mapping(_runtime_config("f" * 64))

    def test_profile_model_credential_and_authority_drift_fail_closed(self) -> None:
        original = json.loads(shadow.ADVISOR_PROFILE_PATH.read_text())
        mutations = (
            lambda value: value["bindings"]["kimi-k3-max"].__setitem__(
                "api_model", "attacker/model"
            ),
            lambda value: value["bindings"]["kimi-k3-max"].__setitem__(
                "credential_env", "ATTACKER_KEY"
            ),
            lambda value: value["invariants"].__setitem__(
                "caller_cannot_select_binding", False
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, mutate in enumerate(mutations):
                value = json.loads(json.dumps(original))
                mutate(value)
                path = Path(temporary) / f"mutated-{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(shadow.ShadowProviderError):
                    shadow.ConnectedShadowProfile(path)

    def test_public_stage_contains_no_openrouter_secret_shape(self) -> None:
        paths = (
            ROUTING_PATH,
            shadow.ADVISOR_PROFILE_PATH,
            ROOT / "tools/model_provider_shadow_v4.py",
            WORKER_PATH,
            POLICY_PATH,
        )
        for path in paths:
            secret_prefix = "sk-or-" + "v1-"
            self.assertNotIn(secret_prefix, path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
