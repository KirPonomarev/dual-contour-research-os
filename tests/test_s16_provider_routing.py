from __future__ import annotations

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
    FixtureProviderAdapter,
    KnownProviderFailure,
    ModelBrokerError,
    ModelCallBroker,
    ModelErrorObservation,
    ModelProviderRouting,
    ModelRoleRegistry,
    ProviderResult,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    AT,
    AT_SENT,
    RecordingCommitter,
    policy,
    seeded_ledger,
    spec,
)


ROLE_PROFILE = (
    ROOT / "contracts" / "a1" / "v1" / "profiles" / "model_role_registry_v1.json"
)
ROLE_PROFILE_SHA256 = hashlib.sha256(ROLE_PROFILE.read_bytes()).hexdigest()
ROUTING_PROFILE = ROOT / "provenance" / "model-provider-routing-v1.json"
ROUTING_PROFILE_SHA256 = "37db8596a8245a6b1ea2bc5bce1495a4e7dadb314876e51397ad11dd194b3dc6"
ROUTED = frozenset(
    {
        "deepseek-v4-flash",
        "deepseek-v4-pro",
        "glm-5.2-max",
        "gpt-5.6-sol-xhigh",
        "gpt-5.6-sol-max",
    }
)


def role_registry(
    *, overrides: dict[str, str | None] | None = None
) -> ModelRoleRegistry:
    return ModelRoleRegistry(
        ROLE_PROFILE,
        expected_profile_sha256=ROLE_PROFILE_SHA256,
        binding_revision="s16-fixture-v1",
        binding_overrides=overrides,
    )


def routing(
    profile: Path = ROUTING_PROFILE,
    *,
    expected_sha256: str = ROUTING_PROFILE_SHA256,
    registry: ModelRoleRegistry | None = None,
) -> ModelProviderRouting:
    return ModelProviderRouting(
        profile,
        expected_profile_sha256=expected_sha256,
        role_registry=registry or role_registry(),
    )


class ProviderRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temp_path = Path(self.temporary.name)

    def mutated_profile(self, mutator) -> tuple[Path, str]:  # type: ignore[no-untyped-def]
        value = json.loads(ROUTING_PROFILE.read_text())
        mutator(value)
        path = self.temp_path / ("mutated-" + str(len(list(self.temp_path.iterdir()))) + ".json")
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_profile_is_exact_fixture_only_and_reserve_stays_disabled(self) -> None:
        router = routing()
        self.assertEqual(router.profile_sha256, ROUTING_PROFILE_SHA256)
        for name in ROUTED:
            binding = router.binding(name)
            self.assertEqual(binding.availability, "FIXTURE_ONLY")
            self.assertEqual(binding.fixture_eval_status, "PASS")
            self.assertEqual(binding.api_identifier_status, "UNVERIFIED")
            self.assertEqual(binding.allowed_input_classes, ("D0", "D1"))
        reserve = router.binding("qwen-reserve-slot")
        self.assertEqual(reserve.availability, "DISABLED_UNEVALUATED")
        self.assertEqual(reserve.fixture_eval_status, "NOT_RUN")
        self.assertIsNone(reserve.candidate_api_identifier)
        self.assertEqual(
            router.binding("deepseek-v4-flash").provenance_group,
            router.binding("deepseek-v4-pro").provenance_group,
        )
        self.assertEqual(
            router.binding("gpt-5.6-sol-xhigh").provenance_group,
            router.binding("gpt-5.6-sol-max").provenance_group,
        )

    def test_digest_semantics_registry_drift_and_unevaluated_routes_fail_closed(self) -> None:
        with self.assertRaises(ModelBrokerError):
            routing(expected_sha256="0" * 64)
        with self.assertRaises(ModelBrokerError):
            routing(registry=role_registry(overrides={"SCOUT_FAST": "replacement"}))

        mutations = {
            "real-provider": lambda value: value["invariants"].__setitem__(
                "real_provider_calls", True
            ),
            "unevaluated-route": lambda value: value["bindings"][
                "deepseek-v4-flash"
            ].__setitem__("fixture_eval_status", "NOT_RUN"),
            "activate-reserve": lambda value: value["roles"][
                "ARBITER_RESERVE"
            ].__setitem__("primary", "qwen-reserve-slot"),
            "split-family": lambda value: value["bindings"][
                "gpt-5.6-sol-max"
            ].__setitem__("provenance_group", "openai:fake-independent-effort"),
            "widen-cap": lambda value: value["council"].__setitem__(
                "max_calls", 5
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                path, digest = self.mutated_profile(mutate)
                with self.assertRaises(ModelBrokerError):
                    routing(path, expected_sha256=digest)

    def test_primary_fallback_privacy_and_unavailable_actions_are_deterministic(self) -> None:
        router = routing()
        first = router.route(
            "SCOUT_FAST", "D0", available_bindings=ROUTED
        )
        replay = router.route(
            "SCOUT_FAST", "D0", available_bindings=ROUTED
        )
        self.assertEqual(first, replay)
        self.assertEqual(first.binding, "deepseek-v4-flash")
        self.assertFalse(first.used_fallback)
        fallback = router.route(
            "SCOUT_FAST",
            "D1",
            available_bindings=frozenset({"deepseek-v4-pro"}),
        )
        self.assertEqual(fallback.binding, "deepseek-v4-pro")
        self.assertTrue(fallback.used_fallback)
        self.assertEqual(
            router.route(
                "SCOUT_FAST", "D0", available_bindings=frozenset()
            ).status,
            "PARKED",
        )
        self.assertEqual(
            router.route(
                "CRITIC_PRIMARY", "D0", available_bindings=frozenset()
            ).status,
            "WAIT_PROVIDER",
        )
        with self.assertRaises(ModelBrokerError):
            router.route("SCOUT_FAST", "D2", available_bindings=ROUTED)
        with self.assertRaises(ModelBrokerError):
            router.route(
                "SCOUT_FAST", "D0", available_bindings={"deepseek-v4-flash"}  # type: ignore[arg-type]
            )
        with self.assertRaises(ModelBrokerError):
            router.route(
                "SCOUT_FAST",
                "D0",
                available_bindings=frozenset({"attacker-binding"}),
            )
        with self.assertRaises(ModelBrokerError):
            router.route(
                "ARBITER_RESERVE",
                "D0",
                available_bindings=frozenset({"qwen-reserve-slot"}),
            )

    def test_council_is_policy_selected_capped_and_never_independence_evidence(self) -> None:
        router = routing()
        expected_counts = {"STANDARD": 2, "MATERIAL": 3, "CRITICAL": 4}
        for tier, count in expected_counts.items():
            with self.subTest(tier=tier):
                plan = router.plan_council(
                    tier, "D0", available_bindings=ROUTED
                )
                self.assertEqual(plan.status, "ROUTED")
                self.assertEqual(plan.call_count, count)
                self.assertLessEqual(plan.call_count, plan.max_calls)
                self.assertEqual(
                    plan.independence_status, "INDEPENDENCE_NOT_ESTABLISHED"
                )
                self.assertFalse(plan.consensus_is_evidence)
        waiting = router.plan_council(
            "STANDARD",
            "D1",
            available_bindings=frozenset({"deepseek-v4-pro"}),
        )
        self.assertEqual(waiting.status, "WAIT_PROVIDER")
        self.assertEqual(waiting.call_count, 1)
        self.assertNotIn("binding", inspect.signature(router.plan_council).parameters)
        with self.assertRaises(ModelBrokerError):
            router.plan_council("ATTACKER_TIER", "D0", available_bindings=ROUTED)

    def test_fixture_adapter_obeys_protocol_and_never_performs_connected_fallback(self) -> None:
        router = routing()
        request = b"public synthetic adapter request"
        result = ProviderResult(
            raw_response=b'{"fixture":true}',
            actual_tokens=3,
            actual_cost_units=1,
            provider_receipt_ref="fixture:response-001",
        )
        adapter = FixtureProviderAdapter(
            router.binding("deepseek-v4-flash"),
            {hashlib.sha256(request).hexdigest(): result},
        )
        self.assertEqual(
            adapter.invoke(
                call_id="model-call:" + "a" * 64,
                request_bytes=request,
                max_tokens=4,
            ),
            result,
        )
        with self.assertRaises(KnownProviderFailure) as missing:
            adapter.invoke(
                call_id="model-call:" + "b" * 64,
                request_bytes=b"unregistered",
                max_tokens=4,
            )
        self.assertEqual(missing.exception.code, "FIXTURE_CASE_NOT_REGISTERED")
        with self.assertRaises(KnownProviderFailure) as over_limit:
            adapter.invoke(
                call_id="model-call:" + "c" * 64,
                request_bytes=request,
                max_tokens=2,
            )
        self.assertEqual(over_limit.exception.code, "FIXTURE_TOKEN_LIMIT_EXCEEDED")
        with self.assertRaises(ModelBrokerError):
            FixtureProviderAdapter(router.binding("qwen-reserve-slot"), {})

    def test_fixture_adapter_runs_through_existing_durable_broker(self) -> None:
        database = self.temp_path / "broker.sqlite3"
        request = b"public synthetic model request"
        result = ProviderResult(
            raw_response=b'{"synthetic":"routed"}',
            actual_tokens=7,
            actual_cost_units=2,
            provider_receipt_ref="fixture:routed-response",
        )
        router = routing()
        with seeded_ledger(database) as ledger:
            broker = ModelCallBroker(
                registry=role_registry(), ledger=ledger, budget_policy=policy()
            )
            call = spec(request=request, key="s16-routed-call")
            handle = broker.prepare(call, event_at=AT)
            adapter = FixtureProviderAdapter(
                router.binding("deepseek-v4-flash"),
                {hashlib.sha256(request).hexdigest(): result},
            )
            completed = broker.execute(
                handle.call_id,
                request_bytes=request,
                adapter=adapter,
                response_committer=RecordingCommitter(ledger, handle.call_id),
                event_at=AT_SENT,
            )
            self.assertEqual(completed.state, "SUCCEEDED")
            self.assertEqual(
                [item.snapshot["state"] for item in ledger.model_call_history(handle.call_id)],
                ["PROPOSED", "RESERVED", "SENT", "SUCCEEDED"],
            )

    def test_correlation_counts_pairs_uncertainty_and_same_family_dependence(self) -> None:
        router = routing()
        same_family = (
            ModelErrorObservation("case-1", "deepseek-v4-flash", True),
            ModelErrorObservation("case-1", "deepseek-v4-pro", True),
            ModelErrorObservation("case-2", "deepseek-v4-flash", True),
            ModelErrorObservation("case-2", "deepseek-v4-pro", False),
            ModelErrorObservation("unpaired", "deepseek-v4-flash", False),
        )
        snapshot = router.correlation_snapshot(
            "deepseek-v4-flash", "deepseek-v4-pro", same_family
        )
        self.assertEqual(snapshot.sample_size, 2)
        self.assertEqual((snapshot.left_errors, snapshot.right_errors), (2, 1))
        self.assertEqual(snapshot.joint_errors, 1)
        self.assertEqual(snapshot.joint_error_rate_ppm, 500_000)
        self.assertLess(snapshot.uncertainty_low_ppm, snapshot.joint_error_rate_ppm)
        self.assertGreater(snapshot.uncertainty_high_ppm, snapshot.joint_error_rate_ppm)
        self.assertEqual(
            snapshot.independence_status, "CORRELATED_SAME_PROVENANCE_GROUP"
        )
        cross = router.correlation_snapshot(
            "glm-5.2-max", "gpt-5.6-sol-xhigh", ()
        )
        self.assertEqual(cross.sample_size, 0)
        self.assertEqual(cross.uncertainty_high_ppm, 1_000_000)
        self.assertEqual(
            cross.independence_status, "INDEPENDENCE_NOT_ESTABLISHED"
        )
        with self.assertRaises(ModelBrokerError):
            router.correlation_snapshot("glm-5.2-max", "glm-5.2-max", ())
        with self.assertRaises(ModelBrokerError):
            router.correlation_snapshot(
                "glm-5.2-max",
                "gpt-5.6-sol-xhigh",
                (
                    ModelErrorObservation("case", "glm-5.2-max", False),
                    ModelErrorObservation("case", "glm-5.2-max", True),
                ),
            )

    def test_governance_evidence_is_integrity_bound_and_contains_no_connected_material(self) -> None:
        source = json.loads(
            (
                ROOT
                / "docs"
                / "receipts"
                / "source-freeze"
                / "s16-model-provider-routing-fixtures.json"
            ).read_text()
        )
        reuse = json.loads(
            (
                ROOT
                / "docs"
                / "receipts"
                / "reuse"
                / "s16-provider-adapters-routing.json"
            ).read_text()
        )
        for receipt in (source, reuse):
            digest = hashlib.sha256(
                json.dumps(
                    receipt["payload"], sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
            self.assertEqual(receipt["integrity"]["payload_sha256"], digest)
        text = ROUTING_PROFILE.read_text().lower()
        for forbidden in (
            "https://api.",
            "authorization",
            "bearer ",
            "api_key",
            "secret_key",
        ):
            self.assertNotIn(forbidden, text)
        self.assertEqual(
            source["payload"]["selected_source_sha"], ROUTING_PROFILE_SHA256
        )
        self.assertIn(
            "parked-until-S17-connected-shadow",
            reuse["payload"]["candidates"][3]["disposition"],
        )


if __name__ == "__main__":
    unittest.main()
