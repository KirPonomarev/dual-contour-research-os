from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import model_provider_shadow as shadow  # noqa: E402
from research_bridge.model_broker import (  # noqa: E402
    ModelBrokerError,
    ModelCallBroker,
    ModelErrorObservation,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    AT,
    AT_RECONCILED,
    AT_SENT,
    policy,
    registry,
    seeded_ledger,
    spec,
)
from tests.test_s16_provider_routing import ROUTED, routing  # noqa: E402


def raw_envelope(binding: str, body: bytes, *, status: int = 200) -> bytes:
    return json.dumps(
        {
            "binding": binding,
            "protocol": "OPENAI_CHAT_COMPLETIONS",
            "http_status": status,
            "headers": {"x-request-id": "synthetic-hostile"},
            "body_base64": base64.b64encode(body).decode(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class StaticRawAdapter:
    model_binding = "deepseek-v4-flash"

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.calls = 0

    def invoke_raw(self, *, call_id: str, request_bytes: bytes, max_tokens: int) -> bytes:
        self.calls += 1
        return self.raw


class ProviderSpecificHostileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = shadow.ConnectedShadowProfile()

    def execute(self, raw: bytes, *, key: str):
        database = self.root / f"{key}.sqlite3"
        adapter = StaticRawAdapter(raw)
        request = b"synthetic-public-provider-hostile"
        with seeded_ledger(database) as ledger:
            broker = ModelCallBroker(
                registry=registry(), ledger=ledger, budget_policy=policy()
            )
            call = spec(request=request, key=key)
            prepared = broker.prepare(call, event_at=AT)
            completed = broker.execute_raw(
                prepared.call_id,
                request_bytes=request,
                adapter=adapter,
                response_committer=shadow.CASCommitter(
                    self.root / f"{key}-cas", quota_bytes=16_384
                ),
                response_parser=shadow.HTTPResponseParser(
                    "deepseek-v4-flash", "OPENAI_CHAT_COMPLETIONS"
                ),
                event_at=AT_SENT,
            )
            snapshot = dict(ledger.model_call_state(completed.call_id).snapshot)
            history = [row.snapshot["state"] for row in ledger.model_call_history(completed.call_id)]
        return completed.call_id, adapter, snapshot, history, database

    def test_duplicate_keys_and_nonfinite_numbers_commit_then_become_unknown(self) -> None:
        attacks = (
            b'{"id":"a","id":"b","choices":[{}],"usage":{"total_tokens":1}}',
            b'{"id":"a","choices":[{}],"usage":{"total_tokens":NaN}}',
            b'{"id":"a","choices":[{}],"usage":{"total_tokens":Infinity}}',
        )
        for index, body in enumerate(attacks):
            with self.subTest(index=index):
                call_id, adapter, snapshot, history, _ = self.execute(
                    raw_envelope("deepseek-v4-flash", body),
                    key=f"strict-json-{index}",
                )
                self.assertEqual(adapter.calls, 1)
                self.assertEqual(snapshot["state"], "UNKNOWN")
                self.assertTrue(str(snapshot["response_ref"]).startswith("cas:sha256:"))
                self.assertFalse(snapshot["budget_released"])
                self.assertFalse(snapshot["auto_retry"])
                self.assertEqual(history, ["PROPOSED", "RESERVED", "SENT", "UNKNOWN"])
                self.assertTrue(call_id.startswith("model-call:"))

    def test_malformed_success_and_http_failure_are_conservative_unknown_without_retry(self) -> None:
        cases = (
            raw_envelope("deepseek-v4-flash", b'{"id":"","choices":[{}],"usage":{"total_tokens":1}}'),
            raw_envelope("deepseek-v4-flash", b'{"id":"ok","choices":[{}],"usage":{"total_tokens":true}}'),
            raw_envelope("deepseek-v4-flash", b'{"error":{"type":"rate_limit"}}', status=429),
        )
        for index, raw in enumerate(cases):
            with self.subTest(index=index):
                _, adapter, snapshot, _, _ = self.execute(raw, key=f"malformed-{index}")
                self.assertEqual(adapter.calls, 1)
                self.assertEqual(snapshot["state"], "UNKNOWN")
                self.assertFalse(snapshot["auto_retry"])
                self.assertFalse(snapshot["budget_released"])

    def test_adapter_rejects_oversize_body_and_hostile_headers_before_envelope(self) -> None:
        binding = self.profile.binding("deepseek-v4-flash")
        oversize = shadow.HTTPRawAdapter(
            "deepseek-v4-flash",
            binding,
            "synthetic-key",
            timeout=1,
            maximum=8,
            transport=lambda *_args: (200, {}, b"x" * 9),
        )
        with self.assertRaisesRegex(shadow.ShadowProviderError, "adapter bound"):
            oversize.invoke_raw(
                call_id="model-call:" + "a" * 64,
                request_bytes=b"{}",
                max_tokens=1,
            )
        hostile_header = shadow.HTTPRawAdapter(
            "deepseek-v4-flash",
            binding,
            "synthetic-key",
            timeout=1,
            maximum=128,
            transport=lambda *_args: (200, {"x-request-id": "x" * 513}, b"{}"),
        )
        with self.assertRaisesRegex(shadow.ShadowProviderError, "headers"):
            hostile_header.invoke_raw(
                call_id="model-call:" + "b" * 64,
                request_bytes=b"{}",
                max_tokens=1,
            )

    def test_unknown_can_only_release_after_exact_idempotent_reconciliation(self) -> None:
        call_id, _, snapshot, _, database = self.execute(
            raw_envelope(
                "deepseek-v4-flash",
                b'{"id":"bad","choices":[],"usage":{"total_tokens":1}}',
            ),
            key="partial-settlement",
        )
        self.assertEqual(snapshot["state"], "UNKNOWN")
        receipt = "billing-receipt:sha256:" + hashlib.sha256(b"synthetic-exact-billing").hexdigest()
        with seeded_ledger(database) as ledger:
            broker = ModelCallBroker(
                registry=registry(), ledger=ledger, budget_policy=policy()
            )
            first = broker.reconcile(
                call_id,
                actual_tokens=0,
                actual_cost_units=0,
                provider_receipt_ref=receipt,
                event_at=AT_RECONCILED,
                idempotency_key="s18-exact-reconcile",
            )
            replay = broker.reconcile(
                call_id,
                actual_tokens=0,
                actual_cost_units=0,
                provider_receipt_ref=receipt,
                event_at=AT_RECONCILED,
                idempotency_key="s18-exact-reconcile",
            )
            self.assertEqual(first, replay)
            reconciled = ledger.model_call_state(call_id).snapshot
            self.assertEqual(reconciled["state"], "RECONCILED")
            self.assertTrue(reconciled["budget_released"])
            with self.assertRaises(ModelBrokerError):
                broker.reconcile(
                    call_id,
                    actual_tokens=1,
                    actual_cost_units=0,
                    provider_receipt_ref=receipt,
                    event_at=AT_RECONCILED,
                    idempotency_key="s18-conflicting-reconcile",
                )

    def test_drift_fallback_and_temporary_kimi_candidate_fail_closed(self) -> None:
        value = json.loads(shadow.PROFILE_PATH.read_text())
        mutations = (
            lambda item: item["bindings"]["deepseek-v4-flash"].__setitem__("api_model", "drifted"),
            lambda item: item["bindings"]["glm-5.2-max"].__setitem__("credential_env", "ATTACKER_KEY"),
            lambda item: item["bindings"]["gpt-5.6-sol-max"]["request_options"].__setitem__("store", True),
        )
        for index, mutate in enumerate(mutations):
            candidate = json.loads(json.dumps(value))
            mutate(candidate)
            path = self.root / f"drift-{index}.json"
            path.write_text(json.dumps(candidate))
            with self.assertRaises(shadow.ShadowProviderError):
                shadow.ConnectedShadowProfile(path)

        router = routing()
        unavailable = router.plan_council(
            "CRITICAL", "D0", available_bindings=ROUTED - {"gpt-5.6-sol-xhigh", "gpt-5.6-sol-max"}
        )
        self.assertEqual(unavailable.status, "WAIT_PROVIDER")
        with self.assertRaises(ModelBrokerError):
            router.route(
                "CRITIC_DEEP",
                "D0",
                available_bindings=frozenset({"kimi-k3-temporary-shadow-candidate"}),
            )

    def test_collusion_like_agreement_never_establishes_independence(self) -> None:
        router = routing()
        observations = tuple(
            observation
            for case in ("case-1", "case-2", "case-3")
            for observation in (
                ModelErrorObservation(case, "deepseek-v4-pro", True),
                ModelErrorObservation(case, "glm-5.2-max", True),
            )
        )
        snapshot = router.correlation_snapshot(
            "deepseek-v4-pro", "glm-5.2-max", observations
        )
        self.assertEqual(snapshot.sample_size, 3)
        self.assertEqual(snapshot.joint_errors, 3)
        self.assertEqual(snapshot.joint_error_rate_ppm, 1_000_000)
        self.assertEqual(snapshot.independence_status, "INDEPENDENCE_NOT_ESTABLISHED")
        self.assertGreater(snapshot.uncertainty_low_ppm, 0)

    def test_preflight_and_hostile_paths_never_print_credentials(self) -> None:
        secret = "synthetic-secret-never-print-s18"
        output = io.StringIO()
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": secret}, clear=True):
            with redirect_stdout(output):
                self.assertEqual(shadow._preflight(self.profile), 0)
        self.assertNotIn(secret, output.getvalue())
        source = (ROOT / "tools" / "model_provider_shadow.py").read_text()
        self.assertNotIn("automatic_retry=True", source)


if __name__ == "__main__":
    unittest.main()
