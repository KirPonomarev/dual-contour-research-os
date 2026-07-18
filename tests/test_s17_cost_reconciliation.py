from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import inspect
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
    ProviderResult,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    AT,
    AT_RECONCILED,
    AT_SENT,
    RecordingAdapter,
    RecordingCommitter,
    policy,
    registry,
    seeded_ledger,
    spec,
)


class CostReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "shadow.sqlite3"
        self.profile = shadow.ConnectedShadowProfile()

    def ambiguous_success(self, *, key: str = "s17-cost") -> str:
        with seeded_ledger(self.database) as ledger:
            broker = ModelCallBroker(
                registry=registry(), ledger=ledger, budget_policy=policy()
            )
            call = spec(key=key)
            handle = broker.prepare(call, event_at=AT)
            completed = broker.execute(
                handle.call_id,
                request_bytes=call.request_bytes,
                adapter=RecordingAdapter(
                    ledger,
                    result=ProviderResult(
                        b'{"synthetic":"provider-response"}',
                        5,
                        None,
                        "provider:synthetic-unsettled",
                    ),
                ),
                response_committer=RecordingCommitter(ledger, handle.call_id),
                event_at=AT_SENT,
            )
            self.assertEqual(completed.state, "SUCCEEDED")
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertTrue(state["ambiguous_usage"])
            self.assertFalse(state["budget_released"])
            return handle.call_id

    def args(self, call_id: str, *, tokens: int = 5, cost: int = 2) -> argparse.Namespace:
        return argparse.Namespace(
            ledger=str(self.database),
            call_id=call_id,
            actual_tokens=tokens,
            actual_cost_units=cost,
            provider_receipt_ref="billing-receipt:sha256:" + "7" * 64,
            event_at=AT_RECONCILED,
            idempotency_key="s17-cost-reconcile",
        )

    def test_exact_billing_evidence_reconciles_and_releases_once(self) -> None:
        call_id = self.ambiguous_success()
        output = io.StringIO()
        with patch.object(
            shadow, "_http_post", side_effect=AssertionError("network forbidden")
        ):
            with redirect_stdout(output):
                code = shadow._reconcile(self.args(call_id), self.profile)
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["state"], "RECONCILED")
        self.assertEqual(result["actual_tokens"], 5)
        self.assertEqual(result["actual_cost_units"], 2)
        self.assertFalse(result["ambiguous_usage"])
        self.assertTrue(result["budget_released"])
        self.assertEqual(result["network_calls"], 0)
        self.assertFalse(result["credential_access"])
        self.assertFalse(result["secrets_printed"])

    def test_exact_replay_is_idempotent_and_conflicting_replay_fails_closed(self) -> None:
        call_id = self.ambiguous_success()
        first = io.StringIO()
        replay = io.StringIO()
        with redirect_stdout(first):
            self.assertEqual(shadow._reconcile(self.args(call_id), self.profile), 0)
        with redirect_stdout(replay):
            self.assertEqual(shadow._reconcile(self.args(call_id), self.profile), 0)
        self.assertEqual(json.loads(first.getvalue()), json.loads(replay.getvalue()))
        with self.assertRaises(ModelBrokerError):
            shadow._reconcile(self.args(call_id, cost=3), self.profile)

    def test_reconcile_before_terminal_state_cannot_release_budget(self) -> None:
        with seeded_ledger(self.database) as ledger:
            broker = ModelCallBroker(
                registry=registry(), ledger=ledger, budget_policy=policy()
            )
            call = spec(key="s17-premature-reconcile")
            handle = broker.prepare(call, event_at=AT)
        with self.assertRaises(ModelBrokerError):
            shadow._reconcile(self.args(handle.call_id), self.profile)
        with seeded_ledger(self.database) as ledger:
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertEqual(state["state"], "RESERVED")
            self.assertFalse(state["budget_released"])

    def test_reconciliation_code_has_no_transport_or_environment_credential_path(self) -> None:
        source = inspect.getsource(shadow._reconcile)
        self.assertNotIn("_http_post", source)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("HTTPRawAdapter", source)
        self.assertIn("broker.reconcile", source)


if __name__ == "__main__":
    unittest.main()
