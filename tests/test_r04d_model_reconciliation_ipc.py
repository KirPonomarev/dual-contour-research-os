from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.control import ControlError, ControlRequest
from tests import test_r04b_broker_scout_ipc as r04b


OPERATOR_UID = 10001
AVAILABLE_BINDING = "gpt-5.6-sol-xhigh"


class ModelReconciliationIPCAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = r04b.BrokerScoutIPCHandshakeTests(methodName="runTest")
        self.runtime.setUp()

    def tearDown(self) -> None:
        self.runtime.tearDown()

    @staticmethod
    def _receipt_ref(label: str) -> str:
        return "provider-billing:sha256:" + hashlib.sha256(label.encode()).hexdigest()

    def _terminal_call(self, suffix: str = "one"):
        config = self.runtime._config(available=[AVAILABLE_BINDING])
        daemon = self.runtime._daemon(config)
        daemon.start()
        self.runtime._bootstrap_claim(daemon, suffix)
        body = "One bounded public synthetic accounting proposal."
        reservation = self.runtime._reserve(
            daemon,
            "CRITIC_DEEP",
            body,
            suffix,
        )
        self.runtime._begin(daemon, reservation, body, suffix)
        completed = self.runtime._request(
            daemon,
            r04b.WORKER_UID,
            "complete_model_call",
            "complete:" + suffix,
            {
                "call_id": reservation["call_id"],
                "dispatch_token": reservation["dispatch_token"],
                "outcome": "SUCCEEDED",
                "response_ref": "cas:sha256:"
                + hashlib.sha256(body.encode()).hexdigest(),
                "actual_tokens": 17,
                "actual_cost_units": None,
                "provider_receipt_ref": "provider-response:sha256:"
                + hashlib.sha256((suffix + ":response").encode()).hexdigest(),
                "failure_code": None,
            },
        )
        self.assertEqual(completed.result["state"], "SUCCEEDED")
        self.assertTrue(completed.result["ambiguous_usage"])
        self.assertFalse(completed.result["budget_released"])
        return config, daemon, reservation

    def test_operator_reconciles_once_and_restart_replay_is_zero_write(self) -> None:
        config, daemon, reservation = self._terminal_call()
        payload = {
            "call_id": reservation["call_id"],
            "actual_tokens": 17,
            "actual_cost_units": 1,
            "provider_receipt_ref": self._receipt_ref("exact"),
        }
        before = daemon._ledger.event_count()
        reconciled = self.runtime._request(
            daemon,
            OPERATOR_UID,
            "reconcile_model_call",
            "reconcile:exact",
            payload,
        )
        self.assertEqual(reconciled.result["state"], "RECONCILED")
        self.assertTrue(reconciled.result["budget_released"])
        self.assertFalse(reconciled.result["ambiguous_usage"])
        self.assertEqual(reconciled.result["actual_tokens"], 17)
        self.assertEqual(reconciled.result["actual_cost_units"], 1)
        self.assertEqual(daemon._ledger.event_count(), before + 1)

        daemon.close()
        reopened = self.runtime._daemon(config)
        reopened.start()
        replay_before = reopened._ledger.event_count()
        replayed = self.runtime._request(
            reopened,
            OPERATOR_UID,
            "reconcile_model_call",
            "reconcile:after-restart",
            payload,
        )
        self.assertEqual(replayed.result, reconciled.result)
        self.assertEqual(reopened._ledger.event_count(), replay_before)

    def test_operator_may_reconcile_exact_terminal_accounting_after_expiry(self) -> None:
        _, daemon, reservation = self._terminal_call("late-expiry")
        daemon._clock = lambda: r04b.NOW + timedelta(hours=2)
        payload = {
            "call_id": reservation["call_id"],
            "actual_tokens": 17,
            "actual_cost_units": 1,
            "provider_receipt_ref": self._receipt_ref("late-expiry"),
        }
        before = daemon._ledger.event_count()
        reconciled = self.runtime._request(
            daemon,
            OPERATOR_UID,
            "reconcile_model_call",
            "reconcile:late-expiry",
            payload,
        )
        self.assertEqual(reconciled.result["state"], "RECONCILED")
        self.assertEqual(
            daemon._ledger.model_call_state(reservation["call_id"]).snapshot[
                "previous_state"
            ],
            "SUCCEEDED",
        )
        self.assertFalse(reconciled.result["ambiguous_usage"])
        self.assertTrue(reconciled.result["budget_released"])
        self.assertEqual(daemon._ledger.event_count(), before + 1)

        replay_before = daemon._ledger.event_count()
        replayed = self.runtime._request(
            daemon,
            OPERATOR_UID,
            "reconcile_model_call",
            "reconcile:late-expiry-replay",
            payload,
        )
        self.assertEqual(replayed.result, reconciled.result)
        self.assertEqual(daemon._ledger.event_count(), replay_before)

        conflict = dict(payload)
        conflict["actual_cost_units"] = 2
        with self.assertRaises(ControlError):
            self.runtime._request(
                daemon,
                OPERATOR_UID,
                "reconcile_model_call",
                "reconcile:late-expiry-conflict",
                conflict,
            )
        self.assertEqual(daemon._ledger.event_count(), replay_before)

    def test_role_version_shape_and_nonterminal_guards_fail_closed(self) -> None:
        _, daemon, reservation = self._terminal_call("guards")
        payload = {
            "call_id": reservation["call_id"],
            "actual_tokens": 17,
            "actual_cost_units": 1,
            "provider_receipt_ref": self._receipt_ref("guards"),
        }
        for uid in (r04b.SCOUT_UID, r04b.WORKER_UID):
            with self.assertRaises(ControlError):
                self.runtime._request(
                    daemon,
                    uid,
                    "reconcile_model_call",
                    f"reconcile:denied:{uid}",
                    payload,
                )
        with self.assertRaises(ControlError):
            ControlRequest(
                version="1.1",
                request_id="legacy-reconcile",
                idempotency_key="legacy-reconcile",
                command="reconcile_model_call",
                payload=payload,
            )
        for name, value in (
            ("actual_tokens", None),
            ("actual_tokens", -1),
            ("actual_cost_units", True),
        ):
            invalid = dict(payload)
            invalid[name] = value
            with self.assertRaises(ControlError):
                ControlRequest(
                    version="1.2",
                    request_id="invalid-" + name,
                    idempotency_key="invalid-" + name,
                    command="reconcile_model_call",
                    payload=invalid,
                )

        self.runtime._bootstrap_claim(daemon, "reserved")
        reserved = self.runtime._reserve(
            daemon,
            "CRITIC_DEEP",
            "Another bounded public proposal.",
            "reserved",
        )
        nonterminal = {
            "call_id": reserved["call_id"],
            "actual_tokens": 0,
            "actual_cost_units": 0,
            "provider_receipt_ref": self._receipt_ref("nonterminal"),
        }
        before = daemon._ledger.event_count()
        with self.assertRaises(ControlError):
            self.runtime._request(
                daemon,
                OPERATOR_UID,
                "reconcile_model_call",
                "reconcile:nonterminal",
                nonterminal,
            )
        self.assertEqual(daemon._ledger.event_count(), before)


if __name__ == "__main__":
    unittest.main()
