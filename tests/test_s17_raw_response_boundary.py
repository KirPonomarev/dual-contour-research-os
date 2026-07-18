from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.model_broker import (  # noqa: E402
    KnownProviderFailure,
    ModelBrokerError,
    ModelCallBroker,
    ProviderAccounting,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    AT,
    AT_SENT,
    policy,
    registry,
    seeded_ledger,
    spec,
)


class RawAdapter:
    model_binding = "deepseek-v4-flash"

    def __init__(self, events: list[str], result: bytes | Exception) -> None:
        self.events = events
        self.result = result
        self.calls = 0

    def invoke_raw(self, *, call_id: str, request_bytes: bytes, max_tokens: int) -> bytes:
        self.calls += 1
        self.events.append("receive")
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class OrderedCommitter:
    def __init__(self, events: list[str], *, fail: bool = False) -> None:
        self.events = events
        self.fail = fail

    def commit_response(self, raw_response: bytes) -> str:
        self.events.append("commit")
        if self.fail:
            raise OSError("synthetic CAS fault")
        return "cas:sha256:" + hashlib.sha256(raw_response).hexdigest()


class OrderedParser:
    model_binding = "deepseek-v4-flash"

    def __init__(
        self,
        events: list[str],
        result: ProviderAccounting | Exception | object,
    ) -> None:
        self.events = events
        self.result = result
        self.calls = 0

    def parse_response(
        self, *, raw_response: bytes, response_ref: str, max_tokens: int
    ) -> ProviderAccounting:
        self.calls += 1
        self.events.append("parse")
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


class RawResponseBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "raw.sqlite3"

    @staticmethod
    def broker(ledger) -> ModelCallBroker:  # type: ignore[no-untyped-def]
        return ModelCallBroker(registry=registry(), ledger=ledger, budget_policy=policy())

    def test_raw_bytes_are_committed_before_parse_and_success_settlement(self) -> None:
        events: list[str] = []
        raw = b'{"id":"synthetic","usage":{"total_tokens":3}}'
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec(key="raw-success")
            handle = broker.prepare(call, event_at=AT)
            completed = broker.execute_raw(
                handle.call_id,
                request_bytes=call.request_bytes,
                adapter=RawAdapter(events, raw),
                response_committer=OrderedCommitter(events),
                response_parser=OrderedParser(
                    events,
                    ProviderAccounting(3, 1, "provider:synthetic-raw-success"),
                ),
                event_at=AT_SENT,
            )
            self.assertEqual(events, ["receive", "commit", "parse"])
            self.assertEqual(completed.state, "SUCCEEDED")
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertEqual(
                state["response_ref"],
                "cas:sha256:" + hashlib.sha256(raw).hexdigest(),
            )
            self.assertFalse(state["budget_released"])

    def test_commit_failure_never_parses_and_is_unknown_without_retry(self) -> None:
        events: list[str] = []
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec(key="raw-commit-fault")
            handle = broker.prepare(call, event_at=AT)
            adapter = RawAdapter(events, b'{"synthetic":"response"}')
            parser = OrderedParser(events, ProviderAccounting(2, 1, None))
            completed = broker.execute_raw(
                handle.call_id,
                request_bytes=call.request_bytes,
                adapter=adapter,
                response_committer=OrderedCommitter(events, fail=True),
                response_parser=parser,
                event_at=AT_SENT,
            )
            self.assertEqual(events, ["receive", "commit"])
            self.assertEqual(parser.calls, 0)
            self.assertEqual(completed.state, "UNKNOWN")
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertIsNone(state["response_ref"])
            self.assertFalse(state["auto_retry"])
            self.assertFalse(state["budget_released"])
            with self.assertRaises(ModelBrokerError):
                broker.execute_raw(
                    handle.call_id,
                    request_bytes=call.request_bytes,
                    adapter=adapter,
                    response_committer=OrderedCommitter(events),
                    response_parser=parser,
                    event_at=AT_SENT,
                )
            self.assertEqual(adapter.calls, 1)

    def test_parse_ambiguity_retains_committed_evidence_and_is_unknown(self) -> None:
        events: list[str] = []
        raw = b'{"synthetic":"malformed-accounting"}'
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec(key="raw-parse-fault")
            handle = broker.prepare(call, event_at=AT)
            completed = broker.execute_raw(
                handle.call_id,
                request_bytes=call.request_bytes,
                adapter=RawAdapter(events, raw),
                response_committer=OrderedCommitter(events),
                response_parser=OrderedParser(events, ValueError("malformed")),
                event_at=AT_SENT,
            )
            self.assertEqual(events, ["receive", "commit", "parse"])
            self.assertEqual(completed.state, "UNKNOWN")
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertEqual(
                state["response_ref"],
                "cas:sha256:" + hashlib.sha256(raw).hexdigest(),
            )
            self.assertFalse(state["budget_released"])

    def test_response_bearing_failure_is_committed_and_conservatively_unknown(self) -> None:
        events: list[str] = []
        raw = b'{"error":{"code":"rate_limit"}}'
        failure = KnownProviderFailure(
            "RATE_LIMITED",
            actual_tokens=0,
            actual_cost_units=0,
            provider_receipt_ref="provider:synthetic-known-failure",
        )
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec(key="raw-known-failure")
            handle = broker.prepare(call, event_at=AT)
            completed = broker.execute_raw(
                handle.call_id,
                request_bytes=call.request_bytes,
                adapter=RawAdapter(events, raw),
                response_committer=OrderedCommitter(events),
                response_parser=OrderedParser(events, failure),
                event_at=AT_SENT,
            )
            self.assertEqual(events, ["receive", "commit", "parse"])
            self.assertEqual(completed.state, "UNKNOWN")
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertEqual(state["failure_code"], "AMBIGUOUS_PROVIDER_OUTCOME")
            self.assertFalse(state["budget_released"])
            self.assertEqual(
                state["response_ref"],
                "cas:sha256:" + hashlib.sha256(raw).hexdigest(),
            )

    def test_binding_mismatch_fails_before_sent_or_egress(self) -> None:
        events: list[str] = []
        parser = OrderedParser(events, ProviderAccounting(1, 1, None))
        parser.model_binding = "glm-5.2-max"
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec(key="raw-parser-binding-mismatch")
            handle = broker.prepare(call, event_at=AT)
            adapter = RawAdapter(events, b"response")
            with self.assertRaises(ModelBrokerError):
                broker.execute_raw(
                    handle.call_id,
                    request_bytes=call.request_bytes,
                    adapter=adapter,
                    response_committer=OrderedCommitter(events),
                    response_parser=parser,
                    event_at=AT_SENT,
                )
            self.assertEqual(events, [])
            self.assertEqual(adapter.calls, 0)
            self.assertEqual(broker.state(handle.call_id).state, "RESERVED")


if __name__ == "__main__":
    unittest.main()
