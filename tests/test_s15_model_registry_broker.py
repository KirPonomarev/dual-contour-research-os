from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.ledger import JobLedger, LedgerError  # noqa: E402
from research_bridge.model_broker import (  # noqa: E402
    KnownProviderFailure,
    ModelBrokerError,
    ModelBudgetPolicy,
    ModelCallBroker,
    ModelCallSpec,
    ModelRoleRegistry,
    ProviderResult,
)
from tests.test_a1_storage_v2 import projection_states  # noqa: E402
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS  # noqa: E402


PROFILE = ROOT / "contracts" / "a1" / "v1" / "profiles" / "model_role_registry_v1.json"
PROFILE_SHA256 = hashlib.sha256(PROFILE.read_bytes()).hexdigest()
AT = "2026-07-18T12:00:00Z"
AT_SENT = "2026-07-18T12:00:01Z"
AT_RECONCILED = "2026-07-18T12:00:02Z"
EXPIRES = "2026-07-18T13:00:00Z"
AT_AFTER_EXPIRY = "2026-07-18T14:00:00Z"
EXPIRES_AFTER_RECONCILIATION = "2026-07-18T15:00:00Z"
POLICY_REF = "budget-policy:sha256:" + "a" * 64
SCOPE_REF = "budget-scope:sha256:" + "b" * 64


def registry(
    *, revision: str = "initial-v1", overrides: dict[str, str | None] | None = None
) -> ModelRoleRegistry:
    return ModelRoleRegistry(
        PROFILE,
        expected_profile_sha256=PROFILE_SHA256,
        binding_revision=revision,
        binding_overrides=overrides,
    )


def policy(
    *, active: int = 4, tokens: int = 1_000, cost: int = 100
) -> ModelBudgetPolicy:
    return ModelBudgetPolicy(
        policy_ref=POLICY_REF,
        scope_ref=SCOPE_REF,
        max_active_calls=active,
        max_reserved_tokens=tokens,
        max_reserved_cost_units=cost,
    )


def spec(
    *,
    role: str = "SCOUT_FAST",
    classification: str = "D0",
    request: bytes = b"synthetic public model request",
    key: str = "model-call-synthetic-001",
    max_tokens: int = 100,
    max_cost: int = 5,
    expires_at: str = EXPIRES,
) -> ModelCallSpec:
    return ModelCallSpec(
        role=role,
        role_assignment_ref="assignment:deterministic-policy-v1",
        classification=classification,
        request_bytes=request,
        max_tokens=max_tokens,
        max_cost_units=max_cost,
        expires_at=expires_at,
        idempotency_key=key,
    )


def seeded_ledger(path: Path, ledger_class: type[JobLedger] = JobLedger) -> JobLedger:
    ledger = ledger_class(path)
    ledger.append_a1_bundle(
        objects=BASE_DOCUMENTS,
        projections=projection_states("s15-model-base"),
        idempotency_key="s15-model-base",
        event_at=AT,
    )
    return ledger


class RecordingAdapter:
    model_binding = "deepseek-v4-flash"

    def __init__(
        self,
        ledger: JobLedger,
        *,
        result: ProviderResult | Exception | BaseException | None = None,
    ) -> None:
        self.ledger = ledger
        self.result = result or ProviderResult(
            raw_response=b'{"synthetic":"response"}',
            actual_tokens=12,
            actual_cost_units=2,
            provider_receipt_ref="provider:synthetic-receipt-001",
        )
        self.calls = 0
        self.observed_states: list[str] = []

    def invoke(self, *, call_id: str, request_bytes: bytes, max_tokens: int) -> ProviderResult:
        self.calls += 1
        self.observed_states.append(self.ledger.model_call_state(call_id).snapshot["state"])
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class RecordingCommitter:
    def __init__(self, ledger: JobLedger, call_id: str, *, fail: bool = False) -> None:
        self.ledger = ledger
        self.call_id = call_id
        self.fail = fail
        self.calls = 0
        self.observed_states: list[str] = []

    def commit_response(self, raw_response: bytes) -> str:
        self.calls += 1
        self.observed_states.append(
            self.ledger.model_call_state(self.call_id).snapshot["state"]
        )
        if self.fail:
            raise OSError("synthetic response commit fault")
        return "cas:sha256:" + hashlib.sha256(raw_response).hexdigest()


class SentFaultLedger(JobLedger):
    fail_sent = False

    def append_model_call_transition(self, *, snapshot, idempotency_key, event_at):  # type: ignore[no-untyped-def]
        if self.fail_sent and snapshot["state"] == "SENT":
            raise LedgerError("synthetic crash before durable SENT")
        return super().append_model_call_transition(
            snapshot=snapshot,
            idempotency_key=idempotency_key,
            event_at=event_at,
        )


class ModelRegistryBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "model.sqlite3"

    def broker(self, ledger: JobLedger, *, role_registry: ModelRoleRegistry | None = None, budget: ModelBudgetPolicy | None = None) -> ModelCallBroker:
        return ModelCallBroker(
            registry=role_registry or registry(),
            ledger=ledger,
            budget_policy=budget or policy(),
        )

    def test_registry_is_exact_replaceable_versioned_and_non_authoritative(self) -> None:
        initial = registry()
        self.assertEqual(initial.route("SCOUT_FAST", "D0").model_binding, "deepseek-v4-flash")
        self.assertEqual(initial.route("RESEARCH_WORKER", "D1").model_binding, "deepseek-v4-pro")
        with self.assertRaises(ModelBrokerError):
            initial.route("ARBITER_RESERVE", "D0")
        with self.assertRaises(ModelBrokerError):
            initial.route("SCOUT_FAST", "D2")
        with self.assertRaises(ModelBrokerError):
            registry(overrides={"ARBITER_RESERVE": "unproven-arbiter"})
        replaced = registry(
            revision="shadow-evaluated-v2",
            overrides={"SCOUT_FAST": "replacement-shadow-model"},
        )
        self.assertEqual(
            replaced.route("SCOUT_FAST", "D0").model_binding,
            "replacement-shadow-model",
        )
        self.assertNotEqual(initial.registry_sha256, replaced.registry_sha256)

    def test_privacy_and_invalid_role_fail_before_any_call_event(self) -> None:
        with seeded_ledger(self.database) as ledger:
            before = ledger.event_count()
            with self.assertRaises(ModelBrokerError):
                spec(classification="D2")
            with self.assertRaises(ModelBrokerError):
                self.broker(ledger).prepare(spec(role="UNKNOWN_ROLE"), event_at=AT)
            self.assertEqual(ledger.event_count(), before)

    def test_prepare_is_durable_idempotent_and_stores_no_request_bytes(self) -> None:
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec()
            first = broker.prepare(call, event_at=AT)
            second = broker.prepare(call, event_at=AT)
            self.assertEqual(first, second)
            history = ledger.model_call_history(first.call_id)
            self.assertEqual([record.snapshot["state"] for record in history], ["PROPOSED", "RESERVED"])
            self.assertEqual(ledger.event_count(), 3)
            self.assertEqual(history[-1].snapshot["budget_released"], False)
            self.assertEqual(history[-1].snapshot["auto_retry"], False)
            serialized = str([dict(record.snapshot) for record in history])
            self.assertNotIn(call.request_bytes.decode(), serialized)
            self.assertTrue(ledger.verify_chain())
            self.assertTrue(ledger.verify_a1_coverage())

    def test_reservation_and_sent_precede_provider_and_raw_response_commit(self) -> None:
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec()
            handle = broker.prepare(call, event_at=AT)
            adapter = RecordingAdapter(ledger)
            committer = RecordingCommitter(ledger, handle.call_id)
            result = broker.execute(
                handle.call_id,
                request_bytes=call.request_bytes,
                adapter=adapter,
                response_committer=committer,
                event_at=AT_SENT,
            )
            self.assertEqual(result.state, "SUCCEEDED")
            self.assertEqual(adapter.observed_states, ["SENT"])
            self.assertEqual(committer.observed_states, ["SENT"])
            history = ledger.model_call_history(handle.call_id)
            self.assertEqual(
                [record.snapshot["state"] for record in history],
                ["PROPOSED", "RESERVED", "SENT", "SUCCEEDED"],
            )
            self.assertTrue(history[-1].snapshot["response_ref"].startswith("cas:sha256:"))
            self.assertFalse(history[-1].snapshot["budget_released"])

    def test_crash_before_sent_never_invokes_provider(self) -> None:
        with seeded_ledger(self.database, SentFaultLedger) as ledger:
            broker = self.broker(ledger)
            call = spec()
            handle = broker.prepare(call, event_at=AT)
            ledger.fail_sent = True  # type: ignore[attr-defined]
            adapter = RecordingAdapter(ledger)
            with self.assertRaises(ModelBrokerError):
                broker.execute(
                    handle.call_id,
                    request_bytes=call.request_bytes,
                    adapter=adapter,
                    response_committer=RecordingCommitter(ledger, handle.call_id),
                    event_at=AT_SENT,
                )
            self.assertEqual(adapter.calls, 0)
            self.assertEqual(broker.state(handle.call_id).state, "RESERVED")

    def test_process_crash_after_sent_recovers_unknown_without_retry_or_release(self) -> None:
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            call = spec()
            handle = broker.prepare(call, event_at=AT)
            adapter = RecordingAdapter(ledger, result=SystemExit("synthetic process crash"))
            with self.assertRaises(SystemExit):
                broker.execute(
                    handle.call_id,
                    request_bytes=call.request_bytes,
                    adapter=adapter,
                    response_committer=RecordingCommitter(ledger, handle.call_id),
                    event_at=AT_SENT,
                )
            self.assertEqual(broker.state(handle.call_id).state, "SENT")
            recovered = broker.recover_sent(handle.call_id, event_at=AT_RECONCILED)
            self.assertEqual(recovered.state, "UNKNOWN")
            state = ledger.model_call_state(handle.call_id).snapshot
            self.assertTrue(state["ambiguous_usage"])
            self.assertFalse(state["budget_released"])
            self.assertFalse(state["auto_retry"])
            with self.assertRaises(ModelBrokerError):
                broker.execute(
                    handle.call_id,
                    request_bytes=call.request_bytes,
                    adapter=adapter,
                    response_committer=RecordingCommitter(ledger, handle.call_id),
                    event_at=AT_RECONCILED,
                )
            self.assertEqual(adapter.calls, 1)

    def test_provider_or_response_commit_ambiguity_becomes_unknown(self) -> None:
        for label, adapter_result, commit_fail in (
            ("provider", RuntimeError("synthetic provider ambiguity"), False),
            ("commit", None, True),
        ):
            with self.subTest(label=label):
                database = Path(self.temporary.name) / f"{label}.sqlite3"
                with seeded_ledger(database) as ledger:
                    broker = self.broker(ledger)
                    call = spec(key=f"ambiguity-{label}")
                    handle = broker.prepare(call, event_at=AT)
                    adapter = RecordingAdapter(ledger, result=adapter_result)
                    result = broker.execute(
                        handle.call_id,
                        request_bytes=call.request_bytes,
                        adapter=adapter,
                        response_committer=RecordingCommitter(
                            ledger, handle.call_id, fail=commit_fail
                        ),
                        event_at=AT_SENT,
                    )
                    self.assertEqual(result.state, "UNKNOWN")
                    self.assertFalse(
                        ledger.model_call_state(handle.call_id).snapshot["budget_released"]
                    )

    def test_known_failure_and_ambiguous_success_require_reconciliation(self) -> None:
        cases = (
            (
                "known-failure",
                KnownProviderFailure(
                    "RATE_LIMITED",
                    actual_tokens=3,
                    actual_cost_units=1,
                    provider_receipt_ref="provider:known-failure",
                ),
                "FAILED_KNOWN",
            ),
            (
                "ambiguous-success",
                ProviderResult(b"ambiguous-success", None, None, None),
                "SUCCEEDED",
            ),
        )
        for label, adapter_result, terminal in cases:
            with self.subTest(label=label):
                database = Path(self.temporary.name) / f"{label}.sqlite3"
                with seeded_ledger(database) as ledger:
                    broker = self.broker(ledger)
                    call = spec(key=label)
                    handle = broker.prepare(call, event_at=AT)
                    result = broker.execute(
                        handle.call_id,
                        request_bytes=call.request_bytes,
                        adapter=RecordingAdapter(ledger, result=adapter_result),
                        response_committer=RecordingCommitter(ledger, handle.call_id),
                        event_at=AT_SENT,
                    )
                    self.assertEqual(result.state, terminal)
                    self.assertFalse(ledger.model_call_state(handle.call_id).snapshot["budget_released"])
                    settled = broker.reconcile(
                        handle.call_id,
                        actual_tokens=3,
                        actual_cost_units=1,
                        provider_receipt_ref=f"provider:reconciled-{label}",
                        event_at=AT_RECONCILED,
                        idempotency_key=f"settlement-{label}",
                    )
                    replay = broker.reconcile(
                        handle.call_id,
                        actual_tokens=3,
                        actual_cost_units=1,
                        provider_receipt_ref=f"provider:reconciled-{label}",
                        event_at=AT_RECONCILED,
                        idempotency_key=f"settlement-{label}",
                    )
                    self.assertEqual(settled, replay)
                    self.assertTrue(ledger.model_call_state(handle.call_id).snapshot["budget_released"])
                    with self.assertRaises(ModelBrokerError):
                        broker.reconcile(
                            handle.call_id,
                            actual_tokens=4,
                            actual_cost_units=1,
                            provider_receipt_ref=f"provider:reconciled-{label}",
                            event_at=AT_RECONCILED,
                            idempotency_key=f"settlement-{label}",
                        )

    def test_expired_terminal_calls_reconcile_exactly_and_release_budget(self) -> None:
        terminal_cases = (
            (
                "succeeded",
                ProviderResult(
                    b"late-success",
                    12,
                    2,
                    "provider:late-success",
                ),
                "SUCCEEDED",
            ),
            (
                "failed-known",
                KnownProviderFailure(
                    "RATE_LIMITED",
                    actual_tokens=3,
                    actual_cost_units=1,
                    provider_receipt_ref="provider:late-failed-known",
                ),
                "FAILED_KNOWN",
            ),
            (
                "unknown",
                RuntimeError("synthetic ambiguous provider result"),
                "UNKNOWN",
            ),
        )
        for label, adapter_result, terminal_state in terminal_cases:
            with self.subTest(label=label):
                database = Path(self.temporary.name) / f"late-{label}.sqlite3"
                with seeded_ledger(database) as ledger:
                    broker = self.broker(
                        ledger,
                        budget=policy(active=1, tokens=100, cost=5),
                    )
                    call = spec(key=f"late-{label}")
                    handle = broker.prepare(call, event_at=AT)
                    terminal = broker.execute(
                        handle.call_id,
                        request_bytes=call.request_bytes,
                        adapter=RecordingAdapter(ledger, result=adapter_result),
                        response_committer=RecordingCommitter(ledger, handle.call_id),
                        event_at=AT_SENT,
                    )
                    self.assertEqual(terminal.state, terminal_state)
                    before = ledger.event_count()

                    with self.assertRaises(ModelBrokerError):
                        broker.reconcile(
                            handle.call_id,
                            actual_tokens=7,
                            actual_cost_units=1,
                            provider_receipt_ref="",
                            event_at=AT_AFTER_EXPIRY,
                            idempotency_key=f"late-empty-receipt-{label}",
                        )
                    self.assertEqual(ledger.event_count(), before)

                    reconciled = broker.reconcile(
                        handle.call_id,
                        actual_tokens=7,
                        actual_cost_units=1,
                        provider_receipt_ref=f"provider:late-reconciled-{label}",
                        event_at=AT_AFTER_EXPIRY,
                        idempotency_key=f"late-reconcile-{label}",
                    )
                    self.assertEqual(reconciled.state, "RECONCILED")
                    snapshot = ledger.model_call_state(handle.call_id).snapshot
                    self.assertEqual(snapshot["previous_state"], terminal_state)
                    self.assertFalse(snapshot["ambiguous_usage"])
                    self.assertTrue(snapshot["budget_released"])
                    self.assertEqual(snapshot["actual_tokens"], 7)
                    self.assertEqual(snapshot["actual_cost_units"], 1)
                    self.assertEqual(
                        snapshot["provider_receipt_ref"],
                        f"provider:late-reconciled-{label}",
                    )

                    replay_before = ledger.event_count()
                    replay = broker.reconcile(
                        handle.call_id,
                        actual_tokens=7,
                        actual_cost_units=1,
                        provider_receipt_ref=f"provider:late-reconciled-{label}",
                        event_at=AT_AFTER_EXPIRY,
                        idempotency_key=f"late-reconcile-{label}",
                    )
                    self.assertEqual(replay, reconciled)
                    self.assertEqual(ledger.event_count(), replay_before)
                    with self.assertRaises(ModelBrokerError):
                        broker.reconcile(
                            handle.call_id,
                            actual_tokens=8,
                            actual_cost_units=1,
                            provider_receipt_ref=f"provider:late-reconciled-{label}",
                            event_at=AT_AFTER_EXPIRY,
                            idempotency_key=f"late-reconcile-{label}",
                        )
                    self.assertEqual(ledger.event_count(), replay_before)

                    next_call = spec(
                        key=f"after-late-reconcile-{label}",
                        request=f"next-{label}".encode(),
                        expires_at=EXPIRES_AFTER_RECONCILIATION,
                    )
                    self.assertEqual(
                        broker.prepare(next_call, event_at=AT_AFTER_EXPIRY).state,
                        "RESERVED",
                    )

    def test_expiry_still_rejects_every_non_reconciliation_transition(self) -> None:
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger)
            before = ledger.event_count()
            with self.assertRaises(ModelBrokerError):
                broker.prepare(spec(key="late-proposed"), event_at=AT_AFTER_EXPIRY)
            self.assertEqual(ledger.event_count(), before)

            reserved_spec = spec(key="late-sent")
            reserved = broker.prepare(reserved_spec, event_at=AT)
            adapter = RecordingAdapter(ledger)
            with self.assertRaises(ModelBrokerError):
                broker.execute(
                    reserved.call_id,
                    request_bytes=reserved_spec.request_bytes,
                    adapter=adapter,
                    response_committer=RecordingCommitter(ledger, reserved.call_id),
                    event_at=AT_AFTER_EXPIRY,
                )
            self.assertEqual(adapter.calls, 0)
            self.assertEqual(broker.state(reserved.call_id).state, "RESERVED")

        sent_database = Path(self.temporary.name) / "late-terminal.sqlite3"
        with seeded_ledger(sent_database) as ledger:
            broker = self.broker(ledger)
            sent_spec = spec(key="late-terminal")
            sent = broker.prepare(sent_spec, event_at=AT)
            crashing = RecordingAdapter(
                ledger,
                result=SystemExit("synthetic crash after durable SENT"),
            )
            with self.assertRaises(SystemExit):
                broker.execute(
                    sent.call_id,
                    request_bytes=sent_spec.request_bytes,
                    adapter=crashing,
                    response_committer=RecordingCommitter(ledger, sent.call_id),
                    event_at=AT_SENT,
                )
            self.assertEqual(broker.state(sent.call_id).state, "SENT")
            before = ledger.event_count()
            with self.assertRaises(ModelBrokerError):
                broker.recover_sent(sent.call_id, event_at=AT_AFTER_EXPIRY)
            self.assertEqual(ledger.event_count(), before)
            self.assertEqual(broker.state(sent.call_id).state, "SENT")

    def test_budget_oversubscription_parks_at_proposed_until_capacity_releases(self) -> None:
        with seeded_ledger(self.database) as ledger:
            broker = self.broker(ledger, budget=policy(active=1, tokens=100, cost=5))
            first_spec = spec(key="budget-first", max_tokens=100, max_cost=5)
            second_spec = spec(key="budget-second", request=b"second", max_tokens=100, max_cost=5)
            first = broker.prepare(first_spec, event_at=AT)
            with self.assertRaises(ModelBrokerError):
                broker.prepare(second_spec, event_at=AT)
            calls = [
                record.snapshot["state"]
                for record in ledger.model_call_history(
                    "model-call:" + hashlib.sha256(b"not-the-real-call-id").hexdigest()
                )
            ]
            self.assertEqual(calls, [])
            adapter = RecordingAdapter(ledger)
            succeeded = broker.execute(
                first.call_id,
                request_bytes=first_spec.request_bytes,
                adapter=adapter,
                response_committer=RecordingCommitter(ledger, first.call_id),
                event_at=AT_SENT,
            )
            broker.reconcile(
                succeeded.call_id,
                actual_tokens=12,
                actual_cost_units=2,
                provider_receipt_ref="provider:first-settlement",
                event_at=AT_RECONCILED,
                idempotency_key="first-settlement",
            )
            second = broker.prepare(second_spec, event_at=AT_RECONCILED)
            self.assertEqual(second.state, "RESERVED")

    def test_registry_drift_blocks_egress_before_sent(self) -> None:
        with seeded_ledger(self.database) as ledger:
            initial = self.broker(ledger)
            call = spec()
            handle = initial.prepare(call, event_at=AT)
            drifted = self.broker(
                ledger,
                role_registry=registry(
                    revision="drift-v2",
                    overrides={"SCOUT_FAST": "replacement-shadow-model"},
                ),
            )
            adapter = RecordingAdapter(ledger)
            with self.assertRaises(ModelBrokerError):
                drifted.execute(
                    handle.call_id,
                    request_bytes=call.request_bytes,
                    adapter=adapter,
                    response_committer=RecordingCommitter(ledger, handle.call_id),
                    event_at=AT_SENT,
                )
            self.assertEqual(adapter.calls, 0)
            self.assertEqual(initial.state(handle.call_id).state, "RESERVED")

    def test_model_calls_use_existing_schema_and_global_order_only(self) -> None:
        with seeded_ledger(self.database) as ledger:
            handle = self.broker(ledger).prepare(spec(), event_at=AT)
            manifest = ledger.storage_coverage_manifest()
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(manifest["ordering_model"], "single-bridge-global-sequence")
            self.assertTrue(manifest["invariants"]["no_second_event_ledger"])
            rows = ledger._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
            self.assertNotIn("bridge_model_calls", {row[0] for row in rows})
            self.assertEqual(
                [record.event.sequence for record in ledger.model_call_history(handle.call_id)],
                [2, 3],
            )
            self.assertTrue(ledger.verify_chain())
            self.assertTrue(ledger.verify_a1_coverage())


if __name__ == "__main__":
    unittest.main()
