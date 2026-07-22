from __future__ import annotations

import hashlib
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.model_broker import (  # noqa: E402
    ModelBrokerError,
    ModelCallBroker,
)
import research_bridge.researchd as researchd_module  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    _MISSION_CHIEF_NULL_CONTENT_VACUOUS_PROFILE_SHA256,
    _MISSION_NULL_CONTENT_VACUOUS_PROFILE_SHA256,
    _MISSION_TOTAL_TOKEN_RESERVATION,
    _MISSION_VACUOUS_PROFILE_SHA256,
    _matches_mission_chief_null_content_vacuous_reconciliation,
    _matches_mission_null_content_vacuous_reconciliation,
    _matches_mission_vacuous_reconciliation,
    _mission_chief_null_content_vacuous_reconciliation_profile,
    _mission_null_content_vacuous_reconciliation_profile,
    _mission_observed_accounting_evidence_ref,
    _mission_vacuous_reconciliation_profile,
    ResearchDaemon,
    ResearchdError,
)
from research_bridge.research_ingress import (  # noqa: E402
    canonical_sha256 as research_canonical_sha256,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    policy,
    registry,
    seeded_ledger,
    spec,
)
from tests.test_r09a_dual_contour_advisors import (  # noqa: E402
    POLICY_PATH as CONNECTED_WORKER_POLICY_PATH,
    shadow as connected_shadow,
    worker as connected_worker_v4,
)


AT = "2026-07-22T14:40:00Z"
SENT_AT = "2026-07-22T14:40:01Z"
TERMINAL_AT = "2026-07-22T14:40:02Z"
RECONCILED_AT = "2026-07-22T14:40:03Z"
RECEIPT = "provider-response:sha256:" + hashlib.sha256(b"response").hexdigest()
EVIDENCE = _mission_observed_accounting_evidence_ref("deepseek-v4-flash")
VACUOUS_EVIDENCE = (
    "accounting-policy:sha256:" + _MISSION_VACUOUS_PROFILE_SHA256
)
VACUOUS_RECEIPT = (
    "provider-response:sha256:"
    "5c10b8434b2fb83e958115af9a6780a7ad4ffb54daf9fe0838a23dcd51357cdc"
)
NULL_CONTENT_EVIDENCE = (
    "accounting-policy:sha256:"
    + _MISSION_NULL_CONTENT_VACUOUS_PROFILE_SHA256
)
NULL_CONTENT_RECEIPT = (
    "provider-response:sha256:"
    "88d0cb2c01ff014b83f14264a255f80e1fd30fb1c2faa831a4d5b9fdb572c3bb"
)
CHIEF_NULL_CONTENT_EVIDENCE = (
    "accounting-policy:sha256:"
    + _MISSION_CHIEF_NULL_CONTENT_VACUOUS_PROFILE_SHA256
)
CHIEF_NULL_CONTENT_RECEIPT = (
    "provider-response:sha256:"
    "2e7d74f4eaea22c081b5909052772d402bb714d42a1d2d8fb50df73c921718d0"
)


class ObservedAccountingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ledger_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _broker(self) -> tuple[ModelCallBroker, object]:
        self.ledger_index += 1
        ledger = seeded_ledger(self.root / f"ledger-{self.ledger_index}.sqlite3")
        broker = ModelCallBroker(
            registry=registry(),
            ledger=ledger,
            budget_policy=policy(active=1, tokens=20_000, cost=1),
        )
        return broker, ledger

    def _expired_prepass_daemon(
        self,
        *,
        step_overrides: dict[str, object] | None = None,
        snapshot: dict[str, object] | None = None,
    ) -> tuple[ResearchDaemon, mock.Mock, dict[str, object]]:
        profile = dict(_mission_vacuous_reconciliation_profile())
        runtime = self.root / f"prepass-{self.ledger_index}"
        self.ledger_index += 1
        runtime.mkdir(mode=0o700)
        mission_sha = str(profile["mission_sha256"])
        payload = {
            "mission_sha256": mission_sha,
            "expires_at": "2026-07-22T16:19:22Z",
        }
        mission_document = {
            "schema_id": "ResearchMissionEnvelope",
            "schema_version": "1.0.0",
            "object_id": "research-mission:" + mission_sha,
            "issued_at": "2026-07-22T14:19:12Z",
            "payload": payload,
            "integrity": {"payload_sha256": research_canonical_sha256(payload)},
        }
        manifest = {
            "schema_id": "ResearchMissionRuntimeManifest",
            "schema_version": "1.0.0",
            "mission_sha256": mission_sha,
            "mission_envelope": mission_document,
            "action_envelope": {},
            "material_event_refs": [],
            "artifact_ref": "cas:sha256:" + "a" * 64,
            "queued_at": "2026-07-22T14:19:22Z",
            "decision_lineage": {},
            "provider_calls_maximum": 5,
            "ingress_provider_calls": 0,
            "domain_writes": 0,
            "canonical_writes": 0,
            "live_authority": False,
        }
        researchd_module._write_immutable_private_json(
            runtime / "research-mission-manifests" / f"{mission_sha}.json",
            manifest,
        )
        step = {
            "schema_id": "ResearchMissionRoleReservationReceipt",
            "schema_version": "1.0.0",
            "mission_sha256": mission_sha,
            "role_index": 1,
            "role": "RESEARCH_WORKER",
            "model_binding": profile["model_binding"],
            "reasoning_effort": "max",
            "call_id": profile["call_id"],
            "request_ref": "cas:sha256:" + str(profile["request_sha256"]),
            "request_sha256": profile["request_sha256"],
            "role_assignment_ref": "role-assignment:exact-vacuous",
            "reserved_at": "2026-07-22T15:31:03Z",
            "fallback_used": False,
            **(step_overrides or {}),
        }
        (runtime / "research-mission-steps").mkdir(mode=0o700)
        researchd_module._write_immutable_private_json(
            runtime / "research-mission-steps" / mission_sha / "1.json",
            step,
        )
        unknown = {
            "state": "UNKNOWN",
            "previous_state": "SENT",
            "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
            "request_sha256": profile["request_sha256"],
            "actual_tokens": None,
            "actual_cost_units": None,
            "provider_receipt_ref": None,
            "response_ref": None,
            "accounting_mode": None,
            "accounting_evidence_ref": None,
            "budget_released": False,
        }
        broker = mock.Mock()
        broker.snapshot.return_value = snapshot or unknown
        daemon = object.__new__(ResearchDaemon)
        daemon._root = runtime
        daemon._started = True
        daemon._model_broker = broker
        daemon._model_routing = mock.Mock()
        return daemon, broker, profile

    def _terminal(
        self,
        *,
        outcome: str = "FAILED_KNOWN",
        tokens: int | None = 4_950,
        receipt: str | None = RECEIPT,
    ) -> tuple[ModelCallBroker, object, str]:
        broker, ledger = self._broker()
        request = b"bounded recovery mission request"
        reserved = broker.prepare(
            spec(
                request=request,
                key="p04-runtime-closure",
                max_tokens=20_000,
                max_cost=1,
                expires_at="2026-07-22T18:00:00Z",
            ),
            event_at=AT,
        )
        broker.begin_external(
            reserved.call_id,
            request_bytes=request,
            event_at=SENT_AT,
        )
        broker.complete_external(
            reserved.call_id,
            outcome=outcome,
            response_ref=None,
            actual_tokens=tokens,
            actual_cost_units=None,
            provider_receipt_ref=receipt,
            failure_code=(
                "TOTAL_TOKEN_LIMIT_EXCEEDED"
                if outcome == "FAILED_KNOWN"
                else None
            ),
            event_at=TERMINAL_AT,
        )
        return broker, ledger, reserved.call_id

    def test_failed_known_observed_cost_reconciles_once_without_zero_claim(self) -> None:
        broker, ledger, call_id = self._terminal()
        before = ledger.event_count()
        result = broker.reconcile_observed_no_numeric_cost(
            call_id,
            actual_tokens=4_950,
            provider_receipt_ref=RECEIPT,
            accounting_evidence_ref=EVIDENCE,
            event_at=RECONCILED_AT,
            idempotency_key="mission:observed-cost:reconcile",
        )
        self.assertEqual(result.state, "RECONCILED")
        snapshot = broker.snapshot(call_id)
        self.assertEqual(snapshot["previous_state"], "FAILED_KNOWN")
        self.assertEqual(snapshot["failure_code"], "TOTAL_TOKEN_LIMIT_EXCEEDED")
        self.assertEqual(snapshot["actual_tokens"], 4_950)
        self.assertIsNone(snapshot["actual_cost_units"])
        self.assertEqual(snapshot["accounting_mode"], "OBSERVED_NO_NUMERIC_COST")
        self.assertEqual(snapshot["accounting_evidence_ref"], EVIDENCE)
        self.assertTrue(snapshot["budget_released"])
        self.assertFalse(snapshot["ambiguous_usage"])
        self.assertEqual(ledger.event_count(), before + 1)

        replay = broker.reconcile_observed_no_numeric_cost(
            call_id,
            actual_tokens=4_950,
            provider_receipt_ref=RECEIPT,
            accounting_evidence_ref=EVIDENCE,
            event_at=RECONCILED_AT,
            idempotency_key="mission:observed-cost:reconcile",
        )
        self.assertEqual(replay.state, "RECONCILED")
        self.assertEqual(ledger.event_count(), before + 1)
        ledger.close()

    def test_observed_cost_rejects_missing_receipt_unknown_fake_mode_and_drift(self) -> None:
        broker, ledger, call_id = self._terminal(receipt=None)
        with self.assertRaises(ModelBrokerError):
            broker.reconcile_observed_no_numeric_cost(
                call_id,
                actual_tokens=4_950,
                provider_receipt_ref=RECEIPT,
                accounting_evidence_ref=EVIDENCE,
                event_at=RECONCILED_AT,
                idempotency_key="missing-receipt",
            )
        ledger.close()

        broker, ledger = self._broker()
        request = b"ambiguous transmission"
        reserved = broker.prepare(
            spec(
                request=request,
                key="p04-unknown",
                max_tokens=20_000,
                max_cost=1,
                expires_at="2026-07-22T18:00:00Z",
            ),
            event_at=AT,
        )
        broker.begin_external(reserved.call_id, request_bytes=request, event_at=SENT_AT)
        broker.complete_external(
            reserved.call_id,
            outcome="UNKNOWN",
            response_ref=None,
            actual_tokens=None,
            actual_cost_units=None,
            provider_receipt_ref=None,
            failure_code=None,
            event_at=TERMINAL_AT,
        )
        with self.assertRaises(ModelBrokerError):
            broker.reconcile_observed_no_numeric_cost(
                reserved.call_id,
                actual_tokens=4_950,
                provider_receipt_ref=RECEIPT,
                accounting_evidence_ref=EVIDENCE,
                event_at=RECONCILED_AT,
                idempotency_key="unknown-rejected",
            )
        ledger.close()

        broker, ledger, call_id = self._terminal()
        for evidence in (
            "accounting-policy:fake",
            "accounting-policy:sha256:" + "0" * 64,
        ):
            with self.assertRaises(ModelBrokerError):
                broker.reconcile_observed_no_numeric_cost(
                    call_id,
                    actual_tokens=4_951,
                    provider_receipt_ref=RECEIPT,
                    accounting_evidence_ref=evidence,
                    event_at=RECONCILED_AT,
                    idempotency_key="fake-or-drift",
                )
        with self.assertRaises(ModelBrokerError):
            broker.reconcile(
                call_id,
                actual_tokens=4_950,
                actual_cost_units=None,  # type: ignore[arg-type]
                provider_receipt_ref=RECEIPT,
                event_at=RECONCILED_AT,
                idempotency_key="numeric-null-rejected",
            )
        ledger.close()

    def test_total_reservation_is_distinct_from_binding_output_ceiling(self) -> None:
        self.assertEqual(_MISSION_TOTAL_TOKEN_RESERVATION, 20_000)
        source = (ROOT / "ops/connected-worker/model_worker_v4.py").read_text()
        self.assertIn('"deepseek-v4-flash": 4096', source)
        self.assertIn('"deepseek-v4-pro": 4096', source)
        self.assertIn('"gpt-5.6-sol-xhigh": 4096', source)
        self.assertIn('"kimi-k3-max": 16384', source)
        self.assertIn("total_token_budget - policy.provider_input_token_margin", source)
        self.assertIn("min(\n        output_budget,", source)

    def test_worker_accepts_20000_total_but_keeps_provider_output_ceilings(self) -> None:
        policy = connected_worker_v4.RuntimePolicy.load(CONNECTED_WORKER_POLICY_PATH)
        profile = connected_shadow.ConnectedShadowProfile(
            connected_shadow.ADVISOR_PROFILE_PATH
        )
        dispatch = {
            "schema_id": "ModelWorkerDispatch",
            "schema_version": "1.1.0",
            "call_id": "model-call:" + "a" * 64,
            "dispatch_token": "b" * 64,
            "request_body": "bounded synthetic recovery mission",
            "model_binding": "deepseek-v4-pro",
            "classification": "D1",
            "max_tokens": 20_000,
            "expires_at": "2026-07-22T18:00:00Z",
            "completion_command": "complete_research_model_call",
            "worker_ipc_extension_sha256": policy.worker_ipc_extension_sha256,
        }
        path = self.root / "worker-dispatch.json"
        path.write_text(json.dumps(dispatch, sort_keys=True, separators=(",", ":")))
        os.chmod(path, 0o600)
        loaded = connected_worker_v4.Dispatch.load(
            path,
            policy=policy,
            profile=profile,
        )
        self.assertEqual(loaded.max_tokens, 20_000)

        request, deepseek_limit = connected_worker_v4._bounded_provider_request(
            "deepseek-v4-pro",
            profile.binding("deepseek-v4-pro"),
            loaded.request_body.encode(),
            total_token_budget=loaded.max_tokens,
            policy=policy,
        )
        self.assertEqual(deepseek_limit, 4096)
        self.assertEqual(json.loads(request)["max_tokens"], 4096)
        _request, kimi_limit = connected_worker_v4._bounded_provider_request(
            "kimi-k3-max",
            profile.binding("kimi-k3-max"),
            loaded.request_body.encode(),
            total_token_budget=loaded.max_tokens,
            policy=policy,
        )
        self.assertEqual(kimi_limit, 16_384)

        dispatch["max_tokens"] = 20_001
        path.write_text(json.dumps(dispatch, sort_keys=True, separators=(",", ":")))
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(
            connected_worker_v4.ConnectedWorkerError,
            "worker token bound is invalid",
        ):
            connected_worker_v4.Dispatch.load(
                path,
                policy=policy,
                profile=profile,
            )

    def test_fake_observed_accounting_profile_fails_closed(self) -> None:
        fake = json.loads(
            (ROOT / "provenance/model-accounting-mode-v1.json").read_text()
        )
        fake["scope"]["monetary_enforcement"] = "FAKE_DISABLED"
        raw = json.dumps(fake, sort_keys=True, separators=(",", ":")).encode()
        path = self.root / "fake-accounting-profile.json"
        path.write_bytes(raw)
        with (
            mock.patch.object(
                researchd_module,
                "_MISSION_ACCOUNTING_PROFILE_PATH",
                path,
            ),
            mock.patch.object(
                researchd_module,
                "_MISSION_ACCOUNTING_PROFILE_SHA256",
                hashlib.sha256(raw).hexdigest(),
            ),
            self.assertRaises(ResearchdError),
        ):
            _mission_observed_accounting_evidence_ref("deepseek-v4-flash")

    def test_exact_unknown_vacuous_output_reconciles_once_without_retry(self) -> None:
        broker, ledger, call_id = self._terminal(
            outcome="UNKNOWN", tokens=None, receipt=None
        )
        before = ledger.event_count()
        result = broker.reconcile_vacuous_unknown(
            call_id,
            actual_tokens=5_551,
            provider_receipt_ref=VACUOUS_RECEIPT,
            accounting_evidence_ref=VACUOUS_EVIDENCE,
            event_at=RECONCILED_AT,
            idempotency_key="mission:exact-vacuous:reconcile",
        )
        self.assertEqual(result.state, "RECONCILED")
        snapshot = broker.snapshot(call_id)
        self.assertEqual(snapshot["previous_state"], "UNKNOWN")
        self.assertEqual(snapshot["failure_code"], "VACUOUS_OUTPUT")
        self.assertEqual(snapshot["actual_tokens"], 5_551)
        self.assertIsNone(snapshot["actual_cost_units"])
        self.assertEqual(snapshot["provider_receipt_ref"], VACUOUS_RECEIPT)
        self.assertEqual(snapshot["accounting_mode"], "OBSERVED_NO_NUMERIC_COST")
        self.assertEqual(snapshot["accounting_evidence_ref"], VACUOUS_EVIDENCE)
        self.assertTrue(snapshot["budget_released"])
        self.assertEqual(ledger.event_count(), before + 1)

        replay = broker.reconcile_vacuous_unknown(
            call_id,
            actual_tokens=5_551,
            provider_receipt_ref=VACUOUS_RECEIPT,
            accounting_evidence_ref=VACUOUS_EVIDENCE,
            event_at=RECONCILED_AT,
            idempotency_key="mission:exact-vacuous:reconcile",
        )
        self.assertEqual(replay.state, "RECONCILED")
        self.assertEqual(ledger.event_count(), before + 1)
        for drift in (
            {"actual_tokens": 5_552},
            {"provider_receipt_ref": "provider-response:sha256:" + "0" * 64},
            {"accounting_evidence_ref": "accounting-policy:sha256:" + "0" * 64},
        ):
            arguments = {
                "actual_tokens": 5_551,
                "provider_receipt_ref": VACUOUS_RECEIPT,
                "accounting_evidence_ref": VACUOUS_EVIDENCE,
                "event_at": RECONCILED_AT,
                "idempotency_key": "mission:exact-vacuous:reconcile",
                **drift,
            }
            with self.assertRaises(ModelBrokerError):
                broker.reconcile_vacuous_unknown(call_id, **arguments)
        ledger.close()

    def test_expired_exact_vacuous_prepass_releases_only_frozen_call(self) -> None:
        daemon, broker, profile = self._expired_prepass_daemon()
        terminal = {
            "state": "RECONCILED",
            "previous_state": "UNKNOWN",
            "failure_code": "VACUOUS_OUTPUT",
            "request_sha256": profile["request_sha256"],
            "actual_tokens": profile["actual_tokens"],
            "actual_cost_units": None,
            "provider_receipt_ref": profile["provider_receipt_ref"],
            "response_ref": None,
            "accounting_mode": "OBSERVED_NO_NUMERIC_COST",
            "accounting_evidence_ref": VACUOUS_EVIDENCE,
            "budget_released": True,
        }
        broker.snapshot.side_effect = [broker.snapshot.return_value, terminal]
        result = daemon._reconcile_expired_exact_vacuous_reservation(
            current=datetime(2026, 7, 22, 21, 31, tzinfo=timezone.utc),
            now="2026-07-22T21:31:00Z",
        )
        self.assertEqual(result, profile["mission_sha256"])
        broker.reconcile_vacuous_unknown.assert_called_once_with(
            profile["call_id"],
            actual_tokens=5_551,
            provider_receipt_ref=VACUOUS_RECEIPT,
            accounting_evidence_ref=VACUOUS_EVIDENCE,
            event_at="2026-07-22T21:31:00Z",
            idempotency_key=(
                "mission:d7bc485d07e1bc94a35cbb3367c8978fa9173e9a85984d0306233faccfde4272:"
                "expired-vacuous-output-reconcile:v1"
            ),
        )

        broker.snapshot.side_effect = None
        broker.snapshot.return_value = terminal
        replay = daemon._reconcile_expired_exact_vacuous_reservation(
            current=datetime(2026, 7, 22, 21, 32, tzinfo=timezone.utc),
            now="2026-07-22T21:32:00Z",
        )
        self.assertEqual(replay, profile["mission_sha256"])
        self.assertEqual(broker.reconcile_vacuous_unknown.call_count, 1)

    def test_expired_vacuous_prepass_rejects_live_or_drifted_tuple(self) -> None:
        daemon, broker, _profile = self._expired_prepass_daemon()
        live = daemon._reconcile_expired_exact_vacuous_reservation(
            current=datetime(2026, 7, 22, 15, 0, tzinfo=timezone.utc),
            now="2026-07-22T15:00:00Z",
        )
        self.assertIsNone(live)
        broker.snapshot.assert_not_called()
        broker.reconcile_vacuous_unknown.assert_not_called()

        drifted, drifted_broker, _ = self._expired_prepass_daemon(
            step_overrides={"request_sha256": "0" * 64},
        )
        rejected = drifted._reconcile_expired_exact_vacuous_reservation(
            current=datetime(2026, 7, 22, 21, 31, tzinfo=timezone.utc),
            now="2026-07-22T21:31:00Z",
        )
        self.assertIsNone(rejected)
        drifted_broker.snapshot.assert_not_called()
        drifted_broker.reconcile_vacuous_unknown.assert_not_called()

    def test_exact_null_content_vacuous_call_reconciles_without_retry(self) -> None:
        profile = dict(_mission_null_content_vacuous_reconciliation_profile())
        step = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "fallback_used": False,
        }
        unknown = {
            "state": "UNKNOWN",
            "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
            "request_sha256": profile["request_sha256"],
            "actual_tokens": None,
            "actual_cost_units": None,
            "provider_receipt_ref": None,
            "response_ref": None,
            "budget_released": False,
        }
        terminal = {
            **unknown,
            "state": "RECONCILED",
            "previous_state": "UNKNOWN",
            "failure_code": "VACUOUS_OUTPUT",
            "actual_tokens": 10_304,
            "provider_receipt_ref": NULL_CONTENT_RECEIPT,
            "accounting_mode": "OBSERVED_NO_NUMERIC_COST",
            "accounting_evidence_ref": NULL_CONTENT_EVIDENCE,
            "budget_released": True,
        }
        broker = mock.Mock()
        broker.snapshot.return_value = terminal
        daemon = object.__new__(ResearchDaemon)
        daemon._started = True
        daemon._model_broker = broker
        daemon._model_routing = mock.Mock()

        result = daemon._reconcile_exact_null_content_vacuous_reservation(
            mission_sha256=str(profile["mission_sha256"]),
            role_index=3,
            role="CRITIC_DEEP",
            model_binding="gpt-5.6-sol-xhigh",
            reasoning_effort="xhigh",
            step=step,
            snapshot=unknown,
            now="2026-07-22T22:32:52Z",
        )
        self.assertEqual(result, terminal)
        broker.reconcile_vacuous_unknown.assert_called_once_with(
            profile["call_id"],
            actual_tokens=10_304,
            provider_receipt_ref=NULL_CONTENT_RECEIPT,
            accounting_evidence_ref=NULL_CONTENT_EVIDENCE,
            event_at="2026-07-22T22:32:52Z",
            idempotency_key=(
                "mission:7d7dcbce44eaa5b1df58d07cdd49d5d094a7d69a717382b984b2183e0b6fa7ab:"
                "3:null-content-vacuous-output-reconcile:v1"
            ),
        )
        self.assertIsNone(result["actual_cost_units"])
        self.assertFalse(profile["zero_cost_claim"])
        self.assertEqual(profile["observed_provider_monetary_cost"], 0.16167625)

    def test_null_content_vacuous_profile_rejects_every_tuple_drift(self) -> None:
        profile = dict(_mission_null_content_vacuous_reconciliation_profile())
        exact = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
        }
        self.assertTrue(
            _matches_mission_null_content_vacuous_reconciliation(**exact)
        )
        drifts = {
            "mission_sha256": "0" * 64,
            "role_index": 4,
            "role": "CHIEF_SCIENTIST",
            "call_id": "model-call:" + "0" * 64,
            "request_sha256": "0" * 64,
            "model_binding": "deepseek-v4-pro",
            "reasoning_effort": "max",
            "failure_code": "MALFORMED_RESPONSE",
        }
        for field, value in drifts.items():
            with self.subTest(field=field):
                candidate = {**exact, field: value}
                self.assertFalse(
                    _matches_mission_null_content_vacuous_reconciliation(
                        **candidate
                    )
                )

        broker = mock.Mock()
        daemon = object.__new__(ResearchDaemon)
        daemon._started = True
        daemon._model_broker = broker
        daemon._model_routing = mock.Mock()
        step = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "call_id": profile["call_id"],
            "request_sha256": "0" * 64,
            "fallback_used": False,
        }
        snapshot = {
            "state": "UNKNOWN",
            "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
            "request_sha256": profile["request_sha256"],
        }
        rejected = daemon._reconcile_exact_null_content_vacuous_reservation(
            mission_sha256=str(profile["mission_sha256"]),
            role_index=3,
            role="CRITIC_DEEP",
            model_binding="gpt-5.6-sol-xhigh",
            reasoning_effort="xhigh",
            step=step,
            snapshot=snapshot,
            now="2026-07-22T22:32:52Z",
        )
        self.assertIsNone(rejected)
        broker.reconcile_vacuous_unknown.assert_not_called()

    def test_exact_chief_null_content_reconciles_without_provider_call(self) -> None:
        profile = dict(
            _mission_chief_null_content_vacuous_reconciliation_profile()
        )
        step = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "fallback_used": False,
        }
        unknown = {
            "state": "UNKNOWN",
            "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
            "request_sha256": profile["request_sha256"],
            "actual_tokens": None,
            "actual_cost_units": None,
            "provider_receipt_ref": None,
            "response_ref": None,
            "budget_released": False,
        }
        terminal = {
            **unknown,
            "state": "RECONCILED",
            "previous_state": "UNKNOWN",
            "failure_code": "VACUOUS_OUTPUT",
            "actual_tokens": 10_382,
            "provider_receipt_ref": CHIEF_NULL_CONTENT_RECEIPT,
            "accounting_mode": "OBSERVED_NO_NUMERIC_COST",
            "accounting_evidence_ref": CHIEF_NULL_CONTENT_EVIDENCE,
            "budget_released": True,
        }
        broker = mock.Mock()
        broker.snapshot.return_value = terminal
        daemon = object.__new__(ResearchDaemon)
        daemon._started = True
        daemon._model_broker = broker
        daemon._model_routing = mock.Mock()

        result = daemon._reconcile_exact_chief_null_content_vacuous_reservation(
            mission_sha256=str(profile["mission_sha256"]),
            role_index=4,
            role="CHIEF_SCIENTIST",
            model_binding="gpt-5.6-sol-xhigh",
            reasoning_effort="xhigh",
            step=step,
            snapshot=unknown,
            now="2026-07-22T23:12:00Z",
        )
        self.assertEqual(result, terminal)
        broker.reconcile_vacuous_unknown.assert_called_once_with(
            profile["call_id"],
            actual_tokens=10_382,
            provider_receipt_ref=CHIEF_NULL_CONTENT_RECEIPT,
            accounting_evidence_ref=CHIEF_NULL_CONTENT_EVIDENCE,
            event_at="2026-07-22T23:12:00Z",
            idempotency_key=(
                "mission:7d7dcbce44eaa5b1df58d07cdd49d5d094a7d69a717382b984b2183e0b6fa7ab:"
                "4:chief-null-content-vacuous-output-reconcile:v1"
            ),
        )
        self.assertIsNone(result["actual_cost_units"])
        self.assertFalse(profile["zero_cost_claim"])
        self.assertEqual(profile["network_calls"], 1)
        self.assertEqual(profile["observed_provider_monetary_cost"], 0.16216375)

    def test_chief_null_content_gate_rejects_every_tuple_drift(self) -> None:
        profile = dict(
            _mission_chief_null_content_vacuous_reconciliation_profile()
        )
        exact = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
        }
        self.assertTrue(
            _matches_mission_chief_null_content_vacuous_reconciliation(**exact)
        )
        drifts = {
            "mission_sha256": "0" * 64,
            "role_index": 3,
            "role": "CRITIC_DEEP",
            "call_id": "model-call:" + "0" * 64,
            "request_sha256": "0" * 64,
            "model_binding": "kimi-k3-max",
            "reasoning_effort": "max",
            "failure_code": "MALFORMED_RESPONSE",
        }
        for field, value in drifts.items():
            with self.subTest(field=field):
                self.assertFalse(
                    _matches_mission_chief_null_content_vacuous_reconciliation(
                        **{**exact, field: value}
                    )
                )

        broker = mock.Mock()
        daemon = object.__new__(ResearchDaemon)
        daemon._started = True
        daemon._model_broker = broker
        daemon._model_routing = mock.Mock()
        step = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "call_id": profile["call_id"],
            "request_sha256": "0" * 64,
            "fallback_used": False,
        }
        rejected = daemon._reconcile_exact_chief_null_content_vacuous_reservation(
            mission_sha256=str(profile["mission_sha256"]),
            role_index=4,
            role="CHIEF_SCIENTIST",
            model_binding="gpt-5.6-sol-xhigh",
            reasoning_effort="xhigh",
            step=step,
            snapshot={
                "state": "UNKNOWN",
                "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
                "request_sha256": profile["request_sha256"],
            },
            now="2026-07-22T23:12:00Z",
        )
        self.assertIsNone(rejected)
        broker.reconcile_vacuous_unknown.assert_not_called()

    def test_vacuous_profile_and_exact_gate_fail_closed_on_any_drift(self) -> None:
        profile = _mission_vacuous_reconciliation_profile()
        exact = {
            "mission_sha256": profile["mission_sha256"],
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "model_binding": profile["model_binding"],
            "failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
        }
        self.assertTrue(_matches_mission_vacuous_reconciliation(**exact))
        drifts = {
            "mission_sha256": "0" * 64,
            "call_id": "model-call:" + "0" * 64,
            "request_sha256": "0" * 64,
            "model_binding": "deepseek-v4-flash",
            "failure_code": "MALFORMED_RESPONSE",
        }
        for field, value in drifts.items():
            with self.subTest(field=field):
                changed = {**exact, field: value}
                self.assertFalse(_matches_mission_vacuous_reconciliation(**changed))

        raw = (ROOT / "provenance/model-vacuous-output-reconciliation-v1.json").read_bytes()
        drifted = json.loads(raw)
        drifted["actual_tokens"] = 5_552
        path = self.root / "drifted-vacuous-profile.json"
        path.write_text(json.dumps(drifted, indent=2) + "\n")
        with (
            mock.patch.object(
                researchd_module, "_MISSION_VACUOUS_PROFILE_PATH", path
            ),
            self.assertRaisesRegex(ResearchdError, "identity drifted"),
        ):
            _mission_vacuous_reconciliation_profile()

    def test_non_unknown_cannot_use_vacuous_reconciliation(self) -> None:
        broker, ledger, call_id = self._terminal()
        with self.assertRaisesRegex(ModelBrokerError, "unresolved UNKNOWN"):
            broker.reconcile_vacuous_unknown(
                call_id,
                actual_tokens=5_551,
                provider_receipt_ref=VACUOUS_RECEIPT,
                accounting_evidence_ref=VACUOUS_EVIDENCE,
                event_at=RECONCILED_AT,
                idempotency_key="not-unknown",
            )
        ledger.close()


class VacuousWorkerOutputTests(unittest.TestCase):
    def test_valid_accounting_empty_output_is_failed_known_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_data = json.loads(CONNECTED_WORKER_POLICY_PATH.read_text())
            policy_data["control_socket"] = str(root / "missing-researchd.sock")
            policy_data["private_store_root"] = str(root / "private-store")
            policy_data["ai_off_path"] = str(root / "AI_OFF")
            policy_data["credential_file"] = str(root / "provider.env")
            policy_path = root / "runtime-policy.json"
            policy_path.write_text(json.dumps(policy_data))
            dispatch = {
                "schema_id": "ModelWorkerDispatch",
                "schema_version": "1.1.0",
                "call_id": "model-call:" + "d" * 64,
                "dispatch_token": "e" * 64,
                "request_body": "bounded synthetic research request",
                "model_binding": "deepseek-v4-pro",
                "classification": "D1",
                "max_tokens": 20_000,
                "expires_at": "2026-07-22T18:00:00Z",
                "completion_command": "complete_research_model_call",
                "worker_ipc_extension_sha256": policy_data[
                    "worker_ipc_extension_sha256"
                ],
            }
            dispatch_path = root / "dispatch.json"
            dispatch_path.write_text(
                json.dumps(dispatch, sort_keys=True, separators=(",", ":"))
            )
            os.chmod(dispatch_path, 0o600)

            body = json.dumps(
                {
                    "id": "synthetic-empty-output",
                    "usage": {
                        "prompt_tokens": 1455,
                        "completion_tokens": 4096,
                        "total_tokens": 5551,
                    },
                    "choices": [
                        {
                            "finish_reason": "length",
                            "message": {"content": "", "reasoning_content": "bounded"},
                        }
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            raw = json.dumps(
                {
                    "binding": "deepseek-v4-pro",
                    "protocol": "OPENAI_CHAT_COMPLETIONS",
                    "http_status": 200,
                    "headers": {"x-request-id": "synthetic-empty"},
                    "body_base64": base64.b64encode(body).decode("ascii"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()

            class Adapter:
                calls = 0

                def invoke_raw(self, **_keywords: object) -> bytes:
                    self.calls += 1
                    return raw

            class Resolver:
                def resolve(self, _name: str) -> str:
                    return "synthetic-private-value"

            class IPC:
                state = "RESERVED"
                completion: dict[str, object] | None = None

                def request(
                    self,
                    command: str,
                    payload: dict[str, object],
                    *,
                    idempotency_key: str,
                ) -> dict[str, object]:
                    self_outer.assertTrue(idempotency_key.startswith("worker:"))
                    if command == "lookup_model_call":
                        return {
                            "call_id": dispatch["call_id"],
                            "state": self.state,
                            "request_sha256": hashlib.sha256(
                                str(dispatch["request_body"]).encode()
                            ).hexdigest(),
                            "model_binding": dispatch["model_binding"],
                            "classification": dispatch["classification"],
                            "max_tokens": dispatch["max_tokens"],
                            "expires_at": dispatch["expires_at"],
                            "auto_retry": False,
                        }
                    if command == "begin_model_call":
                        self.state = "SENT"
                        return {"state": "SENT", "egress_authorized": True}
                    if command == "complete_research_model_call":
                        self.completion = dict(payload)
                        self.state = str(payload["outcome"])
                        return {"state": self.state}
                    raise AssertionError(command)

            self_outer = self
            adapter = Adapter()
            ipc = IPC()
            result = connected_worker_v4.run_dispatch(
                policy_path=policy_path,
                dispatch_path=dispatch_path,
                encryption_attested=True,
                ipc_client=ipc,
                credential_resolver=Resolver(),
                adapter_factory=lambda *_args: adapter,
                event_at=AT,
            )
            self.assertEqual(result["state"], "FAILED_KNOWN")
            self.assertEqual(result["network_calls"], 1)
            self.assertEqual(adapter.calls, 1)
            self.assertIsNotNone(ipc.completion)
            assert ipc.completion is not None
            self.assertEqual(ipc.completion["failure_code"], "VACUOUS_OUTPUT")
            self.assertEqual(ipc.completion["actual_tokens"], 5_551)
            self.assertEqual(
                ipc.completion["provider_receipt_ref"],
                "provider-response:sha256:" + hashlib.sha256(body).hexdigest(),
            )
            self.assertIsNone(ipc.completion["response_ref"])


class DispatcherStartBarrierTests(unittest.TestCase):
    def test_initial_inactive_does_not_false_fail_and_unit_has_one_at(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log_path = root / "systemctl.log"
            phase_path = root / "phase"
            started_path = root / "started"
            call_id = "model-call:" + "8" * 64
            dispatch = {
                "call_id": call_id,
                "dispatch_token": "dispatch-token",
                "request_body": "bounded request",
                "model_binding": "deepseek-v4-flash",
                "classification": "D1",
                "max_tokens": 20_000,
                "expires_at": "2026-07-22T18:00:00Z",
                "completion_command": "complete_research_model_call",
            }
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = inspect ]; then echo true; exit 0; fi\n"
                "case \"$*\" in\n"
                "  *advance_research_missions*) echo '{\"status\":\"WAIT_CURRENT_CALL\"}'; exit 0;;\n"
                "  *list_reserved_model_calls*) echo '"
                + json.dumps(
                    {
                        "status": "FOUND",
                        "reserved_calls": [dispatch],
                        "count": 1,
                        "wip_limit": 1,
                    },
                    separators=(",", ":"),
                )
                + "'; exit 0;;\n"
                "  *lookup_model_call*) echo SUCCEEDED; exit 0;;\n"
                "esac\n"
                "exit 1\n"
            )
            systemctl = fake_bin / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                f"echo \"$*\" >> '{log_path}'\n"
                "case \"$*\" in\n"
                f"  *'start --no-block'*) touch '{started_path}'; echo 0 > '{phase_path}'; exit 0;;\n"
                "  *'property=InvocationID'*)\n"
                f"    if [ ! -f '{started_path}' ]; then echo old; exit 0; fi\n"
                f"    p=$(cat '{phase_path}'); if [ \"$p\" -lt 2 ]; then echo old; else echo new; fi; exit 0;;\n"
                "  *'property=ActiveState'*)\n"
                f"    p=$(cat '{phase_path}'); p=$((p+1)); echo $p > '{phase_path}';\n"
                "    if [ \"$p\" -eq 1 ]; then echo inactive; elif [ \"$p\" -eq 2 ]; then echo activating; else echo inactive; fi; exit 0;;\n"
                "  *'property=Result'*) echo success; exit 0;;\n"
                "  *'property=ExecMainStatus'*) echo 0; exit 0;;\n"
                "esac\n"
                "exit 1\n"
            )
            flock = fake_bin / "flock"
            flock.write_text("#!/bin/sh\nexit 0\n")
            sleep = fake_bin / "sleep"
            sleep.write_text("#!/bin/sh\nexit 0\n")
            for executable in (docker, systemctl, flock, sleep):
                executable.chmod(0o700)
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": str(fake_bin) + os.pathsep + environment["PATH"],
                    "HOME": str(root),
                    "RESEARCH_OS_DISPATCH_DIR": str(root / "dispatch"),
                    "RESEARCH_OS_LOCK_DIR": str(root / "lock"),
                    "RESEARCH_OS_AI_OFF": str(root / "AI_OFF"),
                    "RESEARCH_OS_DISPATCH_TIMEOUT": "20",
                }
            )
            result = subprocess.run(
                ["sh", str(ROOT / "ops/deploy/research-os-advisor-dispatch.sh")],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            log = log_path.read_text()
            self.assertIn(
                "research-os-connected-worker@model-call-" + "8" * 64 + ".service",
                log,
            )
            self.assertNotIn("research-os-connected-worker@@", log)
            self.assertNotIn("CORE_NOT_TERMINAL", result.stderr)


if __name__ == "__main__":
    unittest.main()
