from __future__ import annotations

import hashlib
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
    _MISSION_TOTAL_TOKEN_RESERVATION,
    _mission_observed_accounting_evidence_ref,
    ResearchdError,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    policy,
    registry,
    seeded_ledger,
    spec,
)


AT = "2026-07-22T14:40:00Z"
SENT_AT = "2026-07-22T14:40:01Z"
TERMINAL_AT = "2026-07-22T14:40:02Z"
RECONCILED_AT = "2026-07-22T14:40:03Z"
RECEIPT = "provider-response:sha256:" + hashlib.sha256(b"response").hexdigest()
EVIDENCE = _mission_observed_accounting_evidence_ref("deepseek-v4-flash")


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
