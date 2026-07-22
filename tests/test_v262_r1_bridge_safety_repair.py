import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "ops" / "connected-worker" / "model_worker_v4.py"
POLICY_PATH = ROOT / "ops" / "connected-worker" / "runtime-policy-v4.json"
spec = importlib.util.spec_from_file_location("v262_model_worker", WORKER_PATH)
assert spec is not None and spec.loader is not None
worker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = worker
spec.loader.exec_module(worker)

from research_bridge.admission import canonical_json_sha256  # noqa: E402
from research_bridge.ledger import JobLedger  # noqa: E402
from research_bridge.model_broker import ModelBrokerError, ModelCallBroker  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    _ServiceConfigError,
    _context_binding_from_config,
    _derive_context_identities,
)
from tests.test_s15_model_registry_broker import (  # noqa: E402
    policy as broker_policy,
    registry as broker_registry,
    seeded_ledger,
    spec as broker_spec,
)


EVENT_AT = "2026-07-21T19:45:00Z"
EXPIRES_AT = "2026-07-22T19:45:00Z"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _raw(status: int = 200, output: str = "sufficient synthetic output") -> bytes:
    body = {"error": "synthetic transient"}
    if status == 200:
        body = {
            "id": "synthetic-v262-response",
            "usage": {"total_tokens": 37},
            "choices": [{"message": {"content": output}}],
        }
    return _canonical(
        {
            "binding": "deepseek-v4-pro",
            "protocol": "OPENAI_CHAT_COMPLETIONS",
            "http_status": status,
            "headers": {"x-request-id": "synthetic-v262"},
            "body_base64": base64.b64encode(_canonical(body)).decode(),
        }
    )


class FakeResolver:
    def resolve(self, _name: str) -> str:
        return "synthetic-private-value"


class SequenceAdapter:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def invoke_raw(self, **_keywords: object) -> bytes:
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, bytes)
        return outcome


class FakeIPC:
    def __init__(self, dispatch: dict[str, object], state: str = "RESERVED") -> None:
        self.dispatch = dispatch
        self.state = state
        self.completion: dict[str, object] | None = None

    def request(
        self, command: str, payload: dict[str, object], *, idempotency_key: str
    ) -> dict[str, object]:
        if command == "lookup_model_call":
            return {
                "call_id": self.dispatch["call_id"],
                "state": self.state,
                "request_sha256": hashlib.sha256(
                    str(self.dispatch["request_body"]).encode()
                ).hexdigest(),
                "model_binding": self.dispatch["model_binding"],
                "classification": self.dispatch["classification"],
                "max_tokens": self.dispatch["max_tokens"],
                "expires_at": self.dispatch["expires_at"],
            }
        if command == "begin_model_call":
            self.state = "SENT"
            return {"state": "SENT", "egress_authorized": True}
        if command == "complete_model_call":
            self.completion = dict(payload)
            self.state = str(payload["outcome"])
            return {"state": self.state}
        raise AssertionError((command, idempotency_key))


class BridgeSafetyRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        policy = json.loads(POLICY_PATH.read_text())
        policy["control_socket"] = str(self.base / "researchd.sock")
        policy["private_store_root"] = str(self.base / "private")
        policy["ai_off_path"] = str(self.base / "AI_OFF")
        policy["credential_file"] = str(self.base / "provider.env")
        self.policy_path = self.base / "policy.json"
        self.policy_path.write_text(json.dumps(policy))
        self.dispatch = {
            "schema_id": "ModelWorkerDispatch",
            "schema_version": "1.0.0",
            "call_id": "model-call:sha256:" + hashlib.sha256(b"v262").hexdigest(),
            "dispatch_token": hashlib.sha256(b"v262-token").hexdigest(),
            "request_body": "Produce a bounded D0 synthetic proposal.",
            "model_binding": "deepseek-v4-pro",
            "classification": "D0",
            "max_tokens": 4096,
            "expires_at": EXPIRES_AT,
            "worker_ipc_extension_sha256": policy["worker_ipc_extension_sha256"],
        }
        self.dispatch_path = self.base / "dispatch.json"
        self.dispatch_path.write_bytes(_canonical(self.dispatch))
        os.chmod(self.dispatch_path, 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self, adapter: SequenceAdapter, ipc: FakeIPC | None = None) -> tuple[dict[str, object], FakeIPC]:
        selected_ipc = FakeIPC(self.dispatch) if ipc is None else ipc
        result = worker.run_dispatch(
            policy_path=self.policy_path,
            dispatch_path=self.dispatch_path,
            encryption_attested=True,
            ipc_client=selected_ipc,
            credential_resolver=FakeResolver(),
            adapter_factory=lambda *_args: adapter,
            event_at=EVENT_AT,
        )
        return result, selected_ipc

    def _stored_record(self) -> dict[str, object]:
        policy = json.loads(self.policy_path.read_text())
        store = worker.PrivateResponseStore(
            Path(policy["private_store_root"]),
            encryption_attested=True,
            maximum_record_bytes=policy["max_completion_bytes"],
        )
        record = store.load_record(str(self.dispatch["call_id"]))
        assert record is not None
        return record

    def test_proven_pre_send_failure_retries_once_with_stable_attempt_ids(self) -> None:
        adapter = SequenceAdapter(
            [urllib.error.URLError(socket.gaierror(-2, "synthetic dns")), _raw()]
        )
        result, ipc = self._run(adapter)
        self.assertEqual((result["state"], result["network_calls"]), ("SUCCEEDED", 2))
        self.assertEqual(adapter.calls, 2)
        record = self._stored_record()
        attempts = record["attempts"]
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0]["request_bytes_sent"], False)
        self.assertNotEqual(attempts[0]["attempt_id"], attempts[1]["attempt_id"])
        self.assertEqual(tuple(item["attempt_id"] for item in attempts), result["attempt_ids"])
        self.assertEqual(ipc.completion["outcome"], "SUCCEEDED")

    def test_ambiguous_timeout_and_malformed_response_never_retry(self) -> None:
        for label, outcome, code in (
            ("timeout", TimeoutError("synthetic timeout"), "AMBIGUOUS_TIMEOUT"),
            ("malformed", b"not-json", "MALFORMED_RESPONSE"),
        ):
            with self.subTest(label=label):
                self.dispatch["call_id"] = "model-call:sha256:" + hashlib.sha256(label.encode()).hexdigest()
                self.dispatch_path.write_bytes(_canonical(self.dispatch))
                os.chmod(self.dispatch_path, 0o600)
                adapter = SequenceAdapter([outcome, _raw()])
                result, ipc = self._run(adapter)
                self.assertEqual((result["state"], result["network_calls"]), ("UNKNOWN", 1))
                self.assertEqual(adapter.calls, 1)
                self.assertEqual(ipc.completion["failure_code"], None)
                self.assertEqual(ipc.completion["actual_tokens"], None)
                self.assertEqual(ipc.completion["actual_cost_units"], None)
                self.assertEqual(ipc.completion["provider_receipt_ref"], None)
                self.assertEqual(self._stored_record()["failure_code"], code)

    def test_http_429_retries_only_once_and_restart_sent_never_calls_provider(self) -> None:
        adapter = SequenceAdapter([_raw(429), _raw(429), _raw()])
        result, _ipc = self._run(adapter)
        self.assertEqual((result["state"], result["network_calls"]), ("FAILED_KNOWN", 2))
        self.assertEqual(adapter.calls, 2)
        self.dispatch["call_id"] = "model-call:sha256:" + hashlib.sha256(b"sent").hexdigest()
        self.dispatch_path.write_bytes(_canonical(self.dispatch))
        os.chmod(self.dispatch_path, 0o600)
        guard = SequenceAdapter([AssertionError("provider must not run")])
        replay, _ = self._run(guard, FakeIPC(self.dispatch, state="SENT"))
        self.assertEqual((replay["status"], replay["network_calls"]), ("RECOVERED_UNKNOWN", 0))
        self.assertEqual(guard.calls, 0)

    def test_context_migration_receipt_is_integrity_bound(self) -> None:
        frozen = {
            "core_catalog_sha256": "a" * 64,
            "a1_catalog_sha256": "b" * 64,
            "release_manifest_sha256": "c" * 64,
            "policy_sha256": "d" * 64,
        }
        limits = {"cycle_limits": {"max_model_calls": 1}, "daily_limits": {}}
        first_identity = _derive_context_identities(frozen, limits)
        self.assertEqual(first_identity, _derive_context_identities(frozen, limits))
        runtime_changed = dict(frozen)
        runtime_changed["model_runtime"] = {"binding_revision": "v2"}
        changed_identity = _derive_context_identities(runtime_changed, limits)
        self.assertEqual(
            first_identity["admission_authority_sha256"],
            changed_identity["admission_authority_sha256"],
        )
        self.assertNotEqual(
            first_identity["operational_model_runtime_sha256"],
            changed_identity["operational_model_runtime_sha256"],
        )
        self.assertNotEqual(
            first_identity["context_v2_sha256"],
            changed_identity["context_v2_sha256"],
        )
        authority = "1" * 64
        runtime = "2" * 64
        receipt = {
            "schema_id": "ContextBindingMigrationReceipt",
            "schema_version": "1.0.0",
            "from_context_sha256s": ["3" * 64],
            "to_context_sha256": "4" * 64,
            "admission_authority_sha256": authority,
            "operational_model_runtime_sha256": runtime,
            "ledger_rows_mutated": 0,
        }
        receipt["integrity_sha256"] = canonical_json_sha256(receipt)
        binding = {
            "context_schema_version": "a1-context-v2",
            "admission_authority_sha256": authority,
            "operational_model_runtime_sha256": runtime,
            "migration_receipt": receipt,
        }
        parsed = _context_binding_from_config(binding)
        self.assertEqual(parsed["migration_receipt"]["from_context_sha256s"], ("3" * 64,))
        fresh = dict(binding)
        fresh["migration_receipt"] = None
        self.assertIsNone(_context_binding_from_config(fresh)["migration_receipt"])
        binding["migration_receipt"]["to_context_sha256"] = "5" * 64
        with self.assertRaises(_ServiceConfigError):
            _context_binding_from_config(binding)

    def test_public_model_state_query_is_zero_write_and_dispatch_shell_is_strict(self) -> None:
        ledger_path = self.base / "ledger.sqlite3"
        with JobLedger(ledger_path) as ledger:
            before = ledger.storage_coverage_manifest()
            self.assertEqual(ledger.model_call_states(), ())
            self.assertEqual(ledger.storage_coverage_manifest(), before)
        script = ROOT / "ops" / "deploy" / "research-os-advisor-dispatch.sh"
        subprocess.run(["sh", "-n", str(script)], check=True)
        source = script.read_text()
        self.assertIn("ExecMainStatus", source)
        self.assertIn("query_exact_call_state", source)
        self.assertIn("CORE_NOT_TERMINAL", source)
        self.assertNotIn("Dispatch failed for call at index ${IDX} — continuing", source)

        fake_bin = self.base / "bin"
        fake_bin.mkdir()
        docker = fake_bin / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = inspect ]; then echo true; exit 0; fi\n"
            "if [ \"$1\" = exec ]; then "
            "echo '{\"status\":\"NO_RESERVED_CALLS\",\"reserved_calls\":[],\"count\":0,\"wip_limit\":1}'; exit 0; fi\n"
            "exit 1\n"
        )
        flock = fake_bin / "flock"
        flock.write_text("#!/bin/sh\nexit 0\n")
        systemctl = fake_bin / "systemctl"
        worker_marker = self.base / "worker-started"
        systemctl.write_text(f"#!/bin/sh\ntouch '{worker_marker}'\nexit 99\n")
        for executable in (docker, flock, systemctl):
            executable.chmod(0o700)
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": str(fake_bin) + os.pathsep + environment["PATH"],
                "HOME": str(self.base),
                "RESEARCH_OS_DISPATCH_DIR": str(self.base / "dispatch"),
                "RESEARCH_OS_LOCK_DIR": str(self.base / "lock"),
                "RESEARCH_OS_AI_OFF": str(self.base / "AI_OFF"),
            }
        )
        completed = subprocess.run(
            ["sh", str(script)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(worker_marker.exists())

    def test_fmax_preserves_core_20000_reservation_and_old_profile_fails_closed(self) -> None:
        with seeded_ledger(self.base / "fmax-budget.sqlite3") as ledger:
            broker = ModelCallBroker(
                registry=broker_registry(),
                ledger=ledger,
                budget_policy=broker_policy(tokens=20_000),
            )
            with self.assertRaises(ModelBrokerError):
                broker.prepare(
                    broker_spec(
                        key="fmax-over-20000",
                        max_tokens=20_001,
                    ),
                    event_at="2026-07-18T12:00:00Z",
                )

        stale = json.loads(POLICY_PATH.read_text())
        stale["shadow_profile_sha256"] = (
            "c8c01f75b9c659b96ef1ec11cc114584c4df69b78da5658a8ca0866c7fe414d2"
        )
        stale_path = self.base / "stale-fmax-policy.json"
        stale_path.write_text(json.dumps(stale))
        with self.assertRaises(worker.ConnectedWorkerError):
            worker.RuntimePolicy.load(stale_path)


if __name__ == "__main__":
    unittest.main()
