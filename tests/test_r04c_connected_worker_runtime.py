import contextlib
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "ops" / "connected-worker" / "model_worker.py"
POLICY_PATH = ROOT / "ops" / "connected-worker" / "runtime-policy.json"
CONFIG_PATH = ROOT / "ops" / "release" / "researchd.config.template.json"
RUNBOOK_PATH = ROOT / "ops" / "connected-worker" / "runbook-inputs.json"
spec = importlib.util.spec_from_file_location("r04c_model_worker", WORKER_PATH)
assert spec is not None and spec.loader is not None
worker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = worker
spec.loader.exec_module(worker)

from research_bridge.model_broker import ProviderAccounting  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    ResearchDaemon,
    _service_config_from_mapping,
)


EVENT_AT = "2026-07-19T12:00:00Z"
EXPIRES_AT = "2026-07-20T12:00:00Z"
OUTPUT = '{"proposal":"bounded public synthetic result"}'


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _raw_response(output: str = OUTPUT) -> bytes:
    body = _canonical(
        {
            "id": "synthetic-response-r04c",
            "usage": {"total_tokens": 37},
            "choices": [{"message": {"content": output}}],
        }
    )
    return _canonical(
        {
            "binding": "deepseek-v4-pro",
            "protocol": "OPENAI_CHAT_COMPLETIONS",
            "http_status": 200,
            "headers": {"x-request-id": "synthetic-r04c"},
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
    )


def _composed_config() -> dict[str, object]:
    config = json.loads(CONFIG_PATH.read_text())
    composition = json.loads(RUNBOOK_PATH.read_text())[
        "researchd_runtime_composition"
    ]
    uid = composition["add_allowed_uid"]
    if uid not in config["allowed_uids"]:
        config["allowed_uids"].append(uid)
    config["principal_roles"].update(composition["add_principal_role"])
    config["frozen_bindings"].update(composition["add_frozen_binding"])
    return config


class FakeResolver:
    def __init__(self, value: str) -> None:
        self.value = value

    def resolve(self, _name: str) -> str:
        return self.value


class FakeAdapter:
    def __init__(self, raw: bytes, events: list[str]) -> None:
        self.raw = raw
        self.events = events
        self.calls = 0

    def invoke_raw(self, **_keywords: object) -> bytes:
        self.events.append("provider")
        self.calls += 1
        return self.raw


class FakeIPC:
    def __init__(
        self,
        dispatch: dict[str, object],
        *,
        state: str = "RESERVED",
        events: list[str] | None = None,
        fail_completion_once: bool = False,
    ) -> None:
        self.dispatch = dispatch
        self.state = state
        self.events = [] if events is None else events
        self.fail_completion_once = fail_completion_once
        self.commands: list[str] = []
        self.completion: dict[str, object] | None = None

    def _snapshot(self) -> dict[str, object]:
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
            "auto_retry": False,
        }

    def request(
        self,
        command: str,
        payload: dict[str, object],
        *,
        idempotency_key: str,
    ) -> dict[str, object]:
        self.commands.append(command)
        self.events.append(command)
        self.assert_key(idempotency_key)
        if command == "lookup_model_call":
            return self._snapshot()
        if command == "begin_model_call":
            if self.state != "RESERVED":
                raise worker.ConnectedWorkerError("begin state mismatch")
            self.state = "SENT"
            return {"state": "SENT", "egress_authorized": True}
        if command == "complete_model_call":
            if self.fail_completion_once:
                self.fail_completion_once = False
                raise worker.ConnectedWorkerError("synthetic completion interruption")
            self.completion = dict(payload)
            self.state = str(payload["outcome"])
            return {"state": self.state}
        raise AssertionError(command)

    @staticmethod
    def assert_key(value: str) -> None:
        if not value.startswith("worker:") or len(value) > 256:
            raise AssertionError("invalid worker idempotency key")


class ConnectedWorkerRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.store_root = self.base / "private-store"
        self.policy_path = self.base / "runtime-policy.json"
        policy = json.loads(POLICY_PATH.read_text())
        policy["control_socket"] = str(self.base / "missing-researchd.sock")
        policy["private_store_root"] = str(self.store_root)
        policy["ai_off_path"] = str(self.base / "AI_OFF")
        policy["credential_file"] = str(self.base / "provider.env")
        self.policy = policy
        self.policy_path.write_text(json.dumps(policy))
        self.dispatch = {
            "schema_id": "ModelWorkerDispatch",
            "schema_version": "1.0.0",
            "call_id": "model-call:sha256:" + hashlib.sha256(b"r04c-call").hexdigest(),
            "dispatch_token": hashlib.sha256(b"r04c-token").hexdigest(),
            "request_body": "Produce one bounded D0 synthetic proposal.",
            "model_binding": "deepseek-v4-pro",
            "classification": "D0",
            "max_tokens": 128,
            "expires_at": EXPIRES_AT,
            "worker_ipc_extension_sha256": policy[
                "worker_ipc_extension_sha256"
            ],
        }
        self.dispatch_path = self.base / "dispatch.json"
        self._write_owner_file(self.dispatch_path, _canonical(self.dispatch))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_owner_file(path: Path, raw: bytes) -> None:
        path.write_bytes(raw)
        os.chmod(path, 0o600)

    def _run(
        self,
        ipc: FakeIPC,
        adapter: FakeAdapter,
        *,
        resolver: FakeResolver | None = None,
        encryption_attested: bool = True,
    ) -> dict[str, object]:
        return worker.run_dispatch(
            policy_path=self.policy_path,
            dispatch_path=self.dispatch_path,
            encryption_attested=encryption_attested,
            ipc_client=ipc,
            credential_resolver=FakeResolver("synthetic-private-value")
            if resolver is None
            else resolver,
            adapter_factory=lambda *_args: adapter,
            event_at=EVENT_AT,
        )

    def test_shipped_config_is_exact_and_truthfully_waits_for_provider(self) -> None:
        base_config = json.loads(CONFIG_PATH.read_text())
        self.assertEqual(base_config["allowed_uids"], [10001, 10002, 10003])
        self.assertNotIn("model_runtime", base_config["frozen_bindings"])
        service = _service_config_from_mapping(_composed_config())
        self.assertEqual(service.principal_roles[10004], "connected_worker")
        runtime = service.frozen_bindings["model_runtime"]
        self.assertEqual(runtime["available_bindings"], ())
        self.assertEqual(runtime["max_active_calls"], 4)
        self.assertLessEqual(runtime["max_reserved_tokens"], 200000)
        self.assertLessEqual(runtime["max_reserved_cost_units"], 100)
        loaded = worker.RuntimePolicy.load(POLICY_PATH)
        self.assertEqual(loaded.worker_uid, 10004)
        self.assertEqual(loaded.worker_gid, 10001)

    def test_dispatch_is_owner_only_strict_and_exactly_bound(self) -> None:
        profile = worker.ConnectedShadowProfile()
        policy = worker.RuntimePolicy.load(self.policy_path)
        loaded = worker.Dispatch.load(
            self.dispatch_path, policy=policy, profile=profile
        )
        self.assertEqual(loaded.call_id, self.dispatch["call_id"])
        os.chmod(self.dispatch_path, 0o640)
        with self.assertRaises(worker.ConnectedWorkerError):
            worker.Dispatch.load(self.dispatch_path, policy=policy, profile=profile)
        self._write_owner_file(self.dispatch_path, _canonical(self.dispatch))
        changed = dict(self.dispatch)
        changed["worker_ipc_extension_sha256"] = "f" * 64
        self._write_owner_file(self.dispatch_path, _canonical(changed))
        with self.assertRaises(worker.ConnectedWorkerError):
            worker.Dispatch.load(self.dispatch_path, policy=policy, profile=profile)

    def test_ai_off_and_missing_credential_stop_before_ipc_and_provider(self) -> None:
        class NoIPC:
            def request(self, *_args: object, **_keywords: object) -> object:
                raise AssertionError("IPC must remain unused")

        adapter = FakeAdapter(_raw_response(), [])
        Path(self.policy["ai_off_path"]).touch()
        result = worker.run_dispatch(
            policy_path=self.policy_path,
            dispatch_path=self.dispatch_path,
            encryption_attested=False,
            ipc_client=NoIPC(),
            credential_resolver=FakeResolver("synthetic-private-value"),
            adapter_factory=lambda *_args: adapter,
            event_at=EVENT_AT,
        )
        self.assertEqual(result["status"], "AI_OFF")
        self.assertEqual(adapter.calls, 0)
        Path(self.policy["ai_off_path"]).unlink()
        result = worker.run_dispatch(
            policy_path=self.policy_path,
            dispatch_path=self.dispatch_path,
            encryption_attested=False,
            ipc_client=NoIPC(),
            credential_resolver=FakeResolver(""),
            adapter_factory=lambda *_args: adapter,
            event_at=EVENT_AT,
        )
        self.assertEqual(result["status"], "WAIT_CREDENTIAL")
        self.assertEqual(adapter.calls, 0)

    def test_ai_off_does_not_stop_core_and_0710_parent_stays_private(self) -> None:
        config = _composed_config()
        runtime = self.base / "core-runtime"
        runtime.mkdir(mode=0o710)
        config["runtime_root"] = str(runtime)
        config["frozen_bindings"]["release_manifest_sha256"] = "f" * 64
        service = _service_config_from_mapping(config)
        daemon = ResearchDaemon(
            runtime,
            authority=service.authority,
            allowed_uids=service.allowed_uids,
            principal_roles=service.principal_roles,
            a1_enabled=service.a1_enabled,
            frozen_bindings=service.frozen_bindings,
            a1_limits=service.a1_limits,
            runner_identity=service.runner_identity,
            input_quota_bytes=service.input_quota_bytes,
            checkpoint_quota_bytes=service.checkpoint_quota_bytes,
            artifact_quota_bytes=service.artifact_quota_bytes,
            maximum_input_bytes=service.maximum_input_bytes,
            deadline_seconds=service.deadline_seconds,
            clock=lambda: datetime.fromisoformat(EVENT_AT[:-1] + "+00:00"),
        )
        Path(self.policy["ai_off_path"]).touch()
        previous_umask = os.umask(0o077)
        try:
            daemon.start()
            os.umask(previous_umask)
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o710)
            self.assertFalse(daemon.pause_snapshot()["paused"])
            self.assertEqual(
                stat.S_IMODE(
                    (runtime / "bridge-job-ledger.sqlite3").stat().st_mode
                ),
                0o600,
            )
        finally:
            os.umask(previous_umask)
            daemon.close()

    def test_success_commits_raw_before_parse_and_binds_exact_output(self) -> None:
        events: list[str] = []
        raw = _raw_response()
        adapter = FakeAdapter(raw, events)
        ipc = FakeIPC(self.dispatch, events=events)
        raw_digest = hashlib.sha256(raw).hexdigest()
        real_parser = worker.HTTPResponseParser

        class OrderingParser:
            model_binding = "deepseek-v4-pro"

            def __init__(self, binding: str, protocol: str) -> None:
                self.inner = real_parser(binding, protocol)

            def parse_response(self, **keywords: object) -> ProviderAccounting:
                events.append("parse")
                raw_path = self_outer.store_root / "objects" / "raw" / raw_digest
                self_outer.assertTrue(raw_path.is_file())
                self_outer.assertEqual(
                    stat.S_IMODE(raw_path.stat().st_mode), 0o600
                )
                return self.inner.parse_response(**keywords)

        self_outer = self
        with mock.patch.object(worker, "HTTPResponseParser", OrderingParser):
            result = self._run(ipc, adapter)
        self.assertEqual(result["state"], "SUCCEEDED")
        self.assertEqual(adapter.calls, 1)
        self.assertLess(events.index("begin_model_call"), events.index("provider"))
        self.assertLess(events.index("provider"), events.index("parse"))
        self.assertLess(events.index("parse"), events.index("complete_model_call"))
        expected_output_ref = "cas:sha256:" + hashlib.sha256(OUTPUT.encode()).hexdigest()
        self.assertEqual(ipc.completion["response_ref"], expected_output_ref)
        record = worker.PrivateResponseStore(
            self.store_root,
            encryption_attested=True,
            maximum_record_bytes=self.policy["max_completion_bytes"],
        ).load_record(str(self.dispatch["call_id"]))
        self.assertEqual(record["raw_response_ref"], "private-cas:sha256:" + raw_digest)
        self.assertNotIn(raw.decode(), json.dumps(result))
        for path in self.store_root.rglob("*"):
            expected = 0o700 if path.is_dir() else 0o600
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)

    def test_interrupted_callback_replays_completion_without_provider_repeat(self) -> None:
        events: list[str] = []
        adapter = FakeAdapter(_raw_response(), events)
        first = FakeIPC(
            self.dispatch,
            events=events,
            fail_completion_once=True,
        )
        with self.assertRaises(worker.ConnectedWorkerError):
            self._run(first, adapter)
        self.assertEqual(adapter.calls, 1)
        second = FakeIPC(self.dispatch, state="SENT", events=events)
        repeat_guard = FakeAdapter(_raw_response("must not run"), events)
        result = self._run(second, repeat_guard)
        self.assertEqual(result["status"], "COMPLETION_REPLAYED")
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(repeat_guard.calls, 0)
        self.assertEqual(second.state, "SUCCEEDED")

    def test_sent_without_completion_recovers_unknown_without_repeat_storm(self) -> None:
        adapter = FakeAdapter(_raw_response(), [])
        ipc = FakeIPC(self.dispatch, state="SENT")
        result = self._run(ipc, adapter)
        self.assertEqual(result["status"], "RECOVERED_UNKNOWN")
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(adapter.calls, 0)
        second = self._run(ipc, adapter)
        self.assertEqual(second["status"], "ALREADY_TERMINAL")
        self.assertEqual(adapter.calls, 0)

    def test_encryption_attestation_precedes_begin_and_store_lifecycle_is_exact(self) -> None:
        adapter = FakeAdapter(_raw_response(), [])
        ipc = FakeIPC(self.dispatch)
        with self.assertRaises(worker.ConnectedWorkerError):
            self._run(ipc, adapter, encryption_attested=False)
        self.assertEqual(ipc.commands, ["lookup_model_call"])
        self.assertEqual(adapter.calls, 0)

        store = worker.PrivateResponseStore(
            self.store_root,
            encryption_attested=True,
            maximum_record_bytes=self.policy["max_completion_bytes"],
        )
        raw_ref = store.commit_raw(b"private synthetic raw")
        output_ref = store.commit_output(b"sanitized output", maximum=1024)
        backup = self.base / "backups" / "worker-backup.json"
        store.backup(backup)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        restore_root = self.base / "restored-private"
        restored = worker.PrivateResponseStore(
            restore_root,
            encryption_attested=True,
            maximum_record_bytes=self.policy["max_completion_bytes"],
        )
        self.assertEqual(restored.restore(backup), 2)
        self.assertTrue(restored.delete_ref(output_ref))
        raw_path = restored.raw_root / raw_ref.rsplit(":", 1)[1]
        os.utime(raw_path, (1, 1))
        self.assertEqual(
            restored.purge(now_epoch=1000, retention_seconds=10), 1
        )
        self.assertFalse(raw_path.exists())

    def test_owner_only_credential_file_and_cli_errors_are_redacted(self) -> None:
        secret = "synthetic-private-marker-r04c"
        credential_path = Path(self.policy["credential_file"])
        self._write_owner_file(
            credential_path,
            ("DEEPSEEK_API_KEY=" + secret + "\n").encode(),
        )
        self.assertEqual(
            worker._credential_environment(credential_path)["DEEPSEEK_API_KEY"],
            secret,
        )
        stderr = io.StringIO()
        stdout = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            code = worker.main(
                [
                    "run",
                    "--policy",
                    str(self.policy_path),
                    "--dispatch",
                    str(self.dispatch_path),
                    "--storage-encryption-attested",
                ]
            )
        self.assertEqual(code, 30)
        rendered = stderr.getvalue() + stdout.getvalue()
        self.assertNotIn(secret, rendered)
        self.assertNotIn("DEEPSEEK_API_KEY", rendered)
        self.assertIn("CONNECTED_WORKER_FAILED_CLOSED", rendered)
        os.chmod(credential_path, 0o640)
        with self.assertRaises(worker.ConnectedWorkerError):
            worker._credential_environment(credential_path)

    def test_service_container_and_topology_keep_offline_l0_separate(self) -> None:
        bridge = (ROOT / "ops" / "deploy" / "research-os-a1-final.service").read_text()
        unit = (
            ROOT / "ops" / "deploy" / "research-os-connected-worker@.service"
        ).read_text()
        container = (
            ROOT / "ops" / "connected-worker" / "Containerfile"
        ).read_text()
        source = WORKER_PATH.read_text()
        self.assertIn("--network=none", bridge)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", bridge)
        self.assertIn("chmod 0710 /var/lib/research-os", bridge)
        self.assertIn("--network=research-os-provider-egress", unit)
        self.assertIn("--restart=no", unit)
        self.assertIn("Restart=no", unit)
        self.assertIn("--user=10004:10001", unit)
        self.assertIn("research-os-a1-runtime,target=/var/lib/research-os,readonly", unit)
        self.assertNotIn("docker.sock,target=", unit)
        create_line = next(
            line for line in unit.splitlines()
            if line.startswith("ExecStartPre=/usr/bin/docker container create")
        )
        self.assertNotIn("type=bind", create_line)
        self.assertNotIn("--env-file", create_line)
        self.assertIn("research-os-connected-credential", create_line)
        self.assertIn("research-os-connected-dispatch-%i", create_line)
        self.assertIn("install -m 0600 -o 10004 -g 10001", unit)
        self.assertIn("USER 10004:10001", container)
        self.assertNotIn("JobLedger", source)
        self.assertNotIn("ledger.sqlite", source)
        topology = json.loads(
            (ROOT / "ops" / "organism" / "component-declarations.json").read_text()
        )
        component = next(
            item for item in topology["components"]
            if item["component_id"] == "connected-model-worker"
        )
        self.assertEqual(
            component["access"]["network"], "CONNECTED_PROVIDER_EGRESS_ONLY"
        )
        self.assertEqual(
            component["authority_ceiling"], "UNTRUSTED_MODEL_EGRESS_ONLY"
        )


if __name__ == "__main__":
    unittest.main()
