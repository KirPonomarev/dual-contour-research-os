from __future__ import annotations

import copy
from collections.abc import Mapping
import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.control import ControlError  # noqa: E402
from research_bridge.ipc import PeerCredentials, encode_message  # noqa: E402
from research_bridge.researchd import ResearchDaemon, ResearchdError, _service_config_from_mapping  # noqa: E402


CONFIG_PATH = ROOT / "ops/release/researchd.config.template.json"
NOW = datetime(2026, 7, 19, 6, 0, tzinfo=timezone.utc)
COLLECTOR_UID = 10002
SCOUT_UID = 10003
OPERATOR_UID = 10001
PROTOCOL_REF = "research-bridge:l0:chunk-sha256:v1"
L0_TEMPLATE_SHA256 = "53e75c79888c60b304c0e7e5392a53c0ef508146dfd51c5dcb195a648a54f0c6"
IMAGE_DIGEST = "sha256:" + hashlib.sha256(b"r03c-synthetic-offline-image").hexdigest()
RELEASE_SHA256 = hashlib.sha256(b"r03c-synthetic-release").hexdigest()


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _snapshot(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    )


def _config(runtime: Path) -> dict[str, object]:
    value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    value["runtime_root"] = str(runtime)
    value["frozen_bindings"]["release_manifest_sha256"] = RELEASE_SHA256
    value["frozen_bindings"]["admission_runtime"]["corridor_executor_profile"] = {
        "capability_ref": value["frozen_bindings"]["executor_capability_refs"][0],
        "protocol_ref": PROTOCOL_REF,
        "code_sha256": L0_TEMPLATE_SHA256,
        "image_digest": IMAGE_DIGEST,
        "runner_identity": value["runner_identity"],
        "maximum_lifetime_seconds": 120,
    }
    return value


def _model_body(
    evidence_ref: str,
    suffix: str,
    **overrides: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "candidate_id": f"candidate:r03c:{suffix}",
        "draft_revision": 1,
        "experiment_type": "synthetic-fixture-check",
        "estimand": "Difference between the registered fixture and its fixed null.",
        "null_hypothesis": "The registered fixture produces no difference.",
        "falsifier": "The bounded result is byte-identical to the null fixture.",
        "stop_condition": "Stop after one offline deterministic fixture execution.",
        "scope": "Registered sanitized offline fixture only.",
        "expected_output": "One bounded synthetic validation result.",
        "evidence_refs": [evidence_ref],
        "evidence_independence_groups": [[evidence_ref]],
        "executor_family": "registered-offline-l0",
        "resource_request": {
            "wall_seconds": 60,
            "cpu_seconds": 60,
            "memory_mib": 128,
            "output_bytes": 100_000,
            "tokens": 1_000,
            "cost_units": 2,
        },
        "data_classes": ["synthetic"],
        "network_required": False,
        "holdout_access_requested": False,
        "canonical_write_requested": False,
        "private_api_requested": False,
        "live_execution_requested": False,
    }
    value.update(overrides)
    return value


def _reseal(document: dict[str, object]) -> None:
    integrity = document["integrity"]
    if not isinstance(integrity, dict):
        raise AssertionError("synthetic document integrity is not mutable")
    integrity["payload_sha256"] = hashlib.sha256(
        _canonical(document["payload"])
    ).hexdigest()


class CorridorHostileAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.runtime = self.base / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.current = NOW
        self.peer_uid = COLLECTOR_UID
        self.daemons: list[ResearchDaemon] = []

    def tearDown(self) -> None:
        for daemon in reversed(self.daemons):
            daemon.close()
        self.temporary.cleanup()

    def _daemon(
        self,
        *,
        runtime: Path | None = None,
        config: dict[str, object] | None = None,
    ) -> ResearchDaemon:
        selected = runtime or self.runtime
        service = _service_config_from_mapping(config or _config(selected))
        daemon = ResearchDaemon(
            selected,
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
            clock=lambda: self.current,
            credential_resolver=self._credentials,
        )
        self.daemons.append(daemon)
        return daemon

    def _credentials(self, connection: socket.socket) -> PeerCredentials:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1_048_576)
        return PeerCredentials(uid=self.peer_uid, gid=20000, pid=os.getpid())

    def _request(
        self,
        daemon: ResearchDaemon,
        uid: int,
        command: str,
        key: str,
        payload: dict[str, object],
    ):
        self.peer_uid = uid
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1_048_576)
        client.connect(str(daemon.socket_path))
        try:
            client.sendall(
                encode_message(
                    {
                        "version": "1.2",
                        "request_id": f"request:{key}",
                        "idempotency_key": key,
                        "command": command,
                        "payload": payload,
                    }
                )
            )
            client.shutdown(socket.SHUT_WR)
            return daemon.serve_once()
        finally:
            client.close()

    def _publish_input(self, daemon: ResearchDaemon, payload: bytes) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        source = self.base / f"{digest}.synthetic"
        source.write_bytes(payload)
        record = daemon._input_store.publish(  # type: ignore[union-attr]
            source,
            expected_sha256=digest,
            expected_size_bytes=len(payload),
        )
        return record.ref

    def _authority_bundle(
        self,
        daemon: ResearchDaemon,
        *,
        suffix: str,
        evidence_ref: str | None = None,
        candidate_evidence_ref: str | None = None,
        model_overrides: dict[str, object] | None = None,
    ) -> tuple[dict[str, object] | None, object]:
        trusted_ref = evidence_ref or self._publish_input(
            daemon, f"r03c-input:{suffix}".encode("ascii")
        )
        source_key = f"source:{suffix}"
        source = self._request(
            daemon,
            COLLECTOR_UID,
            "submit_source_trigger",
            source_key,
            {
                "source_trigger": {
                    "trigger_id": f"trigger:{suffix}",
                    "collector_id": "collector:uid:10002",
                    "source_ref": f"registered:r03c/{suffix}",
                    "source_content_sha256": trusted_ref.removeprefix("cas:sha256:"),
                    "observed_at": "2026-07-19T05:59:00Z",
                    "summary": "Sanitized registered synthetic corridor signal.",
                    "evidence_refs": [trusted_ref],
                    "transport_idempotency_key": source_key,
                }
            },
        )
        event_ref = source.result["material_event"]["object_id"]
        claim = self._request(
            daemon,
            SCOUT_UID,
            "claim_proposal",
            f"claim:{suffix}",
            {"material_event_ref": event_ref},
        )
        selected_ref = candidate_evidence_ref or trusted_ref
        body = _model_body(selected_ref, suffix)
        if model_overrides:
            body.update(model_overrides)
        envelope = {
            "material_event_ref": event_ref,
            "claim_token": claim.result["claim_token"],
            "model_output": json.dumps(body, sort_keys=True, separators=(",", ":")),
            "critique_output": json.dumps(
                {
                    "accepted": True,
                    "falsifier_present": True,
                    "critique": "Bounded registered proposal is testable.",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "model_call_ref": f"model-call:fixture-worker:{suffix}",
            "critique_call_ref": f"model-call:fixture-critic:{suffix}",
        }
        response = self._request(
            daemon,
            SCOUT_UID,
            "submit_proposal",
            f"proposal:{suffix}",
            {"proposal_envelope": envelope},
        )
        admission = response.result["admission"]
        bundle = _plain(admission["authority_bundle"])
        if bundle is not None and not isinstance(bundle, dict):
            raise AssertionError("authority bundle is not a JSON object")
        return bundle, admission

    def _submit(self, daemon: ResearchDaemon, bundle: dict[str, object]):
        job_payload = bundle["job_spec"]["payload"]
        key = job_payload["idempotency_key"]
        return self._request(
            daemon,
            OPERATOR_UID,
            "submit",
            key,
            {
                "job_spec": bundle["job_spec"],
                "permit": bundle["permit"],
                "lease": bundle["lease"],
            },
        )

    def _assert_no_execution(self, daemon: ResearchDaemon) -> None:
        self.assertEqual(daemon._ledger.event_count("claim"), 0)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("checkpoint"), 0)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("complete"), 0)  # type: ignore[union-attr]

    def test_full_af_unix_corridor_executes_and_validates_once_then_reopens_byte_exact(self) -> None:
        daemon = self._daemon()
        daemon.start()
        bundle, admission = self._authority_bundle(daemon, suffix="full")
        self.assertEqual(admission["decision"], "ADMIT")
        self.assertEqual(admission["authority_status"], "ISSUED")
        self.assertEqual(admission["authority_reason"], "AUTHORITY_CHAIN_ISSUED")
        self.assertIsInstance(bundle, dict)
        assert bundle is not None

        submitted = self._submit(daemon, bundle)
        execution = submitted.result["execution_receipt"]
        validation = submitted.result["validation_receipt"]
        self.assertEqual(execution["schema_id"], "ExecutionReceipt")
        self.assertEqual(
            execution["payload"]["exit_classification"], "mechanical-success"
        )
        self.assertEqual(validation["schema_id"], "ValidationReceipt")
        self.assertEqual(validation["payload"]["proposed_outcome"], "VALIDATED_MECHANICAL")
        self.assertEqual(validation["payload"]["protocol_ref"], PROTOCOL_REF)
        self.assertEqual(validation["payload"]["holdout_access_ref"], "holdout:none")
        self.assertEqual(daemon._ledger.event_count("claim"), 1)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("checkpoint"), 1)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("complete"), 1)  # type: ignore[union-attr]

        before_duplicate = _snapshot(self.runtime)
        with self.assertRaises(ControlError):
            self._submit(daemon, bundle)
        self.assertEqual(_snapshot(self.runtime), before_duplicate)
        self.assertEqual(daemon._ledger.event_count("claim"), 1)  # type: ignore[union-attr]

        job_ref = bundle["job_spec"]["object_id"]
        before_lookup = _snapshot(self.runtime)
        lookup = self._request(
            daemon,
            OPERATOR_UID,
            "lookup",
            "lookup:full",
            {"job_spec_ref": job_ref},
        )
        self.assertEqual(_canonical(lookup.result), _canonical(submitted.result))
        self.assertEqual(_snapshot(self.runtime), before_lookup)

        daemon.close()
        reopened = self._daemon()
        reopened.start()
        reopened_before = _snapshot(self.runtime)
        recovered = self._request(
            reopened,
            OPERATOR_UID,
            "lookup",
            "lookup:full:reopen",
            {"job_spec_ref": job_ref},
        )
        self.assertEqual(_canonical(recovered.result), _canonical(submitted.result))
        self.assertEqual(_snapshot(self.runtime), reopened_before)
        self.assertEqual(reopened._ledger.event_count("claim"), 1)  # type: ignore[union-attr]

    def test_scout_and_collector_cannot_activate_issued_authority(self) -> None:
        daemon = self._daemon()
        daemon.start()
        bundle, admission = self._authority_bundle(daemon, suffix="role-denial")
        self.assertEqual(admission["authority_status"], "ISSUED")
        assert bundle is not None
        key = bundle["job_spec"]["payload"]["idempotency_key"]
        payload = {
            "job_spec": bundle["job_spec"],
            "permit": bundle["permit"],
            "lease": bundle["lease"],
        }
        for uid in (SCOUT_UID, COLLECTOR_UID):
            with self.subTest(uid=uid), self.assertRaises(ControlError):
                self._request(daemon, uid, "submit", key, payload)
        self._assert_no_execution(daemon)
        self.assertEqual(_snapshot(self.runtime / "staging-by-attempt-digest"), ())

    def test_protocol_mismatch_stops_before_staging_claim_or_budget_reservation(self) -> None:
        daemon = self._daemon()
        daemon.start()
        bundle, _ = self._authority_bundle(daemon, suffix="protocol")
        assert bundle is not None
        hostile = copy.deepcopy(bundle)
        hostile["job_spec"]["payload"]["protocol_ref"] = "protocol:wrong-l0"
        _reseal(hostile["job_spec"])
        before = _snapshot(self.runtime / "staging-by-attempt-digest")
        with self.assertRaises(ControlError):
            self._submit(daemon, hostile)
        self.assertEqual(_snapshot(self.runtime / "staging-by-attempt-digest"), before)
        self._assert_no_execution(daemon)

    def test_forged_mixed_and_expired_documents_never_reach_runner(self) -> None:
        cases = ("forged", "refenced", "mixed", "expired")
        for case in cases:
            with self.subTest(case=case):
                root = self.base / case
                root.mkdir(mode=0o700)
                self.current = NOW
                daemon = self._daemon(runtime=root)
                daemon.start()
                first, _ = self._authority_bundle(daemon, suffix=f"{case}-a")
                assert first is not None
                hostile = copy.deepcopy(first)
                if case == "forged":
                    hostile["permit"]["payload"]["network_class"] = "connected"
                elif case == "refenced":
                    hostile["lease"]["payload"]["fencing_token"] = "fence-hostile"
                    _reseal(hostile["lease"])
                elif case == "mixed":
                    second, _ = self._authority_bundle(daemon, suffix=f"{case}-b")
                    assert second is not None
                    hostile["permit"] = second["permit"]
                    hostile["lease"] = second["lease"]
                else:
                    self.current = NOW + timedelta(seconds=121)
                with self.assertRaises(ControlError):
                    self._submit(daemon, hostile)
                self._assert_no_execution(daemon)
                daemon.close()

    def test_spoof_private_live_canonical_holdout_and_budget_candidates_mint_no_authority(self) -> None:
        cases: list[tuple[str, dict[str, object], str | None]] = [
            ("private", {"private_api_requested": True}, None),
            ("live", {"live_execution_requested": True}, None),
            ("canonical", {"canonical_write_requested": True}, None),
            ("holdout", {"holdout_access_requested": True}, None),
            (
                "budget",
                {
                    "resource_request": {
                        "wall_seconds": 60,
                        "cpu_seconds": 60,
                        "memory_mib": 128,
                        "output_bytes": 100_000,
                        "tokens": 1_000,
                        "cost_units": 101,
                    }
                },
                None,
            ),
            (
                "spoof",
                {},
                "cas:sha256:" + hashlib.sha256(b"unregistered-spoof").hexdigest(),
            ),
        ]
        for label, overrides, candidate_ref in cases:
            with self.subTest(case=label):
                root = self.base / label
                root.mkdir(mode=0o700)
                daemon = self._daemon(runtime=root)
                daemon.start()
                bundle, admission = self._authority_bundle(
                    daemon,
                    suffix=label,
                    candidate_evidence_ref=candidate_ref,
                    model_overrides=overrides,
                )
                self.assertNotEqual(admission["decision"], "ADMIT")
                self.assertEqual(admission["authority_status"], "NOT_ISSUED")
                self.assertIsNone(bundle)
                self._assert_no_execution(daemon)
                daemon.close()

    def test_validator_failure_after_durable_completion_recovers_by_restart_lookup(self) -> None:
        daemon = self._daemon()
        daemon.start()
        bundle, _ = self._authority_bundle(daemon, suffix="validator-crash")
        assert bundle is not None
        with patch(
            "research_bridge.validation.DeterministicL0Validator.validate",
            side_effect=RuntimeError("synthetic validator crash"),
        ):
            with self.assertRaises(ControlError):
                self._submit(daemon, bundle)
        self.assertEqual(daemon._ledger.event_count("claim"), 1)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("checkpoint"), 1)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("complete"), 1)  # type: ignore[union-attr]

        daemon.close()
        reopened = self._daemon()
        reopened.start()
        job_ref = bundle["job_spec"]["object_id"]
        recovered = self._request(
            reopened,
            OPERATOR_UID,
            "lookup",
            "lookup:validator-crash",
            {"job_spec_ref": job_ref},
        )
        self.assertEqual(
            recovered.result["execution_receipt"]["payload"]["exit_classification"],
            "mechanical-success",
        )
        self.assertEqual(
            recovered.result["validation_receipt"]["payload"]["proposed_outcome"],
            "VALIDATED_MECHANICAL",
        )
        self.assertEqual(reopened._ledger.event_count("claim"), 1)  # type: ignore[union-attr]

    def test_corrupt_artifact_makes_independent_lookup_fail_without_new_attempt(self) -> None:
        daemon = self._daemon()
        daemon.start()
        bundle, _ = self._authority_bundle(daemon, suffix="artifact-corrupt")
        assert bundle is not None
        submitted = self._submit(daemon, bundle)
        artifact_ref = submitted.result["execution_receipt"]["payload"]["artifact_refs"][0]
        digest = artifact_ref.removeprefix("cas:sha256:")
        object_path = self.runtime / "artifact-cas" / "objects" / digest
        os.chmod(object_path, 0o600)
        object_path.write_bytes(b"corrupt")
        os.chmod(object_path, 0o444)
        counts = tuple(
            daemon._ledger.event_count(kind)  # type: ignore[union-attr]
            for kind in ("claim", "checkpoint", "complete")
        )
        with self.assertRaises(ControlError):
            self._request(
                daemon,
                OPERATOR_UID,
                "lookup",
                "lookup:artifact-corrupt",
                {"job_spec_ref": bundle["job_spec"]["object_id"]},
            )
        self.assertEqual(
            tuple(
                daemon._ledger.event_count(kind)  # type: ignore[union-attr]
                for kind in ("claim", "checkpoint", "complete")
            ),
            counts,
        )

    def test_second_writer_is_rejected_and_execution_remains_in_process_offline(self) -> None:
        daemon = self._daemon()
        daemon.start()
        contender = self._daemon()
        with self.assertRaises(ResearchdError):
            contender.start()

        bundle, _ = self._authority_bundle(daemon, suffix="offline")
        assert bundle is not None
        self.assertEqual(bundle["permit"]["payload"]["network_class"], "offline")
        self.assertEqual(bundle["job_spec"]["payload"]["network_policy"], "offline")
        for module_name in ("l0.py", "execution.py", "validation.py"):
            tree = ast.parse(
                (ROOT / "src" / "research_bridge" / module_name).read_text(
                    encoding="utf-8"
                )
            )
            imported = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names
            }
            self.assertTrue(
                imported.isdisjoint(
                    {"http", "requests", "socket", "subprocess", "urllib"}
                )
            )
            forbidden_calls = {
                f"{node.func.value.id}.{node.func.attr}"
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in {"execv", "execve", "fork", "popen", "spawnv", "system"}
            }
            self.assertEqual(forbidden_calls, set())
        submitted = self._submit(daemon, bundle)
        self.assertEqual(submitted.result["validation_receipt"]["payload"]["holdout_access_ref"], "holdout:none")
        self.assertEqual(
            {path.name for path in self.base.iterdir()},
            {"runtime", hashlib.sha256(b"r03c-input:offline").hexdigest() + ".synthetic"},
        )


if __name__ == "__main__":
    unittest.main()
