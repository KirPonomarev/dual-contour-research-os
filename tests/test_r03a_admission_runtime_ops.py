from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.control import ControlError  # noqa: E402
from research_bridge.ipc import PeerCredentials, encode_message  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    ResearchDaemon,
    ResearchdError,
    _ServiceConfigError,
    _service_config_from_mapping,
)


CONFIG_PATH = ROOT / "ops/release/researchd.config.template.json"
ROUTE_SHA256 = "37db8596a8245a6b1ea2bc5bce1495a4e7dadb314876e51397ad11dd194b3dc6"
ROUTE_REF = (
    "provenance/model-provider-routing-v1.json#sha256:" + ROUTE_SHA256
)
RELEASE_SHA256 = hashlib.sha256(b"r03a-r2-release").hexdigest()
NOW = datetime(2026, 7, 19, 6, 0, tzinfo=timezone.utc)
COLLECTOR_UID = 10002
SCOUT_UID = 10003


def _plain(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _config(runtime: Path) -> dict[str, object]:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config["runtime_root"] = str(runtime)
    config["frozen_bindings"]["release_manifest_sha256"] = RELEASE_SHA256
    return config


def _model_body(evidence_ref: str) -> dict[str, object]:
    return {
        "candidate_id": "candidate:r03a-r2",
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


class AdmissionRuntimeOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.runtime = self.base / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.peer_uid = COLLECTOR_UID
        self.daemons: list[ResearchDaemon] = []

    def tearDown(self) -> None:
        for daemon in reversed(self.daemons):
            daemon.close()
        self.temporary.cleanup()

    def _daemon(self, config: dict[str, object] | None = None) -> ResearchDaemon:
        service = _service_config_from_mapping(config or _config(self.runtime))
        daemon = ResearchDaemon(
            self.runtime,
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
            clock=lambda: NOW,
            credential_resolver=lambda _: PeerCredentials(
                uid=self.peer_uid, gid=20000, pid=os.getpid()
            ),
        )
        self.daemons.append(daemon)
        return daemon

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
        source = self.base / (hashlib.sha256(payload).hexdigest() + ".fixture")
        source.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        record = daemon._input_store.publish(  # type: ignore[union-attr]
            source,
            expected_sha256=digest,
            expected_size_bytes=len(payload),
        )
        return record.ref

    def _submit_candidate(
        self,
        daemon: ResearchDaemon,
        *,
        evidence_ref: str,
        candidate_evidence_ref: str | None = None,
        suffix: str = "one",
    ):
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
                    "source_ref": f"registered:r03a-r2/{suffix}",
                    "source_content_sha256": evidence_ref.removeprefix("cas:sha256:"),
                    "observed_at": "2026-07-19T05:59:00Z",
                    "summary": "Sanitized registered synthetic admission signal.",
                    "evidence_refs": [evidence_ref],
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
        selected_ref = candidate_evidence_ref or evidence_ref
        envelope = {
            "material_event_ref": event_ref,
            "claim_token": claim.result["claim_token"],
            "model_output": json.dumps(
                _model_body(selected_ref), sort_keys=True, separators=(",", ":")
            ),
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
        return response, envelope

    def test_shipped_binding_and_corridor_issuer_roles_are_exact_and_start(self) -> None:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        route_path, route_digest = ROUTE_REF.split("#sha256:", 1)
        self.assertEqual(
            hashlib.sha256((ROOT / route_path).read_bytes()).hexdigest(),
            route_digest,
        )
        self.assertEqual(
            raw["trusted_issuers"]["JobSpec"]["authority_class"],
            "admission-controller",
        )
        self.assertEqual(
            raw["trusted_issuers"]["Permit"]["authority_class"],
            "permit-authority",
        )
        self.assertEqual(
            raw["trusted_issuers"]["AttemptLease"]["authority_class"],
            "researchd",
        )
        runtime = raw["frozen_bindings"]["admission_runtime"]
        self.assertEqual(runtime["model_route_proof_ref"], ROUTE_REF)
        self.assertIsNone(runtime["corridor_executor_profile"])
        daemon = self._daemon()
        daemon.start()
        self.assertEqual(type(daemon._a1_backend).__name__, "DurableDiscoveryService")

    def test_real_af_unix_registered_cas_admits_then_waits_for_exact_profile(self) -> None:
        daemon = self._daemon()
        daemon.start()
        evidence_ref = self._publish_input(daemon, b"registered-r03a-r2-input")
        first, envelope = self._submit_candidate(daemon, evidence_ref=evidence_ref)
        admission = first.result["admission"]
        self.assertEqual(admission["decision"], "ADMIT")
        self.assertEqual(admission["authority_status"], "WAIT_AUTHORITY")
        self.assertEqual(admission["authority_reason"], "CORRIDOR_PROFILE_UNAVAILABLE")
        self.assertIsNone(admission["authority_bundle"])
        self.assertIsNone(admission.get("job_spec"))
        self.assertIsNone(admission.get("permit"))
        self.assertIsNone(admission.get("lease"))
        after = daemon._ledger.event_count()  # type: ignore[union-attr]

        replay = self._request(
            daemon,
            SCOUT_UID,
            "submit_proposal",
            "proposal:one",
            {"proposal_envelope": envelope},
        )
        self.assertEqual(_plain(replay.result), _plain(first.result))
        self.assertEqual(daemon._ledger.event_count(), after)  # type: ignore[union-attr]

        daemon.close()
        reopened = self._daemon()
        reopened.start()
        reopened_replay = self._request(
            reopened,
            SCOUT_UID,
            "submit_proposal",
            "proposal:one",
            {"proposal_envelope": envelope},
        )
        self.assertEqual(_plain(reopened_replay.result), _plain(first.result))
        self.assertEqual(reopened._ledger.event_count(), after)  # type: ignore[union-attr]

    def test_evidence_spoof_is_rejected_and_mints_no_authority(self) -> None:
        daemon = self._daemon()
        daemon.start()
        trusted_ref = self._publish_input(daemon, b"trusted-input")
        spoofed_ref = "cas:sha256:" + hashlib.sha256(b"unregistered-input").hexdigest()
        response, _ = self._submit_candidate(
            daemon,
            evidence_ref=trusted_ref,
            candidate_evidence_ref=spoofed_ref,
            suffix="spoof",
        )
        admission = response.result["admission"]
        self.assertEqual(admission["decision"], "REJECT")
        self.assertEqual(admission["authority_status"], "NOT_ISSUED")
        self.assertEqual(admission["authority_reason"], "ADMISSION_NOT_ADMITTED")
        self.assertIsNone(admission["authority_bundle"])

    def test_invalid_runtime_and_profile_shapes_fail_config_closed(self) -> None:
        mutations = []
        missing = _config(self.runtime)
        missing["frozen_bindings"]["admission_runtime"] = {}
        mutations.append(missing)
        empty_route = _config(self.runtime)
        empty_route["frozen_bindings"]["admission_runtime"]["model_route_proof_ref"] = ""
        mutations.append(empty_route)
        extra = _config(self.runtime)
        extra["frozen_bindings"]["admission_runtime"]["unexpected"] = True
        mutations.append(extra)
        empty_profile = _config(self.runtime)
        empty_profile["frozen_bindings"]["admission_runtime"]["corridor_executor_profile"] = {}
        mutations.append(empty_profile)
        unfrozen_capability = _config(self.runtime)
        unfrozen_capability["frozen_bindings"]["admission_runtime"]["corridor_executor_profile"] = {
            "capability_ref": "capability:unfrozen",
            "protocol_ref": "protocol:synthetic-hostile",
            "code_sha256": "1" * 64,
            "image_digest": "sha256:" + "2" * 64,
            "runner_identity": "pre-soak-offline-l0",
            "maximum_lifetime_seconds": 120,
        }
        mutations.append(unfrozen_capability)
        for config in mutations:
            with self.subTest(case=len(mutations)):
                with self.assertRaises(_ServiceConfigError):
                    _service_config_from_mapping(config)

    def test_route_tamper_and_obsolete_corridor_roles_remain_fail_closed(self) -> None:
        daemon = self._daemon()
        daemon.start()
        evidence_ref = self._publish_input(daemon, b"route-drift-input")
        self._submit_candidate(daemon, evidence_ref=evidence_ref, suffix="route")
        daemon.close()

        drifted = _config(self.runtime)
        drifted["frozen_bindings"]["admission_runtime"]["model_route_proof_ref"] = (
            "provenance/model-provider-routing-v1.json#sha256:" + "f" * 64
        )
        with self.assertRaises(ResearchdError):
            self._daemon(drifted).start()

        obsolete_root = self.base / "obsolete"
        obsolete_root.mkdir(mode=0o700)
        self.runtime = obsolete_root
        obsolete = _config(obsolete_root)
        obsolete["trusted_issuers"]["JobSpec"]["authority_class"] = "job-authority"
        obsolete["trusted_issuers"]["AttemptLease"]["authority_class"] = "lease-authority"
        obsolete["frozen_bindings"]["admission_runtime"]["corridor_executor_profile"] = {
            "capability_ref": obsolete["frozen_bindings"]["executor_capability_refs"][0],
            "protocol_ref": "protocol:synthetic-hostile-only",
            "code_sha256": "1" * 64,
            "image_digest": "sha256:" + "2" * 64,
            "runner_identity": "pre-soak-offline-l0",
            "maximum_lifetime_seconds": 120,
        }
        obsolete_daemon = self._daemon(obsolete)
        obsolete_daemon.start()
        obsolete_ref = self._publish_input(obsolete_daemon, b"obsolete-role-input")
        response, _ = self._submit_candidate(
            obsolete_daemon, evidence_ref=obsolete_ref, suffix="obsolete"
        )
        admission = response.result["admission"]
        self.assertEqual(admission["decision"], "ADMIT")
        self.assertEqual(admission["authority_status"], "WAIT_AUTHORITY")
        self.assertEqual(admission["authority_reason"], "CORRIDOR_AUTHORITY_UNAVAILABLE")
        self.assertIsNone(admission["authority_bundle"])

    def test_ai_off_legacy_starts_without_admission_backend(self) -> None:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        config = {
            key: value
            for key, value in config.items()
            if key not in {"a1_enabled", "principal_roles", "frozen_bindings", "a1_limits"}
        }
        config["schema_version"] = "1.0.0"
        config["runtime_root"] = str(self.runtime)
        config["allowed_uids"] = [os.geteuid()]
        service = _service_config_from_mapping(config)
        daemon = ResearchDaemon(
            self.runtime,
            authority=service.authority,
            allowed_uids=service.allowed_uids,
            principal_roles=service.principal_roles,
            a1_enabled=False,
            runner_identity=service.runner_identity,
        )
        self.daemons.append(daemon)
        daemon.start()
        self.assertIsNone(daemon._a1_backend)
        with self.assertRaises(ControlError):
            self._request(
                daemon,
                os.geteuid(),
                "claim_next_proposal",
                "legacy-deny",
                {},
            )


if __name__ == "__main__":
    unittest.main()
