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
sys.path.insert(0, str(ROOT / "tools"))

from research_bridge.control import ControlError  # noqa: E402
from research_bridge.ipc import PeerCredentials, encode_message  # noqa: E402
from research_bridge.research_ingress import (  # noqa: E402
    ROLE_SEQUENCE,
    ResearchIngressError,
    canonical_sha256,
    mission_evidence_ref,
    validate_mission_artifact,
    validate_research_ingress_action_envelope,
    validate_research_mission_envelope,
)
from research_bridge.researchd import (  # noqa: E402
    ResearchDaemon,
    _service_config_from_mapping,
)
from physical_release_control import COLLECTOR_ID, source_trigger  # noqa: E402
from research_ingress_control import research_source_trigger  # noqa: E402


CONFIG_PATH = ROOT / "ops/release/researchd.config.template.json"
ROLE_PATH = ROOT / "contracts/a1/v1/profiles/model_role_registry_v1.json"
ROUTING_PATH = ROOT / "provenance/model-provider-routing-v2.json"
NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
NOW_TEXT = "2026-07-22T12:00:00Z"
COLLECTOR_UID = 10002
SCOUT_UID = 10003
WORKER_UID = 10004
PLAN_SHA = hashlib.sha256(b"recovery-plan-v3.1").hexdigest()
MISSION_SHA = hashlib.sha256(b"recovery-mission-v3.1").hexdigest()
HOST_SHA = hashlib.sha256(b"bounded-host").hexdigest()
BRIDGE_FINGERPRINT = hashlib.sha256(b"bridge-project").hexdigest()
MARKET_FINGERPRINT = hashlib.sha256(b"market-project").hexdigest()
SECURITY_FINGERPRINT = hashlib.sha256(b"security-project").hexdigest()
MARKET_BINDING_SHA = hashlib.sha256(b"market-binding").hexdigest()
SECURITY_BINDING_SHA = hashlib.sha256(b"security-binding").hexdigest()
BRIDGE_HEAD = "1" * 40
MARKET_HEAD = "2" * 40
SECURITY_HEAD = "3" * 40
ARTIFACT = b"# Bounded Recovery research\nOnly sanitized D1 claims and public refs."


def _document(schema: str, object_id: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema_id": schema,
        "schema_version": "1.0.0",
        "object_id": object_id,
        "issued_at": "2026-07-22T11:59:00Z",
        "payload": payload,
        "integrity": {"payload_sha256": canonical_sha256(payload)},
    }


def _mission() -> dict[str, object]:
    artifact_sha = hashlib.sha256(ARTIFACT).hexdigest()
    payload = {
        "mission_sha256": MISSION_SHA,
        "plan_sha256": PLAN_SHA,
        "artifact_ref": "cas:sha256:" + artifact_sha,
        "artifact_sha256": artifact_sha,
        "prepared_kimi_request_ref": "cas:sha256:" + artifact_sha,
        "prepared_kimi_request_sha256": artifact_sha,
        "artifact_size_bytes": len(ARTIFACT),
        "artifact_schema_id": "RecoveryPlanResearchPrompt/1.0.0",
        "data_class": "D1_INTERNAL_SANITIZED",
        "project_fingerprints": {
            "bridge": BRIDGE_FINGERPRINT,
            "market": MARKET_FINGERPRINT,
            "security": SECURITY_FINGERPRINT,
        },
        "runtime_heads": {
            "bridge": BRIDGE_HEAD,
            "market": MARKET_HEAD,
            "security": SECURITY_HEAD,
        },
        "domain_binding_sha256s": {
            "market": MARKET_BINDING_SHA,
            "security": SECURITY_BINDING_SHA,
        },
        "paired_execution_id": "paired-research-ingress:" + hashlib.sha256(
            b"paired-execution"
        ).hexdigest(),
        "expected_trigger_domains": ["market", "security"],
        "provider_boundary": {
            "roles": [item[0] for item in ROLE_SEQUENCE],
            "bindings": [item[1] for item in ROLE_SEQUENCE],
            "reasoning_efforts": [item[2] for item in ROLE_SEQUENCE],
            "maximum_calls": 5,
            "maximum_calls_per_role": 1,
            "fallback_allowed": False,
        },
        "expires_at": "2026-07-22T18:00:00Z",
        "stop_conditions": ["identity-drift", "provider-ambiguity"],
        "rollback": "Retain immutable receipts and stop future role reservations.",
        "forbidden_boundaries": ["domain-write", "live-action", "D2-D3"],
        "live_authority": False,
        "domain_write_authority": False,
        "canonical_write_authority": False,
    }
    return _document(
        "ResearchMissionEnvelope", "research-mission:" + MISSION_SHA, payload
    )


def _action(mission: dict[str, object] | None = None) -> dict[str, object]:
    mission_document = _mission() if mission is None else mission
    mission_payload = mission_document["payload"]
    action_id = "research-ingress-action:" + hashlib.sha256(b"action").hexdigest()
    payload = {
        "action_id": action_id,
        "mission_sha256": mission_payload["mission_sha256"],
        "plan_sha256": mission_payload["plan_sha256"],
        "mission_envelope_sha256": canonical_sha256(mission_document),
        "exact_host_fingerprint": HOST_SHA,
        "exact_service": "research-os-a1-ingress.service",
        "exact_uid": COLLECTOR_UID,
        "paired_execution_id": mission_payload["paired_execution_id"],
        "domain_binding_sha256s": copy.deepcopy(
            mission_payload["domain_binding_sha256s"]
        ),
        "expected_trigger_domains": ["market", "security"],
        "provider_calls_maximum": 5,
        "ingress_provider_calls": 0,
        "domain_writes": 0,
        "canonical_writes": 0,
        "live_authority": False,
        "expires_at": "2026-07-22T18:00:00Z",
        "stop_conditions": ["identity-drift", "provider-ambiguity"],
        "rollback": "Retain receipts and stop future role reservations.",
        "forbidden_boundaries": ["domain-write", "direct-provider-call"],
        "authority_source_hash": hashlib.sha256(b"owner-authority").hexdigest(),
    }
    return _document("ResearchIngressActionEnvelope", action_id, payload)


def _proof(domain: str) -> dict[str, object]:
    binding = MARKET_BINDING_SHA if domain == "market" else SECURITY_BINDING_SHA
    fingerprint = MARKET_FINGERPRINT if domain == "market" else SECURITY_FINGERPRINT
    head = MARKET_HEAD if domain == "market" else SECURITY_HEAD
    return {
        "domain": domain,
        "binding_sha256": binding,
        "content_sha256": hashlib.sha256((domain + "-payload").encode()).hexdigest(),
        "produced_at": "2026-07-22T11:59:30Z",
        "snapshot_identity": f"{domain}:snapshot:" + hashlib.sha256(domain.encode()).hexdigest(),
        "data_class": "D1_INTERNAL_SANITIZED",
        "producer_project_fingerprint": fingerprint,
        "producer_runtime_head": head,
    }


class ResearchIngressContractTests(unittest.TestCase):
    def test_schemas_wrappers_and_frozen_p04_trigger_are_additive(self) -> None:
        for name in (
            "ResearchMissionEnvelope.schema.json",
            "ResearchIngressActionEnvelope.schema.json",
        ):
            value = json.loads(
                (ROOT / "contracts/research/v1" / name).read_text(encoding="utf-8")
            )
            self.assertFalse(value["additionalProperties"])
        mission = _mission()
        action = _action(mission)
        validated = validate_research_mission_envelope(mission, now=NOW)
        validate_research_ingress_action_envelope(
            action, mission, expected_host_fingerprint=HOST_SHA, now=NOW
        )
        validate_mission_artifact(ARTIFACT, validated)

        legacy = source_trigger(_proof("market"))
        self.assertEqual(
            legacy["evidence_refs"],
            ["registered:domain-export-binding/" + MARKET_BINDING_SHA],
        )
        self.assertEqual(
            set(legacy),
            {
                "trigger_id",
                "collector_id",
                "source_ref",
                "source_content_sha256",
                "observed_at",
                "summary",
                "evidence_refs",
                "transport_idempotency_key",
            },
        )
        paired = [
            research_source_trigger(_proof(domain), validated)
            for domain in ("market", "security")
        ]
        self.assertEqual([item["collector_id"] for item in paired], [COLLECTOR_ID] * 2)
        self.assertEqual(
            [item["evidence_refs"][1] for item in paired],
            [mission_evidence_ref(MISSION_SHA)] * 2,
        )
        self.assertNotEqual(
            paired[0]["transport_idempotency_key"],
            paired[1]["transport_idempotency_key"],
        )

    def test_hostile_mission_action_and_artifact_cases_fail_closed(self) -> None:
        mission = _mission()
        mutations = []
        wrong_plan = copy.deepcopy(mission)
        wrong_plan["payload"]["plan_sha256"] = "0" * 64
        wrong_plan["integrity"]["payload_sha256"] = canonical_sha256(
            wrong_plan["payload"]
        )
        validate_research_mission_envelope(wrong_plan, now=NOW)
        with self.assertRaises(ResearchIngressError):
            validate_research_ingress_action_envelope(
                _action(mission),
                wrong_plan,
                expected_host_fingerprint=HOST_SHA,
                now=NOW,
            )
        stale = copy.deepcopy(mission)
        stale["payload"]["expires_at"] = "2026-07-22T11:59:30Z"
        stale["integrity"]["payload_sha256"] = canonical_sha256(stale["payload"])
        mutations.append(stale)
        swapped = copy.deepcopy(mission)
        swapped["payload"]["domain_binding_sha256s"]["security"] = MARKET_BINDING_SHA
        swapped["integrity"]["payload_sha256"] = canonical_sha256(swapped["payload"])
        mutations.append(swapped)
        extra = copy.deepcopy(mission)
        extra["payload"]["unexpected"] = True
        extra["integrity"]["payload_sha256"] = canonical_sha256(extra["payload"])
        mutations.append(extra)
        wrong_runtime = copy.deepcopy(mission)
        wrong_runtime["payload"]["runtime_heads"]["market"] = "not-a-git-sha"
        wrong_runtime["integrity"]["payload_sha256"] = canonical_sha256(
            wrong_runtime["payload"]
        )
        mutations.append(wrong_runtime)
        wrong_prepared_request = copy.deepcopy(mission)
        wrong_prepared_request["payload"]["prepared_kimi_request_sha256"] = (
            "e" * 64
        )
        wrong_prepared_request["integrity"]["payload_sha256"] = canonical_sha256(
            wrong_prepared_request["payload"]
        )
        mutations.append(wrong_prepared_request)
        for mutated in mutations:
            with self.assertRaises(ResearchIngressError):
                validate_research_mission_envelope(mutated, now=NOW)

        wrong_action = _action(mission)
        wrong_action["payload"]["exact_host_fingerprint"] = "f" * 64
        wrong_action["integrity"]["payload_sha256"] = canonical_sha256(
            wrong_action["payload"]
        )
        with self.assertRaises(ResearchIngressError):
            validate_research_ingress_action_envelope(
                wrong_action, mission, expected_host_fingerprint=HOST_SHA, now=NOW
            )

        validated = validate_research_mission_envelope(mission, now=NOW)
        for raw in (
            b"D2_DOMAIN_CONFIDENTIAL payload",
            b"-----BEGIN PRIVATE KEY-----\nsecret",
            ARTIFACT + b"tampered",
        ):
            with self.assertRaises(ResearchIngressError):
                validate_mission_artifact(raw, validated)


class ResearchMissionRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.runtime = Path(self.temporary.name) / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.peer_uid = COLLECTOR_UID
        self.daemons: list[ResearchDaemon] = []

    def tearDown(self) -> None:
        for daemon in reversed(self.daemons):
            daemon.close()
        self.temporary.cleanup()

    def _config(self) -> dict[str, object]:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        config["runtime_root"] = str(self.runtime)
        config["frozen_bindings"]["release_manifest_sha256"] = hashlib.sha256(
            b"mission-release"
        ).hexdigest()
        config["allowed_uids"].append(WORKER_UID)
        config["principal_roles"][str(WORKER_UID)] = "connected_worker"
        config["frozen_bindings"]["model_runtime"] = {
            "role_registry_sha256": hashlib.sha256(ROLE_PATH.read_bytes()).hexdigest(),
            "routing_profile_sha256": hashlib.sha256(ROUTING_PATH.read_bytes()).hexdigest(),
            "role_evaluation_sha256": "111a7ac1dc954466b19d5e408debeeefcf65c76b5b025a743a2433be910c1e75",
            "worker_ipc_extension_sha256": "467b2e5dd8583939d13e216a9f29e3578b0cc720a27081ca4f8723ad5726bac3",
            "binding_revision": "p04-research-ingress-v1",
            "budget_policy_ref": "budget-policy:sha256:" + "a" * 64,
            "budget_scope_ref": "budget-scope:sha256:" + "b" * 64,
            "max_active_calls": 1,
            "max_reserved_tokens": 20_000,
            "max_reserved_cost_units": 40,
            "available_bindings": [
                "deepseek-v4-flash",
                "deepseek-v4-pro",
                "kimi-k3-max",
                "gpt-5.6-sol-xhigh",
            ],
            "role_binding_overrides": {
                "CRITIC_PRIMARY": "kimi-k3-max",
                "CRITIC_DEEP": "gpt-5.6-sol-xhigh",
                "CHIEF_SCIENTIST": "gpt-5.6-sol-xhigh",
            },
        }
        return config

    def _daemon(self) -> ResearchDaemon:
        service = _service_config_from_mapping(self._config())
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
                uid=self.peer_uid, gid=20_000, pid=os.getpid()
            ),
        )
        daemon.start()
        self.daemons.append(daemon)
        return daemon

    def _request(
        self,
        daemon: ResearchDaemon,
        uid: int,
        command: str,
        key: str,
        payload: dict[str, object],
        *,
        version: str = "1.2",
    ):
        self.peer_uid = uid
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(daemon.socket_path))
        try:
            client.sendall(
                encode_message(
                    {
                        "version": version,
                        "request_id": "request:" + hashlib.sha256(key.encode()).hexdigest(),
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

    def _materialize_pair(self, daemon: ResearchDaemon) -> tuple[str, str]:
        mission_payload = validate_research_mission_envelope(_mission(), now=NOW)
        refs = []
        for domain in ("market", "security"):
            trigger = research_source_trigger(_proof(domain), mission_payload)
            response = self._request(
                daemon,
                COLLECTOR_UID,
                "submit_source_trigger",
                str(trigger["transport_idempotency_key"]),
                {"source_trigger": trigger},
            )
            refs.append(response.result["material_event"]["object_id"])
        return refs[0], refs[1]

    def _queue(self, daemon: ResearchDaemon, refs: tuple[str, str]):
        return self._request(
            daemon,
            COLLECTOR_UID,
            "queue_research_mission",
            "queue:" + MISSION_SHA,
            {
                "mission_envelope": _mission(),
                "action_envelope": _action(),
                "material_event_refs": list(refs),
                "artifact_body": ARTIFACT.decode(),
                "expected_host_fingerprint": HOST_SHA,
            },
            version="1.3",
        )

    def _advance(self, daemon: ResearchDaemon, suffix: str):
        return self._request(
            daemon,
            SCOUT_UID,
            "advance_research_missions",
            "advance:" + suffix,
            {},
            version="1.3",
        )

    def test_queue_requires_both_domains_and_replay_is_one_shot(self) -> None:
        daemon = self._daemon()
        refs = self._materialize_pair(daemon)
        before = daemon._ledger.event_count()
        with self.assertRaises(ControlError):
            self._queue(daemon, (refs[0], refs[0]))
        self.assertEqual(daemon._ledger.event_count(), before)

        queued = self._queue(daemon, refs)
        self.assertEqual(queued.result["status"], "QUEUED")
        self.assertEqual(queued.result["provider_calls_consumed"], 0)
        self.assertEqual(tuple(queued.result["expected_trigger_domains"]), ("market", "security"))
        replay = self._queue(daemon, refs)
        self.assertEqual(replay.result["status"], "ALREADY_QUEUED")

        swapped = (refs[1], refs[0])
        with self.assertRaises(ControlError):
            self._queue(daemon, swapped)

    def test_reserved_request_survives_daemon_crash_without_duplicate(self) -> None:
        daemon = self._daemon()
        refs = self._materialize_pair(daemon)
        self._queue(daemon, refs)
        reserved = self._advance(daemon, "first")
        self.assertEqual(reserved.result["status"], "RESERVED")
        call_id = reserved.result["call_id"]
        request_sha = reserved.result["request_ref"].removeprefix("cas:sha256:")
        daemon.close()

        reopened = self._daemon()
        listed = self._request(
            reopened,
            WORKER_UID,
            "list_reserved_model_calls",
            "list:after-crash",
            {"maximum": 1},
        )
        self.assertEqual(listed.result["count"], 1)
        item = listed.result["reserved_calls"][0]
        self.assertEqual(item["call_id"], call_id)
        self.assertEqual(hashlib.sha256(item["request_body"].encode()).hexdigest(), request_sha)
        self.assertEqual(item["completion_command"], "complete_research_model_call")
        replay = self._advance(reopened, "after-crash")
        self.assertEqual(replay.result["status"], "WAIT_CURRENT_CALL")
        self.assertEqual(replay.result["call_id"], call_id)

    def test_five_exact_roles_reconcile_and_preserve_full_lineage(self) -> None:
        daemon = self._daemon()
        refs = self._materialize_pair(daemon)
        queued = self._queue(daemon, refs)
        self.assertEqual(queued.result["source_trigger_count"], 2)

        observed = []
        for index, (role, binding, effort) in enumerate(ROLE_SEQUENCE):
            reserved = self._advance(daemon, f"reserve:{index}")
            self.assertEqual(reserved.result["status"], "RESERVED")
            self.assertEqual(reserved.result["role"], role)
            self.assertEqual(reserved.result["model_binding"], binding)
            self.assertEqual(reserved.result["reasoning_effort"], effort)
            self.assertFalse(reserved.result["used_fallback"])
            listed = self._request(
                daemon,
                WORKER_UID,
                "list_reserved_model_calls",
                f"list:{index}",
                {"maximum": 1},
            )
            item = listed.result["reserved_calls"][0]
            self.assertEqual(item["research_mission_sha256"], MISSION_SHA)
            self.assertEqual(item["research_role_index"], index)
            self.assertEqual(item["completion_command"], "complete_research_model_call")
            begun = self._request(
                daemon,
                WORKER_UID,
                "begin_model_call",
                f"begin:{index}",
                {
                    "call_id": item["call_id"],
                    "dispatch_token": item["dispatch_token"],
                    "request_body": item["request_body"],
                },
            )
            self.assertEqual(begun.result["state"], "SENT")
            output = f"{role} bounded result {index}; no authority claimed."
            output_ref = "cas:sha256:" + hashlib.sha256(output.encode()).hexdigest()
            completed = self._request(
                daemon,
                WORKER_UID,
                "complete_research_model_call",
                f"complete:{index}",
                {
                    "call_id": item["call_id"],
                    "dispatch_token": item["dispatch_token"],
                    "outcome": "SUCCEEDED",
                    "response_ref": output_ref,
                    "response_body": output,
                    "actual_tokens": 100 + index,
                    "actual_cost_units": 1,
                    "provider_receipt_ref": f"provider-receipt:mission/{index}",
                    "failure_code": None,
                },
                version="1.3",
            )
            self.assertEqual(completed.result["state"], "SUCCEEDED")
            observed.append(item["call_id"])

        terminal = self._advance(daemon, "terminal")
        self.assertEqual(terminal.result["status"], "MODEL_CHAIN_COMPLETE")
        self.assertEqual(tuple(terminal.result["call_ids"]), tuple(observed))
        status = self._request(
            daemon,
            SCOUT_UID,
            "research_mission_status",
            "status:terminal",
            {"mission_sha256": MISSION_SHA},
            version="1.3",
        )
        self.assertEqual(status.result["status"], "MODEL_CHAIN_COMPLETE")
        self.assertEqual(status.result["provider_calls_reserved"], 5)
        self.assertTrue(all(call["state"] == "RECONCILED" for call in status.result["calls"]))
        self.assertTrue(all(call["budget_released"] for call in status.result["calls"]))
        self.assertEqual(
            [call["model_binding"] for call in status.result["calls"]],
            [item[1] for item in ROLE_SEQUENCE],
        )
        self.assertEqual(tuple(status.result["material_event_refs"]), refs)
        self.assertEqual(status.result["domain_writes"], 0)
        self.assertEqual(status.result["canonical_writes"], 0)
        self.assertFalse(status.result["live_authority"])


if __name__ == "__main__":
    unittest.main()
