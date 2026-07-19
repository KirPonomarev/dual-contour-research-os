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
NOW = datetime(2026, 7, 19, 6, 0, tzinfo=timezone.utc)
COLLECTOR_UID = 10002
SCOUT_UID = 10003
WORKER_UID = 10004
RELEASE_SHA256 = hashlib.sha256(b"r04b-assurance-release").hexdigest()
ROLE_REGISTRY_SHA256 = (
    "4faf6765f48a952e4d35540d92797330517938b34b8d2f12cde791e761a32eac"
)
ROUTING_PROFILE_SHA256 = (
    "37db8596a8245a6b1ea2bc5bce1495a4e7dadb314876e51397ad11dd194b3dc6"
)
ROLE_EVALUATION_SHA256 = (
    "111a7ac1dc954466b19d5e408debeeefcf65c76b5b025a743a2433be910c1e75"
)
WORKER_EXTENSION_SHA256 = (
    "03d91f027bb6975c55d84acaef188546bcd24af9944a72f4ff9314296399d07a"
)


def _model_body(evidence_ref: str) -> str:
    return json.dumps(
        {
            "candidate_id": "candidate:r04b-assurance",
            "draft_revision": 1,
            "experiment_type": "synthetic-fixture-check",
            "estimand": "Difference between one public fixture and its fixed null.",
            "null_hypothesis": "The public fixture produces no difference.",
            "falsifier": "The bounded result is byte-identical to the null fixture.",
            "stop_condition": "Stop after one offline deterministic fixture execution.",
            "scope": "Public sanitized offline fixture only.",
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
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _critique_body() -> str:
    return json.dumps(
        {
            "accepted": True,
            "falsifier_present": True,
            "critique": "The bounded public synthetic proposal is testable.",
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class BrokerScoutIPCHandshakeTests(unittest.TestCase):
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

    def _config(
        self,
        *,
        available: list[str] | None = None,
        max_active_calls: int = 4,
    ) -> dict[str, object]:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        config["runtime_root"] = str(self.runtime)
        config["frozen_bindings"]["release_manifest_sha256"] = RELEASE_SHA256
        if WORKER_UID not in config["allowed_uids"]:
            config["allowed_uids"].append(WORKER_UID)
        config["principal_roles"][str(WORKER_UID)] = "connected_worker"
        config["frozen_bindings"]["model_runtime"] = {
            "role_registry_sha256": ROLE_REGISTRY_SHA256,
            "routing_profile_sha256": ROUTING_PROFILE_SHA256,
            "role_evaluation_sha256": ROLE_EVALUATION_SHA256,
            "worker_ipc_extension_sha256": WORKER_EXTENSION_SHA256,
            "binding_revision": "r04b-assurance-v1",
            "budget_policy_ref": "budget-policy:sha256:"
            + hashlib.sha256(b"r04b-assurance-policy").hexdigest(),
            "budget_scope_ref": "budget-scope:sha256:"
            + hashlib.sha256(b"r04b-assurance-scope").hexdigest(),
            "max_active_calls": max_active_calls,
            "max_reserved_tokens": 20_000,
            "max_reserved_cost_units": 40,
            "available_bindings": list(
                ["deepseek-v4-pro", "glm-5.2-max"]
                if available is None
                else available
            ),
        }
        return config

    def _daemon(self, config: dict[str, object]) -> ResearchDaemon:
        service = _service_config_from_mapping(config)
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

    def _bootstrap_claim(self, daemon: ResearchDaemon, suffix: str = "one"):
        evidence_ref = f"public:evidence/r04b/{suffix}"
        source = self._request(
            daemon,
            COLLECTOR_UID,
            "submit_source_trigger",
            f"source:{suffix}",
            {
                "source_trigger": {
                    "trigger_id": f"trigger:{suffix}",
                    "collector_id": "collector:uid:10002",
                    "source_ref": f"public:r04b/{suffix}",
                    "source_content_sha256": hashlib.sha256(
                        suffix.encode()
                    ).hexdigest(),
                    "observed_at": "2026-07-19T05:59:00Z",
                    "summary": "Sanitized public synthetic handshake signal.",
                    "evidence_refs": [evidence_ref],
                    "transport_idempotency_key": f"source:{suffix}",
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
        return evidence_ref, event_ref, claim.result["claim_token"]

    @staticmethod
    def _reservation_payload(role: str, body: str) -> dict[str, object]:
        return {
            "role": role,
            "role_assignment_ref": f"role-assignment:r04b/{role.lower()}",
            "classification": "D0",
            "request_body": body,
            "max_tokens": 1_000,
            "max_cost_units": 5,
            "expires_at": "2026-07-19T07:00:00Z",
        }

    def _reserve(
        self,
        daemon: ResearchDaemon,
        role: str,
        body: str,
        suffix: str,
    ) -> dict[str, object]:
        return dict(
            self._request(
                daemon,
                SCOUT_UID,
                "reserve_model_call",
                f"reserve:{suffix}",
                self._reservation_payload(role, body),
            ).result
        )

    def _begin(
        self,
        daemon: ResearchDaemon,
        reservation: dict[str, object],
        body: str,
        suffix: str,
    ):
        return self._request(
            daemon,
            WORKER_UID,
            "begin_model_call",
            f"begin:{suffix}",
            {
                "call_id": reservation["call_id"],
                "dispatch_token": reservation["dispatch_token"],
                "request_body": body,
            },
        )

    def _complete(
        self,
        daemon: ResearchDaemon,
        reservation: dict[str, object],
        body: str,
        suffix: str,
    ):
        payload = {
            "call_id": reservation["call_id"],
            "dispatch_token": reservation["dispatch_token"],
            "outcome": "SUCCEEDED",
            "response_ref": "cas:sha256:"
            + hashlib.sha256(body.encode()).hexdigest(),
            "actual_tokens": 120,
            "actual_cost_units": 1,
            "provider_receipt_ref": f"provider-receipt:r04b/{suffix}",
            "failure_code": None,
        }
        return (
            self._request(
                daemon,
                WORKER_UID,
                "complete_model_call",
                f"complete:{suffix}",
                payload,
            ),
            payload,
        )

    def test_model_runtime_config_is_exact_optional_and_budget_bounded(self) -> None:
        service = _service_config_from_mapping(self._config(available=[]))
        self.assertEqual(
            service.principal_roles[WORKER_UID], "connected_worker"
        )
        self.assertEqual(
            service.frozen_bindings["model_runtime"][
                "worker_ipc_extension_sha256"
            ],
            WORKER_EXTENSION_SHA256,
        )

        stale = self._config()
        stale["frozen_bindings"]["model_runtime"][
            "worker_ipc_extension_sha256"
        ] = "f" * 64
        with self.assertRaises(_ServiceConfigError):
            _service_config_from_mapping(stale)

        excess = self._config()
        excess["frozen_bindings"]["model_runtime"]["max_reserved_tokens"] = (
            200_001
        )
        with self.assertRaises(_ServiceConfigError):
            _service_config_from_mapping(excess)

        missing_role = self._config()
        missing_role["allowed_uids"].remove(WORKER_UID)
        del missing_role["principal_roles"][str(WORKER_UID)]
        with self.assertRaises(_ServiceConfigError):
            _service_config_from_mapping(missing_role)

        extra_role = self._config()
        del extra_role["frozen_bindings"]["model_runtime"]
        with self.assertRaises(_ServiceConfigError):
            _service_config_from_mapping(extra_role)

    def test_unavailable_and_fallback_routes_stop_before_call_ledger_write(self) -> None:
        daemon = self._daemon(self._config(available=["deepseek-v4-flash"]))
        daemon.start()
        self._bootstrap_claim(daemon)
        before = daemon._ledger.event_count()

        unavailable = self._request(
            daemon,
            SCOUT_UID,
            "reserve_model_call",
            "reserve:chief-unavailable",
            self._reservation_payload("CHIEF_SCIENTIST", "bounded check"),
        )
        self.assertEqual(unavailable.result["status"], "WAIT_PROVIDER")
        self.assertEqual(daemon._ledger.event_count(), before)

        with self.assertRaises(ControlError):
            self._request(
                daemon,
                SCOUT_UID,
                "reserve_model_call",
                "reserve:fallback",
                self._reservation_payload("RESEARCH_WORKER", "fallback check"),
            )
        self.assertEqual(daemon._ledger.event_count(), before)

    def test_identity_request_and_dispatch_binding_precede_egress_ack(self) -> None:
        daemon = self._daemon(self._config())
        daemon.start()
        self._bootstrap_claim(daemon)
        body = "first line\nsecond line"
        reservation = self._reserve(
            daemon, "RESEARCH_WORKER", body, "identity"
        )
        self.assertEqual(reservation["state"], "RESERVED")

        with self.assertRaises(ControlError):
            self._request(
                daemon,
                SCOUT_UID,
                "begin_model_call",
                "begin:wrong-role",
                {
                    "call_id": reservation["call_id"],
                    "dispatch_token": reservation["dispatch_token"],
                    "request_body": body,
                },
            )
        with self.assertRaises(ControlError):
            self._request(
                daemon,
                WORKER_UID,
                "begin_model_call",
                "begin:changed-body",
                {
                    "call_id": reservation["call_id"],
                    "dispatch_token": reservation["dispatch_token"],
                    "request_body": body + " changed",
                },
            )
        with self.assertRaises(ControlError):
            self._request(
                daemon,
                WORKER_UID,
                "begin_model_call",
                "begin:changed-token",
                {
                    "call_id": reservation["call_id"],
                    "dispatch_token": "0" * 64,
                    "request_body": body,
                },
            )
        self.assertEqual(
            daemon._ledger.model_call_state(reservation["call_id"]).snapshot[
                "state"
            ],
            "RESERVED",
        )

        sent = self._begin(daemon, reservation, body, "identity")
        self.assertTrue(sent.result["egress_authorized"])
        self.assertEqual(sent.result["state"], "SENT")
        history = daemon._ledger.model_call_history(reservation["call_id"])
        self.assertEqual(
            [record.snapshot["state"] for record in history],
            ["PROPOSED", "RESERVED", "SENT"],
        )
        with self.assertRaises(ControlError):
            self._begin(daemon, reservation, body, "identity-replay")
        self.assertEqual(len(daemon._ledger.model_call_history(reservation["call_id"])), 3)

    def test_completion_replay_lookup_and_conflict_are_zero_write(self) -> None:
        daemon = self._daemon(self._config())
        daemon.start()
        self._bootstrap_claim(daemon)
        body = _model_body("public:evidence/r04b/completion")
        reservation = self._reserve(
            daemon, "RESEARCH_WORKER", body, "completion"
        )
        self._begin(daemon, reservation, body, "completion")
        completed, payload = self._complete(
            daemon, reservation, body, "completion"
        )
        self.assertEqual(completed.result["state"], "SUCCEEDED")
        self.assertNotIn("response_body", completed.result)
        after_complete = daemon._ledger.event_count()

        replay = self._request(
            daemon,
            WORKER_UID,
            "complete_model_call",
            "complete:replay",
            payload,
        )
        self.assertEqual(replay.result["state"], "SUCCEEDED")
        self.assertEqual(daemon._ledger.event_count(), after_complete)

        conflicting = dict(payload)
        conflicting["actual_tokens"] = 121
        with self.assertRaises(ControlError):
            self._request(
                daemon,
                WORKER_UID,
                "complete_model_call",
                "complete:conflict",
                conflicting,
            )
        self.assertEqual(daemon._ledger.event_count(), after_complete)

        lookup = self._request(
            daemon,
            SCOUT_UID,
            "lookup_model_call",
            "lookup:completion",
            {"call_id": reservation["call_id"]},
        )
        self.assertEqual(lookup.result["state"], "SUCCEEDED")
        self.assertEqual(daemon._ledger.event_count(), after_complete)

    def test_restart_recovers_sent_as_unknown_without_repeat_or_release(self) -> None:
        config = self._config()
        daemon = self._daemon(config)
        daemon.start()
        self._bootstrap_claim(daemon)
        body = "restart ambiguity assurance"
        reservation = self._reserve(daemon, "RESEARCH_WORKER", body, "restart")
        self._begin(daemon, reservation, body, "restart")
        before_close = daemon._ledger.event_count()
        daemon.close()

        reopened = self._daemon(config)
        reopened.start()
        self.assertEqual(reopened._ledger.event_count(), before_close + 1)
        recovered = self._request(
            reopened,
            SCOUT_UID,
            "lookup_model_call",
            "lookup:restart",
            {"call_id": reservation["call_id"]},
        )
        self.assertEqual(recovered.result["state"], "UNKNOWN")
        self.assertTrue(recovered.result["ambiguous_usage"])
        self.assertFalse(recovered.result["budget_released"])
        self.assertFalse(recovered.result["auto_retry"])
        with self.assertRaises(ControlError):
            self._begin(reopened, reservation, body, "restart-replay")

        count = reopened._ledger.event_count()
        reopened.close()
        second = self._daemon(config)
        second.start()
        self.assertEqual(second._ledger.event_count(), count)

    def test_budget_exhaustion_retains_existing_reservation_and_parks_proposed(self) -> None:
        daemon = self._daemon(self._config(max_active_calls=1))
        daemon.start()
        self._bootstrap_claim(daemon)
        first = self._reserve(
            daemon, "RESEARCH_WORKER", "first bounded call", "budget-first"
        )
        before = daemon._ledger.event_count()
        with self.assertRaises(ControlError):
            self._reserve(
                daemon, "CRITIC_PRIMARY", "second bounded call", "budget-second"
            )
        self.assertEqual(daemon._ledger.event_count(), before + 1)
        states = daemon._ledger._model_call_states()
        self.assertEqual(
            sorted(record.snapshot["state"] for record in states),
            ["PROPOSED", "RESERVED"],
        )
        self.assertEqual(
            daemon._ledger.model_call_state(first["call_id"]).snapshot["state"],
            "RESERVED",
        )

    def test_proposal_requires_successful_distinct_role_correct_exact_outputs(self) -> None:
        daemon = self._daemon(self._config())
        daemon.start()
        evidence_ref, event_ref, claim_token = self._bootstrap_claim(
            daemon, "proposal"
        )
        model_output = _model_body(evidence_ref)
        critique_output = _critique_body()
        model = self._reserve(
            daemon, "RESEARCH_WORKER", model_output, "proposal-model"
        )
        critique = self._reserve(
            daemon, "CRITIC_PRIMARY", critique_output, "proposal-critique"
        )
        for reservation, body, suffix in (
            (model, model_output, "proposal-model"),
            (critique, critique_output, "proposal-critique"),
        ):
            self._begin(daemon, reservation, body, suffix)
            self._complete(daemon, reservation, body, suffix)

        envelope = {
            "material_event_ref": event_ref,
            "claim_token": claim_token,
            "model_output": model_output,
            "critique_output": critique_output,
            "model_call_ref": model["call_id"],
            "critique_call_ref": critique["call_id"],
        }
        before = daemon._ledger.event_count()
        with self.assertRaises(ControlError):
            self._request(
                daemon,
                WORKER_UID,
                "submit_proposal",
                "proposal:worker-role",
                {"proposal_envelope": envelope},
            )
        self.assertEqual(daemon._ledger.event_count(), before)

        for label, mutate in (
            (
                "same-reference",
                lambda value: value.update(
                    critique_call_ref=value["model_call_ref"]
                ),
            ),
            (
                "mixed-role",
                lambda value: value.update(
                    model_call_ref=value["critique_call_ref"],
                    critique_call_ref=value["model_call_ref"],
                ),
            ),
            (
                "changed-output",
                lambda value: value.update(model_output=value["model_output"] + " "),
            ),
            (
                "missing-call",
                lambda value: value.update(
                    model_call_ref="model-call:" + "0" * 64
                ),
            ),
        ):
            changed = copy.deepcopy(envelope)
            mutate(changed)
            with self.subTest(label=label), self.assertRaises(ControlError):
                self._request(
                    daemon,
                    SCOUT_UID,
                    "submit_proposal",
                    f"proposal:{label}",
                    {"proposal_envelope": changed},
                )
            self.assertEqual(daemon._ledger.event_count(), before)

        accepted = self._request(
            daemon,
            SCOUT_UID,
            "submit_proposal",
            "proposal:accepted",
            {"proposal_envelope": envelope},
        )
        self.assertIn(
            accepted.result["decision"],
            {"CANDIDATE_CREATED", "WAIT_RUNNER"},
        )
        self._request(
            daemon,
            SCOUT_UID,
            "ack_proposal",
            "proposal:ack",
            {
                "material_event_ref": event_ref,
                "claim_token": claim_token,
            },
        )
        self.assertTrue(daemon._ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
