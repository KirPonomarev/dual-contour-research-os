from __future__ import annotations

import concurrent.futures
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.admission import A1AdmissionKernel  # noqa: E402
from research_bridge.control import ControlError, ControlRequest, ControlRouter  # noqa: E402
from research_bridge.discovery import (  # noqa: E402
    DiscoveryError,
    DiscoveryFixtureConfig,
    DiscoveryFixtureService,
    ParserLimits,
    StrictProposalParser,
)
from research_bridge.ipc import (  # noqa: E402
    IPCError,
    PeerCredentials,
    UnixControlServer,
    decode_message,
    encode_message,
)
from tests.test_stage1_authority_policy import synthetic_authority  # noqa: E402


CONTRACT_ROOT = ROOT / "contracts"
A1_SHA = hashlib.sha256((CONTRACT_ROOT / "a1" / "v1" / "catalog.json").read_bytes()).hexdigest()
CORE_SHA = hashlib.sha256((CONTRACT_ROOT / "catalog.json").read_bytes()).hexdigest()
NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
NOW_TEXT = "2026-07-18T12:00:00Z"
HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40
POLICY_SHA = "3" * 64
CONTEXT_SHA = "4" * 64
RELEASE_SHA = "5" * 64


def _energy() -> dict[str, object]:
    return {
        "wall_seconds": 120,
        "cpu_seconds": 120,
        "memory_mib": 256,
        "output_bytes": 1_000_000,
        "tokens": 2_000,
        "cost_units": 10,
    }


def _kernel() -> A1AdmissionKernel:
    return A1AdmissionKernel(
        CONTRACT_ROOT,
        expected_a1_catalog_sha256=A1_SHA,
        expected_core_catalog_sha256=CORE_SHA,
    )


def _config(*, claim_ttl_seconds: int = 300, maximum_reason_feedback: int = 1) -> DiscoveryFixtureConfig:
    return DiscoveryFixtureConfig(
        policy_sha256=POLICY_SHA,
        context_sha256=CONTEXT_SHA,
        classification="D0",
        ledger_revision=7,
        root_energy=_energy(),
        remaining_energy=_energy(),
        allowed_source_prefixes=("https://public.example/research/",),
        collector_bindings={"collector:uid:2001": "collector-public-fixture"},
        repository_id="dual-contour-research-os",
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        release_manifest_sha256=RELEASE_SHA,
        claim_ttl_seconds=claim_ttl_seconds,
        maximum_reason_feedback=maximum_reason_feedback,
    )


def _service(**config_overrides: object) -> DiscoveryFixtureService:
    return DiscoveryFixtureService(_kernel(), _config(**config_overrides))


def _trigger(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "trigger_id": "trigger-public-001",
        "collector_id": "collector-public-fixture",
        "source_ref": "https://public.example/research/item-001",
        "source_content_sha256": "6" * 64,
        "observed_at": "2026-07-18T11:59:00Z",
        "summary": "Public synthetic research signal.",
        "evidence_refs": ["public-evidence:item-001"],
        "transport_idempotency_key": "transport-public-001",
    }
    value.update(overrides)
    return value


def _model_body(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "candidate_id": "candidate-public-001",
        "draft_revision": 1,
        "experiment_type": "synthetic-fixture-check",
        "estimand": "Difference between deterministic fixture output and zero.",
        "null_hypothesis": "The deterministic fixture produces no difference.",
        "falsifier": "Observed output is byte-identical to the null fixture.",
        "stop_condition": "Stop after one registered offline fixture execution.",
        "scope": "Public synthetic offline fixture only.",
        "expected_output": "One synthetic validation-shaped result.",
        "evidence_refs": ["public-evidence:item-001"],
        "evidence_independence_groups": [["public-evidence:item-001"]],
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


def _critique(*, accepted: bool = True, falsifier_present: bool = True, critique: str = "Bounded synthetic proposal is testable.") -> dict[str, object]:
    return {
        "accepted": accepted,
        "falsifier_present": falsifier_present,
        "critique": critique,
    }


def _materialize(service: DiscoveryFixtureService, *, key: str = "source-submit-001") -> dict[str, object]:
    return dict(
        service.submit_source_trigger(
            source_trigger=_trigger(),
            actor="collector:uid:2001",
            idempotency_key=key,
            now=NOW_TEXT,
        )
    )


def _claim(service: DiscoveryFixtureService, event_ref: str, *, actor: str = "scout:uid:3001", now: str = NOW_TEXT) -> dict[str, object]:
    return dict(
        service.claim_proposal(
            material_event_ref=event_ref,
            actor=actor,
            idempotency_key=f"claim-{actor}-{now}",
            now=now,
        )
    )


def _envelope(event_ref: str, token: str, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "material_event_ref": event_ref,
        "claim_token": token,
        "model_output": json.dumps(_model_body(), sort_keys=True),
        "critique_output": json.dumps(_critique(), sort_keys=True),
        "model_call_ref": "model-call:fixture-worker-001",
        "critique_call_ref": "model-call:fixture-critic-001",
    }
    value.update(overrides)
    return value


class _CoreBackend:
    def pause_snapshot(self) -> dict[str, object]:
        return {"paused": False}

    def pause_global(self, **kwargs: object) -> object:
        return object()

    def resume_global(self, **kwargs: object) -> object:
        return object()

    def submit(self, **kwargs: object) -> dict[str, object]:
        return {"accepted": True}

    def lookup(self, **kwargs: object) -> dict[str, object]:
        return {"found": False}


def _router(service: DiscoveryFixtureService) -> ControlRouter:
    return ControlRouter(
        _CoreBackend(),
        a1_backend=service,
        authority=synthetic_authority(),
        clock=lambda: NOW,
    )


class ScoutFixtureTests(unittest.TestCase):
    def test_source_principal_binding_and_idempotency(self) -> None:
        service = _service()
        first = _materialize(service)
        second = _materialize(service)
        self.assertEqual(first, second)
        self.assertEqual(first["decision"], "MATERIAL")
        event = first["material_event"]
        self.assertEqual(event["issuer"], "trusted-event-minter")
        self.assertEqual(event["contour"], "bridge")
        self.assertEqual(event["classification"], "D0")
        self.assertEqual(event["payload"]["policy_sha256"], POLICY_SHA)
        with self.assertRaises(DiscoveryError):
            service.submit_source_trigger(
                source_trigger=_trigger(collector_id="spoofed"),
                actor="collector:uid:2001",
                idempotency_key="wrong-binding",
                now=NOW_TEXT,
            )
        with self.assertRaises(DiscoveryError):
            service.submit_source_trigger(
                source_trigger=_trigger(source_ref="https://public.example/research/changed"),
                actor="collector:uid:2001",
                idempotency_key="source-submit-001",
                now=NOW_TEXT,
            )

    def test_two_scout_race_has_one_owner(self) -> None:
        service = _service()
        event_ref = _materialize(service)["material_event"]["object_id"]

        def claim(actor: str) -> tuple[str, object]:
            try:
                return actor, _claim(service, event_ref, actor=actor)
            except DiscoveryError as exc:
                return actor, exc

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, ("scout:uid:3001", "scout:uid:3002")))
        winners = [value for _, value in results if isinstance(value, dict)]
        losers = [value for _, value in results if isinstance(value, DiscoveryError)]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(len(losers), 1, results)

    def test_expired_claim_reclaim_and_stale_submit_ack_are_blocked(self) -> None:
        service = _service(claim_ttl_seconds=1)
        event_ref = _materialize(service)["material_event"]["object_id"]
        old = _claim(service, event_ref, actor="scout:uid:3001")
        new = _claim(service, event_ref, actor="scout:uid:3002", now="2026-07-18T12:00:02Z")
        self.assertEqual(new["generation"], 2)
        with self.assertRaises(DiscoveryError):
            service.submit_proposal(
                proposal_envelope=_envelope(event_ref, old["claim_token"]),
                actor="scout:uid:3001",
                idempotency_key="stale-submit",
                now="2026-07-18T12:00:02Z",
            )
        with self.assertRaises(DiscoveryError):
            service.ack_proposal(
                material_event_ref=event_ref,
                claim_token=old["claim_token"],
                actor="scout:uid:3001",
                idempotency_key="stale-ack",
                now="2026-07-18T12:00:02Z",
            )

    def test_candidate_projection_replaces_all_trusted_fields(self) -> None:
        service = _service()
        event = _materialize(service)["material_event"]
        claim = _claim(service, event["object_id"])
        response = dict(
            service.submit_proposal(
                proposal_envelope=_envelope(event["object_id"], claim["claim_token"]),
                actor="scout:uid:3001",
                idempotency_key="proposal-001",
                now=NOW_TEXT,
            )
        )
        self.assertEqual(response["decision"], "CANDIDATE_CREATED")
        self.assertNotIn("reason_code", response)
        candidate = response["candidate_spec_draft"]
        self.assertEqual(candidate["schema_id"], "CandidateSpecDraft")
        self.assertNotEqual(candidate["schema_id"], "AdmissionReceipt")
        self.assertEqual(candidate["issuer"], "proposal-ingestor")
        self.assertEqual(candidate["classification"], "D0")
        payload = candidate["payload"]
        self.assertEqual(payload["event_ref"], event["object_id"])
        self.assertEqual(payload["policy_sha256"], POLICY_SHA)
        self.assertEqual(payload["context_sha256"], CONTEXT_SHA)
        self.assertEqual(payload["vcs_identity"]["head_sha"], HEAD_SHA)
        self.assertEqual(payload["vcs_identity"]["contract_catalog_sha256"], CORE_SHA)
        self.assertNotIn("permit", candidate)
        self.assertNotIn("admission", candidate)

    def test_model_cannot_add_trusted_or_unknown_fields(self) -> None:
        service = _service()
        event = _materialize(service)["material_event"]
        claim = _claim(service, event["object_id"])
        body = _model_body(issuer="model", policy_sha256="0" * 64)
        with self.assertRaises(DiscoveryError):
            service.submit_proposal(
                proposal_envelope=_envelope(
                    event["object_id"],
                    claim["claim_token"],
                    model_output=json.dumps(body),
                ),
                actor="scout:uid:3001",
                idempotency_key="proposal-spoof",
                now=NOW_TEXT,
            )

    def test_duplicate_proposal_and_ack_are_idempotent(self) -> None:
        service = _service()
        event_ref = _materialize(service)["material_event"]["object_id"]
        claim = _claim(service, event_ref)
        envelope = _envelope(event_ref, claim["claim_token"])
        first = service.submit_proposal(
            proposal_envelope=envelope,
            actor="scout:uid:3001",
            idempotency_key="proposal-a",
            now=NOW_TEXT,
        )
        second = service.submit_proposal(
            proposal_envelope=envelope,
            actor="scout:uid:3001",
            idempotency_key="proposal-b",
            now=NOW_TEXT,
        )
        self.assertEqual(first, second)
        ack1 = service.ack_proposal(
            material_event_ref=event_ref,
            claim_token=claim["claim_token"],
            actor="scout:uid:3001",
            idempotency_key="ack-a",
            now=NOW_TEXT,
        )
        ack2 = service.ack_proposal(
            material_event_ref=event_ref,
            claim_token=claim["claim_token"],
            actor="scout:uid:3001",
            idempotency_key="ack-b",
            now=NOW_TEXT,
        )
        self.assertEqual(ack1, ack2)

    def test_critique_failure_exposes_only_bounded_coarse_reason(self) -> None:
        service = _service(maximum_reason_feedback=1)
        event_ref = _materialize(service)["material_event"]["object_id"]
        claim = _claim(service, event_ref)
        rejected = _envelope(
            event_ref,
            claim["claim_token"],
            critique_output=json.dumps(_critique(accepted=False, critique="operator-only diagnostic")),
        )
        first = dict(
            service.submit_proposal(
                proposal_envelope=rejected,
                actor="scout:uid:3001",
                idempotency_key="reject-a",
                now=NOW_TEXT,
            )
        )
        self.assertEqual(first, {
            "decision": "REJECTED",
            "reason_code": "MISSING_REQUIRED_FIELD",
            "candidate_spec_draft": None,
            "feedback_remaining": 0,
        })
        self.assertNotIn("operator-only", json.dumps(first))
        second = dict(
            service.submit_proposal(
                proposal_envelope=rejected,
                actor="scout:uid:3001",
                idempotency_key="reject-b",
                now=NOW_TEXT,
            )
        )
        self.assertEqual(second["decision"], "PARKED")
        self.assertEqual(second["reason_code"], "BUDGET_EXHAUSTED")
        self.assertEqual(second["feedback_remaining"], 0)


class StrictParserTests(unittest.TestCase):
    def test_duplicate_keys_oversize_depth_refs_and_nonfinite_fail_closed(self) -> None:
        parser = StrictProposalParser(ParserLimits(maximum_bytes=4096, maximum_depth=8, maximum_references=2))
        invalid = [
            '{"candidate_id":"a","candidate_id":"b"}',
            "{" + '"x":"' + ("a" * 5000) + '"}',
            json.dumps({"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": 1}}}}}}}}}),
            '{"x":NaN}',
        ]
        for raw in invalid:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(DiscoveryError):
                    parser.parse_model_body(raw)
        body = _model_body(
            evidence_refs=["a", "b", "c"],
            evidence_independence_groups=[["a"], ["b"], ["c"]],
        )
        with self.assertRaises(DiscoveryError):
            parser.parse_model_body(json.dumps(body))

    def test_parser_timeout_is_fail_closed(self) -> None:
        ticks = iter((0.0, 1.0))
        parser = StrictProposalParser(
            ParserLimits(maximum_parse_seconds=0.01),
            monotonic=lambda: next(ticks),
        )
        with self.assertRaises(DiscoveryError):
            parser.parse_model_body(json.dumps(_model_body()))


class IPCCompatibilityTests(unittest.TestCase):
    def test_missing_version_is_legacy_1_1_and_new_roles_require_1_2(self) -> None:
        legacy = ControlRequest.from_mapping(
            {
                "request_id": "legacy-status",
                "idempotency_key": "legacy-status-key",
                "command": "status",
                "payload": {},
            }
        )
        self.assertEqual(legacy.version, "1.1")
        router = _router(_service())
        self.assertEqual(router.dispatch(legacy, peer_uid=1000).version, "1.1")
        with self.assertRaises(ControlError):
            router.dispatch(legacy, peer_uid=2001, peer_role="collector")
        with self.assertRaises(ControlError):
            ControlRequest(
                version="1.1",
                request_id="legacy-scout",
                idempotency_key="legacy-scout-key",
                command="claim_proposal",
                payload={"material_event_ref": "event:x"},
            )

    def test_os_verified_role_matrix_blocks_cross_role_commands(self) -> None:
        router = _router(_service())
        status = ControlRequest("1.2", "status", "status-key", "status", {})
        source = ControlRequest(
            "1.2",
            "source",
            "source-key",
            "submit_source_trigger",
            {"source_trigger": _trigger()},
        )
        for request, role, uid in (
            (status, "collector", 2001),
            (status, "scout", 3001),
            (source, "operator", 1000),
            (source, "scout", 3001),
        ):
            with self.subTest(command=request.command, role=role):
                with self.assertRaises(ControlError):
                    router.dispatch(request, peer_uid=uid, peer_role=role)
        accepted = router.dispatch(source, peer_uid=2001, peer_role="collector")
        self.assertEqual(accepted.result["decision"], "MATERIAL")

    def test_request_cannot_supply_or_spoof_principal_role(self) -> None:
        raw = {
            "version": "1.2",
            "request_id": "spoof-role",
            "idempotency_key": "spoof-role-key",
            "command": "submit_source_trigger",
            "payload": {"source_trigger": _trigger()},
            "peer_role": "operator",
        }
        with self.assertRaises(ControlError):
            ControlRequest.from_mapping(raw)

    def test_unix_server_uses_credential_role_not_request_content(self) -> None:
        service = _service()
        router = _router(service)
        server = UnixControlServer(
            "/tmp/not-bound-s02.sock",
            router,
            allowed_uids={2001},
            principal_roles={2001: "collector"},
            credential_resolver=lambda _: PeerCredentials(uid=2001, gid=2001),
        )
        server_side, client_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server_side.close)
        self.addCleanup(client_side.close)
        request = {
            "version": "1.2",
            "request_id": "source-over-ipc",
            "idempotency_key": "source-over-ipc-key",
            "command": "submit_source_trigger",
            "payload": {"source_trigger": _trigger()},
        }
        client_side.sendall(encode_message(request))
        response = server.handle_connection(server_side)
        decoded = decode_message(client_side.recv(262_144), maximum_bytes=262_144)
        self.assertEqual(response.result["decision"], "MATERIAL")
        self.assertEqual(decoded["result"]["decision"], "MATERIAL")

    def test_large_ipc_payload_is_rejected_before_dispatch(self) -> None:
        with self.assertRaises(IPCError):
            encode_message({"payload": "x" * 70_000})

    def test_parser_details_are_coarsened_at_control_boundary(self) -> None:
        service = _service()
        event_ref = _materialize(service)["material_event"]["object_id"]
        claim = _claim(service, event_ref)
        request = ControlRequest(
            "1.2",
            "bad-proposal",
            "bad-proposal-key",
            "submit_proposal",
            {
                "proposal_envelope": _envelope(
                    event_ref,
                    claim["claim_token"],
                    model_output='{"candidate_id":"a","candidate_id":"b"}',
                )
            },
        )
        with self.assertRaisesRegex(ControlError, "control backend operation failed") as caught:
            _router(service).dispatch(request, peer_uid=3001, peer_role="scout")
        self.assertNotIn("duplicate", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
