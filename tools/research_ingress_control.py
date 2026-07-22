#!/usr/bin/env python3
"""Mission-bound paired research ingress over the frozen P04 v1 adapter.

This additive one-shot tool imports the accepted P04 validators, AF_UNIX
transport and O_EXCL receipt primitives without modifying their hash-bound
implementation.  It creates exactly two frozen-shape SourceTriggers, then
queues one mission for the existing Scout/model-broker/dispatcher path.  The
ingress operation itself performs zero provider calls and no domain or
canonical writes.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

import physical_release_control as p04  # noqa: E402
from research_bridge.research_ingress import (  # noqa: E402
    ResearchIngressError,
    canonical_sha256 as research_canonical_sha256,
    mission_evidence_ref,
    validate_mission_artifact,
    validate_research_ingress_action_envelope,
    validate_research_mission_envelope,
)


FROZEN_P04_TOOL_SHA256 = (
    "5e44e460b25a0dd98d8ed49ac7a755884388b3706195b374494290b11bcfcac6"
)
_MAX_CONTROL_REQUEST_BYTES = 262_144


def research_source_trigger(
    proof: Mapping[str, object],
    mission_payload: Mapping[str, object],
) -> dict[str, object]:
    """Create one frozen-shape SourceTrigger with additive mission refs."""

    domain = p04._text(proof.get("domain"), "proof domain", maximum=16)
    if domain not in p04._DOMAINS:
        raise p04.PhysicalReleaseError("proof domain is unsupported")
    binding_sha = p04._sha(proof.get("binding_sha256"), "proof binding SHA")
    content_sha = p04._sha(proof.get("content_sha256"), "proof content SHA")
    observed_at = p04._text(proof.get("produced_at"), "proof produced_at", maximum=64)
    snapshot = p04._text(
        proof.get("snapshot_identity"), "proof snapshot identity", maximum=256
    )
    mission_sha = p04._sha(mission_payload.get("mission_sha256"), "mission SHA")
    paired = p04._text(
        mission_payload.get("paired_execution_id"),
        "paired execution identity",
        maximum=128,
    )
    key_digest = p04.digest_bytes(
        p04.canonical_bytes(
            {
                "binding_sha256": binding_sha,
                "domain": domain,
                "mission_sha256": mission_sha,
                "paired_execution_id": paired,
            }
        )
    )
    return {
        "trigger_id": f"source-trigger:research:{domain}:{key_digest[:32]}",
        "collector_id": p04.COLLECTOR_ID,
        "source_ref": (
            f"registered:domain-export/{domain}/{snapshot}/research-mission/{mission_sha}"
        ),
        "source_content_sha256": content_sha,
        "observed_at": observed_at,
        "summary": (
            f"mission-bound domain-owned immutable {domain} export available; "
            f"paired_execution={paired}"
        ),
        "evidence_refs": [
            f"registered:domain-export-binding/{binding_sha}",
            mission_evidence_ref(mission_sha),
        ],
        "transport_idempotency_key": f"research-ingress:{domain}:{key_digest}",
    }


def _round_trip(socket_path: str, request: Mapping[str, object]) -> dict[str, Any]:
    if not socket_path or "\x00" in socket_path:
        raise p04.PhysicalReleaseError("AF_UNIX socket path is invalid")
    outbound = p04.canonical_bytes(request) + b"\n"
    if len(outbound) > _MAX_CONTROL_REQUEST_BYTES:
        raise p04.PhysicalReleaseError("research control request exceeds transport bound")
    connection: socket.socket | None = None
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if connection.family != socket.AF_UNIX:
            raise p04.PhysicalReleaseError("local transport is not AF_UNIX")
        connection.settimeout(10.0)
        connection.connect(socket_path)
        connection.sendall(outbound)
        frame = bytearray()
        while True:
            remaining = p04._MAX_RESPONSE_BYTES + 1 - len(frame)
            if remaining <= 0:
                raise p04.PhysicalReleaseError("daemon response exceeds transport bound")
            block = connection.recv(min(16_384, remaining))
            if not block:
                break
            frame.extend(block)
    except (OSError, TimeoutError) as exc:
        raise p04.PhysicalReleaseError("local AF_UNIX research control failed") from exc
    finally:
        if connection is not None:
            connection.close()
    if (
        not frame
        or len(frame) > p04._MAX_RESPONSE_BYTES
        or not frame.endswith(b"\n")
        or b"\n" in frame[:-1]
    ):
        raise p04.PhysicalReleaseError("daemon response framing is invalid")
    try:
        response = json.loads(
            frame[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=p04._strict_object,
            parse_constant=p04._reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise p04.PhysicalReleaseError("daemon response is not strict JSON") from exc
    if (
        not isinstance(response, dict)
        or set(response) != {"version", "request_id", "ok", "command", "result"}
        or response.get("version") != request["version"]
        or response.get("request_id") != request["request_id"]
        or response.get("command") != request["command"]
        or response.get("ok") is not True
        or not isinstance(response.get("result"), dict)
    ):
        raise p04.PhysicalReleaseError("daemon did not return a bound success response")
    return response


def _mission_queue_request(
    *,
    mission_envelope: Mapping[str, object],
    action_envelope: Mapping[str, object],
    material_event_refs: Sequence[str],
    artifact_body: str,
    expected_host_fingerprint: str,
) -> dict[str, object]:
    mission_payload = mission_envelope.get("payload")
    if not isinstance(mission_payload, Mapping):
        raise p04.PhysicalReleaseError("mission envelope payload is invalid")
    mission_sha = p04._sha(mission_payload.get("mission_sha256"), "mission SHA")
    key = f"research-mission-queue:{mission_sha}"
    return {
        "version": "1.3",
        "request_id": "request:" + p04.digest_bytes(key.encode("utf-8"))[:32],
        "idempotency_key": key,
        "command": "queue_research_mission",
        "payload": {
            "mission_envelope": dict(mission_envelope),
            "action_envelope": dict(action_envelope),
            "material_event_refs": list(material_event_refs),
            "artifact_body": artifact_body,
            "expected_host_fingerprint": expected_host_fingerprint,
        },
    }


def run_research_ingress(arguments: argparse.Namespace) -> dict[str, object]:
    if os.geteuid() != p04.COLLECTOR_UID:
        raise p04.PhysicalReleaseError(
            "research ingress must run as collector UID 10002"
        )
    legacy_document = p04.read_json(
        arguments.envelope, "P04 v1 ingress action envelope"
    )
    legacy_payload = p04.validate_action_envelope(
        legacy_document,
        None,
        action="ingress",
        expected_host_fingerprint=arguments.expected_host_fingerprint,
    )
    mission_document = p04.read_json(
        arguments.mission_envelope, "research mission envelope"
    )
    action_document = p04.read_json(
        arguments.research_action_envelope,
        "research ingress action envelope",
    )
    try:
        mission = validate_research_mission_envelope(mission_document)
        action = validate_research_ingress_action_envelope(
            action_document,
            mission_document,
            expected_host_fingerprint=arguments.expected_host_fingerprint,
            expected_uid=p04.COLLECTOR_UID,
        )
    except ResearchIngressError as exc:
        raise p04.PhysicalReleaseError(
            "research ingress wrapper validation failed"
        ) from exc
    if mission["plan_sha256"] != p04._sha(
        arguments.expected_plan_sha256, "expected plan SHA"
    ):
        raise p04.PhysicalReleaseError("research ingress plan SHA is stale")
    if mission["mission_sha256"] != p04._sha(
        arguments.expected_mission_sha256, "expected mission SHA"
    ):
        raise p04.PhysicalReleaseError("research ingress mission SHA is stale")
    if mission["prepared_kimi_request_sha256"] != p04._sha(
        arguments.expected_prepared_kimi_request_sha256,
        "expected prepared Kimi request SHA",
    ):
        raise p04.PhysicalReleaseError(
            "research ingress prepared Kimi request SHA is stale"
        )
    runtime_heads = mission["runtime_heads"]
    project_fingerprints = mission["project_fingerprints"]
    if not isinstance(runtime_heads, Mapping) or not isinstance(
        project_fingerprints, Mapping
    ):
        raise p04.PhysicalReleaseError("mission current identity maps are invalid")
    if (
        runtime_heads.get("bridge")
        != p04._git_sha(arguments.expected_bridge_head, "expected Bridge head")
        or project_fingerprints.get("bridge")
        != p04._sha(
            arguments.expected_bridge_project_fingerprint,
            "expected Bridge project fingerprint",
        )
    ):
        raise p04.PhysicalReleaseError("mission Bridge current identity is stale")
    artifact_raw, _ = p04._read_bound(
        arguments.mission_artifact,
        "mission artifact",
        maximum=131_072,
    )
    try:
        validate_mission_artifact(artifact_raw, mission)
        artifact_body = artifact_raw.decode("utf-8", errors="strict")
    except (ResearchIngressError, UnicodeError) as exc:
        raise p04.PhysicalReleaseError("mission artifact validation failed") from exc

    registry = p04.read_json(arguments.registry, "producer registry")
    proofs: list[dict[str, Any]] = []
    for domain in p04._DOMAINS:
        proof = p04.validate_export(
            registry,
            p04.read_json(
                getattr(arguments, f"{domain}_binding"),
                f"{domain} export binding",
            ),
            getattr(arguments, f"{domain}_payload"),
            domain=domain,
        )
        if proof["binding_sha256"] != mission["domain_binding_sha256s"][domain]:
            raise p04.PhysicalReleaseError(
                "mission/domain binding SHA is stale or swapped"
            )
        if proof["producer_runtime_head"] != runtime_heads[domain]:
            raise p04.PhysicalReleaseError("mission domain runtime head is stale")
        if proof["producer_project_fingerprint"] != project_fingerprints[domain]:
            raise p04.PhysicalReleaseError(
                "mission domain project fingerprint is stale"
            )
        proofs.append(proof)

    descriptor = p04._reserve_receipt(arguments.receipt)
    try:
        triggers = [research_source_trigger(proof, mission) for proof in proofs]
        responses = [
            p04._round_trip(arguments.socket, p04._request(trigger))
            for trigger in triggers
        ]
        material_event_refs: list[str] = []
        for response in responses:
            result = response.get("result")
            material_event = (
                result.get("material_event") if isinstance(result, Mapping) else None
            )
            if not isinstance(material_event, Mapping) or not isinstance(
                material_event.get("object_id"), str
            ):
                raise p04.PhysicalReleaseError(
                    "research SourceTrigger did not materialize an event"
                )
            material_event_refs.append(str(material_event["object_id"]))
        if len(material_event_refs) != 2 or len(set(material_event_refs)) != 2:
            raise p04.PhysicalReleaseError(
                "paired research ingress did not create two unique events"
            )
        queue_response = _round_trip(
            arguments.socket,
            _mission_queue_request(
                mission_envelope=mission_document,
                action_envelope=action_document,
                material_event_refs=material_event_refs,
                artifact_body=artifact_body,
                expected_host_fingerprint=arguments.expected_host_fingerprint,
            ),
        )
        queue_result = queue_response["result"]
        if (
            queue_result.get("status") != "QUEUED"
            or queue_result.get("provider_calls_consumed") != 0
        ):
            raise p04.PhysicalReleaseError("research mission queue failed closed")
        receipt_payload = {
            "action": "research-ingress",
            "status": "PASS",
            "legacy_p04_action_envelope_sha256": p04.digest_bytes(
                p04.canonical_bytes(legacy_document)
            ),
            "legacy_p04_action_payload_sha256": p04.payload_sha(legacy_payload),
            "mission_envelope_sha256": research_canonical_sha256(mission_document),
            "research_action_envelope_sha256": research_canonical_sha256(
                action_document
            ),
            "mission_sha256": mission["mission_sha256"],
            "plan_sha256": mission["plan_sha256"],
            "paired_execution_id": mission["paired_execution_id"],
            "mission_artifact_ref": mission["artifact_ref"],
            "mission_artifact_sha256": mission["artifact_sha256"],
            "transport": "AF_UNIX",
            "ingress_principal": p04.COLLECTOR_ID,
            "source_trigger_count": 2,
            "source_trigger_domains": ["market", "security"],
            "source_trigger_ids": [trigger["trigger_id"] for trigger in triggers],
            "material_event_refs": material_event_refs,
            "shared_mission_evidence_ref": mission_evidence_ref(
                str(mission["mission_sha256"])
            ),
            "bindings": proofs,
            "response_digests": [p04.payload_sha(response) for response in responses],
            "queue_response_digest": p04.payload_sha(queue_response),
            "provider_calls": 0,
            "domain_writes": 0,
            "canonical_writes": 0,
            "public_listener_count": 0,
            "live_authority": False,
        }
        receipt = p04._receipt(
            "PhysicalResearchIngressReceipt",
            "physical-research-ingress:" + p04.payload_sha(receipt_payload)[:32],
            receipt_payload,
        )
        p04._finalize_receipt(descriptor, arguments.receipt, receipt)
        return receipt
    except Exception:
        failure_payload = {
            "action": "research-ingress",
            "status": "FAIL_CLOSED",
            "mission_sha256": mission["mission_sha256"],
            "plan_sha256": mission["plan_sha256"],
            "paired_execution_id": mission["paired_execution_id"],
            "provider_calls": 0,
            "domain_writes": 0,
            "canonical_writes": 0,
            "public_listener_count": 0,
            "live_authority": False,
        }
        p04._finalize_receipt(
            descriptor,
            arguments.receipt,
            p04._receipt(
                "PhysicalResearchIngressReceipt",
                "physical-research-ingress-failed:"
                + p04.payload_sha(failure_payload)[:32],
                failure_payload,
            ),
        )
        raise


def self_test() -> dict[str, object]:
    frozen = hashlib.sha256(
        (ROOT / "tools/physical_release_control.py").read_bytes()
    ).hexdigest()
    if frozen != FROZEN_P04_TOOL_SHA256:
        raise p04.PhysicalReleaseError("frozen P04 control executable drifted")
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden = ("AF_" + "INET", "listen" + "(", "urlopen" + "(", "requests" + ".")
    if any(token in source for token in forbidden):
        raise p04.PhysicalReleaseError("research ingress contains a public/network primitive")
    return {
        "status": "PASS",
        "frozen_p04_tool_sha256": frozen,
        "paired_source_trigger_count": 2,
        "expected_trigger_domains": ["market", "security"],
        "provider_calls": 0,
        "domain_writes": 0,
        "canonical_writes": 0,
        "public_listener_count": 0,
        "live_authority": False,
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise p04.PhysicalReleaseError("command arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="research-ingress-control")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("self-test")
    ingress = commands.add_parser("research-ingress-once")
    ingress.add_argument("--registry", type=Path, required=True)
    ingress.add_argument("--market-binding", type=Path, required=True)
    ingress.add_argument("--market-payload", type=Path, required=True)
    ingress.add_argument("--security-binding", type=Path, required=True)
    ingress.add_argument("--security-payload", type=Path, required=True)
    ingress.add_argument("--socket", required=True)
    ingress.add_argument("--envelope", type=Path, required=True)
    ingress.add_argument("--mission-envelope", type=Path, required=True)
    ingress.add_argument("--research-action-envelope", type=Path, required=True)
    ingress.add_argument("--mission-artifact", type=Path, required=True)
    ingress.add_argument("--expected-host-fingerprint", required=True)
    ingress.add_argument("--expected-bridge-head", required=True)
    ingress.add_argument("--expected-bridge-project-fingerprint", required=True)
    ingress.add_argument("--expected-plan-sha256", required=True)
    ingress.add_argument("--expected-mission-sha256", required=True)
    ingress.add_argument("--expected-prepared-kimi-request-sha256", required=True)
    ingress.add_argument("--receipt", type=Path, required=True)
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = (
            self_test()
            if arguments.command == "self-test"
            else run_research_ingress(arguments)
        )
        sys.stdout.write(p04.canonical_bytes(result).decode("utf-8") + "\n")
        return 0
    except p04.PhysicalReleaseError:
        sys.stderr.write("research ingress control failed closed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())


__all__ = [
    "FROZEN_P04_TOOL_SHA256",
    "research_source_trigger",
    "run_research_ingress",
    "self_test",
]
