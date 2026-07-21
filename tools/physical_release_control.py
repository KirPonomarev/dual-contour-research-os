#!/usr/bin/env python3
"""Fail-closed control plane for the V2.5.2 physical release.

This executable is deliberately transport-only.  It verifies immutable,
domain-owned D0/D1 export bindings, emits ref-only SourceTrigger objects over
the existing local AF_UNIX protocol, and binds deployment to the already
qualified R17 image.  It never parses domain payloads, opens a network
listener, writes a domain store, or rebuilds the runtime image.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

RUNTIME_RELEASE_SHA = "0394d6c9e327eceb62f738eca90be3ece015ba79"
RUNTIME_TREE_SHA = "636fda24cbb2da567fb23a4d44fa865ae74ac4bc"
IMAGE_ID = "sha256:e6db8ab087e18b13ac357a751a2e7318c3abb81a4f2af459c930a630ddc65577"
ENGINE_IMAGE_ID = "sha256:d1f56e933a8e498ae9e3a1f70ba0e764785a0de44d6f702f7e1945c3621b671f"
CARRIER_SHA256 = "46e12e35ef89463a9f13028732e35c30ce3aaa7b121834f68a9aeccbf727d9f7"
CARRIER_BYTES = 47_947_776
CARRIER_BINDING_SHA256 = "5ec076442c86d31d1bbec0c0dba029b16588bdd52bfede4e2805ccca8b71e596"
UNIT_SHA256 = "2a070da4ceb6c9ca4e3a54036181c0383d34ca142bea50a4b600010ee2a34eb9"
POLICY_SHA256 = "665bfb70a82d3aa5988d45fa299fb14d2b28926e6267a15ae440e3c03fbb0cd9"
CONFIG_SHA256 = "c97a5b03942edf5746a1362a418b3d7ecad9d5e45620d80305475cefebf7591f"
R17_PACKET_SHA256 = "52ab1772d0c9e3a1b8951d768f039f87b90e3a483d742db7ca0d32f743085b2d"
COLLECTOR_UID = 10002
COLLECTOR_ID = "collector:uid:10002"
MISSION_ID = "DCR_OS_PHYSICAL_RELEASE_20260721"
PROJECT_FINGERPRINTS = frozenset({
    "b371429cb7c01fd6c5dbd430510a264684dab906188d706b7479446c1bd8f154",
    "c0163d56601ed440f972a81818c4ac93aab2241816f92b340f2ca53d5a25ef91",
    "5cc00261c78745d05abfb0aebce5e1f86fbefc2960a9c4284662b1284b0fc08f",
})
SERVICE_NAME = "research-os-a1-bridge.service"
INGRESS_SERVICE_NAME = "research-os-a1-ingress.service"
CONTAINER_NAME = "research-os-a1-bridge"
RUNTIME_VOLUME = "research-os-a1-runtime"
CONFIG_VOLUME = "research-os-a1-config"
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_EXPORT_BYTES = 64 * 1024 * 1024
_MAX_RESPONSE_BYTES = 262_144
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_GIT_SHA = re.compile(r"[a-f0-9]{40}\Z")
_SCHEMA_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DOMAINS = ("market", "security")
_PROJECTS = {
    "market": "crypto-market-lab",
    "security": "security-researcher",
}
_DATA_CLASSES = {"D0_PUBLIC", "D1_INTERNAL_SANITIZED", "PUBLIC_SANITIZED"}
_ACTION_TRANSITIONS = {
    "deploy": ("release:none-service-stopped", RUNTIME_RELEASE_SHA),
    "ingress": (RUNTIME_RELEASE_SHA, RUNTIME_RELEASE_SHA),
    "restart": (RUNTIME_RELEASE_SHA, RUNTIME_RELEASE_SHA),
    "reboot": (RUNTIME_RELEASE_SHA, RUNTIME_RELEASE_SHA),
    "rollback_readiness": (RUNTIME_RELEASE_SHA, RUNTIME_RELEASE_SHA),
}


class PhysicalReleaseError(RuntimeError):
    """A physical-release invariant failed closed."""


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PhysicalReleaseError("value is not canonical JSON") from exc


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def payload_sha(value: object) -> str:
    return digest_bytes(canonical_bytes(value))


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PhysicalReleaseError("JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(_: str) -> object:
    raise PhysicalReleaseError("JSON contains a non-finite number")


def _read_bound(path: Path, label: str, *, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise PhysicalReleaseError(f"{label} must be a regular non-symlink file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise PhysicalReleaseError(f"{label} size is invalid")
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise PhysicalReleaseError(f"{label} identity changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > maximum:
                raise PhysicalReleaseError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
        current = os.lstat(path)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise PhysicalReleaseError(f"{label} changed while read")
        if identity != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns):
            raise PhysicalReleaseError(f"{label} path changed while read")
        raw = b"".join(chunks)
        if len(raw) != opened.st_size:
            raise PhysicalReleaseError(f"{label} short read")
        return raw, opened
    except OSError as exc:
        raise PhysicalReleaseError(f"{label} is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_json(path: Path, label: str) -> dict[str, Any]:
    raw, _ = _read_bound(path, label, maximum=_MAX_JSON_BYTES)
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PhysicalReleaseError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise PhysicalReleaseError(f"{label} must be a JSON object")
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise PhysicalReleaseError(f"{label} keys are invalid")
    return dict(value)


def _text(value: object, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum
    ):
        raise PhysicalReleaseError(f"{label} is invalid")
    return value


def _sha(value: object, label: str) -> str:
    text = _text(value, label, maximum=64)
    if _SHA256.fullmatch(text) is None:
        raise PhysicalReleaseError(f"{label} is not a SHA-256")
    return text


def _git_sha(value: object, label: str) -> str:
    text = _text(value, label, maximum=40)
    if _GIT_SHA.fullmatch(text) is None:
        raise PhysicalReleaseError(f"{label} is not a Git SHA")
    return text


def _timestamp(value: object, label: str) -> datetime:
    text = _text(value, label, maximum=64)
    if not text.endswith("Z"):
        raise PhysicalReleaseError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise PhysicalReleaseError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise PhysicalReleaseError(f"{label} is not UTC")
    return parsed


def _integrity(document: Mapping[str, object], label: str) -> dict[str, Any]:
    payload = document.get("payload")
    integrity = _exact(document.get("integrity"), {"payload_sha256"}, f"{label}.integrity")
    if not isinstance(payload, Mapping):
        raise PhysicalReleaseError(f"{label}.payload must be an object")
    expected = payload_sha(payload)
    if _sha(integrity["payload_sha256"], f"{label}.integrity.payload_sha256") != expected:
        raise PhysicalReleaseError(f"{label} payload integrity mismatch")
    return dict(payload)


def validate_registry(document: Mapping[str, object]) -> dict[str, dict[str, Any]]:
    _exact(
        document,
        {"schema_id", "schema_version", "object_id", "issued_at", "payload", "integrity"},
        "producer registry",
    )
    if document["schema_id"] != "DomainProducerRegistry" or document["schema_version"] != "1.0.0":
        raise PhysicalReleaseError("producer registry schema is unsupported")
    _text(document["object_id"], "producer registry object_id")
    _timestamp(document["issued_at"], "producer registry issued_at")
    payload = _integrity(document, "producer registry")
    _exact(payload, {"producers"}, "producer registry payload")
    producers = payload["producers"]
    if not isinstance(producers, list) or len(producers) != 2:
        raise PhysicalReleaseError("producer registry must contain exactly two producers")
    result: dict[str, dict[str, Any]] = {}
    keys = {
        "domain", "project_id", "project_fingerprint", "runtime_head",
        "producer_schema_id", "producer_schema_version", "data_classes",
        "source_locator_fingerprint",
    }
    for index, item in enumerate(producers):
        producer = _exact(item, keys, f"producer[{index}]")
        domain = _text(producer["domain"], f"producer[{index}].domain", maximum=16)
        if domain not in _DOMAINS or domain in result:
            raise PhysicalReleaseError("producer domain set is invalid")
        if producer["project_id"] != _PROJECTS[domain]:
            raise PhysicalReleaseError("producer project/domain binding is invalid")
        _sha(producer["project_fingerprint"], "producer project fingerprint")
        _git_sha(producer["runtime_head"], "producer runtime head")
        _text(producer["producer_schema_id"], "producer schema id", maximum=128)
        version = _text(producer["producer_schema_version"], "producer schema version", maximum=64)
        if _SCHEMA_VERSION.fullmatch(version) is None:
            raise PhysicalReleaseError("producer schema version is invalid")
        classes = producer["data_classes"]
        if (
            not isinstance(classes, list)
            or not classes
            or len(classes) != len(set(classes))
            or any(item not in _DATA_CLASSES for item in classes)
        ):
            raise PhysicalReleaseError("producer data classes are invalid")
        _sha(producer["source_locator_fingerprint"], "producer locator fingerprint")
        result[domain] = producer
    if set(result) != set(_DOMAINS):
        raise PhysicalReleaseError("producer registry domain set is incomplete")
    return result


def validate_export(
    registry_document: Mapping[str, object],
    binding_document: Mapping[str, object],
    payload_path: Path,
    *,
    domain: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    if domain not in _DOMAINS:
        raise PhysicalReleaseError("export domain is unsupported")
    registry = validate_registry(registry_document)
    _exact(
        binding_document,
        {"schema_id", "schema_version", "object_id", "issued_at", "payload", "integrity"},
        "export binding",
    )
    if binding_document["schema_id"] != "DomainExportBinding" or binding_document["schema_version"] != "1.0.0":
        raise PhysicalReleaseError("export binding schema is unsupported")
    _text(binding_document["object_id"], "export binding object_id")
    _timestamp(binding_document["issued_at"], "export binding issued_at")
    payload = _integrity(binding_document, "export binding")
    keys = {
        "domain", "producer_project_id", "producer_project_fingerprint",
        "producer_runtime_head", "producer_schema_id", "producer_schema_version",
        "data_class", "content_sha256", "payload_size_bytes", "produced_at",
        "freshness_boundary", "immutability_or_snapshot_identity",
        "source_locator_fingerprint", "live_authority", "canonical_write_authority",
    }
    binding = _exact(payload, keys, "export binding payload")
    if binding["domain"] != domain:
        raise PhysicalReleaseError("cross-domain or swapped export rejected")
    producer = registry[domain]
    comparisons = {
        "producer_project_id": "project_id",
        "producer_project_fingerprint": "project_fingerprint",
        "producer_runtime_head": "runtime_head",
        "producer_schema_id": "producer_schema_id",
        "producer_schema_version": "producer_schema_version",
        "source_locator_fingerprint": "source_locator_fingerprint",
    }
    for binding_key, producer_key in comparisons.items():
        if binding[binding_key] != producer[producer_key]:
            raise PhysicalReleaseError(f"export {binding_key} does not match its producer")
    if binding["data_class"] not in producer["data_classes"] or binding["data_class"] not in _DATA_CLASSES:
        raise PhysicalReleaseError("export data class is not permitted")
    _sha(binding["content_sha256"], "export content hash")
    if type(binding["payload_size_bytes"]) is not int or not 0 < binding["payload_size_bytes"] <= _MAX_EXPORT_BYTES:
        raise PhysicalReleaseError("export payload size is invalid")
    produced = _timestamp(binding["produced_at"], "export produced_at")
    boundary = _timestamp(binding["freshness_boundary"], "export freshness boundary")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise PhysicalReleaseError("validation clock must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if boundary <= produced or current < produced or current > boundary:
        raise PhysicalReleaseError("export is future-dated, stale, or has an invalid freshness window")
    snapshot = _text(binding["immutability_or_snapshot_identity"], "export snapshot identity", maximum=256)
    if not snapshot.startswith(f"{domain}:snapshot:") or snapshot.endswith(":latest") or "latest" in snapshot.lower():
        raise PhysicalReleaseError("export is mutable or has the wrong snapshot identity")
    if binding["live_authority"] is not False or binding["canonical_write_authority"] is not False:
        raise PhysicalReleaseError("export grants forbidden authority")
    raw, metadata = _read_bound(payload_path, f"{domain} export payload", maximum=_MAX_EXPORT_BYTES)
    if len(raw) != binding["payload_size_bytes"] or metadata.st_size != binding["payload_size_bytes"]:
        raise PhysicalReleaseError("export payload size does not match binding")
    if digest_bytes(raw) != binding["content_sha256"]:
        raise PhysicalReleaseError("export payload content does not match binding")
    return {
        "domain": domain,
        "binding_sha256": digest_bytes(canonical_bytes(binding_document)),
        "content_sha256": binding["content_sha256"],
        "produced_at": binding["produced_at"],
        "snapshot_identity": snapshot,
        "data_class": binding["data_class"],
        "producer_project_fingerprint": binding["producer_project_fingerprint"],
        "producer_runtime_head": binding["producer_runtime_head"],
    }


def source_trigger(proof: Mapping[str, object]) -> dict[str, object]:
    domain = _text(proof.get("domain"), "proof domain", maximum=16)
    if domain not in _DOMAINS:
        raise PhysicalReleaseError("proof domain is unsupported")
    binding_sha = _sha(proof.get("binding_sha256"), "proof binding SHA")
    content_sha = _sha(proof.get("content_sha256"), "proof content SHA")
    observed_at = _text(proof.get("produced_at"), "proof produced_at", maximum=64)
    snapshot = _text(proof.get("snapshot_identity"), "proof snapshot identity", maximum=256)
    key = f"domain-export:{domain}:{binding_sha}"
    return {
        "trigger_id": f"source-trigger:{domain}:{binding_sha[:32]}",
        "collector_id": COLLECTOR_ID,
        "source_ref": f"registered:domain-export/{domain}/{snapshot}",
        "source_content_sha256": content_sha,
        "observed_at": observed_at,
        "summary": f"domain-owned immutable {domain} export available",
        "evidence_refs": [f"registered:domain-export-binding/{binding_sha}"],
        "transport_idempotency_key": key,
    }


def _round_trip(socket_path: str, request: Mapping[str, object]) -> dict[str, Any]:
    if not socket_path or "\x00" in socket_path:
        raise PhysicalReleaseError("AF_UNIX socket path is invalid")
    outbound = canonical_bytes(request) + b"\n"
    if len(outbound) > 65_536:
        raise PhysicalReleaseError("SourceTrigger request exceeds transport bound")
    connection: socket.socket | None = None
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if connection.family != socket.AF_UNIX:
            raise PhysicalReleaseError("local transport is not AF_UNIX")
        connection.settimeout(5.0)
        connection.connect(socket_path)
        connection.sendall(outbound)
        frame = bytearray()
        while True:
            remaining = _MAX_RESPONSE_BYTES + 1 - len(frame)
            if remaining <= 0:
                raise PhysicalReleaseError("daemon response exceeds transport bound")
            block = connection.recv(min(16_384, remaining))
            if not block:
                break
            frame.extend(block)
    except (OSError, TimeoutError) as exc:
        raise PhysicalReleaseError("local AF_UNIX SourceTrigger submission failed") from exc
    finally:
        if connection is not None:
            connection.close()
    if not frame or len(frame) > _MAX_RESPONSE_BYTES or not frame.endswith(b"\n") or b"\n" in frame[:-1]:
        raise PhysicalReleaseError("daemon response framing is invalid")
    try:
        response = json.loads(
            frame[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PhysicalReleaseError("daemon response is not strict JSON") from exc
    if not isinstance(response, dict):
        raise PhysicalReleaseError("daemon response must be an object")
    expected = {"version", "request_id", "ok", "command", "result"}
    if (
        set(response) != expected
        or response.get("version") != request["version"]
        or response.get("request_id") != request["request_id"]
        or response.get("command") != "submit_source_trigger"
        or response.get("ok") is not True
        or not isinstance(response.get("result"), dict)
    ):
        raise PhysicalReleaseError("daemon did not return a bound success response")
    return response


def _request(trigger: Mapping[str, object]) -> dict[str, object]:
    key = _text(trigger.get("transport_idempotency_key"), "trigger idempotency key", maximum=256)
    request_id = "request:" + digest_bytes(canonical_bytes(trigger))[:32]
    return {
        "version": "1.2",
        "request_id": request_id,
        "idempotency_key": key,
        "command": "submit_source_trigger",
        "payload": {"source_trigger": dict(trigger)},
    }


def _reserve_receipt(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        marker = b'{"status":"INCOMPLETE_RECEIPT_RESERVED_BEFORE_ACTION"}\n'
        if os.write(descriptor, marker) != len(marker):
            raise PhysicalReleaseError("receipt reservation short write")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        return descriptor
    except OSError as exc:
        raise PhysicalReleaseError("owner-only receipt path cannot be reserved without overwrite") from exc


def _finalize_receipt(descriptor: int, path: Path, value: Mapping[str, object]) -> None:
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.geteuid()
        ):
            raise PhysicalReleaseError("reserved receipt identity or ownership changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        raw = canonical_bytes(value) + b"\n"
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    except OSError as exc:
        raise PhysicalReleaseError("reserved owner-only receipt cannot be finalized") from exc
    finally:
        os.close(descriptor)


def _receipt(schema_id: str, object_id: str, payload: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_id": schema_id,
        "schema_version": "1.0.0",
        "object_id": object_id,
        "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "payload": dict(payload),
        "integrity": {"payload_sha256": payload_sha(payload)},
    }


def run_ingress(arguments: argparse.Namespace) -> dict[str, object]:
    if os.geteuid() != COLLECTOR_UID:
        raise PhysicalReleaseError("ingress must run as the single collector UID 10002")
    envelope_document = read_json(arguments.envelope, "ingress action envelope")
    envelope = validate_action_envelope(
        envelope_document,
        None,
        action="ingress",
        expected_host_fingerprint=arguments.expected_host_fingerprint,
    )
    registry = read_json(arguments.registry, "producer registry")
    proofs = []
    for domain in _DOMAINS:
        binding = read_json(getattr(arguments, f"{domain}_binding"), f"{domain} export binding")
        proofs.append(validate_export(registry, binding, getattr(arguments, f"{domain}_payload"), domain=domain))
    descriptor = _reserve_receipt(arguments.receipt)
    try:
        responses = []
        for proof in proofs:
            trigger = source_trigger(proof)
            responses.append(_round_trip(arguments.socket, _request(trigger)))
        receipt_payload = {
            "action": "ingress",
            "status": "PASS",
            "action_envelope_sha256": digest_bytes(canonical_bytes(envelope_document)),
            "action_envelope_payload_sha256": payload_sha(envelope),
            "transport": "AF_UNIX",
            "ingress_principal": COLLECTOR_ID,
            "ingress_principal_count": 1,
            "public_listener_count": 0,
            "domain_writes": False,
            "live_authority": False,
            "bindings": proofs,
            "response_digests": [payload_sha(response) for response in responses],
        }
        receipt = _receipt(
            "OperationalActionReceipt",
            "operational-action:ingress:" + payload_sha(receipt_payload)[:32],
            receipt_payload,
        )
        _finalize_receipt(descriptor, arguments.receipt, receipt)
        return receipt
    except Exception:
        failure_payload = {
            "action": "ingress",
            "status": "FAIL_CLOSED",
            "action_envelope_sha256": digest_bytes(canonical_bytes(envelope_document)),
            "transport": "AF_UNIX",
            "ingress_principal": COLLECTOR_ID,
            "ingress_principal_count": 1,
            "public_listener_count": 0,
            "domain_writes": False,
            "live_authority": False,
        }
        _finalize_receipt(
            descriptor,
            arguments.receipt,
            _receipt(
                "OperationalActionReceipt",
                "operational-action:ingress-failed:" + payload_sha(failure_payload)[:32],
                failure_payload,
            ),
        )
        raise


def validate_deploy_profile(document: Mapping[str, object]) -> dict[str, Any]:
    _exact(
        document,
        {"schema_id", "schema_version", "object_id", "issued_at", "payload", "integrity"},
        "deploy profile",
    )
    if document["schema_id"] != "PhysicalReleaseControlProfile" or document["schema_version"] != "1.0.0":
        raise PhysicalReleaseError("deploy profile schema is unsupported")
    _text(document["object_id"], "deploy profile object_id")
    _timestamp(document["issued_at"], "deploy profile issued_at")
    payload = _integrity(document, "deploy profile")
    keys = {
        "runtime_release_sha", "runtime_tree_sha", "image_id", "engine_image_id", "carrier_sha256",
        "carrier_bytes", "carrier_binding_sha256", "unit_sha256", "policy_sha256",
        "config_sha256", "r17_deployment_packet_sha256", "exact_host_fingerprint",
        "ssh_alias", "known_hosts_path", "carrier_path", "service_name",
        "container_name", "runtime_volume", "config_volume", "public_listener_count",
        "runtime_rebuild", "live_authority",
    }
    profile = _exact(payload, keys, "deploy profile payload")
    expected = {
        "runtime_release_sha": RUNTIME_RELEASE_SHA,
        "runtime_tree_sha": RUNTIME_TREE_SHA,
        "image_id": IMAGE_ID,
        "engine_image_id": ENGINE_IMAGE_ID,
        "carrier_sha256": CARRIER_SHA256,
        "carrier_bytes": CARRIER_BYTES,
        "carrier_binding_sha256": CARRIER_BINDING_SHA256,
        "unit_sha256": UNIT_SHA256,
        "policy_sha256": POLICY_SHA256,
        "config_sha256": CONFIG_SHA256,
        "r17_deployment_packet_sha256": R17_PACKET_SHA256,
        "service_name": SERVICE_NAME,
        "container_name": CONTAINER_NAME,
        "runtime_volume": RUNTIME_VOLUME,
        "config_volume": CONFIG_VOLUME,
        "public_listener_count": 0,
        "runtime_rebuild": False,
        "live_authority": False,
    }
    for key, value in expected.items():
        if profile[key] != value:
            raise PhysicalReleaseError(f"deploy profile {key} drifted from R17")
    _sha(profile["exact_host_fingerprint"], "deploy profile host fingerprint")
    _text(profile["ssh_alias"], "deploy profile SSH alias", maximum=64)
    carrier_path = Path(_text(profile["carrier_path"], "deploy profile carrier path", maximum=4096))
    known_hosts_path = Path(_text(profile["known_hosts_path"], "deploy profile known_hosts path", maximum=4096))
    carrier, metadata = _read_bound(carrier_path, "R17 carrier", maximum=CARRIER_BYTES)
    if len(carrier) != CARRIER_BYTES or metadata.st_size != CARRIER_BYTES or digest_bytes(carrier) != CARRIER_SHA256:
        raise PhysicalReleaseError("R17 carrier bytes do not match the frozen identity")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PhysicalReleaseError("R17 carrier is not owner-only mode 0600")
    _read_bound(known_hosts_path, "known_hosts", maximum=4 * 1024 * 1024)
    return profile


def validate_action_envelope(
    document: Mapping[str, object],
    profile: Mapping[str, object] | None,
    *,
    action: str,
    expected_host_fingerprint: str | None = None,
) -> dict[str, Any]:
    _exact(
        document,
        {"schema_id", "schema_version", "object_id", "issued_at", "payload", "integrity"},
        "action envelope",
    )
    if document["schema_id"] != "OperationalActionEnvelope" or document["schema_version"] != "1.0.0":
        raise PhysicalReleaseError("action envelope schema is unsupported")
    _text(document["object_id"], "action envelope object_id")
    issued = _timestamp(document["issued_at"], "action envelope issued_at")
    payload = _integrity(document, "action envelope")
    required = {
        "project_fingerprints", "mission_id", "sprint_id", "action",
        "exact_host_fingerprint", "exact_service_units", "exact_users_paths_ports_namespaces",
        "from_release_identity", "to_release_identity", "artifact_hashes", "authorized_steps",
        "provider_calls_maximum", "token_and_cost_ceiling", "expires_at", "preflight",
        "stop_conditions", "backup_identity", "rollback_target", "forbidden_boundaries",
        "authority_source_hash",
    }
    envelope = _exact(payload, required, "action envelope payload")
    expires = _timestamp(envelope["expires_at"], "action envelope expires_at")
    now = datetime.now(timezone.utc)
    if issued > now or expires <= issued or now > expires:
        raise PhysicalReleaseError("action envelope is not currently valid")
    host_fingerprint = (
        profile["exact_host_fingerprint"]
        if profile is not None
        else _sha(expected_host_fingerprint, "expected host fingerprint")
    )
    if envelope["action"] != action or envelope["exact_host_fingerprint"] != host_fingerprint:
        raise PhysicalReleaseError("action envelope action or host binding mismatch")
    if envelope["mission_id"] != MISSION_ID:
        raise PhysicalReleaseError("action envelope mission binding is invalid")
    _text(envelope["sprint_id"], "action envelope sprint id", maximum=128)
    transition = _ACTION_TRANSITIONS.get(action)
    if transition is None:
        raise PhysicalReleaseError("action envelope action is unsupported")
    if (envelope["from_release_identity"], envelope["to_release_identity"]) != transition:
        raise PhysicalReleaseError("action envelope release transition is invalid")
    units = envelope["exact_service_units"]
    if (
        not isinstance(units, list)
        or not units
        or len(units) != len(set(units))
        or any(not isinstance(item, str) or not item.endswith(".service") for item in units)
    ):
        raise PhysicalReleaseError("action envelope service set is invalid")
    if action == "deploy" and units != [SERVICE_NAME]:
        raise PhysicalReleaseError("deploy action service set is not exact")
    if action == "ingress" and units != [INGRESS_SERVICE_NAME]:
        raise PhysicalReleaseError("ingress action service set is not exact")
    if action in {"restart", "rollback_readiness"} and SERVICE_NAME not in units:
        raise PhysicalReleaseError("Bridge service is missing from the action service set")
    if action == "reboot" and not {SERVICE_NAME, INGRESS_SERVICE_NAME}.issubset(units):
        raise PhysicalReleaseError("reboot action lacks the persistent Bridge service set")
    if type(envelope["provider_calls_maximum"]) is not int or envelope["provider_calls_maximum"] != 0:
        raise PhysicalReleaseError("deployment envelope must not authorize provider calls")
    fingerprints = envelope["project_fingerprints"]
    if (
        not isinstance(fingerprints, list)
        or len(fingerprints) != 3
        or set(fingerprints) != PROJECT_FINGERPRINTS
    ):
        raise PhysicalReleaseError("action envelope project identity set is incomplete")
    if envelope["authorized_steps"] != [action]:
        raise PhysicalReleaseError("action envelope does not authorize the requested step")
    for field in (
        "exact_users_paths_ports_namespaces",
        "preflight",
        "stop_conditions",
        "forbidden_boundaries",
    ):
        values = envelope[field]
        if (
            not isinstance(values, list)
            or not values
            or len(values) != len(set(values))
            or any(not isinstance(item, str) or not item.strip() for item in values)
        ):
            raise PhysicalReleaseError(f"action envelope {field} is invalid")
    artifacts = envelope["artifact_hashes"]
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or len(artifacts) != len(set(artifacts))
    ):
        raise PhysicalReleaseError("action envelope artifact hash set is invalid")
    for item in artifacts:
        _sha(item, "action envelope artifact hash")
    budget = _exact(
        envelope["token_and_cost_ceiling"],
        {"reserved_tokens_maximum", "cost_units_maximum"},
        "action envelope token and cost ceiling",
    )
    if budget != {"reserved_tokens_maximum": 0, "cost_units_maximum": 0}:
        raise PhysicalReleaseError("deployment/ingress envelope must have a zero provider budget")
    _text(envelope["backup_identity"], "action envelope backup identity", maximum=512)
    _text(envelope["rollback_target"], "action envelope rollback target", maximum=512)
    _sha(envelope["authority_source_hash"], "action envelope authority source hash")
    return envelope


def _render_bundle(profile: Mapping[str, object]) -> object:
    try:
        import pre_soak_deploy as deploy
    except ImportError as exc:  # pragma: no cover - repository invariant
        raise PhysicalReleaseError("owned deploy primitives are unavailable") from exc
    unit_path = ROOT / "ops/deploy/research-os-a1-final.service"
    policy_path = ROOT / "ops/release/final-a1-runtime-policy.json"
    config_path = ROOT / "ops/release/researchd.config.template.json"
    for path, expected, label in (
        (unit_path, UNIT_SHA256, "unit template"),
        (policy_path, POLICY_SHA256, "runtime policy"),
        (config_path, CONFIG_SHA256, "config template"),
    ):
        raw, _ = _read_bound(path, label, maximum=_MAX_JSON_BYTES)
        if digest_bytes(raw) != expected:
            raise PhysicalReleaseError(f"{label} drifted")
    unit = unit_path.read_text(encoding="utf-8")
    rendered = (
        unit.replace("@@IMAGE_ID@@", ENGINE_IMAGE_ID)
        .replace("@@RELEASE_SHA@@", RUNTIME_RELEASE_SHA)
        .replace("@@POLICY_SHA256@@", POLICY_SHA256)
        .replace("@@CONFIG_SHA256@@", CONFIG_SHA256)
    ).encode("utf-8")
    if b"@@" in rendered:
        raise PhysicalReleaseError("rendered unit retains an unresolved token")
    return deploy.ReleaseBundle(
        release_sha=RUNTIME_RELEASE_SHA,
        image_id=ENGINE_IMAGE_ID,
        previous_release_ref="release:none-service-stopped",
        policy_sha256=POLICY_SHA256,
        config_sha256=CONFIG_SHA256,
        archive_sha256=CARRIER_SHA256,
        unit_bytes=rendered,
        unit_sha256=digest_bytes(rendered),
        config_path=config_path,
        archive_path=Path(str(profile["carrier_path"])),
        capsule=None,
    )


def deploy_preflight(profile_document: Mapping[str, object], envelope_document: Mapping[str, object] | None = None) -> dict[str, object]:
    profile = validate_deploy_profile(profile_document)
    if envelope_document is not None:
        validate_action_envelope(envelope_document, profile, action="deploy")
    bundle = _render_bundle(profile)
    return {
        "status": "PASS",
        "runtime_release_sha": RUNTIME_RELEASE_SHA,
        "runtime_tree_sha": RUNTIME_TREE_SHA,
        "image_id": IMAGE_ID,
        "engine_image_id": ENGINE_IMAGE_ID,
        "carrier_sha256": CARRIER_SHA256,
        "carrier_bytes": CARRIER_BYTES,
        "rendered_unit_sha256": bundle.unit_sha256,
        "service_name": SERVICE_NAME,
        "container_name": CONTAINER_NAME,
        "runtime_rebuild": False,
        "public_listener_count": 0,
        "live_authority": False,
    }


def execute_deploy(arguments: argparse.Namespace) -> dict[str, object]:
    profile_document = read_json(arguments.profile, "deploy profile")
    profile = validate_deploy_profile(profile_document)
    envelope_document = read_json(arguments.envelope, "action envelope")
    envelope = validate_action_envelope(envelope_document, profile, action="deploy")
    bundle = _render_bundle(profile)
    deployment_descriptor = _reserve_receipt(arguments.deployment_receipt)
    action_descriptor: int | None = None
    try:
        action_descriptor = _reserve_receipt(arguments.action_receipt)
        import pre_soak_deploy as deploy
        controller = deploy.PreSoakDeployController(
            ssh_alias=profile["ssh_alias"],
            known_hosts_path=Path(profile["known_hosts_path"]),
            target=deploy.FINAL_A1_TARGET,
        )
        deployment_receipt = controller.deploy(bundle)
        _finalize_receipt(deployment_descriptor, arguments.deployment_receipt, deployment_receipt)
        deployment_descriptor = -1
        action_payload = {
            "action": "deploy",
            "status": "PASS",
            "action_envelope_sha256": digest_bytes(canonical_bytes(envelope_document)),
            "action_envelope_payload_sha256": payload_sha(envelope),
            "deploy_profile_sha256": digest_bytes(canonical_bytes(profile_document)),
            "deployment_receipt_sha256": digest_bytes(canonical_bytes(deployment_receipt)),
            "runtime_release_sha": RUNTIME_RELEASE_SHA,
            "runtime_tree_sha": RUNTIME_TREE_SHA,
            "image_id": IMAGE_ID,
            "engine_image_id": ENGINE_IMAGE_ID,
            "carrier_sha256": CARRIER_SHA256,
            "service_name": SERVICE_NAME,
            "runtime_rebuild": False,
            "public_listener_count": 0,
            "live_authority": False,
        }
        receipt = _receipt(
            "OperationalActionReceipt",
            "operational-action:deploy:" + payload_sha(action_payload)[:32],
            action_payload,
        )
        _finalize_receipt(action_descriptor, arguments.action_receipt, receipt)
        action_descriptor = None
        return receipt
    except Exception as exc:
        failure_payload = {
            "action": "deploy",
            "status": "FAIL_CLOSED",
            "action_envelope_sha256": digest_bytes(canonical_bytes(envelope_document)),
            "runtime_release_sha": RUNTIME_RELEASE_SHA,
            "image_id": IMAGE_ID,
            "engine_image_id": ENGINE_IMAGE_ID,
            "service_name": SERVICE_NAME,
            "automatic_sudo_executed": False,
            "automatic_reboot_executed": False,
            "release_done_claimed": False,
        }
        failure = _receipt(
            "OperationalActionReceipt",
            "operational-action:deploy-failed:" + payload_sha(failure_payload)[:32],
            failure_payload,
        )
        if deployment_descriptor != -1:
            _finalize_receipt(deployment_descriptor, arguments.deployment_receipt, failure)
        if action_descriptor is not None:
            _finalize_receipt(action_descriptor, arguments.action_receipt, failure)
        raise PhysicalReleaseError("exact-R17 deployment failed closed") from exc


def validate_artifact(document: Mapping[str, object], *, root: Path = ROOT) -> dict[str, object]:
    _exact(
        document,
        {"schema_id", "schema_version", "object_id", "issued_at", "payload", "integrity"},
        "control artifact",
    )
    if document["schema_id"] != "PhysicalReleaseControlArtifact" or document["schema_version"] != "1.0.0":
        raise PhysicalReleaseError("control artifact schema is unsupported")
    _timestamp(document["issued_at"], "control artifact issued_at")
    payload = _integrity(document, "control artifact")
    required = {
        "runtime_release_sha", "runtime_tree_sha", "image_id", "engine_image_id", "carrier_sha256",
        "carrier_bytes", "ingress_executable", "ingress_executable_sha256",
        "domain_consumers", "ingress_principal", "ingress_principal_count",
        "transport", "public_listener_count", "domain_writes", "live_authority",
        "runtime_inputs_changed", "deploy_wrapper_mode", "forbidden_legacy_entrypoints",
    }
    artifact = _exact(payload, required, "control artifact payload")
    expected = {
        "runtime_release_sha": RUNTIME_RELEASE_SHA,
        "runtime_tree_sha": RUNTIME_TREE_SHA,
        "image_id": IMAGE_ID,
        "engine_image_id": ENGINE_IMAGE_ID,
        "carrier_sha256": CARRIER_SHA256,
        "carrier_bytes": CARRIER_BYTES,
        "ingress_executable": "tools/physical_release_control.py",
        "domain_consumers": ["market", "security"],
        "ingress_principal": COLLECTOR_ID,
        "ingress_principal_count": 1,
        "transport": "AF_UNIX",
        "public_listener_count": 0,
        "domain_writes": False,
        "live_authority": False,
        "runtime_inputs_changed": False,
        "deploy_wrapper_mode": "exact-R17-via-owned-low-level-primitives",
        "forbidden_legacy_entrypoints": ["tools/pre_soak_deploy.py:run", "tools/final_deployment_rebind.py"],
    }
    for key, value in expected.items():
        if artifact[key] != value:
            raise PhysicalReleaseError(f"control artifact {key} is invalid")
    executable, _ = _read_bound(root / artifact["ingress_executable"], "ingress executable", maximum=_MAX_JSON_BYTES)
    if _sha(artifact["ingress_executable_sha256"], "ingress executable SHA") != digest_bytes(executable):
        raise PhysicalReleaseError("ingress executable hash drifted")
    return {"status": "PASS", "artifact_payload_sha256": payload_sha(artifact)}


def _document(schema: str, object_id: str, issued_at: str, payload: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_id": schema,
        "schema_version": "1.0.0",
        "object_id": object_id,
        "issued_at": issued_at,
        "payload": dict(payload),
        "integrity": {"payload_sha256": payload_sha(payload)},
    }


def self_test() -> dict[str, object]:
    now = datetime(2026, 7, 20, 22, 0, tzinfo=timezone.utc)
    issued = "2026-07-20T21:59:00Z"
    producers = []
    exports: dict[str, tuple[dict[str, object], bytes]] = {}
    for index, domain in enumerate(_DOMAINS):
        locator = hashlib.sha256(f"locator-{domain}".encode()).hexdigest()
        schema = f"example.{domain}.snapshot.v1"
        producers.append({
            "domain": domain,
            "project_id": _PROJECTS[domain],
            "project_fingerprint": hashlib.sha256(f"project-{domain}".encode()).hexdigest(),
            "runtime_head": str(index + 1) * 40,
            "producer_schema_id": schema,
            "producer_schema_version": "1.0.0",
            "data_classes": ["D0_PUBLIC"],
            "source_locator_fingerprint": locator,
        })
        raw = canonical_bytes({"synthetic": True, "domain": domain})
        binding_payload = {
            "domain": domain,
            "producer_project_id": _PROJECTS[domain],
            "producer_project_fingerprint": producers[-1]["project_fingerprint"],
            "producer_runtime_head": producers[-1]["runtime_head"],
            "producer_schema_id": schema,
            "producer_schema_version": "1.0.0",
            "data_class": "D0_PUBLIC",
            "content_sha256": digest_bytes(raw),
            "payload_size_bytes": len(raw),
            "produced_at": issued,
            "freshness_boundary": "2026-07-20T23:59:00Z",
            "immutability_or_snapshot_identity": f"{domain}:snapshot:{digest_bytes(raw)}",
            "source_locator_fingerprint": locator,
            "live_authority": False,
            "canonical_write_authority": False,
        }
        exports[domain] = (_document("DomainExportBinding", f"binding:{domain}", issued, binding_payload), raw)
    registry = _document("DomainProducerRegistry", "registry:self-test", issued, {"producers": producers})
    validate_registry(registry)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        proofs = {}
        for domain in _DOMAINS:
            binding, raw = exports[domain]
            path = root / f"{domain}.json"
            path.write_bytes(raw)
            proofs[domain] = validate_export(registry, binding, path, domain=domain, now=now)
            trigger = source_trigger(proofs[domain])
            if trigger["collector_id"] != COLLECTOR_ID or not trigger["source_ref"].startswith(f"registered:domain-export/{domain}/"):
                raise PhysicalReleaseError("valid SourceTrigger self-test failed")
        hostile = 0
        market_binding, _ = exports["market"]
        try:
            validate_export(registry, market_binding, root / "market.json", domain="security", now=now)
        except PhysicalReleaseError:
            hostile += 1
        stale = json.loads(json.dumps(exports["security"][0]))
        stale["payload"]["freshness_boundary"] = "2026-07-20T21:59:30Z"
        stale["integrity"]["payload_sha256"] = payload_sha(stale["payload"])
        try:
            validate_export(registry, stale, root / "security.json", domain="security", now=now)
        except PhysicalReleaseError:
            hostile += 1
        mutable = json.loads(json.dumps(exports["market"][0]))
        mutable["payload"]["immutability_or_snapshot_identity"] = "market:snapshot:latest"
        mutable["integrity"]["payload_sha256"] = payload_sha(mutable["payload"])
        try:
            validate_export(registry, mutable, root / "market.json", domain="market", now=now)
        except PhysicalReleaseError:
            hostile += 1
        (root / "market.json").write_bytes(b"tampered")
        try:
            validate_export(registry, exports["market"][0], root / "market.json", domain="market", now=now)
        except PhysicalReleaseError:
            hostile += 1
        try:
            validate_export(registry, exports["market"][0], root / "missing", domain="market", now=now)
        except PhysicalReleaseError:
            hostile += 1
        action_now = datetime.now(timezone.utc)
        action_issued = action_now.isoformat(timespec="seconds").replace("+00:00", "Z")
        action_expires = datetime.fromtimestamp(action_now.timestamp() + 600, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        host_fingerprint = hashlib.sha256(b"self-test-host").hexdigest()
        envelope_payload = {
            "project_fingerprints": sorted(PROJECT_FINGERPRINTS),
            "mission_id": MISSION_ID,
            "sprint_id": "P03_NAMESPACED_PERMANENT_VPS_DEPLOY",
            "action": "deploy",
            "exact_host_fingerprint": host_fingerprint,
            "exact_service_units": [SERVICE_NAME],
            "exact_users_paths_ports_namespaces": ["uid:10001", "namespace:research-os-a1"],
            "from_release_identity": "release:none-service-stopped",
            "to_release_identity": RUNTIME_RELEASE_SHA,
            "artifact_hashes": [CARRIER_SHA256, UNIT_SHA256, POLICY_SHA256, CONFIG_SHA256],
            "authorized_steps": ["deploy"],
            "provider_calls_maximum": 0,
            "token_and_cost_ceiling": {"reserved_tokens_maximum": 0, "cost_units_maximum": 0},
            "expires_at": action_expires,
            "preflight": ["host-identity", "namespace-collision", "rollback-ready"],
            "stop_conditions": ["identity-drift", "domain-service-impact"],
            "backup_identity": "backup:pre-deploy:none-service-stopped",
            "rollback_target": "release:none-service-stopped",
            "forbidden_boundaries": ["domain-write", "public-listener", "runtime-rebuild"],
            "authority_source_hash": hashlib.sha256(b"self-test-authority").hexdigest(),
        }
        envelope = _document(
            "OperationalActionEnvelope",
            "action-envelope:self-test",
            action_issued,
            envelope_payload,
        )
        validate_action_envelope(
            envelope,
            {"exact_host_fingerprint": host_fingerprint},
            action="deploy",
        )
        ingress_payload = json.loads(json.dumps(envelope_payload))
        ingress_payload.update({
            "sprint_id": "P04_DUAL_DOMAIN_BOUNDED_REMOTE_E2E",
            "action": "ingress",
            "exact_service_units": [INGRESS_SERVICE_NAME],
            "from_release_identity": RUNTIME_RELEASE_SHA,
            "authorized_steps": ["ingress"],
        })
        ingress_envelope = _document(
            "OperationalActionEnvelope",
            "action-envelope:self-test-ingress",
            action_issued,
            ingress_payload,
        )
        validate_action_envelope(
            ingress_envelope,
            None,
            action="ingress",
            expected_host_fingerprint=host_fingerprint,
        )
        wrong_host = json.loads(json.dumps(envelope))
        wrong_host["payload"]["exact_host_fingerprint"] = hashlib.sha256(b"wrong-host").hexdigest()
        wrong_host["integrity"]["payload_sha256"] = payload_sha(wrong_host["payload"])
        try:
            validate_action_envelope(
                wrong_host,
                {"exact_host_fingerprint": host_fingerprint},
                action="deploy",
            )
        except PhysicalReleaseError:
            hostile += 1
        receipt_path = root / "receipt.json"
        receipt_descriptor = _reserve_receipt(receipt_path)
        receipt_value = _receipt(
            "OperationalActionReceipt",
            "operational-action:self-test",
            {"action": "self-test", "status": "PASS"},
        )
        _finalize_receipt(receipt_descriptor, receipt_path, receipt_value)
        if stat.S_IMODE(os.lstat(receipt_path).st_mode) != 0o600 or read_json(receipt_path, "self-test receipt") != receipt_value:
            raise PhysicalReleaseError("receipt reservation/finalization self-test failed")
        if hostile != 6:
            raise PhysicalReleaseError("hostile export self-tests did not all fail closed")
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden = (
        "AF_" + "INET",
        "listen" + "(",
        "bind" + "(",
        "urlopen" + "(",
        "requests" + ".",
    )
    if any(token in source for token in forbidden):
        raise PhysicalReleaseError("ingress source contains a forbidden public/network listener primitive")
    unit_template = (ROOT / "ops/deploy/research-os-a1-final.service").read_text(encoding="utf-8")
    rendered_unit = unit_template.replace("@@IMAGE_ID@@", ENGINE_IMAGE_ID)
    if (
        IMAGE_ID == ENGINE_IMAGE_ID
        or "@@IMAGE_ID@@" not in unit_template
        or ENGINE_IMAGE_ID not in rendered_unit
        or IMAGE_ID in rendered_unit
    ):
        raise PhysicalReleaseError("portable-to-engine image identity mapping self-test failed")
    return {
        "status": "PASS",
        "valid_domains": 2,
        "hostile_cases_rejected": 6,
        "ingress_principal_count": 1,
        "public_listener_count": 0,
        "runtime_rebuild": False,
        "runtime_release_sha": RUNTIME_RELEASE_SHA,
        "image_id": IMAGE_ID,
        "engine_image_id": ENGINE_IMAGE_ID,
        "portable_to_engine_mapping": True,
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PhysicalReleaseError("command arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="physical-release-control")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("self-test")
    artifact = commands.add_parser("validate-artifact")
    artifact.add_argument("--artifact", type=Path, required=True)
    registry = commands.add_parser("validate-registry")
    registry.add_argument("--registry", type=Path, required=True)
    export = commands.add_parser("validate-export")
    export.add_argument("--registry", type=Path, required=True)
    export.add_argument("--binding", type=Path, required=True)
    export.add_argument("--payload", type=Path, required=True)
    export.add_argument("--domain", choices=_DOMAINS, required=True)
    ingress = commands.add_parser("ingress-once")
    ingress.add_argument("--registry", type=Path, required=True)
    ingress.add_argument("--market-binding", type=Path, required=True)
    ingress.add_argument("--market-payload", type=Path, required=True)
    ingress.add_argument("--security-binding", type=Path, required=True)
    ingress.add_argument("--security-payload", type=Path, required=True)
    ingress.add_argument("--socket", required=True)
    ingress.add_argument("--envelope", type=Path, required=True)
    ingress.add_argument("--expected-host-fingerprint", required=True)
    ingress.add_argument("--receipt", type=Path, required=True)
    envelope = commands.add_parser("validate-envelope")
    envelope.add_argument("--envelope", type=Path, required=True)
    envelope.add_argument("--expected-host-fingerprint", required=True)
    envelope.add_argument("--action", choices=tuple(_ACTION_TRANSITIONS), required=True)
    preflight = commands.add_parser("deploy-preflight")
    preflight.add_argument("--profile", type=Path, required=True)
    preflight.add_argument("--envelope", type=Path)
    deploy = commands.add_parser("deploy")
    deploy.add_argument("--profile", type=Path, required=True)
    deploy.add_argument("--envelope", type=Path, required=True)
    deploy.add_argument("--deployment-receipt", type=Path, required=True)
    deploy.add_argument("--action-receipt", type=Path, required=True)
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "self-test":
            result: object = self_test()
        elif arguments.command == "validate-artifact":
            result = validate_artifact(read_json(arguments.artifact, "control artifact"))
        elif arguments.command == "validate-registry":
            result = {"status": "PASS", "domains": sorted(validate_registry(read_json(arguments.registry, "producer registry")))}
        elif arguments.command == "validate-export":
            result = validate_export(
                read_json(arguments.registry, "producer registry"),
                read_json(arguments.binding, "export binding"),
                arguments.payload,
                domain=arguments.domain,
            )
        elif arguments.command == "ingress-once":
            result = run_ingress(arguments)
        elif arguments.command == "validate-envelope":
            document = read_json(arguments.envelope, "action envelope")
            validated = validate_action_envelope(
                document,
                None,
                action=arguments.action,
                expected_host_fingerprint=arguments.expected_host_fingerprint,
            )
            result = {
                "status": "PASS",
                "action": arguments.action,
                "payload_sha256": payload_sha(validated),
            }
        elif arguments.command == "deploy-preflight":
            profile = read_json(arguments.profile, "deploy profile")
            envelope = read_json(arguments.envelope, "action envelope") if arguments.envelope else None
            result = deploy_preflight(profile, envelope)
        elif arguments.command == "deploy":
            result = execute_deploy(arguments)
        else:  # pragma: no cover
            raise PhysicalReleaseError("unsupported command")
        sys.stdout.write(canonical_bytes(result).decode("utf-8") + "\n")
        return 0
    except PhysicalReleaseError:
        sys.stderr.write("physical release control failed closed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(run())


__all__ = [
    "PhysicalReleaseError",
    "canonical_bytes",
    "deploy_preflight",
    "payload_sha",
    "self_test",
    "source_trigger",
    "validate_action_envelope",
    "validate_artifact",
    "validate_deploy_profile",
    "validate_export",
    "validate_registry",
]
