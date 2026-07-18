#!/usr/bin/env python3
"""Validate the non-deploying Stage 4 to A1 isolation/recovery packet."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "ops" / "deploy" / "stage4-a1-isolation-release-packet.json"
EXPECTED_SOURCE_HEAD = "cf33dcea6566e69da0253f6b7613a9761a937713"
EXPECTED_MANIFEST_SHA256 = "9ceae0bda066cf52577cec0fdc1d7230e92b3e4010f65b81613abf6a0a8a90dd"
EXPECTED_PACKET_KEYS = {
    "schema_id", "packet_id", "source_head", "predecessor", "candidate",
    "cutover", "recovery", "authority", "runbook_ref", "integrity",
}
EXPECTED_AUTHORITY = {
    "packet_grants_deployment": False,
    "packet_grants_reboot": False,
    "packet_grants_sudo": False,
    "packet_grants_canonical_mutation": False,
    "packet_grants_live_action": False,
    "deployment_approval_receipt_required": True,
}


class Stage4PacketError(RuntimeError):
    """Packet, unit, or runbook violates the frozen preparation boundary."""


def _strict_json(path: Path) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise Stage4PacketError(f"duplicate JSON key in {path.name}")
            value[key] = item
        return value

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                Stage4PacketError(f"non-finite JSON value: {token}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Stage4PacketError(f"cannot read strict JSON: {path}") from exc
    if not isinstance(value, dict):
        raise Stage4PacketError("packet must be a JSON object")
    return value


def _digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise Stage4PacketError(f"cannot hash {path}") from exc


def _payload_digest(packet: Mapping[str, object]) -> str:
    payload = {key: value for key, value in packet.items() if key != "integrity"}
    try:
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise Stage4PacketError("packet is not canonical JSON data") from exc
    return hashlib.sha256(encoded).hexdigest()


def validate_packet(root: Path = ROOT, *, packet: Mapping[str, object] | None = None) -> dict[str, object]:
    value = dict(packet) if packet is not None else _strict_json(root / PACKET.relative_to(ROOT))
    if set(value) != EXPECTED_PACKET_KEYS or value.get("schema_id") != "research-os.stage4-a1-isolation-release-packet.v1":
        raise Stage4PacketError("packet identity or shape mismatch")
    if value.get("source_head") != EXPECTED_SOURCE_HEAD:
        raise Stage4PacketError("packet source head mismatch")
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{EXPECTED_SOURCE_HEAD}^{{commit}}"],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if exists.returncode != 0:
        raise Stage4PacketError("packet source head does not exist")

    predecessor = value.get("predecessor")
    candidate = value.get("candidate")
    cutover = value.get("cutover")
    recovery = value.get("recovery")
    authority = value.get("authority")
    integrity = value.get("integrity")
    for label, item in (
        ("predecessor", predecessor), ("candidate", candidate), ("cutover", cutover),
        ("recovery", recovery), ("authority", authority), ("integrity", integrity),
    ):
        if not isinstance(item, Mapping):
            raise Stage4PacketError(f"{label} shape mismatch")

    manifest = root / "docs" / "receipts" / "release" / "s4-release-manifest.json"
    if predecessor.get("release_manifest_sha256") != EXPECTED_MANIFEST_SHA256 or _digest(manifest) != EXPECTED_MANIFEST_SHA256:
        raise Stage4PacketError("predecessor immutable release manifest mismatch")
    legacy = set(predecessor.get("mutable_namespaces", []))
    current = set(candidate.get("mutable_namespaces", []))
    if not legacy or not current or legacy & current or cutover.get("namespace_intersection") != []:
        raise Stage4PacketError("Stage 4 and A1 mutable namespaces are not isolated")
    if (
        cutover.get("concurrent_activation") is not False
        or cutover.get("predecessor_must_be_stopped") is not True
        or cutover.get("single_writer_required") is not True
        or cutover.get("automatic_cutover") is not False
        or candidate.get("runtime_model") != "ONE_BRIDGE_PROCESS_ONE_LEDGER_ONE_WRITER_A1_ADDITIVE"
    ):
        raise Stage4PacketError("cutover can create concurrent writers")

    unit_ref = candidate.get("unit_ref")
    if not isinstance(unit_ref, str) or not unit_ref.startswith("ops/deploy/"):
        raise Stage4PacketError("candidate unit ref is invalid")
    unit_path = root / unit_ref
    if candidate.get("unit_sha256") != _digest(unit_path):
        raise Stage4PacketError("candidate unit digest mismatch")
    try:
        unit = unit_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise Stage4PacketError("candidate unit cannot be read") from exc
    if (
        candidate.get("supervisor") != "systemd-user"
        or candidate.get("container_restart_policy") != "no"
        or candidate.get("systemd_restart_policy") != "on-failure"
        or unit.count("--restart=no") != 1
        or "--restart=unless-stopped" in unit
        or len(re.findall(r"(?m)^Restart=on-failure$", unit)) != 1
        or "research-os-bridge-runtime" in unit
        or "research-os-bridge-config" in unit
        or "source=research-os-a1-runtime" not in unit
        or "source=research-os-a1-config" not in unit
    ):
        raise Stage4PacketError("candidate does not have one supervisor and isolated mounts")

    if (
        recovery.get("r0_pre_authorized") is not True
        or recovery.get("r0_scope") != "SAME_RELEASE_SAME_IMAGE_SAME_POLICY_SAME_CONFIG_SAME_SCHEMA_ONLY"
        or recovery.get("changed_release_requires_human_approval") is not True
        or recovery.get("rollback_requires_receipt") is not True
        or recovery.get("restore_requires_clean-verification") is not True
    ):
        raise Stage4PacketError("recovery authority is too broad")
    if dict(authority) != EXPECTED_AUTHORITY:
        raise Stage4PacketError("packet grants external or canonical authority")
    if integrity.get("profile") != "core-json-sha256-v1" or integrity.get("payload_sha256") != _payload_digest(value):
        raise Stage4PacketError("packet integrity mismatch")

    runbook_ref = value.get("runbook_ref")
    if not isinstance(runbook_ref, str) or not re.fullmatch(r"docs/[A-Z0-9_]+\.md", runbook_ref):
        raise Stage4PacketError("runbook ref is invalid")
    try:
        runbook = (root / runbook_ref).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise Stage4PacketError("runbook cannot be read") from exc
    required_runbook = (
        "VPS-only preflight", "Same-release R0 recovery", "Changed release cutover",
        "DeploymentApprovalReceipt", "Automatic cutover is forbidden",
        "systemctl --user restart research-os-a1-bridge.service",
    )
    if any(item not in runbook for item in required_runbook):
        raise Stage4PacketError("runbook omits a mandatory boundary or command")
    return value


def main() -> int:
    value = validate_packet()
    print(f"stage4_a1_isolation_packet=GREEN:{value['packet_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
