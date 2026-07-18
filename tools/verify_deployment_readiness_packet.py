#!/usr/bin/env python3
"""Fail-closed structural deployment-readiness verifier; performs no external action."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "ops/deploy/deployment-readiness-packet.json"
SOURCE_HEAD = "94f203fc2e0fb85a6578d78a22b0f0bcefdf4c9b"


class ReadinessError(RuntimeError):
    pass


def digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ReadinessError(f"missing readiness dependency: {path}") from exc


def payload_digest(value: Mapping[str, object]) -> str:
    payload = {key: item for key, item in value.items() if key != "integrity"}
    try:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ReadinessError("readiness packet is not canonical JSON data") from exc
    return hashlib.sha256(raw).hexdigest()


def load_packet(path: Path = PACKET) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise ReadinessError("duplicate JSON key")
            value[key] = item
        return value
    try:
        value = json.loads(path.read_text(), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ReadinessError("non-finite JSON")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadinessError("invalid readiness packet") from exc
    if not isinstance(value, dict):
        raise ReadinessError("readiness packet must be an object")
    return value


def validate(root: Path = ROOT, packet: Mapping[str, object] | None = None) -> dict[str, object]:
    value = dict(packet) if packet is not None else load_packet(root / PACKET.relative_to(ROOT))
    expected_keys = {"schema_id", "packet_id", "source_head", "exact_head_ci", "release", "isolation", "backup_draft", "restore_draft", "rollback", "authority", "readiness", "integrity"}
    if set(value) != expected_keys or value.get("schema_id") != "research-os.deployment-readiness-packet.v1" or value.get("source_head") != SOURCE_HEAD:
        raise ReadinessError("readiness identity or shape mismatch")
    if subprocess.run(["git", "cat-file", "-e", f"{SOURCE_HEAD}^{{commit}}"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode != 0:
        raise ReadinessError("readiness source head does not exist")
    ci = value["exact_head_ci"]
    release = value["release"]
    isolation = value["isolation"]
    backup = value["backup_draft"]
    restore = value["restore_draft"]
    rollback = value["rollback"]
    authority = value["authority"]
    readiness = value["readiness"]
    integrity = value["integrity"]
    if any(not isinstance(item, Mapping) for item in (ci, release, isolation, backup, restore, rollback, authority, readiness, integrity)):
        raise ReadinessError("readiness section shape mismatch")
    if ci.get("conclusion") != "success" or ci.get("run_id") != 29659711260 or SOURCE_HEAD not in str(value.get("source_head")):
        raise ReadinessError("exact-head CI is not green")
    refs = (
        (release, "manifest_ref", "manifest_sha256"),
        (isolation, "packet_ref", "packet_sha256"),
        (isolation, "integration_ref", "integration_sha256"),
        (backup, "controller_ref", "controller_sha256"),
        (authority, "approval_issuer_ref", "approval_issuer_sha256"),
    )
    for section, ref_key, hash_key in refs:
        ref = section.get(ref_key)
        if not isinstance(ref, str) or digest(root / ref) != section.get(hash_key):
            raise ReadinessError(f"readiness dependency drift: {ref_key}")
    manifest = load_packet(root / str(release["manifest_ref"]))
    manifest_payload = manifest.get("payload")
    if not isinstance(manifest_payload, Mapping):
        raise ReadinessError("release manifest shape mismatch")
    for key in ("release_sha", "policy_sha256", "config_sha256", "schema_sha256"):
        if release.get(key) != manifest_payload.get(key):
            raise ReadinessError(f"release binding mismatch: {key}")
    if release.get("image_id") not in manifest_payload.get("image_digests", []):
        raise ReadinessError("release image binding mismatch")
    if (
        backup.get("state") != "RUNTIME_EVIDENCE_REQUIRED" or backup.get("encrypted") is not True
        or backup.get("off_host") is not True or backup.get("repository_locator_in_git") is not False
        or backup.get("credential_in_git") is not False or restore.get("state") != "RUNTIME_EVIDENCE_REQUIRED"
        or restore.get("clean_target_required") is not True or restore.get("manifest_equality_required") is not True
        or restore.get("destructive_restore") is not False
    ):
        raise ReadinessError("backup or restore draft overclaims runtime evidence")
    if rollback.get("target") != manifest_payload.get("previous_release_ref") or rollback.get("receipt_required") is not True:
        raise ReadinessError("rollback target is not exact and receipted")
    if (
        authority.get("deployment_approval_receipt_required") is not True
        or authority.get("human_confirmation_required") is not True
        or authority.get("maximum_approval_ttl_seconds") != 300
        or authority.get("packet_grants_external_action") is not False
    ):
        raise ReadinessError("human authority boundary widened")
    if readiness != {
        "structural_deployability": "PASS_FOR_FROZEN_SCOPE",
        "backup_restore_path": "EXECUTABLE_SYNTHETIC_PROOF",
        "actual_backup_receipt": "WAIT_OPERATOR_RUNTIME_EVIDENCE",
        "actual_restore_receipt": "WAIT_OPERATOR_RUNTIME_EVIDENCE",
        "deployment_authority": "WAIT_HUMAN_AUTHORITY",
        "status": "READY_FOR_HUMAN_REVIEW_NOT_READY_TO_DEPLOY",
    }:
        raise ReadinessError("readiness status overclaims deployability")
    if integrity.get("profile") != "core-json-sha256-v1" or integrity.get("payload_sha256") != payload_digest(value):
        raise ReadinessError("readiness packet integrity mismatch")
    return value


def main() -> int:
    value = validate()
    print(f"deployment_readiness=GREEN:{value['readiness']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
