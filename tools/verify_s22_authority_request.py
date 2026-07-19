#!/usr/bin/env python3
"""Verify that S22 is a bounded request and cannot act as authority."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
REQUEST = ROOT / "docs/receipts/requests/s22-final-deployment-authority-request.json"
BASE_SHA = "d28bef12cbf6acd1747ddf0e3ec51671c4ca2dcb"
RELEASE_SHA = "b2c2e6a8c4e0a364ef82e8e51540433aa91430d4"
RELEASE_TREE = "7d6bd1e13d651950cced23dfe75a24946a3218fc"


class AuthorityRequestError(RuntimeError):
    pass


def digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise AuthorityRequestError(f"missing request dependency: {path}") from exc


def payload_digest(value: Mapping[str, object]) -> str:
    payload = {key: item for key, item in value.items() if key != "integrity"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def load(path: Path = REQUEST) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorityRequestError("authority request is invalid JSON") from exc
    if not isinstance(value, dict):
        raise AuthorityRequestError("authority request must be an object")
    return value


def validate(root: Path = ROOT, request: Mapping[str, object] | None = None) -> dict[str, object]:
    value = dict(request) if request is not None else load(root / REQUEST.relative_to(ROOT))
    if value.get("schema_id") != "research-os.human-authority-request.v1" or value.get("request_base_sha") != BASE_SHA:
        raise AuthorityRequestError("request identity mismatch")
    if subprocess.run(["git", "cat-file", "-e", f"{BASE_SHA}^{{commit}}"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode != 0:
        raise AuthorityRequestError("request base does not exist")
    if value.get("status") != "WAIT_HUMAN_REVIEW" or value.get("grants_authority") is not False or value.get("review_decision") != "PENDING":
        raise AuthorityRequestError("request impersonates approval")
    issued = datetime.fromisoformat(str(value["issued_at"]).replace("Z", "+00:00"))
    expires = datetime.fromisoformat(str(value["valid_until"]).replace("Z", "+00:00"))
    if issued.tzinfo is None or issued.utcoffset() != timezone.utc.utcoffset(issued) or not issued < expires <= issued + timedelta(days=1):
        raise AuthorityRequestError("request validity window is invalid")
    release = value.get("release_proposal")
    evidence = value.get("evidence")
    blast = value.get("blast_radius")
    integrity = value.get("integrity")
    if any(not isinstance(item, Mapping) for item in (release, evidence, blast, integrity)):
        raise AuthorityRequestError("request section shape mismatch")
    for ref_key, hash_key in (("manifest_ref", "manifest_sha256"),):
        if digest(root / str(release[ref_key])) != release.get(hash_key):
            raise AuthorityRequestError("release proposal drift")
    for ref_key, hash_key in (
        ("final_deployment_packet_ref", "final_deployment_packet_sha256"),
        ("final_freeze_receipt_ref", "final_freeze_receipt_sha256"),
        ("readiness_packet_ref", "readiness_packet_sha256"),
        ("isolation_packet_ref", "isolation_packet_sha256"),
        ("runbook_ref", "runbook_sha256"),
    ):
        if digest(root / str(evidence[ref_key])) != evidence.get(hash_key):
            raise AuthorityRequestError("request evidence drift")
    if (
        release.get("final_release_rebind_required") is not False
        or release.get("release_sha") != RELEASE_SHA
        or release.get("release_tree_sha") != RELEASE_TREE
        or release.get("image_build_state") != "WAIT_AUTHORIZED_DEPLOYMENT_PREFLIGHT"
        or evidence.get("exact_head_ci_sha") != BASE_SHA
        or evidence.get("exact_head_ci_run") != 29668388814
    ):
        raise AuthorityRequestError("request could authorize a stale final release")
    if blast != {"service": "research-os-a1-bridge.service", "container": "research-os-a1-bridge", "network": "none", "published_ports": 0, "live_capability": False, "canonical_mutation": False, "concurrent_predecessor_writer": False}:
        raise AuthorityRequestError("blast radius widened")
    required_denies = {"AUTO_APPROVAL", "AUTO_EXECUTE", "SUDO_BYPASS", "UNAPPROVED_REBOOT_OR_RESTORE", "LIVE_TRADING", "AUTONOMOUS_LIVE_SECURITY", "PUBLICATION", "CANONICAL_OR_POLICY_MUTATION"}
    if set(value.get("hard_denies", [])) != required_denies:
        raise AuthorityRequestError("hard-deny set drifted")
    preconditions = set(value.get("mandatory_preconditions", []))
    if not {"S38_FINAL_RELEASE_FREEZE_COMPLETE", "EXACT_FINAL_SHA_TREE_AND_RELEASE_MANIFEST_REVIEWED", "EXACT_IMAGE_BUILD_AND_LABELS_VERIFIED", "UNCONSUMED_MAX_300_SECOND_DEPLOYMENT_APPROVAL_RECEIPT", "CURRENT_ENCRYPTED_BACKUP_RECEIPT_PRESENT", "CLEAN_RESTORE_CONTROLLER_SYNTHETIC_PROOF_PRESENT"} <= preconditions:
        raise AuthorityRequestError("mandatory human/deployment preconditions missing")
    if integrity.get("profile") != "core-json-sha256-v1" or integrity.get("payload_sha256") != payload_digest(value):
        raise AuthorityRequestError("request integrity mismatch")
    return value


def main() -> int:
    request = validate()
    print(f"s22_authority_request=GREEN:{request['status']}:grants_authority=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
