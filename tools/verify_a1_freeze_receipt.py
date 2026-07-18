#!/usr/bin/env python3
"""Verify the additive A1 authority-freeze receipt and immutable candidate chain."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs" / "receipts" / "A1_CONTRACTS_FROZEN.json"
A1_DIR = ROOT / "contracts" / "a1" / "v1"
CANDIDATE_RECEIPT = ROOT / "docs" / "receipts" / "integration" / "e0-a1-contract-candidate.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_sha(paths: list[Path]) -> str:
    manifest = "".join(f"{path.relative_to(ROOT)} {sha(path)}\n" for path in paths)
    return hashlib.sha256(manifest.encode()).hexdigest()


def fail(reason: str) -> None:
    print(f"a1_freeze_receipt=FAILED reason={reason}")
    raise SystemExit(1)


def commit_exists(value: str) -> bool:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{value}^{{commit}}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def main() -> int:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if receipt.get("receipt_type") != "A1_CONTRACTS_FROZEN":
        fail("type")
    if receipt.get("receipt_version") != "1.0.0":
        fail("version")
    if receipt.get("status") != "A1_CONTRACTS_FROZEN" or receipt.get("issuer") != "agent-0":
        fail("status_or_issuer")

    exact_hashes = {
        "core_catalog_sha256": ROOT / "contracts" / "catalog.json",
        "a1_catalog_sha256": A1_DIR / "catalog.json",
        "ownership_registry_sha256": ROOT / "ownership" / "registry.json",
        "candidate_integration_receipt_sha256": CANDIDATE_RECEIPT,
    }
    for field, path in exact_hashes.items():
        if receipt.get(field) != sha(path):
            fail(f"hash_mismatch:{field}")

    catalog = json.loads((A1_DIR / "catalog.json").read_text(encoding="utf-8"))
    if catalog.get("status") != "frozen":
        fail("catalog_status")
    profile_paths = sorted((A1_DIR / "profiles").glob("*.json"))
    schema_paths = sorted(A1_DIR.glob("*.schema.json"))
    if receipt.get("profile_count") != len(profile_paths):
        fail("profile_count")
    if receipt.get("schema_count") != len(schema_paths):
        fail("schema_count")
    if receipt.get("profile_manifest_sha256") != manifest_sha(profile_paths):
        fail("profile_manifest")
    if receipt.get("generated_schema_manifest_sha256") != manifest_sha(schema_paths):
        fail("schema_manifest")
    for path in profile_paths:
        if json.loads(path.read_text(encoding="utf-8")).get("status") != "frozen":
            fail(f"profile_status:{path.name}")

    frozen_head = receipt.get("frozen_bundle_head_sha", "")
    if not commit_exists(frozen_head):
        fail("frozen_commit_missing")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", frozen_head, "HEAD"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ancestor.returncode:
        fail("frozen_commit_not_ancestor")
    ci = receipt.get("exact_head_ci", {})
    if ci.get("head_sha") != frozen_head or ci.get("conclusion") != "success":
        fail("exact_head_ci")

    candidate = json.loads(CANDIDATE_RECEIPT.read_text(encoding="utf-8"))
    candidate_audit = candidate.get("payload", {}).get("audit_results", {})
    if candidate_audit.get("a1_catalog_sha256") != receipt.get("candidate_catalog_sha256"):
        fail("candidate_catalog_chain")
    if candidate.get("payload", {}).get("remote_ci_ref") != "https://github.com/KirPonomarev/dual-contour-research-os/actions/runs/29641095258":
        fail("candidate_ci_chain")

    denied = set(receipt.get("scope", {}).get("does_not_allow", []))
    required_denies = {
        "autonomous-canonical-mutation", "promotion-without-human-authority", "publication",
        "live-trading", "live-security-execution", "true-holdout-access",
        "d2-d3-payload-in-public-repository", "bridge-write-of-domain-scientific-truth",
        "deployment", "policy-authority-expansion",
    }
    if not required_denies <= denied:
        fail("scope_denies")

    print("a1_freeze_receipt=GREEN")
    print(f"frozen_bundle_head_sha={frozen_head}")
    print(f"a1_catalog_sha256={receipt['a1_catalog_sha256']}")
    print(f"schemas={len(schema_paths)} profiles={len(profile_paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
