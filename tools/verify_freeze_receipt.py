#!/usr/bin/env python3
"""Verify that the public contract-freeze receipt still matches its baseline."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs" / "receipts" / "CONTRACTS_FROZEN.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(reason: str) -> None:
    print(f"freeze_receipt=FAILED reason={reason}")
    raise SystemExit(1)


def main() -> int:
    receipt = json.loads(RECEIPT.read_text())
    if receipt.get("status") != "CONTRACTS_FROZEN":
        fail("status")
    checks = {
        "catalog_sha256": ROOT / "contracts" / "catalog.json",
        "ownership_registry_sha256": ROOT / "ownership" / "registry.json",
        "development_agent_contract_sha256": ROOT / "docs" / "DEVELOPMENT_AGENT_CONTRACT.md",
        "agents_sha256": ROOT / "AGENTS.md",
    }
    for field, path in checks.items():
        if receipt.get(field) != sha(path):
            fail(f"hash_mismatch:{field}")

    manifest = "".join(
        f"{path.relative_to(ROOT)} {sha(path)}\n"
        for path in sorted((ROOT / "contracts" / "v1").glob("*.json"))
    )
    if receipt.get("generated_schema_manifest_sha256") != hashlib.sha256(manifest.encode()).hexdigest():
        fail("schema_manifest")
    if receipt.get("schema_count") != len(list((ROOT / "contracts" / "v1").glob("*.json"))):
        fail("schema_count")

    baseline = receipt.get("baseline_head_sha", "")
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{baseline}^{{commit}}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode:
        fail("baseline_commit_missing")
    ci = receipt.get("exact_head_ci", {})
    if ci.get("head_sha") != baseline or ci.get("conclusion") != "success":
        fail("baseline_ci")

    print("freeze_receipt=GREEN")
    print(f"baseline_head_sha={baseline}")
    print(f"catalog_sha256={receipt['catalog_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
