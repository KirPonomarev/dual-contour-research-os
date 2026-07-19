#!/usr/bin/env python3
"""Validate the additive E5 MethodCard catalog without rewriting Core freeze."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "provenance" / "method-card-declassification-v1.json"
CATALOG = ROOT / "contracts" / "e5" / "v1" / "catalog.json"
SCHEMAS = {
    "DeclassificationReceipt": ROOT / "contracts" / "e5" / "v1" / "DeclassificationReceipt.schema.json",
    "MethodCard": ROOT / "contracts" / "e5" / "v1" / "MethodCard.schema.json",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if profile.get("core_catalog_sha256") != _sha(ROOT / "contracts" / "catalog.json"):
        raise SystemExit("e5_contract_validation=FAILED reason=core_catalog_drift")
    if profile.get("e5_catalog_sha256") != _sha(CATALOG):
        raise SystemExit("e5_contract_validation=FAILED reason=e5_catalog_drift")
    if catalog.get("status") != "frozen-additive" or catalog.get("core_catalog_sha256") != profile["core_catalog_sha256"]:
        raise SystemExit("e5_contract_validation=FAILED reason=catalog_boundary")
    expected = {
        "DeclassificationReceipt": ("domain-declassification-authority", "method-transfer-eligibility-only"),
        "MethodCard": ("domain-declassification-authority", "declassified-method-reference-only"),
    }
    if set(catalog.get("contracts", {})) != set(expected):
        raise SystemExit("e5_contract_validation=FAILED reason=catalog_contract_set")
    for name, path in SCHEMAS.items():
        schema = json.loads(path.read_text(encoding="utf-8"))
        if profile["schema_sha256"].get(name) != _sha(path):
            raise SystemExit(f"e5_contract_validation=FAILED reason=schema_digest:{name}")
        writer, authority = expected[name]
        if schema.get("title") != name or schema.get("additionalProperties") is not False:
            raise SystemExit(f"e5_contract_validation=FAILED reason=schema_shape:{name}")
        if schema.get("x-owner") != "domain" or schema.get("x-writer") != writer or schema.get("x-authority") != authority:
            raise SystemExit(f"e5_contract_validation=FAILED reason=schema_authority:{name}")
        if schema["properties"]["payload"].get("additionalProperties") is not False:
            raise SystemExit(f"e5_contract_validation=FAILED reason=payload_open:{name}")
    print("e5_contract_validation=GREEN")
    print("e5_contracts=2")
    print("core_catalog_sha256=" + profile["core_catalog_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
