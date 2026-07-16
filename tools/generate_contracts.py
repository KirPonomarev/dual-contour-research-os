#!/usr/bin/env python3
"""Generate one strict JSON Schema per contract from the canonical catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "contracts" / "catalog.json"
OUT = ROOT / "contracts" / "v1"


def field_schema(kind: str) -> dict:
    if kind == "string":
        return {"type": "string", "minLength": 1}
    if kind == "sha256":
        return {"type": "string", "pattern": "^[a-f0-9]{64}$"}
    if kind == "integer":
        return {"type": "integer", "minimum": 0}
    if kind == "number":
        return {"type": "number", "minimum": 0}
    if kind == "boolean":
        return {"type": "boolean"}
    if kind == "array":
        return {"type": "array"}
    if kind == "string_array":
        return {"type": "array", "items": {"type": "string", "minLength": 1}}
    if kind == "integer_array":
        return {"type": "array", "items": {"type": "integer"}}
    if kind == "object":
        return {"type": "object"}
    raise ValueError(f"unknown field kind: {kind}")


def build_schema(name: str, version: str, spec: dict) -> dict:
    payload_fields = spec["required_payload"]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://github.com/KirPonomarev/dual-contour-research-os/contracts/v1/{name}.schema.json",
        "title": name,
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_id",
            "schema_version",
            "object_id",
            "issued_at",
            "issuer",
            "contour",
            "classification",
            "payload",
            "integrity",
        ],
        "properties": {
            "schema_id": {"const": name},
            "schema_version": {"const": version},
            "object_id": {"type": "string", "minLength": 1},
            "issued_at": {"type": "string", "format": "date-time"},
            "issuer": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "authority_class"],
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "authority_class": {"type": "string", "minLength": 1},
                },
            },
            "contour": {"enum": ["bridge", "market", "security", "governance"]},
            "classification": {
                "enum": [
                    "D0_PUBLIC",
                    "D1_INTERNAL_SANITIZED",
                    "D2_DOMAIN_CONFIDENTIAL",
                    "D3_RESTRICTED",
                ]
            },
            "payload": {
                "type": "object",
                "additionalProperties": False,
                "required": list(payload_fields),
                "properties": {key: field_schema(kind) for key, kind in payload_fields.items()},
            },
            "integrity": {
                "type": "object",
                "additionalProperties": False,
                "required": ["payload_sha256", "parent_refs"],
                "properties": {
                    "payload_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    "parent_refs": {"type": "array", "items": {"type": "string", "minLength": 1}},
                },
            },
        },
        "x-owner": spec["owner"],
        "x-writer": spec["writer"],
        "x-authority": spec["authority"],
    }


def encoded(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    catalog = json.loads(CATALOG.read_text())
    version = catalog["schema_version"]
    OUT.mkdir(parents=True, exist_ok=True)
    expected_names = set()
    failures = []

    for name, spec in sorted(catalog["contracts"].items()):
        target = OUT / f"{name}.schema.json"
        expected_names.add(target.name)
        content = encoded(build_schema(name, version, spec))
        if args.check:
            if not target.exists() or target.read_bytes() != content:
                failures.append(str(target.relative_to(ROOT)))
        else:
            target.write_bytes(content)

    extras = sorted(path.name for path in OUT.glob("*.schema.json") if path.name not in expected_names)
    if extras:
        failures.extend(f"unexpected:{name}" for name in extras)

    digest = hashlib.sha256(CATALOG.read_bytes()).hexdigest()
    if failures:
        print("contract_generation=FAILED")
        print("mismatches=" + ",".join(failures))
        return 1
    print("contract_generation=GREEN")
    print(f"catalog_sha256={digest}")
    print(f"schemas={len(expected_names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
