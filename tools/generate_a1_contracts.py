#!/usr/bin/env python3
"""Generate the strict public A1 schemas from the A1 freeze-candidate catalog."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "contracts" / "a1" / "v1" / "catalog.json"
OUTPUT_DIR = CATALOG_PATH.parent


def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def build_schema(name: str, spec: dict, catalog: dict) -> dict:
    integrity_profile = catalog["integrity_profile_id"]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://contracts.dual-contour.invalid/a1/v1/{name}.schema.json",
        "title": name,
        "type": "object",
        "additionalProperties": False,
        "required": catalog["common_required"],
        "properties": {
            "schema_id": {"const": name},
            "schema_version": {"const": catalog["schema_version"]},
            "object_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "issued_at": {"type": "string", "format": "date-time"},
            "issuer": {"const": spec["writer"]},
            "contour": {"const": spec["contour"]},
            "classification": {"enum": spec["classifications"]},
            "payload": {
                "type": "object",
                "additionalProperties": False,
                "required": spec["payload_required"],
                "properties": copy.deepcopy(spec["payload_properties"]),
            },
            "integrity": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile_id", "payload_sha256", "parent_refs"],
                "properties": {
                    "profile_id": {"const": integrity_profile},
                    "payload_sha256": {"$ref": "#/$defs/sha256"},
                    "parent_refs": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "uniqueItems": True,
                    },
                },
            },
        },
        "$defs": copy.deepcopy(catalog["$defs"]),
        "x-dual-contour": {
            "owner": spec["owner"],
            "writer": spec["writer"],
            "authority": spec["authority"],
            "catalog_status": catalog["status"],
            "core_catalog_sha256": catalog["core_catalog_sha256"],
        },
    }


def rendered_schemas() -> dict[Path, str]:
    catalog = load_catalog()
    return {
        OUTPUT_DIR / f"{name}.schema.json": json.dumps(
            build_schema(name, spec, catalog),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
        for name, spec in sorted(catalog["contracts"].items())
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated schemas drift")
    args = parser.parse_args()

    drift: list[str] = []
    for path, expected in rendered_schemas().items():
        if args.check:
            actual = path.read_text(encoding="utf-8") if path.exists() else None
            if actual != expected:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(expected, encoding="utf-8")

    if drift:
        print("A1 generated schema drift:")
        for path in drift:
            print(f"- {path}")
        return 1
    if args.check:
        print("A1 generated schemas: GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
