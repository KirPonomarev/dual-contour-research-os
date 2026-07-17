#!/usr/bin/env python3
"""Verify the immutable candidate ReleaseManifest and its committed SPDX SBOM."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RELEASE_SHA = "5c2bd7c090fada6e5b65dc955e80b256d88252de"
IMAGE_DIGEST = "sha256:36069ee7a9db78af747d7fad65f9e33073824f27be898cdc0b7dd3b77ac5c235"
BASE_DIGEST = "65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d"
CI_REF = "https://github.com/KirPonomarev/dual-contour-research-os/actions/runs/29618911213"
COMMON_FIELDS = {"schema_id", "schema_version", "object_id", "issued_at", "issuer", "contour", "classification", "payload", "integrity"}
PAYLOAD_FIELDS = {"release_sha", "image_digests", "policy_sha256", "config_sha256", "schema_sha256", "dependency_lock_sha256", "sbom_ref", "previous_release_ref"}


def _json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"invalid artifact: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"artifact is not an object: {path.name}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inspect(root: Path = ROOT, *, check_git: bool = True) -> dict[str, Any]:
    failures: list[str] = []
    manifest_path = root / "docs/receipts/release/s4-release-manifest.json"
    sbom_path = root / "docs/receipts/release/s4-release-sbom.spdx.json"
    manifest = _json(manifest_path)
    sbom = _json(sbom_path)
    payload = manifest.get("payload")
    integrity = manifest.get("integrity")
    if set(manifest) != COMMON_FIELDS or manifest.get("schema_id") != "ReleaseManifest" or manifest.get("schema_version") != "1.0.0":
        failures.append("manifest.schema")
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        failures.append("manifest.payload_shape")
        payload = {}
    if not isinstance(integrity, dict) or integrity.get("payload_sha256") != _payload_sha(payload):
        failures.append("manifest.payload_integrity")
    sbom_sha = _sha(sbom_path)
    expected = {
        "release_sha": RELEASE_SHA,
        "image_digests": [IMAGE_DIGEST],
        "policy_sha256": _sha(root / "ops/release/runtime-policy.json"),
        "config_sha256": _sha(root / "ops/release/researchd.config.template.json"),
        "schema_sha256": _sha(root / "contracts/catalog.json"),
        "dependency_lock_sha256": _sha(root / "ops/release/dependency-lock.json"),
        "sbom_ref": f"artifact:sha256:{sbom_sha}",
        "previous_release_ref": "release:none-service-stopped",
    }
    if payload != expected:
        failures.append("manifest.binding")
    parents = integrity.get("parent_refs", []) if isinstance(integrity, dict) else []
    for required in (f"git:{RELEASE_SHA}", "ci:29618911213", f"image:{IMAGE_DIGEST}", f"artifact:sha256:{sbom_sha}"):
        if required not in parents:
            failures.append("manifest.parent_binding")
            break
    packages = sbom.get("packages")
    relationships = sbom.get("relationships")
    if sbom.get("spdxVersion") != "SPDX-2.3" or not isinstance(packages, list) or len(packages) != 107:
        failures.append("sbom.shape")
        packages = []
    ids = [row.get("SPDXID") for row in packages if isinstance(row, dict)]
    if len(ids) != len(set(ids)) or "SPDXRef-ReleaseImage" not in ids or "SPDXRef-PythonRuntime" not in ids:
        failures.append("sbom.identities")
    image = next((row for row in packages if isinstance(row, dict) and row.get("SPDXID") == "SPDXRef-ReleaseImage"), {})
    python = next((row for row in packages if isinstance(row, dict) and row.get("SPDXID") == "SPDXRef-PythonRuntime"), {})
    if image.get("versionInfo") != RELEASE_SHA or image.get("checksums") != [{"algorithm": "SHA256", "checksumValue": IMAGE_DIGEST.removeprefix("sha256:")}]:
        failures.append("sbom.image_binding")
    if python.get("versionInfo") != "3.11.14" or python.get("checksums") != [{"algorithm": "SHA256", "checksumValue": BASE_DIGEST}]:
        failures.append("sbom.base_binding")
    related = {row.get("relatedSpdxElement") for row in relationships if isinstance(row, dict)} if isinstance(relationships, list) else set()
    if any(identifier not in related and identifier != "SPDXRef-ReleaseImage" for identifier in ids):
        failures.append("sbom.relationships")
    integration = _json(root / "docs/receipts/integration/s4-rootless-release-blueprint.json")
    audit = integration.get("payload", {}).get("audit_results", {})
    if integration.get("payload", {}).get("head_sha") != RELEASE_SHA or integration.get("payload", {}).get("remote_ci_ref") != CI_REF or audit.get("candidate_image_id") != IMAGE_DIGEST:
        failures.append("integration.binding")
    if check_git:
        result = subprocess.run(["git", "cat-file", "-e", f"{RELEASE_SHA}^{{commit}}"], cwd=root, check=False, capture_output=True)
        if result.returncode != 0:
            failures.append("release_sha.missing")
    if not re.fullmatch(r"[a-f0-9]{64}", sbom_sha):
        failures.append("sbom.digest")
    return {
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "release_sha": RELEASE_SHA,
        "image_digest": IMAGE_DIGEST,
        "sbom_sha256": sbom_sha,
        "sbom_package_count": len(packages),
        "declares_ready_for_72h_soak": False,
        "external_action_authority": False,
    }


def main() -> int:
    result = inspect()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
