#!/usr/bin/env python3
"""Verify the deterministic, rootless, no-network release image blueprint."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / "ops" / "release"
BASE_DIGEST = "sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d"


class BlueprintError(RuntimeError):
    pass


def _load(name: str) -> dict[str, Any]:
    path = OPS / name
    if path.is_symlink() or not path.is_file():
        raise BlueprintError(f"{name} must be a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BlueprintError(f"{name} is invalid") from exc
    if not isinstance(value, dict):
        raise BlueprintError(f"{name} must be an object")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect(root: Path = ROOT) -> dict[str, Any]:
    global ROOT, OPS
    prior_root, prior_ops = ROOT, OPS
    ROOT, OPS = root, root / "ops" / "release"
    try:
        containerfile = (OPS / "Containerfile").read_text(encoding="utf-8")
        lock = _load("dependency-lock.json")
        config = _load("researchd.config.template.json")
        policy = _load("runtime-policy.json")
        notice = (OPS / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

        failures: list[str] = []
        required_lines = (
            f"FROM python@{BASE_DIGEST}",
            "ARG RELEASE_SHA",
            'org.opencontainers.image.revision="${RELEASE_SHA}"',
            "COPY --chown=10001:10001 src/ /opt/research-os/src/",
            "USER 10001:10001",
            'ENTRYPOINT ["python", "-m", "research_bridge.researchd"]',
            'CMD ["--config", "/run/research-os/researchd.json"]',
        )
        if any(line not in containerfile for line in required_lines):
            failures.append("container.required_boundary")
        upper = containerfile.upper()
        if " ADD " in f" {upper} " or any(term in containerfile for term in ("apt-get", "curl ", "wget ", "pip install")):
            failures.append("container.unpinned_install_or_add")
        if lock != {
            "schema_version": "research-os.release-dependency-lock.v1",
            "platform": "linux/amd64",
            "base_image": f"docker.io/library/python@{BASE_DIGEST}",
            "base_tag_observed": "python:3.11.14-slim-bookworm",
            "python_version": "3.11.14",
            "python_dependencies": [],
            "operating_system_family": "debian-bookworm",
            "transitive_package_inventory": "generated-from-image-dpkg-query-and-bound-in-release-SBOM",
            "network_required_at_runtime": False,
        }:
            failures.append("dependency_lock.drift")
        if (
            config.get("schema_id") != "ResearchdServiceConfig"
            or config.get("allowed_uids") != [10001]
            or config.get("runtime_root") != "/var/lib/research-os"
            or config.get("policy_snapshots") != {}
            or config.get("approval_receipts") != {}
            or set(config.get("trusted_issuers", {})) != {"JobSpec", "Permit", "AttemptLease", "PolicySnapshot", "ApprovalReceipt"}
        ):
            failures.append("config.boundary")
        expected_policy = {
            "network": "none",
            "published_ports": [],
            "read_only_root_filesystem": True,
            "cap_drop": ["ALL"],
            "security_options": ["no-new-privileges:true"],
            "user": "10001:10001",
            "control_transport": "AF_UNIX",
            "external_action_authority": False,
        }
        if any(policy.get(key) != value for key, value in expected_policy.items()):
            failures.append("runtime_policy.boundary")
        if BASE_DIGEST not in notice or "/usr/local/lib/python3.11/LICENSE.txt" not in notice or "/usr/share/doc/*/copyright" not in notice:
            failures.append("third_party_notice.incomplete")
        if dockerignore.splitlines() != ["**", "!src/", "!src/**"]:
            failures.append("build_context.not_minimal")
        return {
            "status": "PASS" if not failures else "FAIL",
            "failures": failures,
            "base_digest": BASE_DIGEST,
            "platform": "linux/amd64",
            "network_at_runtime": False,
            "external_action_authority": False,
            "hashes": {
                name: _sha(OPS / name)
                for name in (
                    "Containerfile",
                    "dependency-lock.json",
                    "researchd.config.template.json",
                    "runtime-policy.json",
                    "THIRD_PARTY_NOTICES.md",
                )
            } | {"dockerignore": _sha(ROOT / ".dockerignore")},
        }
    finally:
        ROOT, OPS = prior_root, prior_ops


def main() -> int:
    result = inspect()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
