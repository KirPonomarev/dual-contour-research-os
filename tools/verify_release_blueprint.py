#!/usr/bin/env python3
"""Verify the deterministic, rootless, no-network release image blueprint."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPS = ROOT / "ops" / "release"
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.researchd import (  # noqa: E402
    _ServiceConfigError,
    _service_config_from_mapping,
)

BASE_DIGEST = "sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_TRUSTED_SCHEMAS = {
    "JobSpec",
    "Permit",
    "AttemptLease",
    "PolicySnapshot",
    "ApprovalReceipt",
}
_LEGACY_CONFIG_KEYS = {
    "schema_id",
    "schema_version",
    "runtime_root",
    "runner_identity",
    "allowed_uids",
    "input_quota_bytes",
    "checkpoint_quota_bytes",
    "artifact_quota_bytes",
    "maximum_input_bytes",
    "deadline_seconds",
    "trusted_issuers",
    "policy_snapshots",
    "approval_receipts",
}
_A1_CONFIG_KEYS = _LEGACY_CONFIG_KEYS | {
    "a1_enabled",
    "principal_roles",
    "frozen_bindings",
    "a1_limits",
}
_EXPECTED_BUILD_CONTEXT = (
    "**",
    "!src/",
    "!src/**",
    "!tools/",
    "!tools/model_provider_shadow.py",
    "!provenance/",
    "!provenance/model-provider-connected-shadow-v2.json",
    "!provenance/model-provider-routing-v1.json",
    "!provenance/model-worker-ipc-extension-v1.json",
    "!contracts/",
    "!contracts/catalog.json",
    "!contracts/a1/",
    "!contracts/a1/v1/",
    "!contracts/a1/v1/**",
    "!contracts/a1/v1/profiles/",
    "!contracts/a1/v1/profiles/model_role_registry_v1.json",
    "!ops/",
    "!ops/connected-worker/",
    "!ops/connected-worker/**",
)


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


def _config_mode(config: dict[str, Any]) -> str | None:
    """Classify only an exact legacy boundary or a parseable full A1 boundary."""

    common = (
        config.get("schema_id") == "ResearchdServiceConfig"
        and config.get("runtime_root") == "/var/lib/research-os"
        and set(config.get("trusted_issuers", {})) == _TRUSTED_SCHEMAS
        and config.get("approval_receipts") == {}
    )
    if not common:
        return None
    if set(config) == _LEGACY_CONFIG_KEYS:
        if (
            config.get("schema_version") == "1.0.0"
            and config.get("allowed_uids") == [10001]
            and config.get("policy_snapshots") == {}
        ):
            return "legacy-operator-only"
        return None
    if set(config) != _A1_CONFIG_KEYS:
        return None
    if (
        config.get("schema_version") != "1.1.0"
        or config.get("a1_enabled") is not True
        or config.get("allowed_uids") != [10001, 10002, 10003]
        or config.get("principal_roles")
        != {"10001": "operator", "10002": "collector", "10003": "scout"}
    ):
        return None
    bindings = config.get("frozen_bindings")
    policies = config.get("policy_snapshots")
    if (
        not isinstance(bindings, dict)
        or not isinstance(policies, dict)
        or len(policies) != 1
        or _SHA256.fullmatch(str(bindings.get("policy_sha256"))) is None
        or set(policies) != {bindings.get("policy_sha256")}
    ):
        return None
    try:
        _service_config_from_mapping(config)
    except (TypeError, ValueError, _ServiceConfigError):
        return None
    return "a1-enabled"


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
            "COPY --chown=10001:10001 contracts/catalog.json /opt/research-os/contracts/catalog.json",
            "COPY --chown=10001:10001 contracts/a1/v1/ /opt/research-os/contracts/a1/v1/",
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
        config_mode = _config_mode(config)
        if config_mode is None:
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
        if tuple(dockerignore.splitlines()) != _EXPECTED_BUILD_CONTEXT:
            failures.append("build_context.not_minimal")
        return {
            "status": "PASS" if not failures else "FAIL",
            "failures": failures,
            "base_digest": BASE_DIGEST,
            "platform": "linux/amd64",
            "network_at_runtime": False,
            "external_action_authority": False,
            "config_mode": config_mode,
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
