#!/usr/bin/env python3
"""Strict current-release context validation with zero external side effects."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Mapping

from capability_proof import (
    CapabilityProofError,
    assess_capability_proof,
    canonical_json_sha256,
    validate_capability_proof,
)


_GIT_RE = re.compile(r"^[a-f0-9]{40}$")
_SHA_RE = re.compile(r"^[a-f0-9]{64}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[A-Za-z0-9][A-Za-z0-9._:@/+%-]{0,1023}$")
_CONTEXT_KEYS = {
    "schema_id", "schema_version", "release_sha", "tree_sha",
    "repository_evidence_head_sha", "release_bundles", "catalog_sha256",
    "image_digests", "sbom", "dependency_inventory",
    "environment_compatibility_ref", "observed_at", "ci", "e2e",
    "invalidation_refs", "grants_authority",
}
_BUNDLE_KEYS = {"paths", "sha256"}
_ARTIFACT_KEYS = {"path", "sha256"}
_CI_KEYS = {"head_sha", "workflow", "run_id", "conclusion", "ref", "grants_authority"}
_E2E_KEYS = {
    "proof_ref", "release_sha", "tree_sha", "image_digests",
    "config_sha256", "policy_sha256", "provider_sha256",
    "environment_compatibility_ref", "status", "valid_until",
    "grants_authority",
}
_BUNDLE_NAMES = {"code", "config", "policy", "provider"}
_CATALOG_PATHS = {
    "core": "contracts/catalog.json",
    "a1": "contracts/a1/v1/catalog.json",
    "e5": "contracts/e5/v1/catalog.json",
}


class ReleaseCurrentnessError(RuntimeError):
    """The supplied evidence does not describe one current frozen release."""


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ReleaseCurrentnessError(f"{label} shape is invalid")
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ReleaseCurrentnessError(f"{label} is not canonical JSON data") from exc


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise ReleaseCurrentnessError(f"{label} must be SHA-256")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_RE.fullmatch(value) is None:
        raise ReleaseCurrentnessError(f"{label} must be a full Git SHA")
    return value


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise ReleaseCurrentnessError(f"{label} must be a normalized reference")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReleaseCurrentnessError(f"{label} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseCurrentnessError(f"{label} must be RFC3339 UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReleaseCurrentnessError(f"{label} must be RFC3339 UTC")
    return parsed.astimezone(timezone.utc)


def _path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ReleaseCurrentnessError(f"{label} is not a repository-relative path")
    parsed = PurePosixPath(value)
    if str(parsed) != value or ".." in parsed.parts or "." in parsed.parts:
        raise ReleaseCurrentnessError(f"{label} is not a normalized path")
    return value


def _git_bytes(root: Path, commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseCurrentnessError(f"release input is absent from exact subject: {relative}")
    return result.stdout


def _git_text(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise ReleaseCurrentnessError("Git subject validation failed")
    return result.stdout.strip()


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def _bundle_sha256(
    root: Path,
    release_commit: str,
    evidence_commit: str,
    value: object,
    label: str,
) -> dict[str, object]:
    bundle = _exact(value, _BUNDLE_KEYS, label)
    paths = bundle["paths"]
    if (
        not isinstance(paths, list)
        or not paths
        or any(not isinstance(item, str) for item in paths)
        or paths != sorted(set(paths))
    ):
        raise ReleaseCurrentnessError(f"{label}.paths must be a sorted unique non-empty array")
    normalized = [_path(item, f"{label}.paths") for item in paths]
    material: dict[str, str] = {}
    for relative in normalized:
        release_bytes = _git_bytes(root, release_commit, relative)
        if not hmac.compare_digest(
            hashlib.sha256(release_bytes).digest(),
            hashlib.sha256(_git_bytes(root, evidence_commit, relative)).digest(),
        ):
            raise ReleaseCurrentnessError(
                f"{label} changed after the frozen release subject"
            )
        material[relative] = hashlib.sha256(release_bytes).hexdigest()
    if _sha(bundle["sha256"], f"{label}.sha256") != canonical_json_sha256(material):
        raise ReleaseCurrentnessError(f"{label} differs from the exact release subject")
    return bundle


def _artifact(root: Path, commit: str, value: object, label: str) -> dict[str, object]:
    artifact = _exact(value, _ARTIFACT_KEYS, label)
    relative = _path(artifact["path"], f"{label}.path")
    actual = hashlib.sha256(_git_bytes(root, commit, relative)).hexdigest()
    if _sha(artifact["sha256"], f"{label}.sha256") != actual:
        raise ReleaseCurrentnessError(f"{label} differs from the repository evidence head")
    return artifact


def validate_release_currentness_context(
    root: Path,
    value: Mapping[str, object],
    *,
    require_checked_out_evidence_head: bool = True,
) -> dict[str, object]:
    """Recompute every release dimension represented by one sanitized context."""

    root = root.resolve()
    context = _exact(value, _CONTEXT_KEYS, "release currentness context")
    if (
        context["schema_id"] != "ReleaseCurrentnessContext"
        or context["schema_version"] != "1.0.0"
        or context["grants_authority"] is not False
    ):
        raise ReleaseCurrentnessError("release currentness identity or authority is invalid")
    release_sha = _git_sha(context["release_sha"], "release_sha")
    evidence_head = _git_sha(context["repository_evidence_head_sha"], "repository_evidence_head_sha")
    tree_sha = _git_sha(context["tree_sha"], "tree_sha")
    if _git_text(root, "rev-parse", f"{release_sha}^{{tree}}") != tree_sha:
        raise ReleaseCurrentnessError("release tree differs from the exact Git subject")
    if not _is_ancestor(root, release_sha, evidence_head):
        raise ReleaseCurrentnessError("release is outside repository evidence ancestry")
    if require_checked_out_evidence_head and _git_text(root, "rev-parse", "HEAD") != evidence_head:
        raise ReleaseCurrentnessError("repository evidence head is not checked out exactly")

    bundles = context["release_bundles"]
    if not isinstance(bundles, Mapping) or set(bundles) != _BUNDLE_NAMES:
        raise ReleaseCurrentnessError("release bundle coverage is incomplete")
    context["release_bundles"] = {
        name: _bundle_sha256(
            root,
            release_sha,
            evidence_head,
            bundles[name],
            f"release_bundles.{name}",
        )
        for name in sorted(_BUNDLE_NAMES)
    }

    catalogs = context["catalog_sha256"]
    if not isinstance(catalogs, Mapping) or set(catalogs) != set(_CATALOG_PATHS):
        raise ReleaseCurrentnessError("catalog coverage is incomplete")
    for name, relative in _CATALOG_PATHS.items():
        actual = hashlib.sha256(_git_bytes(root, release_sha, relative)).hexdigest()
        if _sha(catalogs[name], f"catalog_sha256.{name}") != actual:
            raise ReleaseCurrentnessError(f"{name} catalog differs from the release subject")

    images = context["image_digests"]
    if (
        not isinstance(images, list)
        or not images
        or images != sorted(set(images))
        or any(not isinstance(item, str) or not item.startswith("sha256:") or _SHA_RE.fullmatch(item[7:]) is None for item in images)
    ):
        raise ReleaseCurrentnessError("image digest set is invalid")
    context["sbom"] = _artifact(root, evidence_head, context["sbom"], "sbom")
    context["dependency_inventory"] = _artifact(
        root, evidence_head, context["dependency_inventory"], "dependency_inventory"
    )
    environment = _ref(context["environment_compatibility_ref"], "environment_compatibility_ref")
    observed = _timestamp(context["observed_at"], "observed_at")
    invalidations = context["invalidation_refs"]
    if not isinstance(invalidations, list) or invalidations:
        raise ReleaseCurrentnessError("current release has an active invalidation")

    ci = _exact(context["ci"], _CI_KEYS, "CI evidence")
    if (
        _git_sha(ci["head_sha"], "ci.head_sha") != evidence_head
        or not isinstance(ci["workflow"], str)
        or not ci["workflow"]
        or isinstance(ci["run_id"], bool)
        or not isinstance(ci["run_id"], int)
        or ci["run_id"] < 1
        or ci["conclusion"] != "success"
        or ci["grants_authority"] is not False
    ):
        raise ReleaseCurrentnessError("exact-head CI evidence is not green")
    _ref(ci["ref"], "ci.ref")

    e2e = _exact(context["e2e"], _E2E_KEYS, "functional E2E evidence")
    expected_e2e = {
        "release_sha": release_sha,
        "tree_sha": tree_sha,
        "image_digests": images,
        "config_sha256": context["release_bundles"]["config"]["sha256"],
        "policy_sha256": context["release_bundles"]["policy"]["sha256"],
        "provider_sha256": context["release_bundles"]["provider"]["sha256"],
        "environment_compatibility_ref": environment,
    }
    if any(e2e[name] != expected for name, expected in expected_e2e.items()):
        raise ReleaseCurrentnessError("functional E2E evidence is mixed with another release")
    if e2e["status"] != "PASS" or e2e["grants_authority"] is not False:
        raise ReleaseCurrentnessError("functional E2E evidence is not a non-authoritative PASS")
    _ref(e2e["proof_ref"], "e2e.proof_ref")
    if _timestamp(e2e["valid_until"], "e2e.valid_until") <= observed:
        raise ReleaseCurrentnessError("functional E2E evidence is expired")
    return context


def assess_capability_for_release(
    root: Path,
    receipt: Mapping[str, object],
    context: Mapping[str, object],
    *,
    code_sha256: str,
    config_sha256: str,
    policy_sha256: str,
    schema_sha256: str,
) -> dict[str, object]:
    """Require one capability proof to be current for the recomputed release."""

    current = validate_release_currentness_context(root, context)
    try:
        proof = validate_capability_proof(receipt)
        assessment = assess_capability_proof(
            proof,
            now=str(current["observed_at"]),
            subject_ref=f"git:{current['release_sha']}",
            code_sha256=code_sha256,
            config_sha256=config_sha256,
            policy_sha256=policy_sha256,
            schema_sha256=schema_sha256,
            environment_compatibility_ref=str(current["environment_compatibility_ref"]),
        )
    except CapabilityProofError as exc:
        raise ReleaseCurrentnessError("capability proof structure is invalid") from exc
    if assessment.status != "PASS_FOR_FROZEN_SCOPE":
        raise ReleaseCurrentnessError(
            "capability proof is stale: " + ",".join(assessment.invalidation_reasons)
        )
    payload = proof["payload"]
    dependencies = payload["critical_dependencies"]
    required = {
        f"catalog:core:{current['catalog_sha256']['core']}",
        f"catalog:a1:{current['catalog_sha256']['a1']}",
    }
    if not isinstance(dependencies, list) or not required <= set(dependencies):
        raise ReleaseCurrentnessError("capability proof omits current catalog dependencies")
    return proof


__all__ = [
    "ReleaseCurrentnessError",
    "assess_capability_for_release",
    "validate_release_currentness_context",
]
