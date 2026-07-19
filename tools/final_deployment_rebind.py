#!/usr/bin/env python3
"""Operationally bind and deploy the frozen S38 candidate without widening authority.

``prepare`` performs local-only exact-candidate image construction and emits a
private runtime ReleaseManifest, SPDX SBOM and build receipt. ``deploy`` accepts
only that manifest plus verified backup/restore evidence and consumes one
authenticated DeploymentApprovalReceipt immediately before the first remote
mutation. The module never discovers credentials, host locators or operator
keys and never performs reboot, restore, live-domain or canonical actions.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence, TextIO


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import pre_soak_deploy as deploy  # noqa: E402
from research_bridge.deployment import (  # noqa: E402
    DeploymentApprovalConsumer,
    DeploymentGateError,
)


CANDIDATE_SHA = "b2c2e6a8c4e0a364ef82e8e51540433aa91430d4"
CANDIDATE_TREE = "7d6bd1e13d651950cced23dfe75a24946a3218fc"
S38_REBIND_SHA = "7d9a6459be07678a57a779118dd328a37eff2855"
FINAL_MANIFEST = ROOT / "docs/receipts/release/s38-final-release-manifest.json"
FINAL_MANIFEST_SHA256 = "0439dee8e058914fe8e11416112e4a985e4bfec11502bb2cd0fd5b883295c369"
SUPERSESSION = ROOT / "docs/receipts/release/r00-superseded-release.json"
SUPERSESSION_SHA256 = "5dcda4584a475e564e05a9a715b8e27d8e52950fc9eb781c8ee0376f8611a9e6"
POLICY = ROOT / "ops/release/final-a1-runtime-policy.json"
CONFIG = ROOT / "ops/release/researchd.config.template.json"
DEPENDENCY_LOCK = ROOT / "ops/release/dependency-lock.json"
A1_UNIT = ROOT / "ops/deploy/research-os-a1-final.service"
BASE_SBOM = ROOT / "docs/receipts/release/s4-release-sbom.spdx.json"
CORE_SCHEMA_SHA256 = "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50"
PREVIOUS_RELEASE = "release:none-service-stopped"
IMAGE_TAG = f"dual-contour-research-os:s38-{CANDIDATE_SHA[:12]}"
_MAX_JSON = 8 * 1024 * 1024
_MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_IMAGE = re.compile(r"^sha256:[a-f0-9]{64}$")
_EXACT_CI = re.compile(r"^github-actions:[1-9][0-9]*@[a-f0-9]{40}$")


class FinalDeploymentRebindError(RuntimeError):
    """The exact final release or its deployment authority failed closed."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FinalDeploymentRebindError("value is not canonical JSON") from exc


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        raise FinalDeploymentRebindError("artifact cannot be hashed") from exc
    return digest.hexdigest()


def _historical_text(subject: str, relative: str) -> str:
    """Read one immutable release input from the superseded Git subject."""

    if not relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise FinalDeploymentRebindError("historical artifact path is invalid")
    if _SHA256.fullmatch(subject) is None and re.fullmatch(r"[a-f0-9]{40}", subject) is None:
        raise FinalDeploymentRebindError("historical artifact subject is invalid")
    return _run(["git", "show", f"{subject}:{relative}"])


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FinalDeploymentRebindError("JSON contains a duplicate key")
        value[key] = item
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise FinalDeploymentRebindError(f"{label} must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_JSON:
            raise FinalDeploymentRebindError(f"{label} size is invalid")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                FinalDeploymentRebindError("JSON contains a non-finite number")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FinalDeploymentRebindError(f"{label} cannot be read") from exc
    if not isinstance(value, dict):
        raise FinalDeploymentRebindError(f"{label} must be an object")
    return value


def _run(arguments: Sequence[str], *, maximum: int = _MAX_COMMAND_OUTPUT) -> str:
    try:
        completed = subprocess.run(
            list(arguments),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=1800,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FinalDeploymentRebindError("bounded local command failed") from exc
    if len(completed.stdout) > maximum or len(completed.stderr) > maximum:
        raise FinalDeploymentRebindError("bounded local command output exceeded limit")
    if completed.returncode != 0:
        raise FinalDeploymentRebindError("bounded local command returned non-zero")
    try:
        return completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FinalDeploymentRebindError("bounded local command output is not UTF-8") from exc


def _write_bytes_exclusive(path: Path, body: bytes, mode: int = 0o600) -> None:
    if not path.parent.is_dir():
        raise FinalDeploymentRebindError("output parent does not exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, mode)
        created = True
        offset = 0
        while offset < len(body):
            offset += os.write(descriptor, body[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(path, mode, follow_symlinks=False)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise FinalDeploymentRebindError("exclusive output write failed") from exc


def _write_json_exclusive(path: Path, value: Mapping[str, object]) -> None:
    _write_bytes_exclusive(path, _canonical(value) + b"\n")


def _copy_exclusive(source: Path, target: Path) -> None:
    if target.exists() or target.is_symlink() or not target.parent.is_dir():
        raise FinalDeploymentRebindError("archive output must be a fresh path")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(target, flags, 0o600)
        created = True
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            descriptor = None
            shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                target.unlink()
            except OSError:
                pass
        raise FinalDeploymentRebindError("archive copy failed") from exc


def _observed() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _require_outside_repository(path: Path, label: str, *, directory: bool = False) -> None:
    try:
        candidate = path.resolve(strict=True) if directory or path.exists() else path.parent.resolve(strict=True) / path.name
        root = ROOT.resolve(strict=True)
    except OSError as exc:
        raise FinalDeploymentRebindError(f"{label} location is unavailable") from exc
    if candidate == root or root in candidate.parents:
        raise FinalDeploymentRebindError(f"{label} must remain outside the repository")


def _require_private_file(path: Path, label: str, *, allow_missing: bool = False) -> None:
    if not path.exists() and not path.is_symlink():
        if not allow_missing:
            raise FinalDeploymentRebindError(f"{label} is unavailable")
        parent = os.lstat(path.parent)
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise FinalDeploymentRebindError(f"{label} parent is invalid")
        if stat.S_IMODE(parent.st_mode) & 0o077:
            raise FinalDeploymentRebindError(f"{label} parent is not owner-only")
        return
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise FinalDeploymentRebindError(f"{label} is not an owner-only regular file")


def _verify_final_manifest() -> dict[str, Any]:
    if _digest_file(FINAL_MANIFEST) != FINAL_MANIFEST_SHA256:
        raise FinalDeploymentRebindError("S38 final manifest digest drifted")
    manifest = _load_json(FINAL_MANIFEST, "S38 final manifest")
    payload = manifest.get("payload")
    integrity = manifest.get("integrity")
    if (
        manifest.get("schema_id") != "FinalCandidateReleaseManifest"
        or not isinstance(payload, dict)
        or not isinstance(integrity, dict)
        or payload.get("candidate_release_sha") != CANDIDATE_SHA
        or payload.get("candidate_tree_sha") != CANDIDATE_TREE
        or payload.get("deployment_allowed") is not False
        or payload.get("grants_authority") is not False
        or integrity.get("payload_sha256") != _digest_bytes(_canonical(payload))
    ):
        raise FinalDeploymentRebindError("S38 final manifest identity is invalid")
    tree = _run(["git", "rev-parse", f"{CANDIDATE_SHA}^{{tree}}"], maximum=1024).strip()
    if tree != CANDIDATE_TREE:
        raise FinalDeploymentRebindError("candidate Git tree is unavailable or drifted")
    return manifest


def _verify_supersession() -> dict[str, Any]:
    if _digest_file(SUPERSESSION) != SUPERSESSION_SHA256:
        raise FinalDeploymentRebindError("release supersession receipt drifted")
    receipt = _load_json(SUPERSESSION, "release supersession receipt")
    payload = receipt.get("payload")
    integrity = receipt.get("integrity")
    if (
        receipt.get("schema_id") != "ReleaseSupersessionReceipt"
        or receipt.get("schema_version") != "1.0.0"
        or receipt.get("object_id") != f"release-supersession:{CANDIDATE_SHA}"
        or not isinstance(payload, dict)
        or not isinstance(integrity, dict)
        or integrity.get("profile_id") != "core-json-sha256-v1"
        or integrity.get("payload_sha256") != _digest_bytes(_canonical(payload))
        or payload.get("candidate_release_sha") != CANDIDATE_SHA
        or payload.get("candidate_tree_sha") != CANDIDATE_TREE
        or payload.get("candidate_manifest_ref")
        != str(FINAL_MANIFEST.relative_to(ROOT))
        or payload.get("candidate_manifest_sha256") != FINAL_MANIFEST_SHA256
        or payload.get("supersession_state") != "SUPERSEDED_REPAIR_REQUIRED"
        or payload.get("historical_integrity_preserved") is not True
        or payload.get("replacement_release_required") is not True
    ):
        raise FinalDeploymentRebindError("release supersession receipt is invalid")
    denied = (
        "deployment_allowed",
        "VPS_mutation_allowed",
        "restore_allowed",
        "reboot_allowed",
        "canonical_mutation_allowed",
        "live_action_allowed",
        "grants_authority",
    )
    request = payload.get("superseded_authority_request")
    reasons = payload.get("reason_codes")
    if (
        any(payload.get(field) is not False for field in denied)
        or not isinstance(reasons, list)
        or set(reasons)
        != {
            "EMPTY_POLICY_RESOLVER",
            "A1_BACKEND_NOT_WIRED",
            "COLLECTOR_SCOUT_ROLES_NOT_WIRED",
            "STATUS_ONLY_DEPLOY_SMOKE",
            "STALE_E2_PROOF",
            "FINAL_FREEZE_NOT_CURRENTNESS_AWARE",
            "PROVIDER_SOURCE_EDGES_NOT_PHYSICALLY_CLOSED",
        }
        or not isinstance(request, dict)
        or request.get("pr") != 25
        or request.get("usable_for_deployment") is not False
    ):
        raise FinalDeploymentRebindError("release supersession deny boundary is invalid")
    return receipt


def _require_deployable_candidate() -> None:
    receipt = _verify_supersession()
    payload = receipt["payload"]
    raise FinalDeploymentRebindError(
        f"candidate is {payload['supersession_state']}; replacement release required"
    )


def _verify_static() -> dict[str, object]:
    manifest = _verify_final_manifest()
    supersession = _verify_supersession()
    expected = {
        str(POLICY.relative_to(ROOT)): (
            S38_REBIND_SHA,
            "b3fc58125b3308c723c25461828b914a2f244dfa260dda7d5eea49467a7fc647",
        ),
        str(CONFIG.relative_to(ROOT)): (
            CANDIDATE_SHA,
            "0b186888a3a1bb8fb028315681bf4073ec4186a0acbdf2f226b5a53d69a9d542",
        ),
        str(DEPENDENCY_LOCK.relative_to(ROOT)): (
            CANDIDATE_SHA,
            "58cd81aa9e5554e5ae88a0d86822e341a6ac25eb8179cca9a9fb3e4512493be9",
        ),
        str(A1_UNIT.relative_to(ROOT)): (
            S38_REBIND_SHA,
            "49412c65c0e1e93d455d5b76e0a0516c618ac677fa63173bb9e89c93a7627b84",
        ),
    }
    historical: dict[str, str] = {}
    for relative, (subject, digest) in expected.items():
        content = _historical_text(subject, relative)
        if _digest_bytes(content.encode("utf-8")) != digest:
            raise FinalDeploymentRebindError(
                f"historical static deployment input drifted: {relative}"
            )
        historical[relative] = content
    unit = historical[str(A1_UNIT.relative_to(ROOT))]
    required = (
        "research-os-a1-bridge",
        "source=research-os-a1-runtime",
        "source=research-os-a1-config",
        "--restart=no",
        "Restart=on-failure",
        "--network=none",
        "RESEARCH_OS_EXTERNAL_ACTION_AUTHORITY=false",
    )
    forbidden = ("--restart=unless-stopped", "--publish", "research-os-bridge-runtime")
    if any(token not in unit for token in required) or any(token in unit for token in forbidden):
        raise FinalDeploymentRebindError("A1 unit does not enforce the frozen isolation profile")
    return {
        "status": "SUPERSEDED_REPAIR_REQUIRED",
        "candidate_release_sha": CANDIDATE_SHA,
        "candidate_tree_sha": CANDIDATE_TREE,
        "final_manifest_ref": str(manifest["object_id"]),
        "supersession_ref": str(supersession["object_id"]),
        "historical_freeze_valid": True,
        "historical_static_subjects": [CANDIDATE_SHA, S38_REBIND_SHA],
        "replacement_release_required": True,
        "A1_namespace": True,
        "single_supervisor": True,
        "deployment_allowed": False,
        "remote_actions": 0,
    }


def _image_inspect(image_tag: str) -> dict[str, Any]:
    raw = _run(["docker", "image", "inspect", image_tag, "--format", "{{json .}}"])
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except json.JSONDecodeError as exc:
        raise FinalDeploymentRebindError("local image inspection is invalid") from exc
    config = value.get("Config") if isinstance(value, dict) else None
    labels = config.get("Labels") if isinstance(config, dict) else None
    image_id = value.get("Id") if isinstance(value, dict) else None
    if (
        not isinstance(image_id, str)
        or _IMAGE.fullmatch(image_id) is None
        or value.get("Os") != "linux"
        or value.get("Architecture") != "amd64"
        or not isinstance(config, dict)
        or config.get("User") != "10001:10001"
        or not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.revision") != CANDIDATE_SHA
    ):
        raise FinalDeploymentRebindError("local image does not match the frozen candidate")
    return value


def _expected_debian_packages(sbom: Mapping[str, object]) -> set[tuple[str, str]]:
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise FinalDeploymentRebindError("base SBOM package inventory is invalid")
    expected: set[tuple[str, str]] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise FinalDeploymentRebindError("base SBOM package entry is invalid")
        if str(package.get("SPDXID", "")).startswith("SPDXRef-Debian-"):
            name, version = package.get("name"), package.get("versionInfo")
            if not isinstance(name, str) or not isinstance(version, str):
                raise FinalDeploymentRebindError("base SBOM Debian package is invalid")
            expected.add((name.split(":", 1)[0], version))
    return expected


def _actual_debian_packages(image_tag: str) -> set[tuple[str, str]]:
    output = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--entrypoint=dpkg-query",
            image_tag,
            "-W",
            "-f=${binary:Package}\\t${Version}\\n",
        ]
    )
    actual: set[tuple[str, str]] = set()
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1]:
            raise FinalDeploymentRebindError("image package inventory is malformed")
        actual.add((fields[0].split(":", 1)[0], fields[1]))
    if not actual:
        raise FinalDeploymentRebindError("image package inventory is empty")
    return actual


def _derived_sbom(image_id: str, observed: str) -> dict[str, Any]:
    sbom = _load_json(BASE_SBOM, "base image SBOM")
    packages = sbom.get("packages")
    if not isinstance(packages, list) or not packages or not isinstance(packages[0], dict):
        raise FinalDeploymentRebindError("base image SBOM release package is invalid")
    digest = image_id.removeprefix("sha256:")
    sbom["name"] = f"dual-contour-research-os-{CANDIDATE_SHA}-linux-amd64"
    sbom["documentNamespace"] = (
        "https://github.com/KirPonomarev/dual-contour-research-os/sbom/"
        f"{CANDIDATE_SHA}/{digest}"
    )
    creation = sbom.get("creationInfo")
    if not isinstance(creation, dict):
        raise FinalDeploymentRebindError("base image SBOM creation info is invalid")
    creation["created"] = observed
    release = packages[0]
    release["versionInfo"] = CANDIDATE_SHA
    release["packageFileName"] = f"dual-contour-research-os@{image_id}"
    release["checksums"] = [{"algorithm": "SHA256", "checksumValue": digest}]
    refs = release.get("externalRefs")
    if not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], dict):
        raise FinalDeploymentRebindError("base image SBOM OCI reference is invalid")
    refs[0]["referenceLocator"] = (
        f"pkg:oci/dual-contour-research-os@sha256%3A{digest}?arch=amd64"
    )
    return sbom


def _release_manifest(image_id: str, sbom_sha256: str, observed: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "release_sha": CANDIDATE_SHA,
        "image_digests": [image_id],
        "policy_sha256": _digest_file(POLICY),
        "config_sha256": _digest_file(CONFIG),
        "schema_sha256": CORE_SCHEMA_SHA256,
        "dependency_lock_sha256": _digest_file(DEPENDENCY_LOCK),
        "sbom_ref": f"artifact:sha256:{sbom_sha256}",
        "previous_release_ref": PREVIOUS_RELEASE,
    }
    payload_sha = _digest_bytes(_canonical(payload))
    return {
        "schema_id": "ReleaseManifest",
        "schema_version": "1.0.0",
        "object_id": f"release-manifest-{payload_sha}",
        "issued_at": observed,
        "issuer": {
            "id": "s38-r1-final-deployment-preflight",
            "authority_class": "release-preflight-assembler",
        },
        "contour": "governance",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {
            "payload_sha256": payload_sha,
            "parent_refs": [
                f"git:{CANDIDATE_SHA}",
                f"tree:{CANDIDATE_TREE}",
                f"artifact:sha256:{FINAL_MANIFEST_SHA256}",
                f"artifact:sha256:{sbom_sha256}",
            ],
        },
    }


def _prepare(output_dir: Path, image_tag: str) -> dict[str, object]:
    _verify_static()
    _require_outside_repository(output_dir, "prepare output", directory=True)
    metadata = os.lstat(output_dir)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FinalDeploymentRebindError("output directory is invalid")
    expected_outputs = (
        output_dir / "final-release-image.tar",
        output_dir / "final-release-sbom.spdx.json",
        output_dir / "final-operational-release-manifest.json",
        output_dir / "final-image-build-receipt.json",
    )
    if any(path.exists() or path.is_symlink() for path in expected_outputs):
        raise FinalDeploymentRebindError("prepare outputs must all be fresh")
    observed = _observed()
    with tempfile.TemporaryDirectory(prefix="dcros-s38-build-") as directory:
        temporary = Path(directory)
        archive_source = temporary / "candidate.tar"
        source = temporary / "source"
        source.mkdir()
        _run(["git", "archive", "--format=tar", f"--output={archive_source}", CANDIDATE_SHA])
        _run(["tar", "-xf", str(archive_source), "-C", str(source)])
        _run(
            [
                "docker",
                "build",
                "--platform=linux/amd64",
                "--build-arg",
                f"RELEASE_SHA={CANDIDATE_SHA}",
                "--tag",
                image_tag,
                "--file",
                str(source / "ops/release/Containerfile"),
                str(source),
            ]
        )
        inspection = _image_inspect(image_tag)
        image_id = str(inspection["Id"])
        base_sbom = _load_json(BASE_SBOM, "base image SBOM")
        if _actual_debian_packages(image_tag) != _expected_debian_packages(base_sbom):
            raise FinalDeploymentRebindError("built image package inventory differs from frozen SBOM")
        saved = temporary / "final-release-image.tar"
        _run(["docker", "save", "--output", str(saved), image_tag], maximum=1024)
        if not saved.is_file() or saved.stat().st_size <= 0:
            raise FinalDeploymentRebindError("saved image archive is empty")
        sbom = _derived_sbom(image_id, observed)
        sbom_bytes = _canonical(sbom) + b"\n"
        sbom_sha = _digest_bytes(sbom_bytes)
        manifest = _release_manifest(image_id, sbom_sha, observed)
        manifest_bytes = _canonical(manifest) + b"\n"
        archive_sha = _digest_file(saved)
        build_payload: dict[str, object] = {
            "status": "PASS_FOR_FROZEN_SCOPE",
            "candidate_release_sha": CANDIDATE_SHA,
            "candidate_tree_sha": CANDIDATE_TREE,
            "image_id": image_id,
            "image_tag": image_tag,
            "image_archive_sha256": archive_sha,
            "image_archive_size_bytes": saved.stat().st_size,
            "platform": "linux/amd64",
            "runtime_user": "10001:10001",
            "package_inventory_equal": True,
            "sbom_sha256": sbom_sha,
            "operational_manifest_sha256": _digest_bytes(manifest_bytes),
            "network_at_runtime": False,
            "remote_actions": 0,
            "grants_deployment_authority": False,
        }
        build_receipt = {
            "schema_id": "FinalImageBuildReceipt",
            "schema_version": "1.0.0",
            "object_id": "final-image-build-" + _digest_bytes(_canonical(build_payload)),
            "issued_at": observed,
            "issuer": {
                "id": "s38-r1-final-deployment-preflight",
                "authority_class": "local-image-build-controller",
            },
            "contour": "governance",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": build_payload,
            "integrity": {
                "payload_sha256": _digest_bytes(_canonical(build_payload)),
                "parent_refs": [
                    f"git:{CANDIDATE_SHA}",
                    f"tree:{CANDIDATE_TREE}",
                    str(manifest["object_id"]),
                ],
            },
        }
        _copy_exclusive(saved, expected_outputs[0])
        _write_bytes_exclusive(expected_outputs[1], sbom_bytes)
        _write_bytes_exclusive(expected_outputs[2], manifest_bytes)
        _write_json_exclusive(expected_outputs[3], build_receipt)
    return {
        "status": "PREPARED_LOCAL_ONLY",
        "candidate_release_sha": CANDIDATE_SHA,
        "image_id": image_id,
        "archive_sha256": archive_sha,
        "output_dir": str(output_dir),
        "deployment_authority": False,
        "remote_actions": 0,
    }


def _verify_prepared(output_dir: Path) -> dict[str, object]:
    _verify_static()
    _require_outside_repository(output_dir, "prepared artifact directory", directory=True)
    archive = output_dir / "final-release-image.tar"
    sbom_path = output_dir / "final-release-sbom.spdx.json"
    manifest_path = output_dir / "final-operational-release-manifest.json"
    receipt_path = output_dir / "final-image-build-receipt.json"
    for path in (archive, sbom_path, manifest_path, receipt_path):
        metadata = os.lstat(path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
        ):
            raise FinalDeploymentRebindError("prepared artifact boundary is invalid")
    sbom = _load_json(sbom_path, "prepared SPDX SBOM")
    manifest = _load_json(manifest_path, "prepared operational manifest")
    receipt = _load_json(receipt_path, "prepared image build receipt")
    payload = manifest.get("payload")
    receipt_payload = receipt.get("payload")
    receipt_integrity = receipt.get("integrity")
    if (
        manifest.get("schema_id") != "ReleaseManifest"
        or not isinstance(payload, dict)
        or payload.get("release_sha") != CANDIDATE_SHA
        or not isinstance(receipt_payload, dict)
        or not isinstance(receipt_integrity, dict)
        or receipt.get("schema_id") != "FinalImageBuildReceipt"
        or receipt_integrity.get("payload_sha256")
        != _digest_bytes(_canonical(receipt_payload))
    ):
        raise FinalDeploymentRebindError("prepared release receipt is invalid")
    images = payload.get("image_digests")
    if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], str):
        raise FinalDeploymentRebindError("prepared release image binding is invalid")
    image_id = images[0]
    archive_sha = _digest_file(archive)
    sbom_sha = _digest_file(sbom_path)
    manifest_sha = _digest_file(manifest_path)
    if (
        payload.get("sbom_ref") != f"artifact:sha256:{sbom_sha}"
        or receipt_payload.get("image_id") != image_id
        or receipt_payload.get("image_archive_sha256") != archive_sha
        or receipt_payload.get("image_archive_size_bytes") != archive.stat().st_size
        or receipt_payload.get("sbom_sha256") != sbom_sha
        or receipt_payload.get("operational_manifest_sha256") != manifest_sha
        or receipt_payload.get("remote_actions") != 0
        or receipt_payload.get("grants_deployment_authority") is not False
    ):
        raise FinalDeploymentRebindError("prepared release evidence binding is invalid")
    packages = sbom.get("packages")
    release_package = packages[0] if isinstance(packages, list) and packages else None
    if (
        not isinstance(release_package, dict)
        or release_package.get("versionInfo") != CANDIDATE_SHA
        or release_package.get("packageFileName") != f"dual-contour-research-os@{image_id}"
    ):
        raise FinalDeploymentRebindError("prepared SPDX release identity is invalid")
    deploy._load_bundle(
        manifest_path=manifest_path,
        policy_path=POLICY,
        config_path=CONFIG,
        unit_path=A1_UNIT,
        archive_path=archive,
        archive_sha256=archive_sha,
        expected_release_sha=CANDIDATE_SHA,
        expected_image_id=image_id,
        expected_previous_release=PREVIOUS_RELEASE,
        expected_config_sha256=_digest_file(CONFIG),
        expected_unit_template_sha256=_digest_file(A1_UNIT),
        expected_policy=_load_json(POLICY, "final A1 runtime policy"),
    )
    return {
        "status": "PREPARED_ARTIFACTS_VERIFIED",
        "candidate_release_sha": CANDIDATE_SHA,
        "image_id": image_id,
        "archive_sha256": archive_sha,
        "sbom_sha256": sbom_sha,
        "operational_manifest_sha256": manifest_sha,
        "deployment_authority": False,
        "remote_actions": 0,
    }


def _read_hex_key(file_descriptor: int) -> bytes:
    if isinstance(file_descriptor, bool) or file_descriptor < 0:
        raise FinalDeploymentRebindError("operator key descriptor is invalid")
    chunks: list[bytes] = []
    total = 0
    while total <= 513:
        chunk = os.read(file_descriptor, 514 - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    encoded = b"".join(chunks).strip()
    if len(encoded) < 64 or len(encoded) > 512 or len(encoded) % 2:
        raise FinalDeploymentRebindError("operator key input is invalid")
    try:
        key = bytes.fromhex(encoded.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FinalDeploymentRebindError("operator key input is invalid") from exc
    if len(key) < 32:
        raise FinalDeploymentRebindError("operator key input is invalid")
    return key


def _deploy(arguments: argparse.Namespace) -> dict[str, object]:
    _verify_static()
    if arguments.environment != "pre-soak":
        raise FinalDeploymentRebindError("only the frozen pre-soak environment is allowed")
    if _EXACT_CI.fullmatch(arguments.remote_ci_ref) is None:
        raise FinalDeploymentRebindError("remote CI reference is not exact")
    for path, label in (
        (arguments.known_hosts, "known-hosts"),
        (arguments.release_manifest, "operational release manifest"),
        (arguments.archive, "image archive"),
        (arguments.backup_receipt, "backup receipt"),
        (arguments.restore_receipt, "restore receipt"),
        (arguments.approval_receipt, "deployment approval receipt"),
        (arguments.approval_ledger, "deployment approval ledger"),
        (arguments.receipt, "deployment receipt"),
    ):
        _require_outside_repository(path, label)
    for path, label in (
        (arguments.known_hosts, "known-hosts"),
        (arguments.release_manifest, "operational release manifest"),
        (arguments.archive, "image archive"),
        (arguments.backup_receipt, "backup receipt"),
        (arguments.restore_receipt, "restore receipt"),
        (arguments.approval_receipt, "deployment approval receipt"),
    ):
        _require_private_file(path, label)
    _require_private_file(arguments.approval_ledger, "deployment approval ledger", allow_missing=True)
    _require_private_file(arguments.receipt, "deployment receipt", allow_missing=True)
    release = _load_json(arguments.release_manifest, "operational release manifest")
    backup = _load_json(arguments.backup_receipt, "backup receipt")
    restore = _load_json(arguments.restore_receipt, "restore receipt")
    approval = _load_json(arguments.approval_receipt, "deployment approval receipt")
    payload = release.get("payload")
    if not isinstance(payload, dict):
        raise FinalDeploymentRebindError("operational release manifest payload is invalid")
    image_digests = payload.get("image_digests")
    if not isinstance(image_digests, list) or len(image_digests) != 1:
        raise FinalDeploymentRebindError("operational release manifest image is invalid")
    image_id = image_digests[0]
    if not isinstance(image_id, str) or _IMAGE.fullmatch(image_id) is None:
        raise FinalDeploymentRebindError("operational release image identity is invalid")
    if payload.get("release_sha") != CANDIDATE_SHA:
        raise FinalDeploymentRebindError("operational release does not bind the S38 candidate")
    operator_key = _read_hex_key(arguments.key_hex_fd)
    bundle = deploy._load_bundle(
        manifest_path=arguments.release_manifest,
        policy_path=POLICY,
        config_path=CONFIG,
        unit_path=A1_UNIT,
        archive_path=arguments.archive,
        archive_sha256=arguments.archive_sha256,
        expected_release_sha=CANDIDATE_SHA,
        expected_image_id=image_id,
        expected_previous_release=PREVIOUS_RELEASE,
        expected_config_sha256=_digest_file(CONFIG),
        expected_unit_template_sha256=_digest_file(A1_UNIT),
        expected_policy=_load_json(POLICY, "final A1 runtime policy"),
    )
    controller = deploy.PreSoakDeployController(
        ssh_alias=arguments.ssh_alias,
        known_hosts_path=arguments.known_hosts,
        target=deploy.FINAL_A1_TARGET,
    )

    def consume_authority() -> Mapping[str, object]:
        consumed_at = _observed()
        previous_umask = os.umask(0o077)
        try:
            with DeploymentApprovalConsumer(
                arguments.approval_ledger,
                trusted_issuer_id=arguments.trusted_issuer_id,
                trusted_key_id=arguments.trusted_key_id,
                operator_key=operator_key,
            ) as consumer:
                event = consumer.consume(
                    release_manifest=release,
                    backup_receipt=backup,
                    restore_receipt=restore,
                    approval_receipt=approval,
                    expected_environment=arguments.environment,
                    exact_remote_ci_ref=arguments.remote_ci_ref,
                    consumed_at=consumed_at,
                )
        finally:
            os.umask(previous_umask)
        return {
            "consumed": True,
            "sequence": event.sequence,
            "approval_object_id": event.approval_object_id,
            "consumption_event_sha256": event.event_sha256,
            "release_sha": event.release_sha,
            "image_digest": event.image_digest,
            "restore_receipt_ref": event.restore_receipt_ref,
            "remote_ci_ref": event.remote_ci_ref,
            "external_domain_action_authorized": False,
        }

    receipt_descriptor = deploy._reserve_receipt(arguments.receipt)
    try:
        receipt = controller.deploy(bundle, authorization=consume_authority)
    except (
        FinalDeploymentRebindError,
        deploy.DeploymentError,
        DeploymentGateError,
        OSError,
    ) as exc:
        failed = deploy._receipt(
            "deploy",
            bundle,
            {
                "reason_code": type(exc).__name__,
                "deployment_state": "UNKNOWN_REQUIRES_RECEIPT_AND_LEDGER_INSPECTION",
                "approval_consumption_state": "UNKNOWN_REQUIRES_LEDGER_INSPECTION",
                "automatic_retry_allowed": False,
                "external_domain_action_authorized": False,
                "declares_ready_for_72h_soak": False,
            },
            clock=lambda: datetime.now(timezone.utc),
            status="FAIL",
        )
        deploy._finalize_receipt(receipt_descriptor, failed)
        raise
    deploy._finalize_receipt(receipt_descriptor, receipt)
    return {
        "status": "DEPLOYED_EXACT_APPROVED_RELEASE",
        "release_sha": CANDIDATE_SHA,
        "image_id": image_id,
        "receipt": str(arguments.receipt),
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise FinalDeploymentRebindError("command arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="final-deployment-rebind")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-static")
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--image-tag", default=IMAGE_TAG)
    verify_prepared = commands.add_parser("verify-prepared")
    verify_prepared.add_argument("--output-dir", type=Path, required=True)
    deploy_command = commands.add_parser("deploy")
    deploy_command.add_argument("--ssh-alias", required=True)
    deploy_command.add_argument("--known-hosts", type=Path, required=True)
    deploy_command.add_argument("--release-manifest", type=Path, required=True)
    deploy_command.add_argument("--archive", type=Path, required=True)
    deploy_command.add_argument("--archive-sha256", required=True)
    deploy_command.add_argument("--backup-receipt", type=Path, required=True)
    deploy_command.add_argument("--restore-receipt", type=Path, required=True)
    deploy_command.add_argument("--approval-receipt", type=Path, required=True)
    deploy_command.add_argument("--approval-ledger", type=Path, required=True)
    deploy_command.add_argument("--trusted-issuer-id", required=True)
    deploy_command.add_argument("--trusted-key-id", required=True)
    deploy_command.add_argument("--key-hex-fd", type=int, default=0)
    deploy_command.add_argument("--environment", default="pre-soak")
    deploy_command.add_argument("--remote-ci-ref", required=True)
    deploy_command.add_argument("--receipt", type=Path, required=True)
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "verify-static":
            result = _verify_static()
        else:
            _require_deployable_candidate()
            if arguments.command == "prepare":
                result = _prepare(arguments.output_dir, arguments.image_tag)
            elif arguments.command == "verify-prepared":
                result = _verify_prepared(arguments.output_dir)
            else:
                result = _deploy(arguments)
        print(json.dumps(result, sort_keys=True), file=output)
        return 0
    except (
        FinalDeploymentRebindError,
        deploy.DeploymentError,
        DeploymentGateError,
        OSError,
    ) as exc:
        print(
            json.dumps(
                {
                    "status": "STOP",
                    "reason_code": type(exc).__name__,
                },
                sort_keys=True,
            ),
            file=errors,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
