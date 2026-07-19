#!/usr/bin/env python3
"""Bounded exact-image deployment and recovery controller for pre-soak.

The controller deliberately has no credential discovery, privilege escalation,
host reboot, registry push, public listener, or domain-service operation.  A
target is selected only by an operator-supplied OpenSSH config alias.  Every
remote Docker command is pinned to the rootless user socket and every mutating
operation is limited to the ``research-os-bridge`` user service and its owned
container/volumes.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from typing import Any, Protocol, TextIO


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.researchd import _service_config_from_mapping  # noqa: E402

SERVICE_NAME = "research-os-bridge.service"
CONTAINER_NAME = "research-os-bridge"
RUNTIME_VOLUME = "research-os-bridge-runtime"
CONFIG_VOLUME = "research-os-bridge-config"
IMAGE_ID = "sha256:36069ee7a9db78af747d7fad65f9e33073824f27be898cdc0b7dd3b77ac5c235"
RELEASE_SHA = "5c2bd7c090fada6e5b65dc955e80b256d88252de"
PREVIOUS_RELEASE = "release:none-service-stopped"
RECEIPT_SCHEMA = "research-os.pre-soak-deployment-receipt.v1"
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_GIT_SHA = re.compile(r"[a-f0-9]{40}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CAPSULE_INPUT_BYTES = 4 * 1024 * 1024
_FROZEN_RELEASE_MANIFEST_SHA256 = "9ceae0bda066cf52577cec0fdc1d7230e92b3e4010f65b81613abf6a0a8a90dd"
_FROZEN_RELEASE_CONFIG_SHA256 = "0b186888a3a1bb8fb028315681bf4073ec4186a0acbdf2f226b5a53d69a9d542"
_LEGACY_UNIT_SHA256 = "f0ea702877b67205a2727537bb0954a6ce15214875d142a9dce76d9fcf8c49c3"
_CAPSULE_MANIFEST_NAME = "capsule-manifest.json"
_CAPSULE_CONFIG_NAME = "researchd.config.json"
_CAPSULE_PARENT_PREFIX = "capsule:sha256:"
_CAPSULE_UNIT_TOKEN = "@@CAPSULE_MANIFEST_SHA256@@"
_EXPECTED_TRUSTED_ISSUERS = {
    "JobSpec": {"issuer_id": "pre-soak-admission-controller", "authority_class": "admission-controller"},
    "Permit": {"issuer_id": "pre-soak-permit-authority", "authority_class": "permit-authority"},
    "AttemptLease": {"issuer_id": "researchd", "authority_class": "researchd"},
    "PolicySnapshot": {"issuer_id": "pre-soak-policy-authority", "authority_class": "policy-authority"},
    "ApprovalReceipt": {"issuer_id": "pre-soak-operator-authority", "authority_class": "operator-authority"},
}
_FROZEN_IMAGE_ENV = [
    "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C.UTF-8",
    "GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D",
    "PYTHON_VERSION=3.11.14",
    "PYTHON_SHA256=8d3ed8ec5c88c1c95f5e558612a725450d2452813ddad5e58fdb1a53b1209b78",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONHASHSEED=0",
    "PYTHONPATH=/opt/research-os/src",
    "PYTHONUNBUFFERED=1",
]
_DOCKER = 'env DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock" /usr/bin/docker'
_REMOTE_BASE = "$HOME/.local/share/research-os-bridge"
_REMOTE_CONFIG = "$HOME/.config/research-os-bridge"
_REMOTE_UNIT = "$HOME/.config/systemd/user/research-os-bridge.service"
_UNIT_TOKENS = frozenset(
    {
        "@@IMAGE_ID@@",
        "@@RELEASE_SHA@@",
        "@@POLICY_SHA256@@",
        "@@CONFIG_SHA256@@",
    }
)
_EXPECTED_POLICY = {
    "schema_version": "research-os.rootless-runtime-policy.v1",
    "environment": "pre-soak",
    "platform": "linux/amd64",
    "user": "10001:10001",
    "network": "none",
    "published_ports": [],
    "read_only_root_filesystem": True,
    "cap_drop": ["ALL"],
    "security_options": ["no-new-privileges:true"],
    "pids_limit": 256,
    "memory_bytes": 2147483648,
    "cpus": 2,
    "restart_policy": "unless-stopped",
    "runtime_mount": {
        "container_path": "/var/lib/research-os",
        "mode": "rw",
        "owner_uid": 10001,
    },
    "config_mount": {
        "container_path": "/run/research-os/researchd.json",
        "mode": "ro",
        "owner_uid": 10001,
        "file_mode": "0600",
    },
    "control_transport": "AF_UNIX",
    "external_action_authority": False,
}


class DeploymentError(RuntimeError):
    """A local invariant or remote deployment assertion failed closed."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class Runner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Run an argv without a local shell and retain only bounded UTF-8 output."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                list(arguments),
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeploymentError("bounded command execution failed") from exc
        if len(completed.stdout) > _MAX_JSON_BYTES or len(completed.stderr) > _MAX_JSON_BYTES:
            raise DeploymentError("command output exceeded its bound")
        try:
            stdout = completed.stdout.decode("utf-8", errors="strict")
            stderr = completed.stderr.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise DeploymentError("command output was not UTF-8") from exc
        return CommandResult(completed.returncode, stdout, stderr)


@dataclass(frozen=True)
class ReleaseBundle:
    release_sha: str
    image_id: str
    previous_release_ref: str
    policy_sha256: str
    config_sha256: str
    archive_sha256: str | None
    unit_bytes: bytes
    unit_sha256: str
    config_path: Path
    archive_path: Path | None
    capsule: CapsuleSeed | None = None


@dataclass(frozen=True)
class DeploymentTarget:
    """Exact mutable namespace and supervisor boundary for one deployment lane."""

    service_name: str
    container_name: str
    runtime_volume: str
    config_volume: str
    remote_slug: str
    docker_restart_policy: str
    conflicting_service_name: str | None = None
    conflicting_container_name: str | None = None

    @property
    def remote_base(self) -> str:
        return f"$HOME/.local/share/{self.remote_slug}"

    @property
    def remote_config(self) -> str:
        return f"$HOME/.config/{self.remote_slug}"

    @property
    def remote_unit(self) -> str:
        return f"$HOME/.config/systemd/user/{self.service_name}"


LEGACY_TARGET = DeploymentTarget(
    service_name=SERVICE_NAME,
    container_name=CONTAINER_NAME,
    runtime_volume=RUNTIME_VOLUME,
    config_volume=CONFIG_VOLUME,
    remote_slug="research-os-bridge",
    docker_restart_policy="unless-stopped",
)

FINAL_A1_TARGET = DeploymentTarget(
    service_name="research-os-a1-bridge.service",
    container_name="research-os-a1-bridge",
    runtime_volume="research-os-a1-runtime",
    config_volume="research-os-a1-config",
    remote_slug="research-os-a1-bridge",
    docker_restart_policy="no",
    conflicting_service_name="research-os-bridge.service",
    conflicting_container_name="research-os-bridge",
)


@dataclass(frozen=True)
class CapsuleObject:
    contour: str
    classification: str
    cas_ref: str
    sha256: str
    size_bytes: int
    source_path: Path


@dataclass(frozen=True)
class CapsuleSeed:
    manifest_sha256: str
    manifest_object_id: str
    config_sha256: str
    config_path: Path
    release_policy_sha256: str
    release_config_sha256: str
    objects: tuple[CapsuleObject, CapsuleObject]


def _regular_file(path: Path, label: str, *, maximum: int | None = None) -> bytes:
    _regular_file_metadata(path, label, maximum=maximum)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DeploymentError(f"{label} cannot be read") from exc


def _regular_file_metadata(
    path: Path,
    label: str,
    *,
    maximum: int | None = None,
) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise DeploymentError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DeploymentError(f"{label} must be a regular file")
    if metadata.st_size <= 0 or (maximum is not None and metadata.st_size > maximum):
        raise DeploymentError(f"{label} size is invalid")
    return metadata


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DeploymentError("JSON contains a duplicate key")
        value[key] = item
    return value


def _json_file(path: Path, label: str) -> dict[str, Any]:
    raw = _regular_file(path, label, maximum=_MAX_JSON_BYTES)
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                DeploymentError("JSON contains a non-finite number")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise DeploymentError(f"{label} must be an object")
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DeploymentError("value is not canonical JSON") from exc


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        raise DeploymentError("release archive cannot be hashed") from exc
    return digest.hexdigest()


def _payload_sha(value: object) -> str:
    return _digest_bytes(_canonical_bytes(value))


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DeploymentError(f"{label} is not a SHA-256")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise DeploymentError(f"{label} is not a Git SHA")
    return value


def _bound_file_bytes(
    path: Path,
    label: str,
    *,
    maximum: int,
    expected_owner: int | None = None,
) -> tuple[bytes, str, int, str]:
    """Read one no-follow regular file once and reject metadata races."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        before_path = os.lstat(path)
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
            raise DeploymentError(f"{label} must be a regular file")
        if before_path.st_size < 0 or before_path.st_size > maximum:
            raise DeploymentError(f"{label} size is invalid")
        if expected_owner is not None and before_path.st_uid != expected_owner:
            raise DeploymentError(f"{label} owner is invalid")
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)
        ):
            raise DeploymentError(f"{label} identity is invalid")
        total = 0
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise DeploymentError(f"{label} size is invalid")
            chunks.append(block)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            stat.S_IMODE(value.st_mode),
            value.st_uid,
            value.st_gid,
            getattr(value, "st_mtime_ns", None),
            getattr(value, "st_ctime_ns", None),
        )
        if (
            identity(before) != identity(after)
            or (after.st_dev, after.st_ino) != (after_path.st_dev, after_path.st_ino)
            or total != before.st_size
        ):
            raise DeploymentError(f"{label} changed during inspection")
        raw = b"".join(chunks)
        return raw, _digest_bytes(raw), total, f"{stat.S_IMODE(before.st_mode):04o}"
    except DeploymentError:
        raise
    except OSError as exc:
        raise DeploymentError(f"{label} is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _inspect_bound_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    expected_owner: int | None = None,
) -> tuple[str, int, str]:
    _, digest, size, mode = _bound_file_bytes(
        path, label, maximum=maximum, expected_owner=expected_owner
    )
    return digest, size, mode


def _json_bound_file(
    path: Path,
    label: str,
    *,
    maximum: int = _MAX_JSON_BYTES,
    expected_owner: int | None = None,
) -> tuple[dict[str, Any], str, int, str]:
    raw, digest, size, mode = _bound_file_bytes(
        path, label, maximum=maximum, expected_owner=expected_owner
    )
    if not raw:
        raise DeploymentError(f"{label} size is invalid")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                DeploymentError("JSON contains a non-finite number")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise DeploymentError(f"{label} must be an object")
    return value, digest, size, mode


def _load_capsule(
    capsule_path: Path,
    *,
    now: datetime | None = None,
) -> CapsuleSeed:
    """Validate the complete sealed capsule before any SSH operation."""

    if ".." in capsule_path.parts:
        raise DeploymentError("capsule path traversal is forbidden")
    try:
        root = os.lstat(capsule_path)
    except OSError as exc:
        raise DeploymentError("capsule root is unavailable") from exc
    if (
        stat.S_ISLNK(root.st_mode)
        or not stat.S_ISDIR(root.st_mode)
        or stat.S_IMODE(root.st_mode) != 0o700
        or root.st_uid != os.geteuid()
    ):
        raise DeploymentError("capsule root ownership or mode is invalid")

    expected_directories = {
        "runtime",
        "runtime/input-cas",
        "runtime/input-cas/objects",
        "runtime/input-cas/.tmp",
    }
    observed_directories: set[str] = set()
    observed_files: set[str] = set()
    try:
        for path in capsule_path.rglob("*"):
            relative = path.relative_to(capsule_path).as_posix()
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                raise DeploymentError("capsule contains a symbolic link")
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
                    raise DeploymentError("capsule directory ownership or mode is invalid")
                observed_directories.add(relative)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_uid != os.geteuid():
                    raise DeploymentError("capsule file owner is invalid")
                observed_files.add(relative)
            else:
                raise DeploymentError("capsule contains an unsupported entry")
    except DeploymentError:
        raise
    except OSError as exc:
        raise DeploymentError("capsule inventory is unavailable") from exc
    if observed_directories != expected_directories:
        raise DeploymentError("capsule directory inventory is unexpected")

    manifest_path = capsule_path / _CAPSULE_MANIFEST_NAME
    manifest, manifest_sha, _, manifest_mode = _json_bound_file(
        manifest_path,
        "capsule manifest",
        maximum=_MAX_JSON_BYTES,
        expected_owner=os.geteuid(),
    )
    common = {
        "schema_id", "schema_version", "object_id", "issued_at", "issuer",
        "contour", "classification", "payload", "integrity",
    }
    if set(manifest) != common or manifest_mode != "0600":
        raise DeploymentError("capsule manifest shape or mode is invalid")
    payload = manifest.get("payload")
    integrity = manifest.get("integrity")
    issuer = manifest.get("issuer")
    payload_fields = {
        "release_manifest_sha256", "release_manifest_ref", "release_sha",
        "image_digest", "release_policy_sha256", "release_config_sha256",
        "runtime_config_sha256", "authority_policy_sha256",
        "resume_approval_ref", "runner_identity", "network_class",
        "external_action_authority", "inputs", "file_hashes",
    }
    if (
        manifest.get("schema_id") != "PreSoakCapsuleManifest"
        or manifest.get("schema_version") != "1.0.0"
        or manifest.get("contour") != "governance"
        or manifest.get("classification") != "D1_INTERNAL_SANITIZED"
        or issuer != {
            "id": "pre-soak-capsule-builder",
            "authority_class": "local-release-capsule-builder",
        }
        or not isinstance(payload, dict)
        or set(payload) != payload_fields
        or not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256", "parent_refs"}
        or integrity.get("payload_sha256") != _payload_sha(payload)
        or manifest.get("object_id") != "pre-soak-capsule-" + _payload_sha(payload)
    ):
        raise DeploymentError("capsule manifest identity or integrity is invalid")
    if (
        payload.get("release_manifest_sha256") != _FROZEN_RELEASE_MANIFEST_SHA256
        or payload.get("release_sha") != RELEASE_SHA
        or payload.get("image_digest") != IMAGE_ID
        or payload.get("release_config_sha256") != _FROZEN_RELEASE_CONFIG_SHA256
        or payload.get("runner_identity") != "pre-soak-offline-l0"
        or payload.get("network_class") != "offline"
        or payload.get("external_action_authority") is not False
    ):
        raise DeploymentError("capsule frozen release binding is invalid")
    release_policy_sha = _sha256(payload.get("release_policy_sha256"), "capsule release policy")
    config_sha = _sha256(payload.get("runtime_config_sha256"), "capsule runtime config")
    authority_policy_sha = _sha256(
        payload.get("authority_policy_sha256"), "capsule authority policy"
    )

    inputs = payload.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != {"market", "security"}:
        raise DeploymentError("capsule must bind exactly market and security inputs")
    objects: list[CapsuleObject] = []
    for contour in ("market", "security"):
        item = inputs.get(contour)
        if not isinstance(item, dict) or set(item) != {
            "classification", "cas_ref", "sha256", "size_bytes"
        }:
            raise DeploymentError("capsule input shape is invalid")
        classification = item.get("classification")
        digest = _sha256(item.get("sha256"), f"{contour} capsule input")
        size = item.get("size_bytes")
        cas_ref = item.get("cas_ref")
        if (
            classification not in {"D0_PUBLIC", "D1_INTERNAL_SANITIZED"}
            or cas_ref != f"cas:sha256:{digest}"
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > _MAX_CAPSULE_INPUT_BYTES
        ):
            raise DeploymentError("capsule input binding is invalid")
        source = capsule_path / "runtime" / "input-cas" / "objects" / digest
        objects.append(CapsuleObject(contour, classification, cas_ref, digest, size, source))
    if objects[0].sha256 == objects[1].sha256:
        raise DeploymentError("capsule must contain two distinct CAS objects")

    config_path = capsule_path / _CAPSULE_CONFIG_NAME
    expected_files = {
        _CAPSULE_MANIFEST_NAME,
        _CAPSULE_CONFIG_NAME,
        "runtime/input-cas/.cas.lock",
        *(f"runtime/input-cas/objects/{item.sha256}" for item in objects),
    }
    if observed_files != expected_files:
        raise DeploymentError("capsule contains an unexpected or unbound file")
    file_hashes = payload.get("file_hashes")
    if not isinstance(file_hashes, list):
        raise DeploymentError("capsule file inventory is invalid")
    config, config_actual_sha, config_size, config_mode = _json_bound_file(
        config_path,
        "capsule runtime config",
        expected_owner=os.geteuid(),
    )
    expected_records: dict[str, dict[str, object]] = {}
    for relative in sorted(expected_files - {_CAPSULE_MANIFEST_NAME}):
        if relative == _CAPSULE_CONFIG_NAME:
            actual_sha, actual_size, actual_mode = config_actual_sha, config_size, config_mode
        else:
            actual_sha, actual_size, actual_mode = _inspect_bound_file(
                capsule_path / relative,
                f"capsule file {relative}",
                maximum=_MAX_CAPSULE_INPUT_BYTES,
                expected_owner=os.geteuid(),
            )
        expected_records[relative] = {
            "relative_path": relative,
            "sha256": actual_sha,
            "size_bytes": actual_size,
            "mode": actual_mode,
        }
    observed_records: dict[str, dict[str, object]] = {}
    for record in file_hashes:
        if not isinstance(record, dict) or set(record) != {
            "relative_path", "sha256", "size_bytes", "mode"
        }:
            raise DeploymentError("capsule file hash record is invalid")
        relative = record.get("relative_path")
        if not isinstance(relative, str) or relative in observed_records:
            raise DeploymentError("capsule file hash path is invalid")
        observed_records[relative] = record
    if observed_records != expected_records:
        raise DeploymentError("capsule file hashes do not match sealed bytes")
    if expected_records[_CAPSULE_CONFIG_NAME]["sha256"] != config_sha or expected_records[_CAPSULE_CONFIG_NAME]["mode"] != "0600":
        raise DeploymentError("capsule config binding or mode is invalid")
    if expected_records["runtime/input-cas/.cas.lock"] != {
        "relative_path": "runtime/input-cas/.cas.lock",
        "sha256": hashlib.sha256(b"").hexdigest(),
        "size_bytes": 0,
        "mode": "0600",
    }:
        raise DeploymentError("capsule CAS lock is invalid")
    for item in objects:
        record = expected_records[f"runtime/input-cas/objects/{item.sha256}"]
        if record["sha256"] != item.sha256 or record["size_bytes"] != item.size_bytes or record["mode"] != "0444":
            raise DeploymentError("capsule CAS object bytes or mode are invalid")
    parent_refs = integrity.get("parent_refs")
    if not isinstance(parent_refs, list) or any(not isinstance(item, str) for item in parent_refs):
        raise DeploymentError("capsule parent references are invalid")
    for required in (objects[0].cas_ref, objects[1].cas_ref, f"image:{IMAGE_ID}"):
        if required not in parent_refs:
            raise DeploymentError("capsule parent references are incomplete")
    config_fields = {
        "schema_id", "schema_version", "runtime_root", "runner_identity",
        "allowed_uids", "input_quota_bytes", "checkpoint_quota_bytes",
        "artifact_quota_bytes", "maximum_input_bytes", "deadline_seconds",
        "trusted_issuers", "policy_snapshots", "approval_receipts",
    }
    policies = config.get("policy_snapshots")
    approvals = config.get("approval_receipts")
    if (
        set(config) != config_fields
        or config.get("schema_id") != "ResearchdServiceConfig"
        or config.get("schema_version") != "1.0.0"
        or config.get("runtime_root") != "/var/lib/research-os"
        or config.get("runner_identity") != "pre-soak-offline-l0"
        or config.get("allowed_uids") != [10001]
        or config.get("input_quota_bytes") != 16 * 1024 * 1024
        or config.get("checkpoint_quota_bytes") != 16 * 1024 * 1024
        or config.get("artifact_quota_bytes") != 16 * 1024 * 1024
        or config.get("maximum_input_bytes") != 4 * 1024 * 1024
        or config.get("deadline_seconds") != 5
        or config.get("trusted_issuers") != _EXPECTED_TRUSTED_ISSUERS
        or not isinstance(policies, dict)
        or set(policies) != {authority_policy_sha}
        or not isinstance(approvals, dict)
        or set(approvals) != {payload.get("resume_approval_ref")}
    ):
        raise DeploymentError("capsule runtime config boundary is invalid")
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise DeploymentError("capsule validation time must be timezone-aware")
    projected = dict(config)
    projected["allowed_uids"] = [os.geteuid()]
    try:
        service = _service_config_from_mapping(projected)
        if (
            service.runtime_root != "/var/lib/research-os"
            or service.runner_identity != "pre-soak-offline-l0"
        ):
            raise DeploymentError("capsule parsed service boundary is invalid")
        service.authority.verify_resume(
            str(payload.get("resume_approval_ref")), now=moment
        )
    except DeploymentError:
        raise
    except Exception as exc:
        raise DeploymentError("capsule active authority is invalid") from exc
    return CapsuleSeed(
        manifest_sha256=manifest_sha,
        manifest_object_id=str(manifest["object_id"]),
        config_sha256=config_sha,
        config_path=config_path,
        release_policy_sha256=release_policy_sha,
        release_config_sha256=_FROZEN_RELEASE_CONFIG_SHA256,
        objects=(objects[0], objects[1]),
    )


def _load_bundle(
    *,
    manifest_path: Path,
    policy_path: Path,
    config_path: Path,
    unit_path: Path,
    archive_path: Path | None = None,
    archive_sha256: str | None = None,
    capsule: CapsuleSeed | None = None,
    expected_release_sha: str = RELEASE_SHA,
    expected_image_id: str = IMAGE_ID,
    expected_previous_release: str = PREVIOUS_RELEASE,
    expected_config_sha256: str = _FROZEN_RELEASE_CONFIG_SHA256,
    expected_unit_template_sha256: str = _LEGACY_UNIT_SHA256,
    expected_policy: Mapping[str, object] = _EXPECTED_POLICY,
) -> ReleaseBundle:
    manifest, _, _, _ = _json_bound_file(manifest_path, "ReleaseManifest")
    policy, policy_sha, _, _ = _json_bound_file(policy_path, "runtime policy")
    if capsule is not None:
        config_path = capsule.config_path
    config_bytes, config_sha, _, _ = _bound_file_bytes(
        config_path, "service config", maximum=_MAX_JSON_BYTES
    )
    unit_template = _regular_file(unit_path, "service unit template", maximum=256_000)

    if policy != expected_policy:
        raise DeploymentError("runtime policy drifted from the frozen boundary")
    if set(manifest) != {
        "schema_id",
        "schema_version",
        "object_id",
        "issued_at",
        "issuer",
        "contour",
        "classification",
        "payload",
        "integrity",
    }:
        raise DeploymentError("ReleaseManifest shape is invalid")
    if manifest.get("schema_id") != "ReleaseManifest" or manifest.get("schema_version") != "1.0.0":
        raise DeploymentError("ReleaseManifest schema is invalid")
    payload = manifest.get("payload")
    integrity = manifest.get("integrity")
    if not isinstance(payload, dict) or not isinstance(integrity, dict):
        raise DeploymentError("ReleaseManifest sections are invalid")
    if integrity.get("payload_sha256") != _payload_sha(payload):
        raise DeploymentError("ReleaseManifest payload integrity is invalid")
    release_sha = payload.get("release_sha")
    if not isinstance(release_sha, str) or _GIT_SHA.fullmatch(release_sha) is None:
        raise DeploymentError("release SHA is invalid")
    images = payload.get("image_digests")
    expected_release_sha = _git_sha(expected_release_sha, "expected release SHA")
    if not isinstance(expected_image_id, str) or not expected_image_id.startswith("sha256:"):
        raise DeploymentError("expected image identity is not an image SHA-256")
    expected_image_id = "sha256:" + _sha256(
        expected_image_id.removeprefix("sha256:"), "expected image identity"
    )
    if not isinstance(images, list) or images != [expected_image_id]:
        raise DeploymentError("release image identity is not the frozen candidate")
    if (
        release_sha != expected_release_sha
        or payload.get("previous_release_ref") != expected_previous_release
    ):
        raise DeploymentError("release or rollback identity is not frozen")
    if payload.get("policy_sha256") != policy_sha or payload.get("config_sha256") != config_sha:
        raise DeploymentError("release policy or config binding is invalid")
    if capsule is not None:
        parent_refs = integrity.get("parent_refs")
        if (
            config_sha != capsule.config_sha256
            or policy_sha != capsule.release_policy_sha256
            or not isinstance(parent_refs, list)
            or f"{_CAPSULE_PARENT_PREFIX}{capsule.manifest_sha256}" not in parent_refs
        ):
            raise DeploymentError("functional release does not bind the sealed capsule")
    elif (
        config_sha != expected_config_sha256
        or _digest_bytes(unit_template) != expected_unit_template_sha256
    ):
        raise DeploymentError("legacy deployment profile is not the exact frozen profile")

    template = unit_template.decode("utf-8", errors="strict")
    allowed_tokens = _UNIT_TOKENS | {_CAPSULE_UNIT_TOKEN}
    observed_tokens = {token for token in allowed_tokens if token in template}
    expected_tokens = _UNIT_TOKENS | ({_CAPSULE_UNIT_TOKEN} if capsule is not None else set())
    if observed_tokens != expected_tokens:
        raise DeploymentError("service unit template tokens are invalid")
    rendered = (
        template.replace("@@IMAGE_ID@@", expected_image_id)
        .replace("@@RELEASE_SHA@@", release_sha)
        .replace("@@POLICY_SHA256@@", policy_sha)
        .replace("@@CONFIG_SHA256@@", config_sha)
    ).encode("utf-8")
    if capsule is not None:
        rendered = rendered.replace(
            _CAPSULE_UNIT_TOKEN.encode("ascii"), capsule.manifest_sha256.encode("ascii")
        )
    if b"@@" in rendered:
        raise DeploymentError("service unit retained an unresolved token")
    has_tmpdir = "--env=TMPDIR=/var/lib/research-os/tmp" in template
    if capsule is not None and not has_tmpdir:
        raise DeploymentError("capsule service unit does not bind the writable TMPDIR")
    if capsule is None and has_tmpdir:
        raise DeploymentError("legacy service unit unexpectedly selects the capsule profile")

    actual_archive_sha: str | None = None
    if archive_path is not None:
        _regular_file_metadata(archive_path, "release archive")
        expected_archive_sha = _sha256(archive_sha256, "archive SHA-256")
        actual_archive_sha = _digest_file(archive_path)
        if actual_archive_sha != expected_archive_sha:
            raise DeploymentError("local release archive SHA-256 does not match")
    elif archive_sha256 is not None:
        raise DeploymentError("archive SHA-256 was supplied without an archive")

    return ReleaseBundle(
        release_sha=release_sha,
        image_id=expected_image_id,
        previous_release_ref=expected_previous_release,
        policy_sha256=policy_sha,
        config_sha256=config_sha,
        archive_sha256=actual_archive_sha,
        unit_bytes=rendered,
        unit_sha256=_digest_bytes(rendered),
        config_path=config_path,
        archive_path=archive_path,
        capsule=capsule,
    )


class PreSoakDeployController:
    """Operate one exact release through an SSH alias and rootless Docker."""

    def __init__(
        self,
        *,
        ssh_alias: str,
        known_hosts_path: Path,
        runner: Runner | None = None,
        clock: Callable[[], datetime] | None = None,
        target: DeploymentTarget = LEGACY_TARGET,
    ) -> None:
        if _ALIAS.fullmatch(ssh_alias) is None:
            raise DeploymentError("target must be a normalized SSH config alias")
        _regular_file(known_hosts_path, "known_hosts", maximum=4 * 1024 * 1024)
        self._alias = ssh_alias
        self._known_hosts = str(known_hosts_path.resolve())
        self._runner = runner or SubprocessRunner()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if target not in {LEGACY_TARGET, FINAL_A1_TARGET}:
            raise DeploymentError("deployment target is not a frozen profile")
        self._target = target

    def _ssh_arguments(self) -> list[str]:
        return [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self._known_hosts}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ConnectTimeout=10",
            self._alias,
        ]

    def _ssh(
        self,
        command: str,
        *,
        input_bytes: bytes | None = None,
        check: bool = True,
        timeout: float = 60.0,
    ) -> CommandResult:
        result = self._runner.run(
            [*self._ssh_arguments(), command],
            input_bytes=input_bytes,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            raise DeploymentError("remote bounded command failed")
        return result

    def _scp(self, source: Path, remote_relative_path: str) -> None:
        if not remote_relative_path or remote_relative_path.startswith(('/', '~')) or ".." in remote_relative_path.split("/"):
            raise DeploymentError("remote relative path is invalid")
        arguments = [
            "scp",
            "-q",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self._known_hosts}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ConnectTimeout=10",
            str(source),
            f"{self._alias}:{remote_relative_path}",
        ]
        result = self._runner.run(arguments, timeout=600.0)
        if result.returncode != 0:
            raise DeploymentError("content-addressed transfer failed")

    def preflight(self) -> dict[str, object]:
        expanded = self._runner.run(
            [*self._ssh_arguments()[:-1], "-G", self._alias], timeout=15.0
        )
        if expanded.returncode != 0 or not expanded.stdout.strip():
            raise DeploymentError("SSH alias cannot be expanded")
        probe = self._ssh(
            "set -eu; uid=\"$(id -u)\"; test \"$uid\" -ne 0; "
            "test \"$(uname -s)\" = Linux; test \"$(uname -m)\" = x86_64; "
            "command -v /usr/bin/docker >/dev/null; command -v systemctl >/dev/null; "
            "command -v loginctl >/dev/null; "
            "command -v sha256sum >/dev/null; command -v install >/dev/null; "
            "command -v mv >/dev/null; command -v cat >/dev/null; command -v stat >/dev/null; "
            "test -S \"/run/user/$uid/docker.sock\"; test -O \"/run/user/$uid/docker.sock\"; "
            "test \"$(loginctl show-user \"$uid\" -p Linger --value)\" = yes; "
            "systemctl --user show-environment >/dev/null; "
            "systemctl --user is-enabled --quiet docker.service; "
            "printf '%s\\n' \"$uid\" \"$(cat /proc/sys/kernel/random/boot_id)\""
        )
        lines = probe.stdout.splitlines()
        if len(lines) != 2 or not lines[0].isdigit() or int(lines[0]) <= 0:
            raise DeploymentError("remote non-root identity proof is invalid")
        if not re.fullmatch(r"[A-Fa-f0-9-]{32,36}", lines[1]):
            raise DeploymentError("remote boot identity proof is invalid")
        info = self._ssh(
            f"{_DOCKER} info --format '{{{{json .SecurityOptions}}}}|{{{{.OSType}}}}|{{{{.Architecture}}}}'"
        ).stdout.strip()
        parts = info.split("|", 2)
        if len(parts) != 3:
            raise DeploymentError("rootless Docker information is invalid")
        try:
            security = json.loads(parts[0])
        except json.JSONDecodeError as exc:
            raise DeploymentError("rootless Docker security information is invalid") from exc
        if (
            not isinstance(security, list)
            or not any(isinstance(item, str) and "rootless" in item for item in security)
            or parts[1] != "linux"
            or parts[2] not in {"x86_64", "amd64"}
        ):
            raise DeploymentError("Docker endpoint is not the required rootless linux/amd64 engine")
        return {
            "ssh_alias_resolved": True,
            "strict_host_key_checking": True,
            "non_root_identity": True,
            "rootless_docker": True,
            "rootless_docker_boot_enabled": True,
            "user_systemd": True,
            "user_lingering": True,
            "platform": "linux/amd64",
        }

    def _remote_sha(self, remote_path: str) -> str:
        result = self._ssh(f"sha256sum -- {remote_path}")
        token = result.stdout.strip().split(maxsplit=1)[0] if result.stdout.strip() else ""
        return _sha256(token, "remote content SHA-256")

    def _image_inspect(self, bundle: ReleaseBundle) -> dict[str, Any]:
        result = self._ssh(
            f"{_DOCKER} image inspect {bundle.image_id} --format '{{{{json .}}}}'"
        )
        value = _json_output(result.stdout, "image inspection")
        config = value.get("Config")
        if not isinstance(config, dict):
            raise DeploymentError("image config inspection is invalid")
        labels = config.get("Labels")
        if (
            value.get("Id") != bundle.image_id
            or value.get("Os") != "linux"
            or value.get("Architecture") != "amd64"
            or config.get("User") != "10001:10001"
            or not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.revision") != bundle.release_sha
        ):
            raise DeploymentError("loaded image does not match the frozen release identity")
        return value

    def _stage_capsule_objects(self, capsule: CapsuleSeed) -> str:
        nonce = _digest_bytes(os.urandom(32))
        incoming_name = f"capsule-{nonce}"
        incoming_relative = f".local/share/{self._target.remote_slug}/incoming/{incoming_name}"
        incoming_remote = f"{self._target.remote_base}/incoming/{incoming_name}"
        created = self._ssh(
            "set -eu; umask 077; directory=" + incoming_remote + "; "
            f"for parent in \"$HOME\" \"$HOME/.local\" \"$HOME/.local/share\" {self._target.remote_base} {self._target.remote_base}/incoming; do "
            "test ! -L \"$parent\"; test -d \"$parent\"; test -O \"$parent\"; "
            "mode=\"$(stat -c %a \"$parent\")\"; test \"$((0$mode & 0022))\" = 0; done; "
            f"test \"$(stat -c %a {self._target.remote_base})\" = 700; "
            f"test \"$(stat -c %a {self._target.remote_base}/incoming)\" = 700; "
            "mkdir -m 0700 -- \"$directory\"; "
            "test ! -L \"$directory\"; test -d \"$directory\"; test -O \"$directory\"; "
            "test \"$(stat -c %a \"$directory\")\" = 700; "
            "printf 'CAPSULE_STAGE_CREATED\\n'"
        )
        if created.stdout.strip() != "CAPSULE_STAGE_CREATED":
            raise DeploymentError("remote capsule staging directory is invalid")
        for item in capsule.objects:
            actual_sha, actual_size, actual_mode = _inspect_bound_file(
                item.source_path,
                f"{item.contour} capsule object",
                maximum=_MAX_CAPSULE_INPUT_BYTES,
                expected_owner=os.geteuid(),
            )
            if (actual_sha, actual_size, actual_mode) != (item.sha256, item.size_bytes, "0444"):
                raise DeploymentError("capsule object changed before transfer")
            self._scp(item.source_path, f"{incoming_relative}/{item.sha256}")
        checks = " ".join(
            f'{item.sha256}) expected_sha={item.sha256}; expected_size={item.size_bytes} ;;'
            for item in capsule.objects
        )
        ready = self._ssh(
            "set -eu; directory=" + incoming_remote + "; "
            "test ! -L \"$directory\"; test -d \"$directory\"; test -O \"$directory\"; "
            "test \"$(stat -c %a \"$directory\")\" = 700; count=0; "
            "for entry in \"$directory\"/* \"$directory\"/.[!.]* \"$directory\"/..?*; do "
            "test -e \"$entry\" || test -L \"$entry\" || continue; count=$((count + 1)); "
            "test ! -L \"$entry\"; test -f \"$entry\"; test -O \"$entry\"; name=${entry##*/}; "
            f"case \"$name\" in {checks} *) exit 42 ;; esac; "
            "chmod 0400 -- \"$entry\"; test \"$(stat -c %a \"$entry\")\" = 400; "
            "test \"$(stat -c %s \"$entry\")\" = \"$expected_size\"; "
            "observed=\"$(sha256sum -- \"$entry\")\"; "
            "test \"${observed%% *}\" = \"$expected_sha\"; done; "
            "test \"$count\" = 2; printf 'CAPSULE_STAGE_READY\\n'"
        )
        if ready.stdout.strip() != "CAPSULE_STAGE_READY":
            raise DeploymentError("remote capsule staging content is invalid")
        return incoming_remote

    def _cleanup_capsule_stage(self, capsule: CapsuleSeed, incoming_remote: str) -> None:
        paths = " ".join(f'"$directory/{item.sha256}"' for item in capsule.objects)
        checks = " ".join(
            f'{item.sha256}) expected={item.sha256} ;;' for item in capsule.objects
        )
        result = self._ssh(
            "set -eu; directory=" + incoming_remote + "; "
            "test ! -L \"$directory\"; test -d \"$directory\"; "
            "for entry in \"$directory\"/* \"$directory\"/.[!.]* \"$directory\"/..?*; do "
            "test -e \"$entry\" || test -L \"$entry\" || continue; "
            "test ! -L \"$entry\"; test -f \"$entry\"; test -O \"$entry\"; "
            "test \"$(stat -c %a \"$entry\")\" = 400; name=${entry##*/}; "
            f"case \"$name\" in {checks} *) exit 43 ;; esac; "
            "observed=\"$(sha256sum -- \"$entry\")\"; "
            "test \"${observed%% *}\" = \"$expected\"; done; "
            f"rm -- {paths}; rmdir -- \"$directory\"; "
            "test ! -e \"$directory\"; printf 'CAPSULE_STAGE_CLEANED\\n'"
        )
        if result.stdout.strip() != "CAPSULE_STAGE_CLEANED":
            raise DeploymentError("remote capsule staging cleanup is invalid")

    @staticmethod
    def _capsule_volume_init_script(capsule: CapsuleSeed) -> str:
        expected = {item.sha256: item.size_bytes for item in capsule.objects}
        return "\n".join(
            (
                "import hashlib, os, stat, sys",
                "UID = GID = 10001",
                f"EXPECTED = {expected!r}",
                f"CONFIG_SHA = {capsule.config_sha256!r}",
                "def fail(): raise SystemExit(70)",
                "def digest(path):",
                "    h = hashlib.sha256()",
                "    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)",
                "    fd = os.open(path, flags)",
                "    try:",
                "        while True:",
                "            block = os.read(fd, 65536)",
                "            if not block: break",
                "            h.update(block)",
                "    finally: os.close(fd)",
                "    return h.hexdigest()",
                "def exact(path, kind, mode):",
                "    st = os.lstat(path)",
                "    if stat.S_ISLNK(st.st_mode): fail()",
                "    if kind == 'dir' and not stat.S_ISDIR(st.st_mode): fail()",
                "    if kind == 'file' and not stat.S_ISREG(st.st_mode): fail()",
                "    if stat.S_IMODE(st.st_mode) != mode or st.st_uid != UID or st.st_gid != GID: fail()",
                "def ensure_dir(path, initialize_empty=False):",
                "    if os.path.lexists(path):",
                "        st = os.lstat(path)",
                "        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode): fail()",
                "        if stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == UID and st.st_gid == GID: return",
                "        if not initialize_empty or os.listdir(path): fail()",
                "        os.chmod(path, 0o700); os.chown(path, UID, GID)",
                "    else:",
                "        os.mkdir(path, 0o700); os.chmod(path, 0o700); os.chown(path, UID, GID)",
                "def fsync_dir(path):",
                "    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))",
                "    try: os.fsync(fd)",
                "    finally: os.close(fd)",
                "def install_exact(source, target, expected_sha, expected_size, mode):",
                "    source_st = os.lstat(source)",
                "    if stat.S_ISLNK(source_st.st_mode) or not stat.S_ISREG(source_st.st_mode): fail()",
                "    source_fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))",
                "    opened = os.fstat(source_fd)",
                "    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (source_st.st_dev, source_st.st_ino) or opened.st_size != expected_size: fail()",
                "    target_fd = None",
                "    created = False",
                "    complete = False",
                "    try:",
                "        if not os.path.lexists(target):",
                "            target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), mode)",
                "            created = True",
                "        h = hashlib.sha256(); total = 0",
                "        while True:",
                "            block = os.read(source_fd, 65536)",
                "            if not block: break",
                "            total += len(block); h.update(block)",
                "            if target_fd is not None:",
                "                view = memoryview(block)",
                "                while view:",
                "                    written = os.write(target_fd, view)",
                "                    if written <= 0: fail()",
                "                    view = view[written:]",
                "        after = os.fstat(source_fd); after_path = os.lstat(source)",
                "        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)",
                "        if identity(opened) != identity(after) or (after.st_dev, after.st_ino) != (after_path.st_dev, after_path.st_ino) or total != expected_size or h.hexdigest() != expected_sha: fail()",
                "        if target_fd is not None:",
                "            os.fchmod(target_fd, mode); os.fchown(target_fd, UID, GID); os.fsync(target_fd)",
                "        complete = True",
                "    finally:",
                "        os.close(source_fd)",
                "        if target_fd is not None: os.close(target_fd)",
                "        if created and not complete:",
                "            try: os.unlink(target)",
                "            except OSError: pass",
                "    exact(target, 'file', mode)",
                "    target_st = os.lstat(target)",
                "    if target_st.st_size != expected_size or digest(target) != expected_sha: fail()",
                "runtime = '/target-runtime'",
                "config_root = '/target-config'",
                "ensure_dir(runtime, initialize_empty=True)",
                "ensure_dir(config_root, initialize_empty=True)",
                "for path in (runtime + '/input-cas', runtime + '/input-cas/objects', runtime + '/input-cas/.tmp', runtime + '/tmp'): ensure_dir(path)",
                "input_root = runtime + '/input-cas'",
                "objects = input_root + '/objects'",
                "temporary = input_root + '/.tmp'",
                "lock = input_root + '/.cas.lock'",
                "if os.path.lexists(lock):",
                "    exact(lock, 'file', 0o600)",
                "    if os.lstat(lock).st_size != 0: fail()",
                "else:",
                "    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)",
                "    os.fchmod(fd, 0o600); os.fchown(fd, UID, GID); os.fsync(fd); os.close(fd)",
                "if set(os.listdir(input_root)) != {'objects', '.tmp', '.cas.lock'}: fail()",
                "if os.listdir(temporary) or os.listdir(runtime + '/tmp'): fail()",
                "if not set(os.listdir(objects)).issubset(set(EXPECTED)): fail()",
                "if set(os.listdir('/source-cas')) != set(EXPECTED): fail()",
                "for name, size in EXPECTED.items(): install_exact('/source-cas/' + name, objects + '/' + name, name, size, 0o444)",
                "if set(os.listdir(objects)) != set(EXPECTED): fail()",
                "source_config = '/source-config/researchd.json'",
                "config_size = os.lstat(source_config).st_size",
                "install_exact(source_config, config_root + '/researchd.json', CONFIG_SHA, config_size, 0o600)",
                "for path in (runtime, input_root, objects, temporary, runtime + '/tmp'): exact(path, 'dir', 0o700)",
                "for path in (objects, input_root, runtime, config_root): fsync_dir(path)",
                "print('CAPSULE_VOLUME_INIT_OK:' + CONFIG_SHA)",
            )
        )

    def _stage_content(self, bundle: ReleaseBundle) -> None:
        if bundle.archive_path is None or bundle.archive_sha256 is None:
            raise DeploymentError("deployment requires a content-addressed archive")
        self._ssh(
            "set -eu; umask 077; "
            f"install -d -m 0700 {self._target.remote_base}/incoming {self._target.remote_config} "
            '"$HOME/.config/systemd/user"'
        )
        archive_relative = f".local/share/{self._target.remote_slug}/incoming/release-{bundle.archive_sha256}.tar"
        archive_remote = f"{self._target.remote_base}/incoming/release-{bundle.archive_sha256}.tar"
        self._scp(bundle.archive_path, archive_relative)
        if self._remote_sha(archive_remote) != bundle.archive_sha256:
            raise DeploymentError("remote release archive SHA-256 does not match")
        self._ssh(f"{_DOCKER} load --input {archive_remote}", timeout=600.0)
        self._image_inspect(bundle)

        config_relative = f".config/{self._target.remote_slug}/researchd-{bundle.config_sha256}.json"
        config_remote = f"{self._target.remote_config}/researchd-{bundle.config_sha256}.json"
        self._scp(bundle.config_path, config_relative)
        if self._remote_sha(config_remote) != bundle.config_sha256:
            raise DeploymentError("remote service config SHA-256 does not match")
        self._ssh(f"chmod 0600 {config_remote}")
        capsule_remote = None
        if bundle.capsule is not None:
            capsule_remote = self._stage_capsule_objects(bundle.capsule)
        self._ssh(f"{_DOCKER} volume create {self._target.runtime_volume}")
        self._ssh(f"{_DOCKER} volume create {self._target.config_volume}")
        if bundle.capsule is None:
            init_command = (
            f"{_DOCKER} run --rm --name={self._target.container_name}-volume-init "
            "--user=0:0 --network=none --read-only "
            "--security-opt=no-new-privileges:true --pids-limit=32 "
            "--memory=134217728 --cpus=0.25 "
            f"--mount=type=bind,source={config_remote},target=/source/researchd.json,readonly "
            f"--mount=type=volume,source={self._target.config_volume},target=/target-config "
            f"--mount=type=volume,source={self._target.runtime_volume},target=/target-runtime "
            f"--entrypoint=/bin/sh {bundle.image_id} -eu -c "
            + shlex.quote(
                "install -m 0600 -o 10001 -g 10001 /source/researchd.json "
                "/target-config/researchd.json; "
                "install -d -m 0700 -o 10001 -g 10001 /target-runtime"
            )
            )
            self._ssh(init_command)
            verify_command = (
            f"{_DOCKER} run --rm --network=none --read-only --cap-drop=ALL "
            "--security-opt=no-new-privileges:true --pids-limit=16 "
            "--memory=67108864 --cpus=0.25 --user=10001:10001 "
            f"--mount=type=volume,source={self._target.config_volume},target=/target-config,readonly "
            f"--mount=type=volume,source={self._target.runtime_volume},target=/target-runtime "
            f"--entrypoint=/bin/sh {bundle.image_id} -eu -c "
            + shlex.quote(
                "test \"$(stat -c %u:%g:%a /target-config/researchd.json)\" "
                "= 10001:10001:600; "
                "test \"$(stat -c %u:%g:%a /target-runtime)\" = 10001:10001:700; "
                "sha256sum /target-config/researchd.json"
            )
            )
            verified = self._ssh(verify_command).stdout.strip().split(maxsplit=1)
            if not verified or verified[0] != bundle.config_sha256:
                raise DeploymentError("container-visible config ownership or digest is invalid")
        else:
            assert capsule_remote is not None
            init_command = (
                f"{_DOCKER} run --rm --name={self._target.container_name}-capsule-volume-init "
                "--user=0:0 --network=none --read-only --cap-drop=ALL "
                "--cap-add=CHOWN --cap-add=DAC_OVERRIDE "
                "--security-opt=no-new-privileges:true --pids-limit=32 "
                "--memory=134217728 --cpus=0.25 "
                f"--mount=type=bind,source={config_remote},target=/source-config/researchd.json,readonly "
                f"--mount=type=bind,source={capsule_remote},target=/source-cas,readonly "
                f"--mount=type=volume,source={self._target.config_volume},target=/target-config "
                f"--mount=type=volume,source={self._target.runtime_volume},target=/target-runtime "
                f"--entrypoint=python {bundle.image_id} -c "
                + shlex.quote(self._capsule_volume_init_script(bundle.capsule))
            )
            proof = self._ssh(init_command).stdout.strip()
            if proof != f"CAPSULE_VOLUME_INIT_OK:{bundle.config_sha256}":
                raise DeploymentError("capsule volume initialization proof is invalid")
            self._cleanup_capsule_stage(bundle.capsule, capsule_remote)

        saved_unit = self._saved_unit(bundle)
        self._ssh(
            f"set -eu; umask 077; cat > {saved_unit}",
            input_bytes=bundle.unit_bytes,
        )
        self._ssh(f"chmod 0600 {saved_unit}")
        if self._remote_sha(saved_unit) != bundle.unit_sha256:
            raise DeploymentError("remote rendered unit SHA-256 does not match")

    def _saved_unit(self, bundle: ReleaseBundle) -> str:
        return f"{self._target.remote_config}/{self._target.remote_slug}.{bundle.release_sha}.service"

    def _install_saved_unit(self, bundle: ReleaseBundle) -> None:
        saved = self._saved_unit(bundle)
        next_unit = f"{self._target.remote_unit}.next"
        self._ssh(f"install -m 0600 {saved} {next_unit}")
        if self._remote_sha(next_unit) != bundle.unit_sha256:
            raise DeploymentError("staged systemd unit SHA-256 does not match")
        try:
            self._ssh(f"mv -f -- {next_unit} {self._target.remote_unit}")
            self._ssh("systemctl --user daemon-reload")
            self._ssh(f"systemctl --user enable --now {self._target.service_name}", timeout=120.0)
        except DeploymentError:
            self._force_stopped(bundle, suffix="activation-failed")
            raise

    def _force_stopped(self, bundle: ReleaseBundle, *, suffix: str) -> None:
        self._ssh(f"systemctl --user disable --now {self._target.service_name}", check=False)
        self._ssh(f"{_DOCKER} stop --time=30 {self._target.container_name}", check=False)
        destination = f"{self._target.remote_config}/{suffix}.{bundle.release_sha}.service"
        self._ssh(
            f"set -eu; if test -f {self._target.remote_unit}; then mv -f -- {self._target.remote_unit} {destination}; fi; "
            "systemctl --user daemon-reload"
        )

    def _systemd_running(self) -> None:
        active = self._ssh(f"systemctl --user is-active {self._target.service_name}")
        if active.stdout.strip() != "active":
            raise DeploymentError("Bridge user service is not active")
        enabled = self._ssh(f"systemctl --user is-enabled {self._target.service_name}")
        if enabled.stdout.strip() not in {"enabled", "enabled-runtime"}:
            raise DeploymentError("Bridge user service is not enabled")

    def _container_inspect(
        self,
        bundle: ReleaseBundle,
        *,
        require_running: bool,
        missing_ok: bool = False,
    ) -> dict[str, Any] | None:
        result = self._ssh(
            f"{_DOCKER} container inspect {self._target.container_name} --format '{{{{json .}}}}'",
            check=False,
        )
        if result.returncode != 0:
            if missing_ok:
                return None
            raise DeploymentError("Bridge container inspection failed")
        value = _json_output(result.stdout, "container inspection")
        config = value.get("Config")
        host = value.get("HostConfig")
        state = value.get("State")
        mounts = value.get("Mounts")
        network = value.get("NetworkSettings")
        if not all(isinstance(item, dict) for item in (config, host, state, network)) or not isinstance(mounts, list):
            raise DeploymentError("container inspection shape is invalid")
        assert isinstance(config, dict) and isinstance(host, dict) and isinstance(state, dict)
        labels = config.get("Labels")
        environment = config.get("Env")
        security = host.get("SecurityOpt")
        cap_drop = host.get("CapDrop")
        restart = host.get("RestartPolicy")
        running = state.get("Running")
        expected_environment = [
            "RESEARCH_OS_ENVIRONMENT=pre-soak",
            "RESEARCH_OS_EXTERNAL_ACTION_AUTHORITY=false",
            *(
                ["TMPDIR=/var/lib/research-os/tmp"]
                if bundle.capsule is not None
                else []
            ),
            *_FROZEN_IMAGE_ENV,
        ]
        tmpdir_entries = (
            [item for item in environment if isinstance(item, str) and item.startswith("TMPDIR=")]
            if isinstance(environment, list)
            else []
        )
        capsule_tmpdir_valid = (
            tmpdir_entries == ["TMPDIR=/var/lib/research-os/tmp"]
            if bundle.capsule is not None
            else tmpdir_entries == []
        )
        capsule_label_valid = (
            isinstance(labels, dict)
            and labels.get("org.research-os.capsule-manifest-sha256")
            == bundle.capsule.manifest_sha256
            if bundle.capsule is not None
            else isinstance(labels, dict)
            and "org.research-os.capsule-manifest-sha256" not in labels
        )
        if (
            value.get("Name") not in {self._target.container_name, f"/{self._target.container_name}"}
            or value.get("Image") != bundle.image_id
            or config.get("Image") != bundle.image_id
            or config.get("User") != "10001:10001"
            or config.get("Entrypoint")
            != ["python", "-m", "research_bridge.researchd"]
            or config.get("Cmd")
            != ["--config", "/run/research-os/researchd.json"]
            or config.get("WorkingDir") != "/opt/research-os"
            or config.get("StopSignal") != "SIGTERM"
            or config.get("Healthcheck") is not None
            or not isinstance(labels, dict)
            or labels.get("org.research-os.release-sha") != bundle.release_sha
            or labels.get("org.research-os.policy-sha256") != bundle.policy_sha256
            or labels.get("org.research-os.config-sha256") != bundle.config_sha256
            or not capsule_label_valid
            or environment != expected_environment
            or not capsule_tmpdir_valid
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or not isinstance(cap_drop, list)
            or {str(item).upper() for item in cap_drop} != {"ALL"}
            or not isinstance(security, list)
            or security != ["no-new-privileges:true"]
            or host.get("CapAdd") not in (None, [])
            or host.get("Privileged") is not False
            or host.get("Devices") not in (None, [])
            or host.get("Binds") not in (None, [])
            or host.get("PidsLimit") != 256
            or host.get("Memory") != 2147483648
            or host.get("NanoCpus") != 2_000_000_000
            or not isinstance(restart, dict)
            or restart.get("Name") != self._target.docker_restart_policy
            or host.get("PortBindings") not in (None, {})
            or running is not require_running
        ):
            raise DeploymentError("container drifted from the frozen runtime policy")
        if (
            len(mounts) != 2
            or any(not isinstance(item, dict) for item in mounts)
            or {item.get("Destination") for item in mounts}
            != {"/var/lib/research-os", "/run/research-os"}
        ):
            raise DeploymentError("container has an unexpected mount")
        mount_by_destination = {
            item.get("Destination"): item for item in mounts if isinstance(item, dict)
        }
        runtime_mount = mount_by_destination.get("/var/lib/research-os")
        config_mount = mount_by_destination.get("/run/research-os")
        if (
            not isinstance(runtime_mount, dict)
            or runtime_mount.get("Type") != "volume"
            or runtime_mount.get("Name") != self._target.runtime_volume
            or runtime_mount.get("RW") is not True
            or not isinstance(config_mount, dict)
            or config_mount.get("Type") != "volume"
            or config_mount.get("Name") != self._target.config_volume
            or config_mount.get("RW") is not False
        ):
            raise DeploymentError("container mounts drifted from the frozen runtime policy")
        ports = network.get("Ports") if isinstance(network, dict) else None
        if ports not in (None, {}):
            raise DeploymentError("container unexpectedly publishes a port")
        return value

    def _pause_snapshot(self) -> tuple[dict[str, Any], str]:
        result = self._ssh(
            f"{_DOCKER} exec --user=10001:10001 {self._target.container_name} python -m "
            "research_bridge.researchctl --socket /var/lib/research-os/researchd.sock "
            "--request-id deployment-verification status"
        )
        response = _json_output(result.stdout, "AF_UNIX status response")
        snapshot = response.get("result")
        if (
            response.get("version") != "1.1"
            or response.get("request_id") != "deployment-verification"
            or response.get("command") != "status"
            or response.get("ok") is not True
            or not isinstance(snapshot, dict)
            or type(snapshot.get("paused")) is not bool
        ):
            raise DeploymentError("AF_UNIX pause-state response is invalid")
        return snapshot, _payload_sha(snapshot)

    def _boot_id_sha256(self) -> str:
        result = self._ssh("cat /proc/sys/kernel/random/boot_id")
        value = result.stdout.strip()
        if re.fullmatch(r"[A-Fa-f0-9-]{32,36}", value) is None:
            raise DeploymentError("boot identity is invalid")
        return _digest_bytes(value.lower().encode("ascii"))

    def _assert_no_conflicting_writer(self) -> None:
        service = self._target.conflicting_service_name
        container = self._target.conflicting_container_name
        if service is None and container is None:
            return
        if not service or not container:
            raise DeploymentError("conflicting writer profile is incomplete")
        if self._ssh(f"systemctl --user is-active --quiet {service}", check=False).returncode == 0:
            raise DeploymentError("conflicting predecessor service is active")
        if self._ssh(f"systemctl --user is-enabled --quiet {service}", check=False).returncode == 0:
            raise DeploymentError("conflicting predecessor service is enabled")
        inspected = self._ssh(
            "set -eu; if state=\"$("
            f"{_DOCKER} container inspect {container} --format '{{{{json .State.Running}}}}' 2>/dev/null"
            ")\"; then printf 'PRESENT:%s\\n' \"$state\"; "
            f"else {_DOCKER} info --format '{{{{.OSType}}}}' >/dev/null; printf 'ABSENT\\n'; fi"
        ).stdout.strip()
        if inspected in {"ABSENT", "PRESENT:false"}:
            return
        if inspected == "PRESENT:true":
            raise DeploymentError("conflicting predecessor container is running")
        raise DeploymentError("conflicting predecessor state is invalid")

    def _verify_running(self, bundle: ReleaseBundle) -> tuple[dict[str, Any], str]:
        self._systemd_running()
        self._container_inspect(bundle, require_running=True)
        return self._pause_snapshot()

    def deploy(
        self,
        bundle: ReleaseBundle,
        *,
        authorization: Callable[[], Mapping[str, object]] | None = None,
    ) -> dict[str, Any]:
        preflight = self.preflight()
        self._assert_no_conflicting_writer()
        inactive = self._ssh(
            f"systemctl --user is-active --quiet {self._target.service_name}", check=False
        )
        if inactive.returncode == 0:
            raise DeploymentError("first-release deploy requires the stopped prior state")
        existing = self._container_inspect(bundle, require_running=False, missing_ok=True)
        if existing is not None:
            # An interrupted retry may retain only the exact stopped candidate.
            self._container_inspect(bundle, require_running=False)
        authorization_evidence: dict[str, object] | None = None
        if authorization is not None:
            supplied = authorization()
            if not isinstance(supplied, Mapping) or supplied.get("consumed") is not True:
                raise DeploymentError("deployment authorization was not durably consumed")
            authorization_evidence = dict(supplied)
            self._assert_no_conflicting_writer()
        self._stage_content(bundle)
        self._install_saved_unit(bundle)
        snapshot, pause_sha = self._verify_running(bundle)
        evidence: dict[str, Any] = {
            "preflight": preflight,
            "archive_sha256": bundle.archive_sha256,
            "remote_archive_verified": True,
            "unit_sha256": bundle.unit_sha256,
            "pause_state": snapshot,
            "pause_state_sha256": pause_sha,
            "runtime_policy_enforced": True,
            "rollback_target": bundle.previous_release_ref,
            "automatic_sudo_executed": False,
            "automatic_reboot_executed": False,
            "declares_ready_for_72h_soak": False,
        }
        if authorization_evidence is not None:
            evidence["deployment_authorization"] = authorization_evidence
        if bundle.capsule is not None:
            evidence.update(
                {
                    "capsule_manifest_sha256": bundle.capsule.manifest_sha256,
                    "capsule_cas_refs": {
                        item.contour: item.cas_ref for item in bundle.capsule.objects
                    },
                    "capsule_objects_verified": True,
                    "runtime_tmpdir": "/var/lib/research-os/tmp",
                }
            )
        return _receipt(
            "deploy",
            bundle,
            evidence,
            clock=self._clock,
        )

    def reboot_boundary(self, bundle: ReleaseBundle) -> dict[str, Any]:
        preflight = self.preflight()
        snapshot, pause_sha = self._verify_running(bundle)
        return _receipt(
            "reboot-boundary",
            bundle,
            {
                "preflight": preflight,
                "before_boot_id_sha256": self._boot_id_sha256(),
                "pause_state": snapshot,
                "pause_state_sha256": pause_sha,
                "operator_action_required": "authorized out-of-band host reboot",
                "automatic_sudo_executed": False,
                "automatic_reboot_executed": False,
                "declares_ready_for_72h_soak": False,
            },
            clock=self._clock,
        )

    def verify_reboot(
        self,
        bundle: ReleaseBundle,
        boundary_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        boundary = _verified_parent_receipt(
            boundary_receipt, action="reboot-boundary", bundle=bundle
        )
        before = _sha256(boundary.get("before_boot_id_sha256"), "before boot identity")
        expected_pause = _sha256(boundary.get("pause_state_sha256"), "pause-state digest")
        preflight = self.preflight()
        after = self._boot_id_sha256()
        if after == before:
            raise DeploymentError("operator-mediated reboot has not changed the boot identity")
        snapshot, pause_sha = self._verify_running(bundle)
        if pause_sha != expected_pause:
            raise DeploymentError("durable pause state changed across the reboot")
        return _receipt(
            "verify-reboot",
            bundle,
            {
                "preflight": preflight,
                "before_boot_id_sha256": before,
                "after_boot_id_sha256": after,
                "boot_identity_changed": True,
                "pause_state": snapshot,
                "pause_state_sha256": pause_sha,
                "parent_receipt_payload_sha256": boundary_receipt["integrity"]["payload_sha256"],
                "automatic_sudo_executed": False,
                "automatic_reboot_executed": False,
                "declares_ready_for_72h_soak": False,
            },
            clock=self._clock,
        )

    def rollback(self, bundle: ReleaseBundle) -> dict[str, Any]:
        preflight = self.preflight()
        snapshot, pause_sha = self._verify_running(bundle)
        self._ssh(f"systemctl --user disable --now {self._target.service_name}", timeout=120.0)
        self._ssh(f"{_DOCKER} stop --time=30 {self._target.container_name}", check=False)
        rolled_back = f"{self._target.remote_config}/rolled-back.{bundle.release_sha}.service"
        self._ssh(
            f"set -eu; if test -f {self._target.remote_unit}; then mv -f -- {self._target.remote_unit} {rolled_back}; fi; "
            "systemctl --user daemon-reload; systemctl --user reset-failed >/dev/null 2>&1 || true"
        )
        if self._ssh(f"systemctl --user is-active --quiet {self._target.service_name}", check=False).returncode == 0:
            raise DeploymentError("rollback did not stop the Bridge user service")
        if self._ssh(f"systemctl --user is-enabled --quiet {self._target.service_name}", check=False).returncode == 0:
            raise DeploymentError("rollback did not disable the Bridge user service")
        self._container_inspect(bundle, require_running=False)
        return _receipt(
            "rollback",
            bundle,
            {
                "preflight": preflight,
                "rollback_target": bundle.previous_release_ref,
                "service_state": "none-service-stopped",
                "state_volumes_preserved": True,
                "saved_unit_sha256": bundle.unit_sha256,
                "pause_state": snapshot,
                "pause_state_sha256": pause_sha,
                "domain_services_mutated": False,
                "automatic_sudo_executed": False,
                "automatic_reboot_executed": False,
                "declares_ready_for_72h_soak": False,
            },
            clock=self._clock,
        )

    def redeploy(
        self,
        bundle: ReleaseBundle,
        rollback_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        rollback = _verified_parent_receipt(
            rollback_receipt, action="rollback", bundle=bundle
        )
        expected_pause = _sha256(rollback.get("pause_state_sha256"), "pause-state digest")
        if rollback.get("service_state") != "none-service-stopped":
            raise DeploymentError("rollback receipt is not the stopped prior state")
        preflight = self.preflight()
        if self._ssh(f"systemctl --user is-active --quiet {self._target.service_name}", check=False).returncode == 0:
            raise DeploymentError("redeploy requires the stopped rollback state")
        if self._remote_sha(self._saved_unit(bundle)) != bundle.unit_sha256:
            raise DeploymentError("saved redeploy unit SHA-256 does not match")
        self._image_inspect(bundle)
        self._container_inspect(bundle, require_running=False)
        self._install_saved_unit(bundle)
        snapshot, pause_sha = self._verify_running(bundle)
        if pause_sha != expected_pause:
            self._force_stopped(bundle, suffix="redeploy-pause-mismatch")
            raise DeploymentError("durable pause state changed across rollback/redeploy")
        return _receipt(
            "redeploy",
            bundle,
            {
                "preflight": preflight,
                "rollback_target": bundle.previous_release_ref,
                "exact_release_restored": True,
                "unit_sha256": bundle.unit_sha256,
                "pause_state": snapshot,
                "pause_state_sha256": pause_sha,
                "parent_receipt_payload_sha256": rollback_receipt["integrity"]["payload_sha256"],
                "domain_services_mutated": False,
                "automatic_sudo_executed": False,
                "automatic_reboot_executed": False,
                "declares_ready_for_72h_soak": False,
            },
            clock=self._clock,
        )


def _json_output(text: str, label: str) -> dict[str, Any]:
    if not text or len(text.encode("utf-8")) > _MAX_JSON_BYTES:
        raise DeploymentError(f"{label} output size is invalid")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                DeploymentError("JSON output contains a non-finite number")
            ),
        )
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"{label} output is not strict JSON") from exc
    if not isinstance(value, dict):
        raise DeploymentError(f"{label} output must be an object")
    return value


def _receipt(
    action: str,
    bundle: ReleaseBundle,
    evidence: Mapping[str, Any],
    *,
    clock: Callable[[], datetime],
    status: str = "PASS",
) -> dict[str, Any]:
    if status not in {"PASS", "FAIL"}:
        raise DeploymentError("receipt status is invalid")
    observed = clock()
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise DeploymentError("receipt clock must be timezone-aware")
    issued_at = observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "action": action,
        "status": status,
        "release_sha": bundle.release_sha,
        "image_id": bundle.image_id,
        "policy_sha256": bundle.policy_sha256,
        "config_sha256": bundle.config_sha256,
        "evidence": dict(evidence),
    }
    if bundle.capsule is not None:
        payload["capsule_manifest_sha256"] = bundle.capsule.manifest_sha256
    return {
        "schema_version": RECEIPT_SCHEMA,
        "issued_at": issued_at,
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {"payload_sha256": _payload_sha(payload)},
    }


def _verified_parent_receipt(
    receipt: Mapping[str, Any],
    *,
    action: str,
    bundle: ReleaseBundle,
) -> Mapping[str, Any]:
    if set(receipt) != {"schema_version", "issued_at", "classification", "payload", "integrity"}:
        raise DeploymentError("parent receipt shape is invalid")
    if receipt.get("schema_version") != RECEIPT_SCHEMA or receipt.get("classification") != "D1_INTERNAL_SANITIZED":
        raise DeploymentError("parent receipt schema is invalid")
    payload = receipt.get("payload")
    integrity = receipt.get("integrity")
    if not isinstance(payload, Mapping) or not isinstance(integrity, Mapping):
        raise DeploymentError("parent receipt sections are invalid")
    if integrity.get("payload_sha256") != _payload_sha(payload):
        raise DeploymentError("parent receipt payload integrity is invalid")
    if (
        payload.get("action") != action
        or payload.get("status") != "PASS"
        or payload.get("release_sha") != bundle.release_sha
        or payload.get("image_id") != bundle.image_id
        or payload.get("policy_sha256") != bundle.policy_sha256
        or payload.get("config_sha256") != bundle.config_sha256
        or payload.get("capsule_manifest_sha256")
        != (bundle.capsule.manifest_sha256 if bundle.capsule is not None else None)
    ):
        raise DeploymentError("parent receipt does not bind the exact release")
    evidence = payload.get("evidence")
    if not isinstance(evidence, Mapping):
        raise DeploymentError("parent receipt evidence is invalid")
    return evidence


def _receipt_file(path: Path) -> dict[str, Any]:
    return _json_file(path, "parent receipt")


def _reserve_receipt(path: Path) -> int:
    if path.exists() or path.is_symlink():
        raise DeploymentError("receipt path must be fresh")
    parent = path.parent
    try:
        metadata = os.lstat(parent)
    except OSError as exc:
        raise DeploymentError("receipt parent is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise DeploymentError("receipt parent must be a directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags, 0o600)
    except OSError as exc:
        raise DeploymentError("receipt cannot be reserved") from exc


def _finalize_receipt(descriptor: int, receipt: Mapping[str, Any]) -> None:
    try:
        body = _canonical_bytes(receipt) + b"\n"
        offset = 0
        while offset < len(body):
            offset += os.write(descriptor, body[offset:])
        os.fsync(descriptor)
    except OSError as exc:
        raise DeploymentError("reserved receipt cannot be finalized") from exc
    finally:
        os.close(descriptor)


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    _finalize_receipt(_reserve_receipt(path), receipt)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise DeploymentError("command arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="pre-soak-deploy")
    parser.add_argument("--ssh-alias", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "docs/receipts/release/s4-release-manifest.json")
    parser.add_argument("--policy", type=Path, default=ROOT / "ops/release/runtime-policy.json")
    parser.add_argument("--config", type=Path, default=ROOT / "ops/release/researchd.config.template.json")
    parser.add_argument("--unit", type=Path)
    parser.add_argument("--capsule", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    commands = parser.add_subparsers(dest="action", required=True)

    deploy = commands.add_parser("deploy")
    deploy.add_argument("--archive", type=Path, required=True)
    deploy.add_argument("--archive-sha256", required=True)

    commands.add_parser("reboot-boundary")
    verify = commands.add_parser("verify-reboot")
    verify.add_argument("--boundary-receipt", type=Path, required=True)
    commands.add_parser("rollback")
    redeploy = commands.add_parser("redeploy")
    redeploy.add_argument("--rollback-receipt", type=Path, required=True)
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    receipt_descriptor: int | None = None
    bundle: ReleaseBundle | None = None
    action = "unknown"
    try:
        arguments = _parser().parse_args(argv)
        action = arguments.action
        archive = arguments.archive if arguments.action == "deploy" else None
        archive_sha = arguments.archive_sha256 if arguments.action == "deploy" else None
        capsule = _load_capsule(arguments.capsule) if arguments.capsule is not None else None
        unit_path = arguments.unit
        if unit_path is None:
            unit_path = ROOT / "ops/deploy" / (
                "research-os-bridge.functional.service"
                if capsule is not None
                else "research-os-bridge.service"
            )
        bundle = _load_bundle(
            manifest_path=arguments.manifest,
            policy_path=arguments.policy,
            config_path=arguments.config,
            unit_path=unit_path,
            archive_path=archive,
            archive_sha256=archive_sha,
            capsule=capsule,
        )
        controller = PreSoakDeployController(
            ssh_alias=arguments.ssh_alias,
            known_hosts_path=arguments.known_hosts,
            runner=runner,
        )
        # Reserve the immutable evidence path before the first external action.
        # A crash leaves an unmistakable incomplete file instead of permitting
        # an unreceipted retry to overwrite history.
        receipt_descriptor = _reserve_receipt(arguments.receipt)
        if arguments.action == "deploy":
            receipt = controller.deploy(bundle)
        elif arguments.action == "reboot-boundary":
            receipt = controller.reboot_boundary(bundle)
        elif arguments.action == "verify-reboot":
            receipt = controller.verify_reboot(
                bundle, _receipt_file(arguments.boundary_receipt)
            )
        elif arguments.action == "rollback":
            receipt = controller.rollback(bundle)
        elif arguments.action == "redeploy":
            receipt = controller.redeploy(
                bundle, _receipt_file(arguments.rollback_receipt)
            )
        else:  # pragma: no cover - argparse owns the closed action set.
            raise DeploymentError("unsupported action")
        _finalize_receipt(receipt_descriptor, receipt)
        receipt_descriptor = None
        output.write(_canonical_bytes(receipt).decode("utf-8") + "\n")
        output.flush()
        return 0
    except DeploymentError:
        if receipt_descriptor is not None and bundle is not None:
            failure = _receipt(
                action,
                bundle,
                {
                    "failure_mode": "failed-closed",
                    "automatic_sudo_executed": False,
                    "automatic_reboot_executed": False,
                    "declares_ready_for_72h_soak": False,
                },
                clock=lambda: datetime.now(timezone.utc),
                status="FAIL",
            )
            try:
                _finalize_receipt(receipt_descriptor, failure)
            except DeploymentError:
                pass
            receipt_descriptor = None
        errors.write("pre-soak deployment failed closed\n")
        errors.flush()
        return 2


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()


__all__ = [
    "CommandResult",
    "DeploymentError",
    "PreSoakDeployController",
    "ReleaseBundle",
    "Runner",
    "run",
]
