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
    policy_sha256: str
    config_sha256: str
    archive_sha256: str | None
    unit_bytes: bytes
    unit_sha256: str
    config_path: Path
    archive_path: Path | None


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


def _load_bundle(
    *,
    manifest_path: Path,
    policy_path: Path,
    config_path: Path,
    unit_path: Path,
    archive_path: Path | None = None,
    archive_sha256: str | None = None,
) -> ReleaseBundle:
    manifest = _json_file(manifest_path, "ReleaseManifest")
    policy = _json_file(policy_path, "runtime policy")
    config_bytes = _regular_file(config_path, "service config", maximum=_MAX_JSON_BYTES)
    unit_template = _regular_file(unit_path, "service unit template", maximum=256_000)

    if policy != _EXPECTED_POLICY:
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
    if not isinstance(images, list) or images != [IMAGE_ID]:
        raise DeploymentError("release image identity is not the frozen candidate")
    if release_sha != RELEASE_SHA or payload.get("previous_release_ref") != PREVIOUS_RELEASE:
        raise DeploymentError("release or rollback identity is not frozen")
    policy_sha = _digest_bytes(_regular_file(policy_path, "runtime policy", maximum=_MAX_JSON_BYTES))
    config_sha = _digest_bytes(config_bytes)
    if payload.get("policy_sha256") != policy_sha or payload.get("config_sha256") != config_sha:
        raise DeploymentError("release policy or config binding is invalid")

    template = unit_template.decode("utf-8", errors="strict")
    observed_tokens = {token for token in _UNIT_TOKENS if token in template}
    if observed_tokens != _UNIT_TOKENS:
        raise DeploymentError("service unit template tokens are invalid")
    rendered = (
        template.replace("@@IMAGE_ID@@", IMAGE_ID)
        .replace("@@RELEASE_SHA@@", release_sha)
        .replace("@@POLICY_SHA256@@", policy_sha)
        .replace("@@CONFIG_SHA256@@", config_sha)
    ).encode("utf-8")
    if b"@@" in rendered:
        raise DeploymentError("service unit retained an unresolved token")

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
        image_id=IMAGE_ID,
        policy_sha256=policy_sha,
        config_sha256=config_sha,
        archive_sha256=actual_archive_sha,
        unit_bytes=rendered,
        unit_sha256=_digest_bytes(rendered),
        config_path=config_path,
        archive_path=archive_path,
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
    ) -> None:
        if _ALIAS.fullmatch(ssh_alias) is None:
            raise DeploymentError("target must be a normalized SSH config alias")
        _regular_file(known_hosts_path, "known_hosts", maximum=4 * 1024 * 1024)
        self._alias = ssh_alias
        self._known_hosts = str(known_hosts_path.resolve())
        self._runner = runner or SubprocessRunner()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

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

    def _stage_content(self, bundle: ReleaseBundle) -> None:
        if bundle.archive_path is None or bundle.archive_sha256 is None:
            raise DeploymentError("deployment requires a content-addressed archive")
        self._ssh(
            "set -eu; umask 077; "
            f"install -d -m 0700 {_REMOTE_BASE}/incoming {_REMOTE_CONFIG} "
            '"$HOME/.config/systemd/user"'
        )
        archive_relative = f".local/share/research-os-bridge/incoming/release-{bundle.archive_sha256}.tar"
        archive_remote = f"{_REMOTE_BASE}/incoming/release-{bundle.archive_sha256}.tar"
        self._scp(bundle.archive_path, archive_relative)
        if self._remote_sha(archive_remote) != bundle.archive_sha256:
            raise DeploymentError("remote release archive SHA-256 does not match")
        self._ssh(f"{_DOCKER} load --input {archive_remote}", timeout=600.0)
        self._image_inspect(bundle)

        config_relative = f".config/research-os-bridge/researchd-{bundle.config_sha256}.json"
        config_remote = f"{_REMOTE_CONFIG}/researchd-{bundle.config_sha256}.json"
        self._scp(bundle.config_path, config_relative)
        if self._remote_sha(config_remote) != bundle.config_sha256:
            raise DeploymentError("remote service config SHA-256 does not match")
        self._ssh(f"chmod 0600 {config_remote}")
        self._ssh(f"{_DOCKER} volume create {RUNTIME_VOLUME}")
        self._ssh(f"{_DOCKER} volume create {CONFIG_VOLUME}")
        init_command = (
            f"{_DOCKER} run --rm --name=research-os-bridge-volume-init "
            "--user=0:0 --network=none --read-only "
            "--security-opt=no-new-privileges:true --pids-limit=32 "
            "--memory=134217728 --cpus=0.25 "
            f"--mount=type=bind,source={config_remote},target=/source/researchd.json,readonly "
            f"--mount=type=volume,source={CONFIG_VOLUME},target=/target-config "
            f"--mount=type=volume,source={RUNTIME_VOLUME},target=/target-runtime "
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
            f"--mount=type=volume,source={CONFIG_VOLUME},target=/target-config,readonly "
            f"--mount=type=volume,source={RUNTIME_VOLUME},target=/target-runtime "
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

        saved_unit = self._saved_unit(bundle)
        self._ssh(
            f"set -eu; umask 077; cat > {saved_unit}",
            input_bytes=bundle.unit_bytes,
        )
        self._ssh(f"chmod 0600 {saved_unit}")
        if self._remote_sha(saved_unit) != bundle.unit_sha256:
            raise DeploymentError("remote rendered unit SHA-256 does not match")

    def _saved_unit(self, bundle: ReleaseBundle) -> str:
        return f"{_REMOTE_CONFIG}/research-os-bridge.{bundle.release_sha}.service"

    def _install_saved_unit(self, bundle: ReleaseBundle) -> None:
        saved = self._saved_unit(bundle)
        next_unit = f"{_REMOTE_UNIT}.next"
        self._ssh(f"install -m 0600 {saved} {next_unit}")
        if self._remote_sha(next_unit) != bundle.unit_sha256:
            raise DeploymentError("staged systemd unit SHA-256 does not match")
        try:
            self._ssh(f"mv -f -- {next_unit} {_REMOTE_UNIT}")
            self._ssh("systemctl --user daemon-reload")
            self._ssh(f"systemctl --user enable --now {SERVICE_NAME}", timeout=120.0)
        except DeploymentError:
            self._force_stopped(bundle, suffix="activation-failed")
            raise

    def _force_stopped(self, bundle: ReleaseBundle, *, suffix: str) -> None:
        self._ssh(f"systemctl --user disable --now {SERVICE_NAME}", check=False)
        self._ssh(f"{_DOCKER} stop --time=30 {CONTAINER_NAME}", check=False)
        destination = f"{_REMOTE_CONFIG}/{suffix}.{bundle.release_sha}.service"
        self._ssh(
            f"set -eu; if test -f {_REMOTE_UNIT}; then mv -f -- {_REMOTE_UNIT} {destination}; fi; "
            "systemctl --user daemon-reload"
        )

    def _systemd_running(self) -> None:
        active = self._ssh(f"systemctl --user is-active {SERVICE_NAME}")
        if active.stdout.strip() != "active":
            raise DeploymentError("Bridge user service is not active")
        enabled = self._ssh(f"systemctl --user is-enabled {SERVICE_NAME}")
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
            f"{_DOCKER} container inspect {CONTAINER_NAME} --format '{{{{json .}}}}'",
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
        if (
            value.get("Name") not in {CONTAINER_NAME, f"/{CONTAINER_NAME}"}
            or value.get("Image") != bundle.image_id
            or config.get("Image") != bundle.image_id
            or config.get("User") != "10001:10001"
            or not isinstance(labels, dict)
            or labels.get("org.research-os.release-sha") != bundle.release_sha
            or labels.get("org.research-os.policy-sha256") != bundle.policy_sha256
            or labels.get("org.research-os.config-sha256") != bundle.config_sha256
            or not isinstance(environment, list)
            or "RESEARCH_OS_ENVIRONMENT=pre-soak" not in environment
            or "RESEARCH_OS_EXTERNAL_ACTION_AUTHORITY=false" not in environment
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or not isinstance(cap_drop, list)
            or {str(item).upper() for item in cap_drop} != {"ALL"}
            or not isinstance(security, list)
            or "no-new-privileges:true" not in security
            or host.get("PidsLimit") != 256
            or host.get("Memory") != 2147483648
            or host.get("NanoCpus") != 2_000_000_000
            or not isinstance(restart, dict)
            or restart.get("Name") != "unless-stopped"
            or host.get("PortBindings") not in (None, {})
            or running is not require_running
        ):
            raise DeploymentError("container drifted from the frozen runtime policy")
        mount_by_destination = {
            item.get("Destination"): item for item in mounts if isinstance(item, dict)
        }
        runtime_mount = mount_by_destination.get("/var/lib/research-os")
        config_mount = mount_by_destination.get("/run/research-os")
        if (
            not isinstance(runtime_mount, dict)
            or runtime_mount.get("Type") != "volume"
            or runtime_mount.get("Name") != RUNTIME_VOLUME
            or runtime_mount.get("RW") is not True
            or not isinstance(config_mount, dict)
            or config_mount.get("Type") != "volume"
            or config_mount.get("Name") != CONFIG_VOLUME
            or config_mount.get("RW") is not False
        ):
            raise DeploymentError("container mounts drifted from the frozen runtime policy")
        ports = network.get("Ports") if isinstance(network, dict) else None
        if ports not in (None, {}):
            raise DeploymentError("container unexpectedly publishes a port")
        return value

    def _pause_snapshot(self) -> tuple[dict[str, Any], str]:
        result = self._ssh(
            f"{_DOCKER} exec --user=10001:10001 {CONTAINER_NAME} python -m "
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

    def _verify_running(self, bundle: ReleaseBundle) -> tuple[dict[str, Any], str]:
        self._systemd_running()
        self._container_inspect(bundle, require_running=True)
        return self._pause_snapshot()

    def deploy(self, bundle: ReleaseBundle) -> dict[str, Any]:
        preflight = self.preflight()
        inactive = self._ssh(
            f"systemctl --user is-active --quiet {SERVICE_NAME}", check=False
        )
        if inactive.returncode == 0:
            raise DeploymentError("first-release deploy requires the stopped prior state")
        existing = self._container_inspect(bundle, require_running=False, missing_ok=True)
        if existing is not None:
            # An interrupted retry may retain only the exact stopped candidate.
            self._container_inspect(bundle, require_running=False)
        self._stage_content(bundle)
        self._install_saved_unit(bundle)
        snapshot, pause_sha = self._verify_running(bundle)
        return _receipt(
            "deploy",
            bundle,
            {
                "preflight": preflight,
                "archive_sha256": bundle.archive_sha256,
                "remote_archive_verified": True,
                "unit_sha256": bundle.unit_sha256,
                "pause_state": snapshot,
                "pause_state_sha256": pause_sha,
                "runtime_policy_enforced": True,
                "rollback_target": PREVIOUS_RELEASE,
                "automatic_sudo_executed": False,
                "automatic_reboot_executed": False,
                "declares_ready_for_72h_soak": False,
            },
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
        self._ssh(f"systemctl --user disable --now {SERVICE_NAME}", timeout=120.0)
        self._ssh(f"{_DOCKER} stop --time=30 {CONTAINER_NAME}", check=False)
        rolled_back = f"{_REMOTE_CONFIG}/rolled-back.{bundle.release_sha}.service"
        self._ssh(
            f"set -eu; if test -f {_REMOTE_UNIT}; then mv -f -- {_REMOTE_UNIT} {rolled_back}; fi; "
            "systemctl --user daemon-reload; systemctl --user reset-failed >/dev/null 2>&1 || true"
        )
        if self._ssh(f"systemctl --user is-active --quiet {SERVICE_NAME}", check=False).returncode == 0:
            raise DeploymentError("rollback did not stop the Bridge user service")
        if self._ssh(f"systemctl --user is-enabled --quiet {SERVICE_NAME}", check=False).returncode == 0:
            raise DeploymentError("rollback did not disable the Bridge user service")
        self._container_inspect(bundle, require_running=False)
        return _receipt(
            "rollback",
            bundle,
            {
                "preflight": preflight,
                "rollback_target": PREVIOUS_RELEASE,
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
        if self._ssh(f"systemctl --user is-active --quiet {SERVICE_NAME}", check=False).returncode == 0:
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
                "rollback_target": PREVIOUS_RELEASE,
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
    parser.add_argument("--unit", type=Path, default=ROOT / "ops/deploy/research-os-bridge.service")
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
        bundle = _load_bundle(
            manifest_path=arguments.manifest,
            policy_path=arguments.policy,
            config_path=arguments.config,
            unit_path=arguments.unit,
            archive_path=archive,
            archive_sha256=archive_sha,
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
