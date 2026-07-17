#!/usr/bin/env python3
"""Fail-closed restic backup and clean-restore evidence controller.

The controller deliberately has no repository-initialization or retention
surface.  It consumes an already provisioned restic repository through an
owner-only repository file and an owner-only password helper.  Repository
locators, credentials, source paths, restore paths, and subprocess output are
never copied into receipts or command output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Protocol, Sequence


RESTIC_VERSION = "0.19.0"
RESTIC_SOURCE_SHA256 = "800779b6c4c2396971c0567b09ccdd435e03155e1a0ec94e8bbf3d98641a8bc2"
RESTIC_BOTTLE_SHA256 = "b69c21f735a13de6c74d6a097199fc6e98fd794c48e287a035dbff434bfcae41"
RESTIC_LICENSE_SHA256 = "6f08a01a9fab5b24e139a09f15cc24a73087c7bc09e3bacf099fdf2d767bf897"

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DESTINATION_REF_RE = re.compile(
    r"^(?:backup-destination|off-host):(?:sha256:)?[a-z0-9][a-z0-9._-]{0,127}$"
)
_SAFE_CODE_RE = re.compile(r"^[a-z0-9_]+$")
_RECEIPT_KEYS = {
    "schema_id",
    "schema_version",
    "object_id",
    "issued_at",
    "issuer",
    "contour",
    "classification",
    "payload",
    "integrity",
}
_BACKUP_PAYLOAD_KEYS = {
    "snapshot_id",
    "source_manifest_sha256",
    "destination_ref",
    "encrypted",
    "started_at",
    "ended_at",
    "verification_result",
}
_RELEASE_PAYLOAD_KEYS = {
    "release_sha",
    "image_digests",
    "policy_sha256",
    "config_sha256",
    "schema_sha256",
    "dependency_lock_sha256",
    "sbom_ref",
    "previous_release_ref",
}
_ALLOWED_RESTIC_COMMANDS = {"cat", "backup", "snapshots", "check", "restore"}
_ENV_ALLOWLIST = {"HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "XDG_CACHE_HOME"}
_REMOTE_REPOSITORY_PREFIXES = (
    "azure:",
    "b2:",
    "gs:",
    "rclone:",
    "rest:http://",
    "rest:https://",
    "s3:",
    "sftp:",
    "swift:",
)


class BackupRestoreError(RuntimeError):
    """A redacted, stable controller failure code."""

    def __init__(self, code: str) -> None:
        if not _SAFE_CODE_RE.fullmatch(code):
            code = "internal_error"
        self.code = code
        super().__init__(code)


class ResticRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None,
        env: Mapping[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[bytes]: ...


@dataclass(frozen=True)
class TreeManifest:
    sha256: str
    entries: tuple[Mapping[str, Any], ...]
    file_count: int
    directory_count: int
    total_bytes: int


def _fail(code: str) -> None:
    raise BackupRestoreError(code)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None:
        _fail(code)
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("clock_not_utc")
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _normalized_absolute(path: Path, code: str, *, must_exist: bool) -> Path:
    raw = Path(path)
    if not raw.is_absolute() or ".." in raw.parts:
        _fail(code)
    try:
        return raw.resolve(strict=must_exist)
    except (OSError, RuntimeError):
        _fail(code)


def _hash_open_regular(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("tree_entry_unreadable")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail("tree_entry_not_regular")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            digest.update(block)
        after = os.fstat(descriptor)
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if not stable or total != after.st_size:
            _fail("tree_changed_during_manifest")
        return digest.hexdigest(), total
    except OSError:
        _fail("tree_entry_unreadable")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def canonical_tree_manifest(root: Path) -> TreeManifest:
    """Return a deterministic names-and-bytes manifest without following links."""

    raw_root = Path(root)
    if raw_root.is_symlink():
        _fail("tree_root_symlink")
    root_path = _normalized_absolute(raw_root, "tree_root_invalid", must_exist=True)
    try:
        root_stat = root_path.lstat()
    except OSError:
        _fail("tree_root_invalid")
    if not stat.S_ISDIR(root_stat.st_mode):
        _fail("tree_root_invalid")

    entries: list[dict[str, Any]] = []
    files = 0
    directories = 0
    total_bytes = 0

    def visit(directory: Path, prefix: PurePosixPath) -> None:
        nonlocal files, directories, total_bytes
        try:
            directory_stat = directory.lstat()
            if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(
                directory_stat.st_mode
            ):
                _fail("tree_symlink_rejected")
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _fail("tree_entry_unreadable")
        for child in children:
            relative = prefix / child.name
            if relative.is_absolute() or ".." in relative.parts:
                _fail("tree_path_traversal")
            relative_text = relative.as_posix()
            if not relative_text or relative_text.startswith("/"):
                _fail("tree_path_traversal")
            try:
                item_stat = child.stat(follow_symlinks=False)
            except OSError:
                _fail("tree_entry_unreadable")
            if stat.S_ISLNK(item_stat.st_mode):
                _fail("tree_symlink_rejected")
            child_path = Path(child.path)
            if stat.S_ISDIR(item_stat.st_mode):
                directories += 1
                entries.append({"relative_path": relative_text, "type": "directory"})
                visit(child_path, relative)
            elif stat.S_ISREG(item_stat.st_mode):
                digest, size = _hash_open_regular(child_path)
                files += 1
                total_bytes += size
                entries.append(
                    {
                        "relative_path": relative_text,
                        "type": "file",
                        "size_bytes": size,
                        "sha256": digest,
                    }
                )
            else:
                _fail("tree_special_entry_rejected")

    visit(root_path, PurePosixPath())
    if files == 0:
        _fail("tree_has_no_files")
    material = {"schema": "dcros.canonical-byte-tree.v1", "entries": entries}
    return TreeManifest(
        sha256=_canonical_sha256(material),
        entries=tuple(entries),
        file_count=files,
        directory_count=directories,
        total_bytes=total_bytes,
    )


def _default_runner(
    argv: Sequence[str],
    *,
    cwd: Path | None,
    env: Mapping[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(argv),
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


class ResticBackupRestoreController:
    """Execute one immutable backup and its clean restore proof."""

    def __init__(
        self,
        *,
        restic_binary: Path,
        repository_file: Path,
        password_command: Path,
        destination_ref: str,
        runner: ResticRunner | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        device_id: Callable[[Path], int] | None = None,
        timeout_seconds: int = 6 * 60 * 60,
    ) -> None:
        if not isinstance(destination_ref, str) or not _DESTINATION_REF_RE.fullmatch(
            destination_ref
        ):
            _fail("destination_ref_not_sanitized")
        if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 24 * 60 * 60:
            _fail("timeout_invalid")
        self._restic_binary_raw = Path(restic_binary)
        self._repository_file_raw = Path(repository_file)
        self._password_command_raw = Path(password_command)
        self.destination_ref = destination_ref
        self._runner = runner or _default_runner
        self._uses_default_runner = runner is None
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic or time.monotonic
        self._device_id = device_id or (lambda path: path.stat().st_dev)
        self._timeout_seconds = timeout_seconds
        self._restic_binary = self._validate_binary()
        (
            self._repository_file,
            self._password_command,
            self._repository_locator_bytes,
            self._local_repository_path,
        ) = self._validate_secret_inputs()

    def _validate_binary(self) -> Path:
        binary = _normalized_absolute(
            self._restic_binary_raw,
            "restic_binary_invalid",
            must_exist=self._uses_default_runner,
        )
        if self._uses_default_runner:
            try:
                mode = binary.stat().st_mode
            except OSError:
                _fail("restic_binary_invalid")
            if not stat.S_ISREG(mode) or mode & stat.S_IXUSR == 0:
                _fail("restic_binary_invalid")
        return binary

    def _validate_secret_file(self, raw: Path, code: str, *, executable: bool) -> Path:
        if raw.is_symlink():
            _fail(code)
        path = _normalized_absolute(raw, code, must_exist=True)
        try:
            metadata = path.stat()
        except OSError:
            _fail(code)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            _fail(code)
        if metadata.st_mode & 0o077:
            _fail(code)
        if executable and metadata.st_mode & stat.S_IXUSR == 0:
            _fail(code)
        if not executable and metadata.st_size > 4096:
            _fail(code)
        if executable and not re.fullmatch(r"/[A-Za-z0-9._/-]+", str(path)):
            _fail(code)
        return path

    @staticmethod
    def _local_repository(locator: str) -> Path:
        raw = Path(locator)
        if (
            not raw.is_absolute()
            or ".." in raw.parts
            or locator != str(raw)
            or raw.is_symlink()
        ):
            _fail("local_repository_invalid")
        try:
            resolved = raw.resolve(strict=True)
            metadata = raw.lstat()
        except (OSError, RuntimeError):
            _fail("local_repository_invalid")
        if resolved != raw or not stat.S_ISDIR(metadata.st_mode):
            _fail("local_repository_invalid")
        return resolved

    def _validate_secret_inputs(self) -> tuple[Path, Path, bytes, Path | None]:
        repository_file = self._validate_secret_file(
            self._repository_file_raw, "repository_file_invalid", executable=False
        )
        password_command = self._validate_secret_file(
            self._password_command_raw, "password_command_invalid", executable=True
        )
        if repository_file == password_command:
            _fail("secret_input_alias")
        try:
            locator_bytes = repository_file.read_bytes()
            locator = locator_bytes.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            _fail("repository_file_invalid")
        if (
            "\x00" in locator
            or "\n" in locator.rstrip("\n")
            or locator.rstrip("\n") != locator.strip()
            or locator.count("\n") > 1
        ):
            _fail("repository_file_invalid")
        locator = locator.rstrip("\n")
        local_repository: Path | None = None
        if not locator.startswith(_REMOTE_REPOSITORY_PREFIXES):
            local_repository = self._local_repository(locator)
        return (
            repository_file,
            password_command,
            locator.encode("utf-8"),
            local_repository,
        )

    @staticmethod
    def _paths_overlap(first: Path, second: Path) -> bool:
        return first == second or first in second.parents or second in first.parents

    def _prove_separate_local_device(self, boundary: Path, device_path: Path) -> None:
        (
            repository_file,
            password_command,
            locator_bytes,
            local_repository,
        ) = self._validate_secret_inputs()
        if locator_bytes != self._repository_locator_bytes:
            _fail("repository_locator_changed")
        if local_repository != self._local_repository_path:
            _fail("local_repository_changed")
        self._repository_file = repository_file
        self._password_command = password_command
        if local_repository is None:
            return
        if self._paths_overlap(local_repository, boundary):
            _fail("local_repository_path_overlap")
        try:
            repository_device = self._device_id(local_repository)
            peer_device = self._device_id(device_path)
        except (OSError, RuntimeError, TypeError, ValueError):
            _fail("local_repository_device_unverified")
        if (
            not isinstance(repository_device, int)
            or isinstance(repository_device, bool)
            or repository_device < 0
            or not isinstance(peer_device, int)
            or isinstance(peer_device, bool)
            or peer_device < 0
        ):
            _fail("local_repository_device_unverified")
        if repository_device == peer_device:
            _fail("local_repository_same_device")

    def _environment(self) -> dict[str, str]:
        safe = {key: value for key, value in os.environ.items() if key in _ENV_ALLOWLIST}
        safe["LANG"] = "C"
        safe["LC_ALL"] = "C"
        return safe

    @staticmethod
    def _as_bytes(value: bytes | str | None) -> bytes:
        if value is None:
            return b""
        return value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")

    def _execute(
        self,
        operation: str,
        command: Sequence[str],
        *,
        repository: bool = True,
        cwd: Path | None = None,
    ) -> bytes:
        (
            repository_file,
            password_command,
            locator_bytes,
            local_repository,
        ) = self._validate_secret_inputs()
        if locator_bytes != self._repository_locator_bytes:
            _fail("repository_locator_changed")
        if local_repository != self._local_repository_path:
            _fail("local_repository_changed")
        self._repository_file = repository_file
        self._password_command = password_command
        if repository:
            if not command or command[0] not in _ALLOWED_RESTIC_COMMANDS:
                _fail("restic_command_not_allowed")
            argv = [
                str(self._restic_binary),
                "--repository-file",
                str(self._repository_file),
                "--password-command",
                str(self._password_command),
                "--no-cache",
                *command,
            ]
        else:
            argv = [str(self._restic_binary), *command]
        try:
            result = self._runner(
                tuple(argv),
                cwd=cwd,
                env=self._environment(),
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError, TimeoutError, ValueError):
            _fail(f"restic_{operation}_failed")
        stdout = self._as_bytes(result.stdout)
        stderr = self._as_bytes(result.stderr)
        if len(stdout) > 32 * 1024 * 1024 or len(stderr) > 32 * 1024 * 1024:
            _fail(f"restic_{operation}_output_too_large")
        if result.returncode != 0:
            _fail(f"restic_{operation}_failed")
        return stdout

    def _verify_version(self) -> None:
        output = self._execute("version", ("version",), repository=False)
        try:
            text = output.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            _fail("restic_version_mismatch")
        if not re.match(rf"^restic {re.escape(RESTIC_VERSION)}(?:\s|$)", text):
            _fail("restic_version_mismatch")

    def _repository_identity(self) -> str:
        output = self._execute("repository_identity", ("cat", "config"))
        try:
            config = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("repository_identity_invalid")
        if not isinstance(config, dict):
            _fail("repository_identity_invalid")
        repository_id = config.get("id")
        repository_version = config.get("version")
        if (
            not isinstance(repository_id, str)
            or not _SHA256_RE.fullmatch(repository_id)
            or not isinstance(repository_version, int)
            or isinstance(repository_version, bool)
            or repository_version < 1
        ):
            _fail("repository_identity_invalid")
        return repository_id

    @staticmethod
    def _load_release_manifest(value: Mapping[str, Any]) -> tuple[str, str]:
        document = dict(value)
        if set(document) != _RECEIPT_KEYS:
            _fail("release_manifest_shape_invalid")
        if (
            document.get("schema_id") != "ReleaseManifest"
            or document.get("schema_version") != "1.0.0"
            or document.get("contour") != "governance"
            or document.get("classification") not in {"D0_PUBLIC", "D1_INTERNAL_SANITIZED"}
        ):
            _fail("release_manifest_shape_invalid")
        object_id = document.get("object_id")
        payload = document.get("payload")
        integrity = document.get("integrity")
        issuer = document.get("issuer")
        if (
            not isinstance(object_id, str)
            or not _OBJECT_ID_RE.fullmatch(object_id)
            or not isinstance(payload, dict)
            or set(payload) != _RELEASE_PAYLOAD_KEYS
            or not isinstance(integrity, dict)
            or set(integrity) != {"payload_sha256", "parent_refs"}
            or not isinstance(issuer, dict)
            or set(issuer) != {"id", "authority_class"}
        ):
            _fail("release_manifest_shape_invalid")
        if any(
            not isinstance(issuer.get(field), str) or not issuer[field]
            for field in ("id", "authority_class")
        ):
            _fail("release_manifest_shape_invalid")
        payload_hash = _canonical_sha256(payload)
        if integrity.get("payload_sha256") != payload_hash:
            _fail("release_manifest_integrity_invalid")
        release_sha = payload.get("release_sha")
        image_digests = payload.get("image_digests")
        if (
            not isinstance(release_sha, str)
            or not re.fullmatch(r"[a-f0-9]{40}", release_sha)
            or not isinstance(image_digests, list)
            or not image_digests
            or any(
                not isinstance(item, str)
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", item)
                for item in image_digests
            )
            or any(
                not isinstance(payload.get(field), str)
                or not _SHA256_RE.fullmatch(payload[field])
                for field in (
                    "policy_sha256",
                    "config_sha256",
                    "schema_sha256",
                    "dependency_lock_sha256",
                )
            )
            or not isinstance(payload.get("sbom_ref"), str)
            or not payload["sbom_ref"]
            or not isinstance(payload.get("previous_release_ref"), str)
            or not payload["previous_release_ref"]
        ):
            _fail("release_manifest_shape_invalid")
        parents = integrity.get("parent_refs")
        if not isinstance(parents, list) or not parents or any(
            not isinstance(item, str) or not item for item in parents
        ):
            _fail("release_manifest_shape_invalid")
        _parse_time(document.get("issued_at"), "release_manifest_time_invalid")
        return object_id, payload_hash

    @staticmethod
    def _snapshot_id_from_backup_output(output: bytes) -> str:
        snapshot_ids: set[str] = set()
        try:
            lines = output.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            _fail("backup_output_invalid")
        for line in lines:
            if not line.strip():
                continue
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                _fail("backup_output_invalid")
            if not isinstance(document, dict):
                _fail("backup_output_invalid")
            snapshot_id = document.get("snapshot_id")
            if snapshot_id is not None:
                if not isinstance(snapshot_id, str) or not _SHA256_RE.fullmatch(snapshot_id):
                    _fail("backup_snapshot_id_invalid")
                snapshot_ids.add(snapshot_id)
        if len(snapshot_ids) != 1:
            _fail("backup_snapshot_id_invalid")
        return next(iter(snapshot_ids))

    def _snapshot_source(
        self,
        snapshot_id: str,
        *,
        manifest_sha256: str,
        release_manifest_sha256: str | None,
        exact_source: Path | None,
    ) -> Path:
        if not _SHA256_RE.fullmatch(snapshot_id):
            _fail("snapshot_id_invalid")
        output = self._execute(
            "snapshot_inspect", ("snapshots", "--json", snapshot_id)
        )
        try:
            documents = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("snapshot_metadata_invalid")
        if not isinstance(documents, list) or len(documents) != 1:
            _fail("snapshot_not_exact")
        snapshot = documents[0]
        if not isinstance(snapshot, dict) or snapshot.get("id") != snapshot_id:
            _fail("snapshot_not_exact")
        tags = snapshot.get("tags")
        paths = snapshot.get("paths")
        required_tags = {f"dcros-manifest-{manifest_sha256}"}
        if release_manifest_sha256 is not None:
            required_tags.add(f"dcros-release-{release_manifest_sha256}")
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            _fail("snapshot_binding_invalid")
        if not required_tags.issubset(set(tags)):
            _fail("snapshot_binding_invalid")
        if not isinstance(paths, list) or len(paths) != 1 or not isinstance(paths[0], str):
            _fail("snapshot_source_invalid")
        raw_path = PurePosixPath(paths[0])
        if not raw_path.is_absolute() or raw_path == PurePosixPath("/") or ".." in raw_path.parts:
            _fail("snapshot_source_invalid")
        source = Path(paths[0])
        if exact_source is not None and source != exact_source:
            _fail("snapshot_source_invalid")
        return source

    def _check_read_data(self) -> None:
        self._execute("check_read_data", ("check", "--read-data"))

    @staticmethod
    def _receipt(
        schema_id: str,
        object_id: str,
        issued_at: str,
        payload: Mapping[str, Any],
        parents: Sequence[str],
    ) -> dict[str, Any]:
        material = dict(payload)
        authority_class = (
            "backup-controller" if schema_id == "BackupReceipt" else "restore-controller"
        )
        return {
            "schema_id": schema_id,
            "schema_version": "1.0.0",
            "object_id": object_id,
            "issued_at": issued_at,
            "issuer": {
                "id": "restic-release-backup-controller",
                "authority_class": authority_class,
            },
            "contour": "governance",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": material,
            "integrity": {
                "payload_sha256": _canonical_sha256(material),
                "parent_refs": list(parents),
            },
        }

    @staticmethod
    def _write_receipt_last(path: Path, receipt: Mapping[str, Any]) -> None:
        raw = Path(path)
        if not raw.is_absolute() or ".." in raw.parts:
            _fail("receipt_path_invalid")
        if os.path.lexists(raw):
            _fail("receipt_already_exists")
        try:
            parent = raw.parent.resolve(strict=True)
        except (OSError, RuntimeError):
            _fail("receipt_path_invalid")
        if not parent.is_dir():
            _fail("receipt_path_invalid")
        target = parent / raw.name
        if os.path.lexists(target):
            _fail("receipt_already_exists")
        encoded = _canonical_bytes(receipt) + b"\n"
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=".incomplete-receipt-",
                dir=parent,
                delete=False,
            ) as handle:
                temporary_name = handle.name
                os.fchmod(handle.fileno(), 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_name, target)
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except FileExistsError:
            _fail("receipt_already_exists")
        except OSError:
            _fail("receipt_write_failed")
        finally:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass

    def backup(
        self,
        *,
        source_root: Path,
        release_manifest: Mapping[str, Any],
        receipt_path: Path,
    ) -> dict[str, Any]:
        if os.path.lexists(receipt_path):
            _fail("receipt_already_exists")
        release_object_id, release_manifest_sha256 = self._load_release_manifest(
            release_manifest
        )
        if Path(source_root).is_symlink():
            _fail("tree_root_symlink")
        source = _normalized_absolute(source_root, "tree_root_invalid", must_exist=True)
        self._prove_separate_local_device(source, source)
        source_before = canonical_tree_manifest(source)
        started_at = _format_time(self._clock())

        self._verify_version()
        repository_id = self._repository_identity()
        manifest_tag = f"dcros-manifest-{source_before.sha256}"
        release_tag = f"dcros-release-{release_manifest_sha256}"
        self._prove_separate_local_device(source, source)
        output = self._execute(
            "backup",
            (
                "backup",
                "--json",
                "--host",
                "dual-contour-research-os",
                "--tag",
                manifest_tag,
                "--tag",
                release_tag,
                "--",
                str(source),
            ),
        )
        snapshot_id = self._snapshot_id_from_backup_output(output)
        self._snapshot_source(
            snapshot_id,
            manifest_sha256=source_before.sha256,
            release_manifest_sha256=release_manifest_sha256,
            exact_source=source,
        )
        self._check_read_data()
        source_after = canonical_tree_manifest(source)
        if source_after.sha256 != source_before.sha256:
            _fail("source_changed_during_backup")
        ended_at = _format_time(self._clock())

        payload = {
            "snapshot_id": snapshot_id,
            "source_manifest_sha256": source_before.sha256,
            "destination_ref": self.destination_ref,
            "encrypted": True,
            "started_at": started_at,
            "ended_at": ended_at,
            "verification_result": "VERIFIED",
        }
        receipt = self._receipt(
            "BackupReceipt",
            f"backup-restic-{snapshot_id}",
            ended_at,
            payload,
            (
                release_object_id,
                f"release-manifest-sha256:{release_manifest_sha256}",
                f"restic-repository-sha256:{hashlib.sha256(repository_id.encode()).hexdigest()}",
                "restic-repository-binding-sha256:"
                + hashlib.sha256(
                    repository_id.encode() + b"\x00" + self._repository_locator_bytes
                ).hexdigest(),
                f"restic-version:{RESTIC_VERSION}",
            ),
        )
        self._write_receipt_last(receipt_path, receipt)
        return receipt

    def _validate_backup_receipt(
        self, value: Mapping[str, Any]
    ) -> tuple[str, str, str, datetime, str, str]:
        document = dict(value)
        if set(document) != _RECEIPT_KEYS:
            _fail("backup_receipt_shape_invalid")
        if (
            document.get("schema_id") != "BackupReceipt"
            or document.get("schema_version") != "1.0.0"
            or document.get("contour") != "governance"
            or document.get("classification") != "D1_INTERNAL_SANITIZED"
        ):
            _fail("backup_receipt_shape_invalid")
        object_id = document.get("object_id")
        issuer = document.get("issuer")
        payload = document.get("payload")
        integrity = document.get("integrity")
        if (
            not isinstance(object_id, str)
            or not object_id
            or not isinstance(issuer, dict)
            or set(issuer) != {"id", "authority_class"}
            or not isinstance(payload, dict)
            or set(payload) != _BACKUP_PAYLOAD_KEYS
            or not isinstance(integrity, dict)
            or set(integrity) != {"payload_sha256", "parent_refs"}
        ):
            _fail("backup_receipt_shape_invalid")
        if issuer != {
            "id": "restic-release-backup-controller",
            "authority_class": "backup-controller",
        }:
            _fail("backup_receipt_issuer_invalid")
        if integrity.get("payload_sha256") != _canonical_sha256(payload):
            _fail("backup_receipt_integrity_invalid")
        parents = integrity.get("parent_refs")
        if not isinstance(parents, list) or any(
            not isinstance(parent, str) or not parent for parent in parents
        ):
            _fail("backup_receipt_shape_invalid")
        snapshot_id = payload.get("snapshot_id")
        manifest_sha256 = payload.get("source_manifest_sha256")
        destination_ref = payload.get("destination_ref")
        if (
            not isinstance(snapshot_id, str)
            or not _SHA256_RE.fullmatch(snapshot_id)
            or not isinstance(manifest_sha256, str)
            or not _SHA256_RE.fullmatch(manifest_sha256)
            or destination_ref != self.destination_ref
            or payload.get("encrypted") is not True
            or payload.get("verification_result") != "VERIFIED"
            or object_id != f"backup-restic-{snapshot_id}"
        ):
            _fail("backup_receipt_claim_invalid")
        started = _parse_time(payload.get("started_at"), "backup_receipt_time_invalid")
        ended = _parse_time(payload.get("ended_at"), "backup_receipt_time_invalid")
        issued = _parse_time(document.get("issued_at"), "backup_receipt_time_invalid")
        if ended < started or issued < ended:
            _fail("backup_receipt_time_invalid")
        repository_parents = [
            parent.removeprefix("restic-repository-sha256:")
            for parent in parents
            if parent.startswith("restic-repository-sha256:")
        ]
        repository_bindings = [
            parent.removeprefix("restic-repository-binding-sha256:")
            for parent in parents
            if parent.startswith("restic-repository-binding-sha256:")
        ]
        if (
            len(repository_parents) != 1
            or not _SHA256_RE.fullmatch(repository_parents[0])
            or len(repository_bindings) != 1
            or not _SHA256_RE.fullmatch(repository_bindings[0])
            or f"restic-version:{RESTIC_VERSION}" not in parents
        ):
            _fail("backup_receipt_repository_binding_invalid")
        return (
            object_id,
            snapshot_id,
            manifest_sha256,
            ended,
            repository_parents[0],
            repository_bindings[0],
        )

    @staticmethod
    def _clean_target(raw: Path) -> Path:
        path = Path(raw)
        if not path.is_absolute() or ".." in path.parts or path.name in {"", ".", ".."}:
            _fail("clean_target_invalid")
        if os.path.lexists(path):
            _fail("clean_target_must_not_exist")
        try:
            parent = path.parent.resolve(strict=True)
        except (OSError, RuntimeError):
            _fail("clean_target_invalid")
        if not parent.is_dir():
            _fail("clean_target_invalid")
        target = parent / path.name
        if os.path.lexists(target):
            _fail("clean_target_must_not_exist")
        return target

    @staticmethod
    def _verify_restore_envelope(target: Path, restored_source: Path) -> None:
        ancestors: set[Path] = set()
        current = restored_source.parent
        while current != target.parent:
            ancestors.add(current)
            if current == target:
                break
            current = current.parent
        if target not in ancestors:
            _fail("restored_source_outside_target")
        try:
            for directory, child_directories, child_files in os.walk(
                target, topdown=True, followlinks=False
            ):
                directory_path = Path(directory)
                for name in [*child_directories, *child_files]:
                    candidate = directory_path / name
                    try:
                        candidate_stat = candidate.lstat()
                    except OSError:
                        _fail("restore_entry_unreadable")
                    if stat.S_ISLNK(candidate_stat.st_mode):
                        _fail("restore_symlink_rejected")
                    within_source = candidate == restored_source or restored_source in candidate.parents
                    if not within_source and candidate not in ancestors:
                        _fail("restore_extra_entry_rejected")
                    if candidate in ancestors and not stat.S_ISDIR(candidate_stat.st_mode):
                        _fail("restore_envelope_invalid")
        except OSError:
            _fail("restore_entry_unreadable")

    def restore(
        self,
        *,
        backup_receipt: Mapping[str, Any],
        clean_target: Path,
        receipt_path: Path,
    ) -> dict[str, Any]:
        if os.path.lexists(receipt_path):
            _fail("receipt_already_exists")
        (
            backup_object_id,
            snapshot_id,
            source_manifest_sha256,
            backup_ended_at,
            expected_repository_commitment,
            expected_repository_binding,
        ) = self._validate_backup_receipt(backup_receipt)
        target = self._clean_target(clean_target)
        self._prove_separate_local_device(target, target.parent)
        started_clock = self._clock()
        started_monotonic = self._monotonic()
        if not isinstance(started_clock, datetime) or backup_ended_at > started_clock:
            _fail("backup_receipt_time_invalid")

        self._verify_version()
        repository_id = self._repository_identity()
        if (
            hashlib.sha256(repository_id.encode()).hexdigest()
            != expected_repository_commitment
        ):
            _fail("repository_identity_mismatch")
        repository_binding = hashlib.sha256(
            repository_id.encode() + b"\x00" + self._repository_locator_bytes
        ).hexdigest()
        if repository_binding != expected_repository_binding:
            _fail("repository_locator_binding_mismatch")
        snapshot_source = self._snapshot_source(
            snapshot_id,
            manifest_sha256=source_manifest_sha256,
            release_manifest_sha256=None,
            exact_source=None,
        )
        self._check_read_data()
        self._prove_separate_local_device(target, target.parent)
        self._execute(
            "restore",
            ("restore", snapshot_id, "--target", str(target), "--verify"),
        )
        if target.is_symlink() or not target.is_dir():
            _fail("clean_restore_missing")

        restored_source = target.joinpath(*PurePosixPath(snapshot_source.as_posix()).parts[1:])
        if restored_source.is_symlink() or not restored_source.is_dir():
            _fail("restored_source_missing")
        self._verify_restore_envelope(target, restored_source)
        restored_manifest = canonical_tree_manifest(restored_source)
        if restored_manifest.sha256 != source_manifest_sha256:
            _fail("restored_manifest_mismatch")
        self._snapshot_source(
            snapshot_id,
            manifest_sha256=source_manifest_sha256,
            release_manifest_sha256=None,
            exact_source=snapshot_source,
        )

        ended_clock = self._clock()
        ended_monotonic = self._monotonic()
        if ended_clock < started_clock or ended_monotonic < started_monotonic:
            _fail("clock_moved_backwards")
        recovery_point_seconds = math.ceil(
            max(0.0, (ended_clock - backup_ended_at).total_seconds())
        )
        recovery_time_seconds = math.ceil(ended_monotonic - started_monotonic)
        ended_at = _format_time(ended_clock)
        clean_target_ref = (
            "clean-target:sha256:"
            + hashlib.sha256(
                _canonical_bytes(
                    {
                        "backup_ref": backup_object_id,
                        "snapshot_id": snapshot_id,
                        "manifest_sha256": restored_manifest.sha256,
                    }
                )
            ).hexdigest()
        )
        payload = {
            "backup_ref": backup_object_id,
            "clean_target_ref": clean_target_ref,
            "restored_manifest_sha256": restored_manifest.sha256,
            "integrity_result": "VERIFIED",
            "recovery_point_seconds": recovery_point_seconds,
            "recovery_time_seconds": recovery_time_seconds,
        }
        receipt = self._receipt(
            "RestoreReceipt",
            f"restore-restic-{snapshot_id}",
            ended_at,
            payload,
            (
                backup_object_id,
                f"backup-payload-sha256:{backup_receipt['integrity']['payload_sha256']}",
                f"restic-repository-sha256:{hashlib.sha256(repository_id.encode()).hexdigest()}",
                f"restic-repository-binding-sha256:{repository_binding}",
            ),
        )
        self._write_receipt_last(receipt_path, receipt)
        return receipt


def _load_json_file(path: Path, code: str) -> dict[str, Any]:
    raw = Path(path)
    if raw.is_symlink():
        _fail(code)
    candidate = _normalized_absolute(raw, code, must_exist=True)
    if not candidate.is_file():
        _fail(code)
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(code)
    if not isinstance(value, dict):
        _fail(code)
    return value


def _controller_from_args(args: argparse.Namespace) -> ResticBackupRestoreController:
    return ResticBackupRestoreController(
        restic_binary=Path(args.restic_binary),
        repository_file=Path(args.repository_file),
        password_command=Path(args.password_command),
        destination_ref=args.destination_ref,
    )


def _add_controller_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--restic-binary", required=True)
    parser.add_argument("--repository-file", required=True)
    parser.add_argument("--password-command", required=True)
    parser.add_argument("--destination-ref", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Produce restic backup and restore receipts")
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup")
    _add_controller_arguments(backup)
    backup.add_argument("--source-root", required=True)
    backup.add_argument("--release-manifest", required=True)
    backup.add_argument("--receipt", required=True)

    restore = commands.add_parser("restore")
    _add_controller_arguments(restore)
    restore.add_argument("--backup-receipt", required=True)
    restore.add_argument("--clean-target", required=True)
    restore.add_argument("--receipt", required=True)

    drill = commands.add_parser("drill")
    _add_controller_arguments(drill)
    drill.add_argument("--source-root", required=True)
    drill.add_argument("--release-manifest", required=True)
    drill.add_argument("--backup-receipt", required=True)
    drill.add_argument("--clean-target", required=True)
    drill.add_argument("--restore-receipt", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        controller = _controller_from_args(args)
        if args.command == "backup":
            receipt = controller.backup(
                source_root=Path(args.source_root),
                release_manifest=_load_json_file(
                    Path(args.release_manifest), "release_manifest_file_invalid"
                ),
                receipt_path=Path(args.receipt),
            )
        elif args.command == "restore":
            receipt = controller.restore(
                backup_receipt=_load_json_file(
                    Path(args.backup_receipt), "backup_receipt_file_invalid"
                ),
                clean_target=Path(args.clean_target),
                receipt_path=Path(args.receipt),
            )
        else:
            controller.backup(
                source_root=Path(args.source_root),
                release_manifest=_load_json_file(
                    Path(args.release_manifest), "release_manifest_file_invalid"
                ),
                receipt_path=Path(args.backup_receipt),
            )
            receipt = controller.restore(
                backup_receipt=_load_json_file(
                    Path(args.backup_receipt), "backup_receipt_file_invalid"
                ),
                clean_target=Path(args.clean_target),
                receipt_path=Path(args.restore_receipt),
            )
        print(_canonical_bytes(receipt).decode("ascii"))
        return 0
    except BackupRestoreError as exc:
        print(f"release_backup_restore=FAIL code={exc.code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
