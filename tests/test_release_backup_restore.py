from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.release_backup_restore import (  # noqa: E402
    RESTIC_BOTTLE_SHA256,
    RESTIC_LICENSE_SHA256,
    RESTIC_SOURCE_SHA256,
    RESTIC_VERSION,
    BackupRestoreError,
    ResticBackupRestoreController,
    canonical_tree_manifest,
    main,
)


SNAPSHOT_ID = "a" * 64
REPOSITORY_ID = "b" * 64
PRIVATE_LOCATOR = "s3:synthetic-private-repository-locator"
PRIVATE_PASSWORD = "synthetic-password-must-never-appear"


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def release_manifest() -> dict[str, object]:
    payload = {
        "release_sha": "1" * 40,
        "image_digests": ["sha256:" + "2" * 64],
        "policy_sha256": "3" * 64,
        "config_sha256": "4" * 64,
        "schema_sha256": "5" * 64,
        "dependency_lock_sha256": "6" * 64,
        "sbom_ref": "artifact:sha256:" + "7" * 64,
        "previous_release_ref": "release:none-service-stopped",
    }
    return {
        "schema_id": "ReleaseManifest",
        "schema_version": "1.0.0",
        "object_id": "release-synthetic-restic-test",
        "issued_at": "2026-07-18T00:00:00Z",
        "issuer": {"id": "synthetic-release-authority", "authority_class": "test"},
        "contour": "governance",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {
            "payload_sha256": canonical_sha256(payload),
            "parent_refs": ["git:" + "1" * 40],
        },
    }


def rebind(document: dict[str, object]) -> None:
    payload = document["payload"]
    integrity = document["integrity"]
    assert isinstance(payload, dict) and isinstance(integrity, dict)
    integrity["payload_sha256"] = canonical_sha256(payload)


class SteppingClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 7, 18, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        value = self.current
        self.current += timedelta(seconds=10)
        return value


class SteppingMonotonic:
    def __init__(self) -> None:
        self.current = 100.0

    def __call__(self) -> float:
        value = self.current
        self.current += 2.2
        return value


class FakeRestic:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str]]] = []
        self.repository_id = REPOSITORY_ID
        self.version = RESTIC_VERSION
        self.source: Path | None = None
        self.tags: list[str] = []
        self.check_fails = False
        self.wrong_snapshot = False
        self.wrong_tags = False
        self.partial_restore = False
        self.symlink_restore = False
        self.extra_restore_entry = False
        self.mutate_source_after_backup = False

    @staticmethod
    def _complete(
        argv: Sequence[str], returncode: int, stdout: bytes = b"", stderr: bytes = b""
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(tuple(argv), returncode, stdout, stderr)

    @staticmethod
    def _command(argv: Sequence[str]) -> str:
        for item in argv[1:]:
            if item in {"version", "cat", "backup", "snapshots", "check", "restore"}:
                return item
        raise AssertionError(f"missing command: {argv!r}")

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None,
        env: Mapping[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd
        self.calls.append((tuple(argv), dict(env)))
        self.assert_safe_invocation(argv, env, timeout)
        command = self._command(argv)
        if command == "version":
            return self._complete(
                argv,
                0,
                f"restic {self.version} compiled with go1.24 on synthetic/amd64\n".encode(),
            )
        if command == "cat":
            return self._complete(
                argv,
                0,
                json.dumps({"version": 2, "id": self.repository_id}).encode(),
            )
        if command == "backup":
            separator = list(argv).index("--")
            self.source = Path(argv[separator + 1])
            self.tags = [
                argv[index + 1] for index, item in enumerate(argv) if item == "--tag"
            ]
            if self.mutate_source_after_backup:
                (self.source / "changed-during-backup.txt").write_text(
                    "changed", encoding="utf-8"
                )
            output = (
                json.dumps({"message_type": "status", "files_done": 2})
                + "\n"
                + json.dumps(
                    {"message_type": "summary", "snapshot_id": SNAPSHOT_ID}
                )
                + "\n"
            ).encode()
            return self._complete(argv, 0, output)
        if command == "snapshots":
            assert self.source is not None
            snapshot_id = "c" * 64 if self.wrong_snapshot else SNAPSHOT_ID
            tags = ["dcros-manifest-" + "d" * 64] if self.wrong_tags else self.tags
            output = json.dumps(
                [{"id": snapshot_id, "tags": tags, "paths": [str(self.source)]}]
            ).encode()
            return self._complete(argv, 0, output)
        if command == "check":
            if self.check_fails:
                return self._complete(
                    argv,
                    1,
                    b"",
                    (PRIVATE_LOCATOR + PRIVATE_PASSWORD).encode(),
                )
            return self._complete(argv, 0, b"repository verified\n")
        if command == "restore":
            assert self.source is not None
            target = Path(argv[list(argv).index("--target") + 1])
            restored = target.joinpath(*self.source.parts[1:])
            restored.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(self.source, restored)
            if self.partial_restore:
                (restored / "nested" / "second.bin").unlink()
            if self.symlink_restore:
                (restored / "escape-link").symlink_to(restored.parent)
            if self.extra_restore_entry:
                (target / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            return self._complete(argv, 0, b"restore verified\n")
        raise AssertionError(command)

    @staticmethod
    def assert_safe_invocation(
        argv: Sequence[str], env: Mapping[str, str], timeout: int
    ) -> None:
        assert timeout > 0
        serialized = "\n".join(argv) + json.dumps(dict(env), sort_keys=True)
        assert PRIVATE_LOCATOR not in serialized
        assert PRIVATE_PASSWORD not in serialized
        assert not any(key.startswith("RESTIC_") for key in env)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        (self.source / "nested").mkdir(parents=True)
        (self.source / "first.txt").write_bytes(b"first\n")
        (self.source / "nested" / "second.bin").write_bytes(b"\x00\x01\x02")
        self.repository_file = root / "repository-file"
        self.repository_file.write_text(PRIVATE_LOCATOR + "\n", encoding="utf-8")
        self.repository_file.chmod(0o600)
        self.password_command = root / "password-command"
        self.password_command.write_text(
            "#!/bin/sh\nexec /usr/bin/security find-generic-password -w -s synthetic-test\n",
            encoding="utf-8",
        )
        self.password_command.chmod(0o700)
        self.fake = FakeRestic()
        self.controller = ResticBackupRestoreController(
            restic_binary=root / "restic-0.19.0",
            repository_file=self.repository_file,
            password_command=self.password_command,
            destination_ref="off-host:encrypted-synthetic-a",
            runner=self.fake,
            clock=SteppingClock(),
            monotonic=SteppingMonotonic(),
        )

    def backup(self) -> tuple[dict[str, object], Path]:
        receipt_path = self.root / "backup-receipt.json"
        receipt = self.controller.backup(
            source_root=self.source,
            release_manifest=release_manifest(),
            receipt_path=receipt_path,
        )
        return receipt, receipt_path


class ReleaseBackupRestoreTests(unittest.TestCase):
    def test_backup_and_clean_restore_emit_contract_shaped_receipts_last(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            source_manifest = canonical_tree_manifest(fixture.source)
            backup, backup_path = fixture.backup()
            self.assertTrue(backup_path.is_file())
            self.assertEqual(json.loads(backup_path.read_text()), backup)
            self.assertEqual(backup["schema_id"], "BackupReceipt")
            backup_payload = backup["payload"]
            assert isinstance(backup_payload, dict)
            self.assertEqual(backup_payload["snapshot_id"], SNAPSHOT_ID)
            self.assertEqual(
                backup_payload["source_manifest_sha256"], source_manifest.sha256
            )
            self.assertTrue(backup_payload["encrypted"])
            self.assertEqual(backup_payload["verification_result"], "VERIFIED")

            target = Path(directory) / "clean-restore"
            restore_path = Path(directory) / "restore-receipt.json"
            restore = fixture.controller.restore(
                backup_receipt=backup,
                clean_target=target,
                receipt_path=restore_path,
            )
            self.assertTrue(restore_path.is_file())
            self.assertEqual(json.loads(restore_path.read_text()), restore)
            self.assertEqual(restore["schema_id"], "RestoreReceipt")
            restore_payload = restore["payload"]
            assert isinstance(restore_payload, dict)
            self.assertEqual(restore_payload["backup_ref"], backup["object_id"])
            self.assertEqual(
                restore_payload["restored_manifest_sha256"], source_manifest.sha256
            )
            self.assertEqual(restore_payload["integrity_result"], "VERIFIED")
            self.assertGreaterEqual(restore_payload["recovery_point_seconds"], 0)
            self.assertEqual(restore_payload["recovery_time_seconds"], 3)

            for receipt in (backup, restore):
                integrity = receipt["integrity"]
                payload = receipt["payload"]
                assert isinstance(integrity, dict) and isinstance(payload, dict)
                self.assertEqual(integrity["payload_sha256"], canonical_sha256(payload))
            public_material = json.dumps([backup, restore], sort_keys=True)
            for private in (
                PRIVATE_LOCATOR,
                PRIVATE_PASSWORD,
                str(fixture.source),
                str(target),
                str(fixture.repository_file),
                str(fixture.password_command),
            ):
                self.assertNotIn(private, public_material)

            commands = [FakeRestic._command(argv) for argv, _ in fixture.fake.calls]
            self.assertIn("check", commands)
            self.assertIn("restore", commands)
            check_calls = [argv for argv, _ in fixture.fake.calls if "check" in argv]
            self.assertTrue(all("--read-data" in argv for argv in check_calls))
            restore_call = next(argv for argv, _ in fixture.fake.calls if "restore" in argv)
            self.assertIn("--verify", restore_call)

    def test_check_failure_emits_no_backup_receipt_and_redacts_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.fake.check_fails = True
            receipt_path = Path(directory) / "backup-receipt.json"
            with self.assertRaisesRegex(BackupRestoreError, "restic_check_read_data_failed"):
                fixture.controller.backup(
                    source_root=fixture.source,
                    release_manifest=release_manifest(),
                    receipt_path=receipt_path,
                )
            self.assertFalse(receipt_path.exists())

    def test_partial_restore_emits_no_restore_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            backup, _ = fixture.backup()
            fixture.fake.partial_restore = True
            restore_path = Path(directory) / "restore-receipt.json"
            with self.assertRaisesRegex(BackupRestoreError, "restored_manifest_mismatch"):
                fixture.controller.restore(
                    backup_receipt=backup,
                    clean_target=Path(directory) / "clean-restore",
                    receipt_path=restore_path,
                )
            self.assertFalse(restore_path.exists())

    def test_source_and_restored_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            (fixture.source / "link").symlink_to(fixture.source / "first.txt")
            with self.assertRaisesRegex(BackupRestoreError, "tree_symlink_rejected"):
                fixture.controller.backup(
                    source_root=fixture.source,
                    release_manifest=release_manifest(),
                    receipt_path=Path(directory) / "backup-receipt.json",
                )

        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            backup, _ = fixture.backup()
            fixture.fake.symlink_restore = True
            with self.assertRaisesRegex(BackupRestoreError, "restore_symlink_rejected"):
                fixture.controller.restore(
                    backup_receipt=backup,
                    clean_target=Path(directory) / "clean-restore",
                    receipt_path=Path(directory) / "restore-receipt.json",
                )

    def test_restore_envelope_rejects_traversal_like_extra_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            backup, _ = fixture.backup()
            fixture.fake.extra_restore_entry = True
            with self.assertRaisesRegex(BackupRestoreError, "restore_extra_entry_rejected"):
                fixture.controller.restore(
                    backup_receipt=backup,
                    clean_target=Path(directory) / "clean-restore",
                    receipt_path=Path(directory) / "restore-receipt.json",
                )

    def test_wrong_snapshot_or_tag_emits_no_receipt(self) -> None:
        for field in ("wrong_snapshot", "wrong_tags"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(Path(directory))
                setattr(fixture.fake, field, True)
                receipt_path = Path(directory) / "backup-receipt.json"
                with self.assertRaises(BackupRestoreError):
                    fixture.controller.backup(
                        source_root=fixture.source,
                        release_manifest=release_manifest(),
                        receipt_path=receipt_path,
                    )
                self.assertFalse(receipt_path.exists())

    def test_repository_identity_is_bound_across_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            backup, _ = fixture.backup()
            fixture.fake.repository_id = "9" * 64
            with self.assertRaisesRegex(BackupRestoreError, "repository_identity_mismatch"):
                fixture.controller.restore(
                    backup_receipt=backup,
                    clean_target=Path(directory) / "clean-restore",
                    receipt_path=Path(directory) / "restore-receipt.json",
                )

    def test_repository_locator_commitment_is_bound_without_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Fixture(root)
            backup, _ = fixture.backup()
            fixture.repository_file.write_text("s3:other-private-repository\n", encoding="utf-8")
            fixture.repository_file.chmod(0o600)
            second_clock = SteppingClock()
            second_clock()
            second_clock()
            second_controller = ResticBackupRestoreController(
                restic_binary=root / "restic-0.19.0",
                repository_file=fixture.repository_file,
                password_command=fixture.password_command,
                destination_ref="off-host:encrypted-synthetic-a",
                runner=fixture.fake,
                clock=second_clock,
                monotonic=SteppingMonotonic(),
            )
            with self.assertRaisesRegex(
                BackupRestoreError, "repository_locator_binding_mismatch"
            ):
                second_controller.restore(
                    backup_receipt=backup,
                    clean_target=root / "clean-restore",
                    receipt_path=root / "restore-receipt.json",
                )
            public_material = json.dumps(backup, sort_keys=True)
            self.assertNotIn(PRIVATE_LOCATOR, public_material)
            self.assertNotIn("other-private-repository", public_material)

    def test_tampered_or_wrong_snapshot_backup_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            backup, _ = fixture.backup()
            tampered = copy.deepcopy(backup)
            payload = tampered["payload"]
            assert isinstance(payload, dict)
            payload["snapshot_id"] = "8" * 64
            with self.assertRaisesRegex(BackupRestoreError, "backup_receipt_integrity_invalid"):
                fixture.controller.restore(
                    backup_receipt=tampered,
                    clean_target=Path(directory) / "clean-a",
                    receipt_path=Path(directory) / "restore-a.json",
                )
            rebind(tampered)
            tampered["object_id"] = "backup-restic-" + "8" * 64
            with self.assertRaisesRegex(BackupRestoreError, "snapshot_not_exact"):
                fixture.controller.restore(
                    backup_receipt=tampered,
                    clean_target=Path(directory) / "clean-b",
                    receipt_path=Path(directory) / "restore-b.json",
                )

    def test_source_change_during_backup_is_rejected_receipt_last(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.fake.mutate_source_after_backup = True
            receipt_path = Path(directory) / "backup-receipt.json"
            with self.assertRaisesRegex(BackupRestoreError, "source_changed_during_backup"):
                fixture.controller.backup(
                    source_root=fixture.source,
                    release_manifest=release_manifest(),
                    receipt_path=receipt_path,
                )
            self.assertFalse(receipt_path.exists())

    def test_clean_target_must_be_nonexistent_and_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            backup, _ = fixture.backup()
            existing = Path(directory) / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(BackupRestoreError, "clean_target_must_not_exist"):
                fixture.controller.restore(
                    backup_receipt=backup,
                    clean_target=existing,
                    receipt_path=Path(directory) / "restore-a.json",
                )
            with self.assertRaisesRegex(BackupRestoreError, "clean_target_invalid"):
                fixture.controller.restore(
                    backup_receipt=backup,
                    clean_target=Path(directory) / "nested" / ".." / "clean",
                    receipt_path=Path(directory) / "restore-b.json",
                )

    def test_owner_only_secret_files_and_exact_version_are_mandatory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Fixture(root)
            fixture.repository_file.chmod(0o644)
            with self.assertRaisesRegex(BackupRestoreError, "repository_file_invalid"):
                ResticBackupRestoreController(
                    restic_binary=root / "restic",
                    repository_file=fixture.repository_file,
                    password_command=fixture.password_command,
                    destination_ref="off-host:encrypted-a",
                    runner=fixture.fake,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Fixture(root)
            fixture.repository_file.write_text("relative-local-repository\n", encoding="utf-8")
            fixture.repository_file.chmod(0o600)
            with self.assertRaisesRegex(BackupRestoreError, "local_repository_invalid"):
                ResticBackupRestoreController(
                    restic_binary=root / "restic",
                    repository_file=fixture.repository_file,
                    password_command=fixture.password_command,
                    destination_ref="off-host:encrypted-a",
                    runner=fixture.fake,
                )

        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            fixture.fake.version = "0.18.1"
            with self.assertRaisesRegex(BackupRestoreError, "restic_version_mismatch"):
                fixture.controller.backup(
                    source_root=fixture.source,
                    release_manifest=release_manifest(),
                    receipt_path=Path(directory) / "backup-receipt.json",
                )

    def test_local_repository_requires_a_separate_device_for_backup_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = Fixture(root)
            repository = root / "synthetic-external-repository"
            repository.mkdir()
            fixture.repository_file.write_text(str(repository) + "\n", encoding="utf-8")
            fixture.repository_file.chmod(0o600)

            same_device = ResticBackupRestoreController(
                restic_binary=root / "restic-0.19.0",
                repository_file=fixture.repository_file,
                password_command=fixture.password_command,
                destination_ref="off-host:encrypted-separate-device-a",
                runner=fixture.fake,
                clock=SteppingClock(),
                monotonic=SteppingMonotonic(),
            )
            with self.assertRaisesRegex(BackupRestoreError, "local_repository_same_device"):
                same_device.backup(
                    source_root=fixture.source,
                    release_manifest=release_manifest(),
                    receipt_path=root / "same-device-backup.json",
                )
            self.assertEqual(fixture.fake.calls, [])

            observed_devices: list[Path] = []

            def separate_device_id(path: Path) -> int:
                observed_devices.append(path)
                return 200 if path == repository else 100

            separate_device = ResticBackupRestoreController(
                restic_binary=root / "restic-0.19.0",
                repository_file=fixture.repository_file,
                password_command=fixture.password_command,
                destination_ref="off-host:encrypted-separate-device-a",
                runner=fixture.fake,
                clock=SteppingClock(),
                monotonic=SteppingMonotonic(),
                device_id=separate_device_id,
            )
            backup_path = root / "separate-device-backup.json"
            backup = separate_device.backup(
                source_root=fixture.source,
                release_manifest=release_manifest(),
                receipt_path=backup_path,
            )
            clean_target = root / "separate-device-clean-restore"
            restore = separate_device.restore(
                backup_receipt=backup,
                clean_target=clean_target,
                receipt_path=root / "separate-device-restore.json",
            )
            self.assertEqual(restore["schema_id"], "RestoreReceipt")
            self.assertIn(repository, observed_devices)
            self.assertIn(fixture.source.resolve(), observed_devices)
            self.assertIn(clean_target.parent, observed_devices)
            public_material = json.dumps([backup, restore], sort_keys=True)
            self.assertNotIn(str(repository), public_material)
            process_material = json.dumps(
                [
                    {"argv": list(argv), "env": dict(environment)}
                    for argv, environment in fixture.fake.calls
                ],
                sort_keys=True,
            )
            self.assertNotIn(str(repository), process_material)

            second_clock = SteppingClock()
            second_clock()
            second_clock()
            same_restore_device = ResticBackupRestoreController(
                restic_binary=root / "restic-0.19.0",
                repository_file=fixture.repository_file,
                password_command=fixture.password_command,
                destination_ref="off-host:encrypted-separate-device-a",
                runner=fixture.fake,
                clock=second_clock,
                monotonic=SteppingMonotonic(),
                device_id=lambda path: 300,
            )
            with self.assertRaisesRegex(BackupRestoreError, "local_repository_same_device"):
                same_restore_device.restore(
                    backup_receipt=backup,
                    clean_target=root / "same-device-clean-restore",
                    receipt_path=root / "same-device-restore.json",
                )

    def test_local_repository_symlink_and_path_overlap_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = Fixture(root)
            real_repository = root / "real-repository"
            real_repository.mkdir()
            repository_link = root / "repository-link"
            repository_link.symlink_to(real_repository, target_is_directory=True)
            fixture.repository_file.write_text(
                str(repository_link) + "\n", encoding="utf-8"
            )
            fixture.repository_file.chmod(0o600)
            with self.assertRaisesRegex(BackupRestoreError, "local_repository_invalid"):
                ResticBackupRestoreController(
                    restic_binary=root / "restic-0.19.0",
                    repository_file=fixture.repository_file,
                    password_command=fixture.password_command,
                    destination_ref="off-host:encrypted-separate-device-a",
                    runner=fixture.fake,
                    device_id=lambda path: 200,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = Fixture(root)
            nested_repository = fixture.source / "nested-repository-mount"
            nested_repository.mkdir()
            fixture.repository_file.write_text(
                str(nested_repository.resolve()) + "\n", encoding="utf-8"
            )
            fixture.repository_file.chmod(0o600)
            controller = ResticBackupRestoreController(
                restic_binary=root / "restic-0.19.0",
                repository_file=fixture.repository_file,
                password_command=fixture.password_command,
                destination_ref="off-host:encrypted-separate-device-a",
                runner=fixture.fake,
                clock=SteppingClock(),
                monotonic=SteppingMonotonic(),
                device_id=lambda path: 200 if path == nested_repository else 100,
            )
            with self.assertRaisesRegex(BackupRestoreError, "local_repository_path_overlap"):
                controller.backup(
                    source_root=fixture.source,
                    release_manifest=release_manifest(),
                    receipt_path=root / "overlap-backup.json",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = Fixture(root)
            repository = root / "separate-repository"
            repository.mkdir()
            fixture.repository_file.write_text(str(repository) + "\n", encoding="utf-8")
            fixture.repository_file.chmod(0o600)
            controller = ResticBackupRestoreController(
                restic_binary=root / "restic-0.19.0",
                repository_file=fixture.repository_file,
                password_command=fixture.password_command,
                destination_ref="off-host:encrypted-separate-device-a",
                runner=fixture.fake,
                clock=SteppingClock(),
                monotonic=SteppingMonotonic(),
                device_id=lambda path: 200 if path == repository else 100,
            )
            backup = controller.backup(
                source_root=fixture.source,
                release_manifest=release_manifest(),
                receipt_path=root / "nonoverlap-backup.json",
            )
            with self.assertRaisesRegex(BackupRestoreError, "local_repository_path_overlap"):
                controller.restore(
                    backup_receipt=backup,
                    clean_target=repository / "forbidden-clean-target",
                    receipt_path=root / "overlap-restore.json",
                )

    def test_destination_ref_rejects_repository_locator_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            for value in (
                "s3:https://storage.example/repository",
                "/private/repository",
                "off-host:user@example.test",
            ):
                with self.subTest(value=value), self.assertRaisesRegex(
                    BackupRestoreError, "destination_ref_not_sanitized"
                ):
                    ResticBackupRestoreController(
                        restic_binary=Path(directory) / "restic",
                        repository_file=fixture.repository_file,
                        password_command=fixture.password_command,
                        destination_ref=value,
                        runner=fixture.fake,
                    )

    def test_receipts_are_exclusive_and_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory))
            receipt_path = Path(directory) / "backup-receipt.json"
            receipt_path.write_text("do-not-overwrite", encoding="utf-8")
            with self.assertRaisesRegex(BackupRestoreError, "receipt_already_exists"):
                fixture.controller.backup(
                    source_root=fixture.source,
                    release_manifest=release_manifest(),
                    receipt_path=receipt_path,
                )
            self.assertEqual(receipt_path.read_text(), "do-not-overwrite")
            self.assertEqual(fixture.fake.calls, [])

    def test_cli_failure_output_contains_only_redacted_code(self) -> None:
        stream = io.StringIO()
        with redirect_stderr(stream):
            result = main(
                [
                    "backup",
                    "--restic-binary",
                    "/missing/restic",
                    "--repository-file",
                    "/missing/repository",
                    "--password-command",
                    "/missing/password-helper",
                    "--destination-ref",
                    "off-host:synthetic-a",
                    "--source-root",
                    "/missing/source",
                    "--release-manifest",
                    "/missing/release.json",
                    "--receipt",
                    "/missing/receipt.json",
                ]
            )
        self.assertEqual(result, 1)
        output = stream.getvalue()
        self.assertIn("code=restic_binary_invalid", output)
        self.assertNotIn("/missing", output)
        self.assertNotIn(PRIVATE_LOCATOR, output)
        self.assertNotIn(PRIVATE_PASSWORD, output)

    def test_pinned_metadata_and_license_are_exact(self) -> None:
        license_path = ROOT / "LICENSES" / "restic-BSD-2-Clause.txt"
        self.assertEqual(
            hashlib.sha256(license_path.read_bytes()).hexdigest(), RESTIC_LICENSE_SHA256
        )
        provenance = json.loads(
            (ROOT / "provenance" / "restic-0.19.0.json").read_text(encoding="utf-8")
        )
        self.assertEqual(provenance["version"], RESTIC_VERSION)
        self.assertEqual(provenance["source"]["sha256"], RESTIC_SOURCE_SHA256)
        self.assertEqual(
            provenance["homebrew_bottle_arm64_tahoe"]["sha256"],
            RESTIC_BOTTLE_SHA256,
        )
        self.assertEqual(provenance["license"]["sha256"], RESTIC_LICENSE_SHA256)
        sbom = json.loads(
            (ROOT / "docs" / "receipts" / "release" / "restic-tool-sbom.spdx.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
        package = sbom["packages"][0]
        self.assertEqual(package["name"], "restic")
        self.assertEqual(package["versionInfo"], RESTIC_VERSION)
        self.assertEqual(package["licenseDeclared"], "BSD-2-Clause")


if __name__ == "__main__":
    unittest.main()
