import copy
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.deployment import (
    DeploymentApprovalConsumer,
    DeploymentGateError,
)


AT = "2026-07-18T00:30:00Z"
CI_REF = "https://github.com/KirPonomarev/dual-contour-research-os/actions/runs/123456789"
RELEASE_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
POLICY_SHA = "c" * 64
CONFIG_SHA = "d" * 64
SCHEMA_SHA = "e" * 64
LOCK_SHA = "f" * 64
MANIFEST_SHA = "1" * 64


def canonical_sha(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def receipt(schema_id: str, object_id: str, payload: dict[str, object], parents: list[str]) -> dict[str, object]:
    return {
        "schema_id": schema_id,
        "schema_version": "1.0.0",
        "object_id": object_id,
        "issued_at": "2026-07-18T00:00:00Z",
        "issuer": {"id": f"synthetic-{schema_id}", "authority_class": "synthetic-test-authority"},
        "contour": "governance",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {"payload_sha256": canonical_sha(payload), "parent_refs": parents},
    }


def fixtures() -> tuple[dict[str, object], ...]:
    release = receipt(
        "ReleaseManifest",
        "release-synthetic-a",
        {
            "release_sha": RELEASE_SHA,
            "image_digests": [IMAGE_DIGEST],
            "policy_sha256": POLICY_SHA,
            "config_sha256": CONFIG_SHA,
            "schema_sha256": SCHEMA_SHA,
            "dependency_lock_sha256": LOCK_SHA,
            "sbom_ref": "sbom:sha256:" + "2" * 64,
            "previous_release_ref": "release-synthetic-previous",
        },
        ["git:" + RELEASE_SHA],
    )
    backup = receipt(
        "BackupReceipt",
        "backup-synthetic-a",
        {
            "snapshot_id": "snapshot-synthetic-a",
            "source_manifest_sha256": MANIFEST_SHA,
            "destination_ref": "off-host:synthetic-encrypted-a",
            "encrypted": True,
            "started_at": "2026-07-17T23:40:00Z",
            "ended_at": "2026-07-17T23:50:00Z",
            "verification_result": "VERIFIED",
        },
        ["release-synthetic-a"],
    )
    restore = receipt(
        "RestoreReceipt",
        "restore-synthetic-a",
        {
            "backup_ref": "backup-synthetic-a",
            "clean_target_ref": "clean-target:synthetic-a",
            "restored_manifest_sha256": MANIFEST_SHA,
            "integrity_result": "VERIFIED",
            "recovery_point_seconds": 600,
            "recovery_time_seconds": 120,
        },
        ["backup-synthetic-a"],
    )
    approval = receipt(
        "DeploymentApprovalReceipt",
        "deployment-approval-synthetic-a",
        {
            "environment": "pre-soak",
            "release_sha": RELEASE_SHA,
            "image_digest": IMAGE_DIGEST,
            "policy_sha256": POLICY_SHA,
            "config_sha256": CONFIG_SHA,
            "schema_sha256": SCHEMA_SHA,
            "remote_ci_ref": CI_REF,
            "restore_receipt_ref": "restore-synthetic-a",
            "rollback_target": "release-synthetic-previous",
            "expires_at": "2026-07-18T01:00:00Z",
            "nonce": "synthetic-deployment-nonce-a",
        },
        ["release-synthetic-a", "restore-synthetic-a"],
    )
    return release, backup, restore, approval


def rebind(document: dict[str, object]) -> None:
    payload = document["payload"]
    integrity = document["integrity"]
    assert isinstance(payload, dict) and isinstance(integrity, dict)
    integrity["payload_sha256"] = canonical_sha(payload)


class DeploymentGateTests(unittest.TestCase):
    def consume(self, database: Path, values: tuple[dict[str, object], ...]):
        release, backup, restore, approval = values
        with DeploymentApprovalConsumer(database) as consumer:
            return consumer.consume(
                release_manifest=release,
                backup_receipt=backup,
                restore_receipt=restore,
                approval_receipt=approval,
                expected_environment="pre-soak",
                exact_remote_ci_ref=CI_REF,
                consumed_at=AT,
            )

    def test_consumes_exact_bindings_and_reopens_with_valid_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "deployment.sqlite3"
            event = self.consume(database, fixtures())
            self.assertEqual(event.sequence, 1)
            self.assertEqual(event.release_sha, RELEASE_SHA)
            self.assertEqual(event.image_digest, IMAGE_DIGEST)
            self.assertFalse(event.bindings["external_action_authorized"])
            with DeploymentApprovalConsumer(database) as reopened:
                self.assertTrue(reopened.verify_chain())

    def test_same_approval_cannot_be_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "deployment.sqlite3"
            values = fixtures()
            self.consume(database, values)
            with self.assertRaisesRegex(DeploymentGateError, "already consumed"):
                self.consume(database, values)

    def test_same_nonce_cannot_be_reused_by_different_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "deployment.sqlite3"
            values = fixtures()
            self.consume(database, values)
            second = copy.deepcopy(values)
            second[3]["object_id"] = "deployment-approval-synthetic-b"
            with self.assertRaisesRegex(DeploymentGateError, "already consumed"):
                self.consume(database, second)

    def test_release_and_approval_bindings_are_exact(self) -> None:
        mutations = (
            ("release_sha", "9" * 40, "release SHA"),
            ("image_digest", "sha256:" + "9" * 64, "image digest"),
            ("policy_sha256", "9" * 64, "policy_sha256"),
            ("config_sha256", "9" * 64, "config_sha256"),
            ("schema_sha256", "9" * 64, "schema_sha256"),
            ("remote_ci_ref", CI_REF + "/wrong", "exact-head CI"),
            ("restore_receipt_ref", "restore-wrong", "clean restore"),
            ("rollback_target", "release-wrong", "rollback target"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                values = list(fixtures())
                approval = values[3]
                payload = approval["payload"]
                assert isinstance(payload, dict)
                payload[field] = value
                rebind(approval)
                with self.assertRaisesRegex(DeploymentGateError, message):
                    self.consume(Path(directory) / "deployment.sqlite3", tuple(values))

    def test_expired_or_not_yet_issued_approval_is_rejected(self) -> None:
        for field, value in (
            ("expires_at", AT),
            ("issued_at", "2026-07-18T00:31:00Z"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                values = list(fixtures())
                approval = values[3]
                if field == "issued_at":
                    approval[field] = value
                else:
                    payload = approval["payload"]
                    assert isinstance(payload, dict)
                    payload[field] = value
                    rebind(approval)
                with self.assertRaisesRegex(DeploymentGateError, "not currently valid"):
                    self.consume(Path(directory) / "deployment.sqlite3", tuple(values))

    def test_unencrypted_backup_or_unclean_restore_is_rejected(self) -> None:
        for index, field, value, message in (
            (1, "encrypted", False, "backup is not encrypted"),
            (1, "verification_result", "FAILED", "backup is not encrypted"),
            (2, "integrity_result", "FAILED", "restore integrity"),
            (2, "restored_manifest_sha256", "9" * 64, "restored manifest differs"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                values = list(fixtures())
                document = values[index]
                payload = document["payload"]
                assert isinstance(payload, dict)
                payload[field] = value
                rebind(document)
                with self.assertRaisesRegex(DeploymentGateError, message):
                    self.consume(Path(directory) / "deployment.sqlite3", tuple(values))

    def test_missing_causal_parent_is_rejected(self) -> None:
        for index, message in ((2, "backup parent"), (3, "release or restore parent")):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                values = list(fixtures())
                integrity = values[index]["integrity"]
                assert isinstance(integrity, dict)
                integrity["parent_refs"] = []
                with self.assertRaisesRegex(DeploymentGateError, message):
                    self.consume(Path(directory) / "deployment.sqlite3", tuple(values))

    def test_tampered_receipt_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            values = list(fixtures())
            payload = values[0]["payload"]
            assert isinstance(payload, dict)
            payload["config_sha256"] = "9" * 64
            with self.assertRaisesRegex(DeploymentGateError, "payload integrity"):
                self.consume(Path(directory) / "deployment.sqlite3", tuple(values))

    def test_private_or_wrong_contour_receipt_is_rejected(self) -> None:
        for field, value in (("classification", "D2_DOMAIN_CONFIDENTIAL"), ("contour", "market")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                values = list(fixtures())
                values[0][field] = value
                with self.assertRaisesRegex(DeploymentGateError, "boundary"):
                    self.consume(Path(directory) / "deployment.sqlite3", tuple(values))

    def test_schema_tampering_is_detected_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "deployment.sqlite3"
            self.consume(database, fixtures())
            with sqlite3.connect(database) as connection:
                connection.execute("DROP TRIGGER deployment_approval_consumption_no_update")
            with self.assertRaisesRegex(DeploymentGateError, "chain is invalid"):
                DeploymentApprovalConsumer(database)

    def test_module_exposes_no_network_or_deployment_executor(self) -> None:
        source = (ROOT / "src/research_bridge/deployment.py").read_text(encoding="utf-8")
        for forbidden in ("import socket", "import urllib", "import requests", "subprocess", "docker", "ssh ", "systemctl"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
