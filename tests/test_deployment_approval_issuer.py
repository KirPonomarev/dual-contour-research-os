import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.deployment import DeploymentApprovalConsumer
from tests.test_deployment_gate import (
    CI_REF,
    OPERATOR_KEY,
    RELEASE_SHA,
    TRUSTED_ISSUER_ID,
    TRUSTED_KEY_ID,
    fixtures,
)


TOOL = ROOT / "tools" / "issue_deployment_approval.py"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def issuer_command(release: Path, restore: Path, output: Path) -> list[str]:
    return [
        sys.executable,
        str(TOOL),
        "--release-manifest",
        str(release),
        "--restore-receipt",
        str(restore),
        "--environment",
        "pre-soak",
        "--remote-ci-ref",
        CI_REF,
        "--issuer-id",
        TRUSTED_ISSUER_ID,
        "--key-id",
        TRUSTED_KEY_ID,
        "--confirm-release-sha",
        RELEASE_SHA,
        "--out",
        str(output),
    ]


class DeploymentApprovalIssuerTests(unittest.TestCase):
    def test_cli_issues_private_exact_bound_receipt_without_logging_key_or_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_path = root / "release.json"
            restore_path = root / "restore.json"
            output_path = root / "approval.json"
            database = root / "deployment.sqlite3"
            release, backup, restore, _approval = fixtures()
            write_json(release_path, release)
            write_json(restore_path, restore)

            completed = subprocess.run(
                issuer_command(release_path, restore_path, output_path),
                input=OPERATOR_KEY.hex() + "\n",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            receipt = json.loads(output_path.read_text(encoding="utf-8"))
            payload = receipt["payload"]
            self.assertIsInstance(payload, dict)
            nonce_token = payload["nonce"]
            self.assertRegex(nonce_token, r"^sha256:[a-f0-9]{64}$")
            self.assertNotIn(OPERATOR_KEY.hex(), completed.stdout + completed.stderr)
            self.assertNotIn(nonce_token, completed.stdout + completed.stderr)
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)
            self.assertEqual(receipt["issuer"]["id"], TRUSTED_ISSUER_ID)
            self.assertEqual(payload["release_sha"], RELEASE_SHA)
            self.assertEqual(receipt["integrity"]["parent_refs"], [release["object_id"], restore["object_id"]])

            with DeploymentApprovalConsumer(
                database,
                trusted_issuer_id=TRUSTED_ISSUER_ID,
                trusted_key_id=TRUSTED_KEY_ID,
                operator_key=OPERATOR_KEY,
            ) as consumer:
                event = consumer.consume(
                    release_manifest=release,
                    backup_receipt=backup,
                    restore_receipt=restore,
                    approval_receipt=receipt,
                    expected_environment="pre-soak",
                    exact_remote_ci_ref=CI_REF,
                    consumed_at=receipt["issued_at"],
                )
            self.assertEqual(event.sequence, 1)

    def test_confirmation_mismatch_stops_before_key_read_or_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_path = root / "release.json"
            restore_path = root / "restore.json"
            output_path = root / "approval.json"
            release, _backup, restore, _approval = fixtures()
            write_json(release_path, release)
            write_json(restore_path, restore)
            command = issuer_command(release_path, restore_path, output_path)
            command[command.index("--confirm-release-sha") + 1] = "9" * 40

            completed = subprocess.run(
                command,
                input="",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("confirmation mismatch", completed.stdout)
            self.assertFalse(output_path.exists())

    def test_cli_never_overwrites_an_existing_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_path = root / "release.json"
            restore_path = root / "restore.json"
            output_path = root / "approval.json"
            release, _backup, restore, _approval = fixtures()
            write_json(release_path, release)
            write_json(restore_path, restore)
            output_path.write_text("preserve-me\n", encoding="utf-8")

            completed = subprocess.run(
                issuer_command(release_path, restore_path, output_path),
                input=OPERATOR_KEY.hex() + "\n",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "preserve-me\n")
            self.assertNotIn(OPERATOR_KEY.hex(), completed.stdout + completed.stderr)

    def test_cli_rejects_short_key_and_ttl_over_five_minutes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_path = root / "release.json"
            restore_path = root / "restore.json"
            output_path = root / "approval.json"
            release, _backup, restore, _approval = fixtures()
            write_json(release_path, release)
            write_json(restore_path, restore)

            short_key = subprocess.run(
                issuer_command(release_path, restore_path, output_path),
                input="00" * 31 + "\n",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(short_key.returncode, 1)
            self.assertIn("key input is invalid", short_key.stdout)
            self.assertFalse(output_path.exists())

            command = issuer_command(release_path, restore_path, output_path)
            command.extend(["--ttl-seconds", "301"])
            too_long = subprocess.run(
                command,
                input=OPERATOR_KEY.hex() + "\n",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(too_long.returncode, 2)
            self.assertIn("between 1 and 300 seconds", too_long.stderr)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
