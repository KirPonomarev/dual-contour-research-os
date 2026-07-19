from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

import final_deployment_rebind as final
import pre_soak_deploy as deploy
from research_bridge.deployment import issue_deployment_approval
from tests.test_deployment_gate import (
    OPERATOR_KEY,
    TRUSTED_ISSUER_ID,
    TRUSTED_KEY_ID,
    fixtures,
)
from tests.test_release_deploy_recovery import FakeRunner


IMAGE_ID = "sha256:" + "8" * 64
CI_REF = "github-actions:29668388814@d28bef12cbf6acd1747ddf0e3ec51671c4ca2dcb"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


class A1FakeRunner(FakeRunner):
    def __init__(self, bundle: deploy.ReleaseBundle) -> None:
        super().__init__(bundle)
        self.predecessor_active = False
        self.predecessor_enabled = False
        self.predecessor_container_running = False

    def run(self, arguments, *, input_bytes=None, timeout=60.0):
        original = tuple(arguments)
        command = original[-1]
        if command.startswith(
            "systemctl --user is-active --quiet research-os-bridge.service"
        ):
            self.commands.append((original, input_bytes))
            return deploy.CommandResult(0 if self.predecessor_active else 3)
        if command.startswith(
            "systemctl --user is-enabled --quiet research-os-bridge.service"
        ):
            self.commands.append((original, input_bytes))
            return deploy.CommandResult(0 if self.predecessor_enabled else 1)
        if "if state=" in command and "container inspect research-os-bridge" in command:
            self.commands.append((original, input_bytes))
            state = "PRESENT:true" if self.predecessor_container_running else "ABSENT"
            return deploy.CommandResult(0, state + "\n")
        translated = list(original)
        translated[-1] = (
            command.replace("research-os-a1-bridge.service", "research-os-bridge.service")
            .replace("research-os-a1-bridge", "research-os-bridge")
            .replace("research-os-a1-runtime", "research-os-bridge-runtime")
            .replace("research-os-a1-config", "research-os-bridge-config")
        )
        result = super().run(translated, input_bytes=input_bytes, timeout=timeout)
        self.commands[-1] = (original, input_bytes)
        return result

    def container_inspect(self) -> dict[str, object]:
        value = super().container_inspect()
        value["Name"] = "/research-os-a1-bridge"
        host = value["HostConfig"]
        assert isinstance(host, dict)
        host["RestartPolicy"] = {"Name": "no"}
        mounts = value["Mounts"]
        assert isinstance(mounts, list)
        mounts[0]["Name"] = "research-os-a1-runtime"
        mounts[1]["Name"] = "research-os-a1-config"
        return value


class FinalDeploymentRebindTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temp = Path(self.temporary.name)
        self.known_hosts = self.temp / "known_hosts"
        self.known_hosts.write_text("synthetic.invalid ssh-ed25519 AAAATEST\n")
        os.chmod(self.known_hosts, 0o600)
        self.archive = self.temp / "release.tar"
        self.archive.write_bytes(b"synthetic exact final image archive")
        os.chmod(self.archive, 0o600)
        self.archive_sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.manifest_path = self.temp / "release.json"
        self.manifest = final._release_manifest(
            IMAGE_ID, "7" * 64, "2026-07-19T01:30:00Z"
        )
        write_json(self.manifest_path, self.manifest)
        self.bundle = deploy._load_bundle(
            manifest_path=self.manifest_path,
            policy_path=final.POLICY,
            config_path=final.CONFIG,
            unit_path=final.A1_UNIT,
            archive_path=self.archive,
            archive_sha256=self.archive_sha,
            expected_release_sha=final.CANDIDATE_SHA,
            expected_image_id=IMAGE_ID,
            expected_previous_release=final.PREVIOUS_RELEASE,
            expected_config_sha256=final._digest_file(final.CONFIG),
            expected_unit_template_sha256=final._digest_file(final.A1_UNIT),
            expected_policy=final._load_json(final.POLICY, "final A1 runtime policy"),
        )

    def test_static_rebind_preserves_candidate_and_wait_authority(self) -> None:
        result = final._verify_static()
        self.assertEqual(result["status"], "SUPERSEDED_REPAIR_REQUIRED")
        self.assertEqual(result["candidate_release_sha"], final.CANDIDATE_SHA)
        self.assertEqual(result["candidate_tree_sha"], final.CANDIDATE_TREE)
        self.assertTrue(result["replacement_release_required"])
        self.assertEqual(
            result["historical_static_subjects"],
            [final.CANDIDATE_SHA, final.S38_REBIND_SHA],
        )
        self.assertNotEqual(
            final._digest_file(final.CONFIG),
            "0b186888a3a1bb8fb028315681bf4073ec4186a0acbdf2f226b5a53d69a9d542",
        )
        self.assertFalse(result["deployment_allowed"])
        self.assertEqual(result["remote_actions"], 0)
        packet = json.loads(
            (ROOT / "ops/deploy/s38-r1-final-deployment-rebind.json").read_text()
        )
        integrity = packet.pop("integrity")
        self.assertEqual(
            integrity["payload_sha256"], hashlib.sha256(final._canonical(packet)).hexdigest()
        )
        self.assertFalse(packet["source_candidate_changed"])
        self.assertEqual(
            packet["causal_order"].index("DURABLE_ONE_SHOT_APPROVAL_CONSUMPTION") + 1,
            packet["causal_order"].index("FIRST_REMOTE_MUTATION"),
        )
        self.assertTrue(all(value is False for value in packet["authority"].values()))

    def test_public_cli_denies_all_superseded_candidate_actions_before_side_effects(
        self,
    ) -> None:
        output_dir = self.temp / "prepared"
        output_dir.mkdir(mode=0o700)
        deploy_receipt = self.temp / "deployment-receipt.json"
        approval_ledger = self.temp / "approval.sqlite3"
        command_lines = (
            ["prepare", "--output-dir", str(output_dir)],
            ["verify-prepared", "--output-dir", str(output_dir)],
            [
                "deploy",
                "--ssh-alias",
                "synthetic_lab",
                "--known-hosts",
                str(self.known_hosts),
                "--release-manifest",
                str(self.manifest_path),
                "--archive",
                str(self.archive),
                "--archive-sha256",
                self.archive_sha,
                "--backup-receipt",
                str(self.temp / "backup.json"),
                "--restore-receipt",
                str(self.temp / "restore.json"),
                "--approval-receipt",
                str(self.temp / "approval.json"),
                "--approval-ledger",
                str(approval_ledger),
                "--trusted-issuer-id",
                TRUSTED_ISSUER_ID,
                "--trusted-key-id",
                TRUSTED_KEY_ID,
                "--key-hex-fd",
                "-1",
                "--remote-ci-ref",
                CI_REF,
                "--receipt",
                str(deploy_receipt),
            ],
        )

        with (
            mock.patch.object(
                final,
                "_require_deployable_candidate",
                wraps=final._require_deployable_candidate,
            ) as deny,
            mock.patch.object(final, "_prepare") as prepare,
            mock.patch.object(final, "_verify_prepared") as verify_prepared,
            mock.patch.object(final, "_deploy") as deploy_command,
        ):
            for arguments in command_lines:
                with self.subTest(command=arguments[0]):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    self.assertEqual(final.run(arguments, stdout=stdout, stderr=stderr), 2)
                    self.assertEqual(stdout.getvalue(), "")
                    failure = json.loads(stderr.getvalue())
                    self.assertEqual(failure["status"], "STOP")
                    self.assertEqual(
                        failure["reason_code"], "FinalDeploymentRebindError"
                    )

        self.assertEqual(deny.call_count, len(command_lines))
        prepare.assert_not_called()
        verify_prepared.assert_not_called()
        deploy_command.assert_not_called()
        self.assertEqual(list(output_dir.iterdir()), [])
        self.assertFalse(approval_ledger.exists())
        self.assertFalse(deploy_receipt.exists())

    def test_final_bundle_uses_A1_namespace_and_single_supervisor(self) -> None:
        rendered = self.bundle.unit_bytes.decode()
        self.assertIn("research-os-a1-bridge", rendered)
        self.assertIn("source=research-os-a1-runtime", rendered)
        self.assertIn("source=research-os-a1-config", rendered)
        self.assertIn("--restart=no", rendered)
        self.assertIn("Restart=on-failure", rendered)
        self.assertNotIn("--restart=unless-stopped", rendered)
        self.assertIn("is-active --quiet research-os-bridge.service", rendered)
        self.assertIn("is-enabled --quiet research-os-bridge.service", rendered)
        self.assertIn("container inspect research-os-bridge", rendered)
        policy = final._load_json(final.POLICY, "final A1 runtime policy")
        self.assertEqual(policy["restart_policy"], "no")

    def test_authority_is_consumed_after_read_only_checks_before_first_mutation(self) -> None:
        runner = A1FakeRunner(self.bundle)
        controller = deploy.PreSoakDeployController(
            ssh_alias="synthetic_lab",
            known_hosts_path=self.known_hosts,
            runner=runner,
            clock=lambda: datetime(2026, 7, 19, 1, 31, tzinfo=timezone.utc),
            target=deploy.FINAL_A1_TARGET,
        )
        marker: list[int] = []

        def authorize():
            marker.append(len(runner.commands))
            return {"consumed": True, "consumption_event_sha256": "9" * 64}

        receipt = controller.deploy(self.bundle, authorization=authorize)
        self.assertEqual(len(marker), 1)
        first_scp = next(
            index for index, (argv, _) in enumerate(runner.commands) if argv[0] == "scp"
        )
        first_install = next(
            index
            for index, (argv, _) in enumerate(runner.commands)
            if argv[0] == "ssh" and "install -d -m 0700" in argv[-1]
        )
        self.assertLess(marker[0], first_scp)
        self.assertLessEqual(marker[0], first_install)
        evidence = receipt["payload"]["evidence"]
        self.assertTrue(evidence["deployment_authorization"]["consumed"])
        command_text = "\n".join(argv[-1] for argv, _ in runner.commands)
        self.assertIn("research-os-a1-bridge.service", command_text)
        self.assertIn("research-os-a1-runtime", command_text)

    def test_missing_authority_or_active_predecessor_stops_before_mutation(self) -> None:
        for active, enabled, running, authorization in (
            (False, False, False, lambda: {"consumed": False}),
            (True, False, False, lambda: {"consumed": True}),
            (False, True, False, lambda: {"consumed": True}),
            (False, False, True, lambda: {"consumed": True}),
        ):
            with self.subTest(active=active, enabled=enabled, running=running):
                runner = A1FakeRunner(self.bundle)
                runner.predecessor_active = active
                runner.predecessor_enabled = enabled
                runner.predecessor_container_running = running
                controller = deploy.PreSoakDeployController(
                    ssh_alias="synthetic_lab",
                    known_hosts_path=self.known_hosts,
                    runner=runner,
                    target=deploy.FINAL_A1_TARGET,
                )
                with self.assertRaises(deploy.DeploymentError):
                    controller.deploy(self.bundle, authorization=authorization)
                self.assertFalse(any(argv[0] == "scp" for argv, _ in runner.commands))
                self.assertFalse(
                    any("install -d -m 0700" in argv[-1] for argv, _ in runner.commands)
                )

    def test_absent_predecessor_probe_is_valid_shell_before_authority(self) -> None:
        class ProbeRunner:
            def __init__(self) -> None:
                self.probe = ""

            def run(self, arguments, *, input_bytes=None, timeout=60.0):
                del input_bytes, timeout
                command = arguments[-1]
                if command.startswith("systemctl --user is-active --quiet"):
                    return deploy.CommandResult(4)
                if command.startswith("systemctl --user is-enabled --quiet"):
                    return deploy.CommandResult(4)
                self.probe = command
                return deploy.CommandResult(0, "ABSENT\n")

        runner = ProbeRunner()
        controller = deploy.PreSoakDeployController(
            ssh_alias="synthetic_lab",
            known_hosts_path=self.known_hosts,
            runner=runner,
            target=deploy.FINAL_A1_TARGET,
        )
        controller._assert_no_conflicting_writer()
        syntax = subprocess.run(
            ["bash", "-n", "-c", runner.probe],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertIn(")\"; then printf 'PRESENT:%s", runner.probe)

    def _authority_documents(self):
        _old_release, backup, restore, _old_approval = fixtures()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        approval = issue_deployment_approval(
            release_manifest=self.manifest,
            restore_receipt=restore,
            environment="pre-soak",
            exact_remote_ci_ref=CI_REF,
            issuer_id=TRUSTED_ISSUER_ID,
            key_id=TRUSTED_KEY_ID,
            operator_key=OPERATOR_KEY,
            issued_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=(now + timedelta(seconds=300)).isoformat().replace("+00:00", "Z"),
            approval_object_id="deployment-approval-final-synthetic",
            nonce="sha256:" + "a" * 64,
        )
        return backup, restore, approval

    def test_final_cli_path_durably_consumes_one_approval_and_replay_fails(self) -> None:
        backup, restore, approval = self._authority_documents()
        backup_path = self.temp / "backup.json"
        restore_path = self.temp / "restore.json"
        approval_path = self.temp / "approval.json"
        for path, value in (
            (backup_path, backup),
            (restore_path, restore),
            (approval_path, approval),
        ):
            write_json(path, value)
        ledger = self.temp / "approval.sqlite3"

        class SyntheticController:
            def __init__(self, **kwargs):
                del kwargs

            def deploy(self, bundle, *, authorization):
                evidence = dict(authorization())
                return deploy._receipt(
                    "deploy",
                    bundle,
                    {"deployment_authorization": evidence},
                    clock=lambda: datetime.now(timezone.utc),
                )

        arguments = argparse_namespace(
            release_manifest=self.manifest_path,
            archive=self.archive,
            archive_sha256=self.archive_sha,
            backup_receipt=backup_path,
            restore_receipt=restore_path,
            approval_receipt=approval_path,
            approval_ledger=ledger,
            ssh_alias="synthetic_lab",
            known_hosts=self.known_hosts,
            trusted_issuer_id=TRUSTED_ISSUER_ID,
            trusted_key_id=TRUSTED_KEY_ID,
            environment="pre-soak",
            remote_ci_ref=CI_REF,
        )
        read_fd, write_fd = os.pipe()
        os.write(write_fd, OPERATOR_KEY.hex().encode() + b"\n")
        os.close(write_fd)
        arguments.key_hex_fd = read_fd
        arguments.receipt = self.temp / "deploy.json"
        try:
            with mock.patch.object(final.deploy, "PreSoakDeployController", SyntheticController):
                result = final._deploy(arguments)
        finally:
            os.close(read_fd)
        self.assertEqual(result["status"], "DEPLOYED_EXACT_APPROVED_RELEASE")
        receipt = json.loads(arguments.receipt.read_text())
        consumed = receipt["payload"]["evidence"]["deployment_authorization"]
        self.assertTrue(consumed["consumed"])
        self.assertEqual(consumed["sequence"], 1)
        self.assertNotIn(OPERATOR_KEY.hex(), json.dumps(receipt))
        self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)

        read_fd, write_fd = os.pipe()
        os.write(write_fd, OPERATOR_KEY.hex().encode() + b"\n")
        os.close(write_fd)
        arguments.key_hex_fd = read_fd
        arguments.receipt = self.temp / "replay.json"
        try:
            with mock.patch.object(final.deploy, "PreSoakDeployController", SyntheticController):
                with self.assertRaisesRegex(Exception, "already consumed"):
                    final._deploy(arguments)
        finally:
            os.close(read_fd)
        failed = json.loads(arguments.receipt.read_text())
        self.assertEqual(failed["payload"]["status"], "FAIL")
        self.assertFalse(failed["payload"]["evidence"]["automatic_retry_allowed"])
        self.assertNotIn(OPERATOR_KEY.hex(), json.dumps(failed))

    def test_runtime_artifacts_must_be_private_and_outside_git(self) -> None:
        public = self.temp / "public.json"
        public.write_text("{}\n")
        with self.assertRaisesRegex(final.FinalDeploymentRebindError, "owner-only"):
            final._require_private_file(public, "fixture")
        os.chmod(public, 0o600)
        with mock.patch.object(final, "ROOT", self.temp):
            with self.assertRaisesRegex(final.FinalDeploymentRebindError, "outside"):
                final._require_outside_repository(public, "fixture")

    def test_public_error_output_never_echoes_operator_key(self) -> None:
        stderr = io.StringIO()
        code = final.run(["deploy"], stdout=io.StringIO(), stderr=stderr)
        self.assertEqual(code, 2)
        self.assertNotIn(OPERATOR_KEY.hex(), stderr.getvalue())
        self.assertNotIn("ssh", stderr.getvalue().lower())


def argparse_namespace(**values):
    class Namespace:
        pass

    value = Namespace()
    for key, item in values.items():
        setattr(value, key, item)
    return value


if __name__ == "__main__":
    unittest.main()
