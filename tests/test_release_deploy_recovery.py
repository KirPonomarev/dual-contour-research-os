import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import io
import os
import subprocess


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import pre_soak_deploy as deploy
import build_pre_soak_capsule as capsule_builder


BOOT_A = "123e4567-e89b-12d3-a456-426614174000"
BOOT_B = "123e4567-e89b-12d3-a456-426614174001"


class FakeRunner:
    def __init__(self, bundle: deploy.ReleaseBundle) -> None:
        self.bundle = bundle
        self.commands: list[tuple[tuple[str, ...], bytes | None]] = []
        self.rootless = True
        self.linger = True
        self.service_active = False
        self.service_enabled = False
        self.container_exists = False
        self.container_running = False
        self.boot_id = BOOT_A
        self.pause_state: dict[str, object] = {"paused": False}
        self.fail_activation = False
        self.tamper_archive = False
        self.remote_capsule_objects: set[str] = set()
        self.unexpected_remote_capsule_object = False
        self.remote_capsule_symlink_race = False
        self.inject_tmpdir = False
        self.container_cap_add: list[str] | None = None
        self.container_privileged = False
        self.container_devices: list[object] | None = None
        self.container_binds: list[str] | None = None
        self.extra_mount = False
        self.omit_capsule_label = False
        self.container_entrypoint = ["python", "-m", "research_bridge.researchd"]
        self.container_cmd = ["--config", "/run/research-os/researchd.json"]
        self.extra_environment: list[str] = []
        self.container_healthcheck: dict[str, object] | None = None

    def run(
        self,
        arguments: list[str] | tuple[str, ...],
        *,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
    ) -> deploy.CommandResult:
        del timeout
        argv = tuple(arguments)
        self.commands.append((argv, input_bytes))
        if argv[0] == "scp":
            destination = argv[-1]
            if self.bundle.capsule is not None and destination.rsplit("/", 1)[-1] in {
                item.sha256 for item in self.bundle.capsule.objects
            }:
                self.remote_capsule_objects.add(destination.rsplit("/", 1)[-1])
            return deploy.CommandResult(0)
        if "-G" in argv:
            return deploy.CommandResult(
                0,
                "host synthetic.invalid\nbatchmode yes\nstricthostkeychecking true\n",
            )
        command = argv[-1]
        if "printf '%s\\n'" in command and "docker.sock" in command:
            if not self.linger:
                return deploy.CommandResult(1, "", "linger disabled")
            return deploy.CommandResult(0, f"1000\n{self.boot_id}\n")
        if "docker info --format" in command:
            security = ["name=seccomp,profile=builtin"]
            if self.rootless:
                security.append("name=rootless")
            return deploy.CommandResult(0, json.dumps(security) + "|linux|x86_64\n")
        if command == "cat /proc/sys/kernel/random/boot_id":
            return deploy.CommandResult(0, self.boot_id + "\n")
        if "CAPSULE_STAGE_CREATED" in command:
            return deploy.CommandResult(0, "CAPSULE_STAGE_CREATED\n")
        if "CAPSULE_STAGE_READY" in command:
            if self.unexpected_remote_capsule_object or self.remote_capsule_symlink_race:
                return deploy.CommandResult(1, "", "unsafe stage")
            return deploy.CommandResult(0, "CAPSULE_STAGE_READY\n")
        if "CAPSULE_STAGE_CLEANED" in command:
            self.remote_capsule_objects.clear()
            return deploy.CommandResult(0, "CAPSULE_STAGE_CLEANED\n")
        if "research-os-bridge-capsule-volume-init" in command:
            return deploy.CommandResult(
                0, f"CAPSULE_VOLUME_INIT_OK:{self.bundle.config_sha256}\n"
            )
        if "sha256sum --" in command:
            if "release-" in command:
                value = "0" * 64 if self.tamper_archive else self.bundle.archive_sha256
            elif self.bundle.capsule is not None and any(
                item.sha256 in command for item in self.bundle.capsule.objects
            ):
                value = next(
                    item.sha256
                    for item in self.bundle.capsule.objects
                    if item.sha256 in command
                )
            elif "researchd-" in command:
                value = self.bundle.config_sha256
            else:
                value = self.bundle.unit_sha256
            return deploy.CommandResult(0, f"{value}  artifact\n")
        if "image inspect" in command:
            return deploy.CommandResult(0, json.dumps(self.image_inspect()) + "\n")
        if "container inspect research-os-bridge --format" in command:
            if not self.container_exists:
                return deploy.CommandResult(1, "", "not found")
            return deploy.CommandResult(0, json.dumps(self.container_inspect()) + "\n")
        if "stat -c %u:%g:%a" in command:
            return deploy.CommandResult(
                0, f"{self.bundle.config_sha256}  /target-config/researchd.json\n"
            )
        if "research_bridge.researchctl" in command:
            response = {
                "version": "1.1",
                "request_id": "deployment-verification",
                "ok": True,
                "command": "status",
                "result": copy.deepcopy(self.pause_state),
            }
            return deploy.CommandResult(0, json.dumps(response) + "\n")
        if command.startswith("systemctl --user is-active --quiet"):
            return deploy.CommandResult(0 if self.service_active else 3)
        if command.startswith("systemctl --user is-active "):
            return deploy.CommandResult(0, "active\n" if self.service_active else "inactive\n")
        if command.startswith("systemctl --user is-enabled --quiet"):
            return deploy.CommandResult(0 if self.service_enabled else 1)
        if command.startswith("systemctl --user is-enabled "):
            return deploy.CommandResult(0, "enabled\n" if self.service_enabled else "disabled\n")
        if command.startswith("systemctl --user enable --now"):
            if self.fail_activation:
                return deploy.CommandResult(1, "", "synthetic activation failure")
            self.service_active = True
            self.service_enabled = True
            self.container_exists = True
            self.container_running = True
            return deploy.CommandResult(0)
        if command.startswith("systemctl --user disable --now"):
            self.service_active = False
            self.service_enabled = False
            self.container_running = False
            return deploy.CommandResult(0)
        if "docker stop --time=30 research-os-bridge" in command:
            self.container_running = False
            return deploy.CommandResult(0)
        return deploy.CommandResult(0)

    def image_inspect(self) -> dict[str, object]:
        return {
            "Id": self.bundle.image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "User": "10001:10001",
                "Labels": {
                    "org.opencontainers.image.revision": self.bundle.release_sha
                },
            },
        }

    def container_inspect(self) -> dict[str, object]:
        return {
            "Name": "/research-os-bridge",
            "Image": self.bundle.image_id,
            "Config": {
                "Image": self.bundle.image_id,
                "User": "10001:10001",
                "Entrypoint": self.container_entrypoint,
                "Cmd": self.container_cmd,
                "WorkingDir": "/opt/research-os",
                "StopSignal": "SIGTERM",
                "Healthcheck": self.container_healthcheck,
                "Labels": {
                    "org.research-os.release-sha": self.bundle.release_sha,
                    "org.research-os.policy-sha256": self.bundle.policy_sha256,
                    "org.research-os.config-sha256": self.bundle.config_sha256,
                    **(
                        {"org.research-os.capsule-manifest-sha256": self.bundle.capsule.manifest_sha256}
                        if self.bundle.capsule is not None and not self.omit_capsule_label
                        else {}
                    ),
                },
                "Env": [
                    "RESEARCH_OS_ENVIRONMENT=pre-soak",
                    "RESEARCH_OS_EXTERNAL_ACTION_AUTHORITY=false",
                ] + (
                    ["TMPDIR=/var/lib/research-os/tmp"]
                    if b"--env=TMPDIR=/var/lib/research-os/tmp" in self.bundle.unit_bytes
                    or self.inject_tmpdir
                    else []
                ) + deploy._FROZEN_IMAGE_ENV + self.extra_environment,
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "CapAdd": self.container_cap_add,
                "Privileged": self.container_privileged,
                "Devices": self.container_devices,
                "Binds": self.container_binds,
                "PidsLimit": 256,
                "Memory": 2147483648,
                "NanoCpus": 2000000000,
                "RestartPolicy": {"Name": "unless-stopped"},
                "PortBindings": {},
            },
            "State": {"Running": self.container_running},
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": "research-os-bridge-runtime",
                    "Destination": "/var/lib/research-os",
                    "RW": True,
                },
                {
                    "Type": "volume",
                    "Name": "research-os-bridge-config",
                    "Destination": "/run/research-os",
                    "RW": False,
                },
            ] + (
                [{"Type": "bind", "Source": "/unsafe", "Destination": "/unsafe", "RW": True}]
                if self.extra_mount
                else []
            ),
            "NetworkSettings": {"Ports": {}},
        }


class ReleaseDeployRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temp = Path(self.temporary.name)
        self.known_hosts = self.temp / "known_hosts"
        self.known_hosts.write_text("synthetic.invalid ssh-ed25519 AAAATEST\n")
        self.archive = self.temp / "release.tar"
        self.archive.write_bytes(b"synthetic exact image archive")
        self.archive_sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.historical_config = self.temp / "historical-researchd.config.json"
        historical_config = subprocess.run(
            ["git", "show", f"{deploy.RELEASE_SHA}:ops/release/researchd.config.template.json"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.historical_config.write_bytes(historical_config)
        self.bundle = deploy._load_bundle(
            manifest_path=ROOT / "docs/receipts/release/s4-release-manifest.json",
            policy_path=ROOT / "ops/release/runtime-policy.json",
            config_path=self.historical_config,
            unit_path=ROOT / "ops/deploy/research-os-bridge.service",
            archive_path=self.archive,
            archive_sha256=self.archive_sha,
        )
        self.clock = lambda: datetime(2026, 7, 18, 1, 0, tzinfo=timezone.utc)

    def test_final_a1_unit_has_private_runtime_tmpdir_on_read_only_root(self) -> None:
        unit = (ROOT / "ops/deploy/research-os-a1-final.service").read_text()
        create_line = next(
            line
            for line in unit.splitlines()
            if "docker container create --name=research-os-a1-bridge" in line
        )
        initialize_line = next(
            line
            for line in unit.splitlines()
            if "research-os-a1-runtime,target=/var/lib/research-os" in line
            and "install -d" in line
        )
        self.assertIn("--read-only", create_line)
        self.assertIn("--network=none", create_line)
        self.assertIn("--env=TMPDIR=/var/lib/research-os/tmp", create_line)
        self.assertIn(
            "install -d -m 0700 -o 10001 -g 10001 /var/lib/research-os/tmp",
            initialize_line,
        )

    def controller(self, runner: FakeRunner) -> deploy.PreSoakDeployController:
        return deploy.PreSoakDeployController(
            ssh_alias="synthetic_lab",
            known_hosts_path=self.known_hosts,
            runner=runner,
            clock=self.clock,
        )

    def functional_bundle(self, suffix: str) -> tuple[Path, deploy.ReleaseBundle]:
        market = self.temp / f"market-{suffix}.json"
        security = self.temp / f"security-{suffix}.json"
        market.write_text('{"contour":"market","value":1}\n')
        security.write_text('{"contour":"security","value":2}\n')
        capsule_path = self.temp / f"capsule-{suffix}"
        capsule_builder.build_capsule(
            release_manifest_path=ROOT / "docs/receipts/release/s4-release-manifest.json",
            market_input_path=market,
            market_classification="D0_PUBLIC",
            security_input_path=security,
            security_classification="D1_INTERNAL_SANITIZED",
            output=capsule_path,
            observed=self.clock(),
        )
        capsule = deploy._load_capsule(capsule_path, now=self.clock())
        manifest = json.loads(
            (ROOT / "docs/receipts/release/s4-release-manifest.json").read_text()
        )
        manifest["payload"]["config_sha256"] = capsule.config_sha256
        manifest["integrity"]["payload_sha256"] = deploy._payload_sha(manifest["payload"])
        manifest["integrity"]["parent_refs"].append(
            "capsule:sha256:" + capsule.manifest_sha256
        )
        functional_manifest = self.temp / f"functional-manifest-{suffix}.json"
        functional_manifest.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        bundle = deploy._load_bundle(
            manifest_path=functional_manifest,
            policy_path=ROOT / "ops/release/runtime-policy.json",
            config_path=ROOT / "ops/release/researchd.config.template.json",
            unit_path=ROOT / "ops/deploy/research-os-bridge.functional.service",
            archive_path=self.archive,
            archive_sha256=self.archive_sha,
            capsule=capsule,
        )
        return capsule_path, bundle

    def test_public_host_profile_has_no_locator_or_mutation_authority(self) -> None:
        profile = json.loads((ROOT / "ops/deploy/host-profile.json").read_text())
        self.assertEqual(profile["locators"], [])
        self.assertEqual(profile["profile_kind"], "capability-requirements-only")
        self.assertFalse(profile["runtime_boundary"]["rootful_container_engine_allowed"])
        self.assertEqual(profile["runtime_boundary"]["network"], "none")
        self.assertEqual(profile["runtime_boundary"]["published_ports"], [])
        self.assertFalse(profile["operator_boundaries"]["automatic_sudo"])
        self.assertFalse(profile["operator_boundaries"]["automatic_reboot"])
        serialized = json.dumps(profile)
        self.assertNotIn("private_target_alias", serialized)
        self.assertNotRegex(serialized, r"(?:\d{1,3}\.){3}\d{1,3}")

    def test_unit_enforces_every_frozen_runtime_policy_field(self) -> None:
        unit = (ROOT / "ops/deploy/research-os-bridge.service").read_text()
        for required in (
            "DOCKER_HOST=unix://%t/docker.sock",
            "--user=10001:10001",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=256",
            "--memory=2147483648",
            "--cpus=2",
            "--restart=unless-stopped",
            "target=/var/lib/research-os",
            "target=/run/research-os,readonly",
            "RESEARCH_OS_EXTERNAL_ACTION_AUTHORITY=false",
            "RestrictAddressFamilies=AF_UNIX",
            "TasksMax=256",
            "MemoryMax=2147483648",
            "CPUQuota=200%",
        ):
            self.assertIn(required, unit)
        for forbidden in ("--publish", "-p ", "--network=bridge", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, unit)
        create = unit.index("ExecStartPre=-/usr/bin/docker container create")
        stop = unit.index("ExecStartPre=-/usr/bin/docker stop --time=30")
        attach = unit.index("ExecStart=/usr/bin/docker start --attach")
        self.assertLess(create, stop)
        self.assertLess(stop, attach)

    def test_unit_resolves_rootless_restart_policy_boot_race(self) -> None:
        unit = (ROOT / "ops/deploy/research-os-bridge.service").read_text()
        self.assertIn("--restart=unless-stopped", unit)
        self.assertIn("ExecStartPre=-/usr/bin/docker stop --time=30", unit)
        self.assertIn("ExecStart=/usr/bin/docker start --attach", unit)
        runner = FakeRunner(self.bundle)
        runner.container_exists = True
        runner.container_running = True  # rootless Docker auto-started it first
        runner.service_active = False
        runner.service_enabled = True
        controller = self.controller(runner)
        # The installed unit deterministically stops then re-attaches the exact
        # container; post-boot verification rejects any different identity.
        runner.service_active = True
        snapshot, digest = controller._verify_running(self.bundle)
        self.assertEqual(snapshot, {"paused": False})
        self.assertEqual(digest, deploy._payload_sha(snapshot))

    def test_functional_capsule_full_recovery_lifecycle_is_exact_and_receipted(self) -> None:
        capsule_path, bundle = self.functional_bundle("lifecycle")
        runner = FakeRunner(bundle)
        controller = self.controller(runner)
        deployed = controller.deploy(bundle)
        evidence = deployed["payload"]["evidence"]
        self.assertEqual(
            evidence["capsule_manifest_sha256"], bundle.capsule.manifest_sha256
        )
        self.assertEqual(
            evidence["capsule_cas_refs"],
            {item.contour: item.cas_ref for item in bundle.capsule.objects},
        )
        self.assertEqual(deployed["payload"]["capsule_manifest_sha256"], bundle.capsule.manifest_sha256)
        serialized = json.dumps(deployed, sort_keys=True)
        self.assertNotIn(str(capsule_path), serialized)
        object_transfers = [
            argv
            for argv, _ in runner.commands
            if argv[0] == "scp"
            and argv[-1].rsplit("/", 1)[-1]
            in {item.sha256 for item in bundle.capsule.objects}
        ]
        self.assertEqual(len(object_transfers), 2)
        self.assertEqual(
            {item[-1].rsplit("/", 1)[-1] for item in object_transfers},
            {item.sha256 for item in bundle.capsule.objects},
        )
        self.assertEqual(runner.remote_capsule_objects, set())
        command_text = "\n".join(" ".join(argv) for argv, _ in runner.commands)
        self.assertIn("--network=none --read-only --cap-drop=ALL", command_text)
        self.assertIn("--cap-add=CHOWN --cap-add=DAC_OVERRIDE", command_text)
        self.assertEqual(command_text.count("--cap-add=CHOWN"), 1)
        self.assertIn("fsync_dir(path)", command_text)
        self.assertIn("CAPSULE_STAGE_CLEANED", command_text)
        self.assertNotIn("--network=bridge", command_text)
        rendered_units = [body for _, body in runner.commands if body and b"[Unit]" in body]
        self.assertTrue(rendered_units)
        self.assertIn(b"--env=TMPDIR=/var/lib/research-os/tmp", rendered_units[-1])
        self.assertIn(
            b"org.research-os.capsule-manifest-sha256="
            + bundle.capsule.manifest_sha256.encode("ascii"),
            rendered_units[-1],
        )

        boundary = controller.reboot_boundary(bundle)
        runner.boot_id = BOOT_B
        verified = controller.verify_reboot(bundle, boundary)
        self.assertTrue(verified["payload"]["evidence"]["boot_identity_changed"])
        rollback = controller.rollback(bundle)
        redeployed = controller.redeploy(bundle, rollback)
        self.assertTrue(redeployed["payload"]["evidence"]["exact_release_restored"])

        actions = {
            "deploy": ["--archive", str(self.archive), "--archive-sha256", self.archive_sha],
            "reboot-boundary": [],
            "verify-reboot": ["--boundary-receipt", str(self.temp / "boundary.json")],
            "rollback": [],
            "redeploy": ["--rollback-receipt", str(self.temp / "rollback.json")],
        }
        for action, trailing in actions.items():
            parsed = deploy._parser().parse_args(
                [
                    "--ssh-alias", "synthetic_lab", "--known-hosts", str(self.known_hosts),
                    "--capsule", str(capsule_path), "--receipt", str(self.temp / f"{action}.json"),
                    action, *trailing,
                ]
            )
            self.assertEqual(parsed.capsule, capsule_path)

    def test_capsule_rejects_unbound_symlink_and_remote_unexpected_object(self) -> None:
        capsule_path, bundle = self.functional_bundle("negative")
        unexpected = capsule_path / "runtime" / "input-cas" / "objects" / ("f" * 64)
        unexpected.symlink_to(bundle.capsule.objects[0].source_path)
        with self.assertRaisesRegex(deploy.DeploymentError, "symbolic link"):
            deploy._load_capsule(capsule_path)

        _, clean_bundle = self.functional_bundle("remote-negative")
        runner = FakeRunner(clean_bundle)
        runner.unexpected_remote_capsule_object = True
        with self.assertRaisesRegex(deploy.DeploymentError, "remote bounded command"):
            self.controller(runner).deploy(clean_bundle)
        self.assertFalse(runner.container_exists)

        _, race_bundle = self.functional_bundle("remote-symlink")
        race_runner = FakeRunner(race_bundle)
        race_runner.remote_capsule_symlink_race = True
        with self.assertRaisesRegex(deploy.DeploymentError, "remote bounded command"):
            self.controller(race_runner).deploy(race_bundle)
        self.assertFalse(race_runner.container_exists)

    def test_capsule_profile_requires_manifest_parent_and_functional_tmpdir(self) -> None:
        _, bundle = self.functional_bundle("binding")
        capsule = bundle.capsule
        self.assertIsNotNone(capsule)
        manifest_path = self.temp / "unbound-functional.json"
        manifest = json.loads(
            (ROOT / "docs/receipts/release/s4-release-manifest.json").read_text()
        )
        manifest["payload"]["config_sha256"] = capsule.config_sha256
        manifest["integrity"]["payload_sha256"] = deploy._payload_sha(manifest["payload"])
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        with self.assertRaisesRegex(deploy.DeploymentError, "bind the sealed capsule"):
            deploy._load_bundle(
                manifest_path=manifest_path,
                policy_path=ROOT / "ops/release/runtime-policy.json",
                config_path=capsule.config_path,
                unit_path=ROOT / "ops/deploy/research-os-bridge.functional.service",
                capsule=capsule,
            )
        bound = json.loads(manifest_path.read_text())
        bound["integrity"]["parent_refs"].append(
            "capsule:sha256:" + capsule.manifest_sha256
        )
        manifest_path.write_text(json.dumps(bound, sort_keys=True) + "\n")
        with self.assertRaisesRegex(deploy.DeploymentError, "tokens"):
            deploy._load_bundle(
                manifest_path=manifest_path,
                policy_path=ROOT / "ops/release/runtime-policy.json",
                config_path=capsule.config_path,
                unit_path=ROOT / "ops/deploy/research-os-bridge.service",
                capsule=capsule,
            )

    def test_capsule_init_script_executes_fresh_and_exact_same_volume_retry(self) -> None:
        _, bundle = self.functional_bundle("init-exec")
        capsule = bundle.capsule
        source_cas = self.temp / "exec-source-cas"
        source_config = self.temp / "exec-source-config" / "researchd.json"
        target_runtime = self.temp / "exec-target-runtime"
        target_config = self.temp / "exec-target-config"
        source_cas.mkdir()
        source_config.parent.mkdir()
        source_config.write_bytes(capsule.config_path.read_bytes())
        for item in capsule.objects:
            (source_cas / item.sha256).write_bytes(item.source_path.read_bytes())
        script = deploy.PreSoakDeployController._capsule_volume_init_script(capsule)
        script = script.replace(
            "UID = GID = 10001", f"UID = {os.geteuid()}; GID = {os.getegid()}"
        )
        for frozen, local in (
            ("/target-runtime", target_runtime),
            ("/target-config", target_config),
            ("/source-cas", source_cas),
            ("/source-config/researchd.json", source_config),
        ):
            script = script.replace(frozen, str(local))
        for _ in range(2):
            exec(compile(script, "capsule-volume-init-smoke", "exec"), {})
        self.assertEqual(target_runtime.stat().st_mode & 0o777, 0o700)
        self.assertEqual((target_runtime / "tmp").stat().st_mode & 0o777, 0o700)
        for item in capsule.objects:
            target = target_runtime / "input-cas" / "objects" / item.sha256
            self.assertEqual(target.stat().st_mode & 0o777, 0o444)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), item.sha256)

    def test_capsule_rejects_resealed_quota_escalation_and_duplicate_json(self) -> None:
        capsule_path, _ = self.functional_bundle("semantic-mutation")
        config_path = capsule_path / capsule_builder.CONFIG_NAME
        manifest_path = capsule_path / capsule_builder.MANIFEST_NAME
        config = json.loads(config_path.read_text())
        config["input_quota_bytes"] = 1024**4
        config_bytes = (
            json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode()
        config_path.write_bytes(config_bytes)
        os.chmod(config_path, 0o600)
        manifest = json.loads(manifest_path.read_text())
        config_sha = hashlib.sha256(config_bytes).hexdigest()
        manifest["payload"]["runtime_config_sha256"] = config_sha
        for record in manifest["payload"]["file_hashes"]:
            if record["relative_path"] == capsule_builder.CONFIG_NAME:
                record["sha256"] = config_sha
                record["size_bytes"] = len(config_bytes)
        payload_sha = deploy._payload_sha(manifest["payload"])
        manifest["object_id"] = "pre-soak-capsule-" + payload_sha
        manifest["integrity"]["payload_sha256"] = payload_sha
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        )
        os.chmod(manifest_path, 0o600)
        with self.assertRaisesRegex(deploy.DeploymentError, "config boundary"):
            deploy._load_capsule(capsule_path, now=self.clock())

        duplicate_path, _ = self.functional_bundle("duplicate-json")
        duplicate_manifest = duplicate_path / capsule_builder.MANIFEST_NAME
        raw = duplicate_manifest.read_text()
        duplicate_manifest.write_text(
            raw.replace('"classification":', '"classification":"D0_PUBLIC","classification":', 1)
        )
        with self.assertRaisesRegex(deploy.DeploymentError, "duplicate key"):
            deploy._load_capsule(duplicate_path, now=self.clock())

    def test_omitting_capsule_cannot_downgrade_functional_lifecycle(self) -> None:
        capsule_path, bundle = self.functional_bundle("downgrade")
        manifest_path = self.temp / "functional-manifest-downgrade.json"
        with self.assertRaisesRegex(deploy.DeploymentError, "exact frozen profile"):
            deploy._load_bundle(
                manifest_path=manifest_path,
                policy_path=ROOT / "ops/release/runtime-policy.json",
                config_path=bundle.capsule.config_path,
                unit_path=ROOT / "ops/deploy/research-os-bridge.service",
                capsule=None,
            )
        runner = FakeRunner(bundle)
        exit_code = deploy.run(
            [
                "--ssh-alias", "synthetic_lab", "--known-hosts", str(self.known_hosts),
                "--manifest", str(manifest_path), "--config", str(bundle.capsule.config_path),
                "--unit", str(ROOT / "ops/deploy/research-os-bridge.functional.service"),
                "--receipt", str(self.temp / "downgrade-receipt.json"), "reboot-boundary",
            ],
            runner=runner,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        self.assertEqual(exit_code, 2)
        self.assertEqual(runner.commands, [])

        legacy_runner = FakeRunner(self.bundle)
        legacy_runner.container_exists = True
        legacy_runner.inject_tmpdir = True
        with self.assertRaisesRegex(deploy.DeploymentError, "runtime policy"):
            self.controller(legacy_runner)._container_inspect(
                self.bundle, require_running=False
            )

    def test_preexisting_container_rejects_privilege_and_mount_supersets(self) -> None:
        _, bundle = self.functional_bundle("unsafe-container")
        mutations = (
            ("container_entrypoint", ["/bin/sh"]),
            ("container_cmd", ["-c", "echo unsafe > /var/lib/research-os/tamper"]),
            ("extra_environment", ["PYTHONPATH=/var/lib/research-os"]),
            ("extra_environment", ["RESEARCH_OS_ENVIRONMENT=pre-soak"]),
            ("container_healthcheck", {"Test": ["CMD-SHELL", "echo unsafe > /var/lib/research-os/tamper"]}),
            ("container_cap_add", ["SYS_ADMIN"]),
            ("container_privileged", True),
            ("container_devices", [{"PathOnHost": "/dev/null"}]),
            ("container_binds", ["/tmp:/unsafe:rw"]),
            ("extra_mount", True),
            ("omit_capsule_label", True),
        )
        for attribute, value in mutations:
            with self.subTest(attribute=attribute, value=value):
                runner = FakeRunner(bundle)
                runner.container_exists = True
                setattr(runner, attribute, value)
                with self.assertRaisesRegex(deploy.DeploymentError, "runtime policy|mount"):
                    self.controller(runner)._container_inspect(
                        bundle, require_running=False
                    )

    def test_local_archive_tamper_stops_before_any_external_action(self) -> None:
        with self.assertRaisesRegex(deploy.DeploymentError, "local release archive"):
            deploy._load_bundle(
                manifest_path=ROOT / "docs/receipts/release/s4-release-manifest.json",
                policy_path=ROOT / "ops/release/runtime-policy.json",
                config_path=self.historical_config,
                unit_path=ROOT / "ops/deploy/research-os-bridge.service",
                archive_path=self.archive,
                archive_sha256="0" * 64,
            )

    def test_rootless_preflight_and_remote_archive_hash_fail_closed(self) -> None:
        runner = FakeRunner(self.bundle)
        runner.rootless = False
        with self.assertRaisesRegex(deploy.DeploymentError, "not the required rootless"):
            self.controller(runner).preflight()
        runner = FakeRunner(self.bundle)
        runner.tamper_archive = True
        with self.assertRaisesRegex(deploy.DeploymentError, "remote release archive"):
            self.controller(runner).deploy(self.bundle)
        remote_commands = [argv[-1] for argv, _ in runner.commands if argv[0] == "ssh"]
        self.assertFalse(any("docker load" in command for command in remote_commands))

    def test_preflight_requires_lingering_before_ssh_can_start_user_manager(self) -> None:
        runner = FakeRunner(self.bundle)
        runner.linger = False
        with self.assertRaisesRegex(deploy.DeploymentError, "remote bounded command"):
            self.controller(runner).preflight()
        probe = next(
            argv[-1]
            for argv, _ in runner.commands
            if argv[0] == "ssh" and "loginctl show-user" in argv[-1]
        )
        self.assertIn("-p Linger --value", probe)
        self.assertIn("systemctl --user is-enabled --quiet docker.service", probe)

    def test_exact_deploy_is_rootless_offline_receipted_and_not_ready(self) -> None:
        runner = FakeRunner(self.bundle)
        receipt = self.controller(runner).deploy(self.bundle)
        payload = receipt["payload"]
        evidence = payload["evidence"]
        self.assertEqual(payload["action"], "deploy")
        self.assertEqual(payload["release_sha"], deploy.RELEASE_SHA)
        self.assertTrue(evidence["runtime_policy_enforced"])
        self.assertFalse(evidence["declares_ready_for_72h_soak"])
        self.assertEqual(evidence["rollback_target"], "release:none-service-stopped")
        self.assertTrue(runner.container_running)
        self.assertEqual(
            receipt["integrity"]["payload_sha256"], deploy._payload_sha(payload)
        )
        command_text = "\n".join(" ".join(argv) for argv, _ in runner.commands)
        self.assertNotIn("sudo", command_text)
        self.assertNotIn("/var/run/docker.sock", command_text)
        self.assertNotIn("--network=bridge", command_text)
        self.assertNotIn("--publish", command_text)
        self.assertIn("unix:///run/user/$(id -u)/docker.sock", command_text)

    def test_failed_activation_automatically_restores_stopped_boundary(self) -> None:
        runner = FakeRunner(self.bundle)
        runner.fail_activation = True
        with self.assertRaisesRegex(deploy.DeploymentError, "remote bounded command"):
            self.controller(runner).deploy(self.bundle)
        self.assertFalse(runner.service_active)
        self.assertFalse(runner.service_enabled)
        commands = [argv[-1] for argv, _ in runner.commands if argv[0] == "ssh"]
        self.assertTrue(any("disable --now research-os-bridge.service" in item for item in commands))
        self.assertTrue(any("activation-failed" in item for item in commands))

    def test_cli_reserves_and_finalizes_failed_action_receipt(self) -> None:
        runner = FakeRunner(self.bundle)
        runner.fail_activation = True
        receipt_path = self.temp / "failed-deploy.json"
        stderr = io.StringIO()
        exit_code = deploy.run(
            [
                "--ssh-alias",
                "synthetic_lab",
                "--known-hosts",
                str(self.known_hosts),
                "--receipt",
                str(receipt_path),
                "--config",
                str(self.historical_config),
                "deploy",
                "--archive",
                str(self.archive),
                "--archive-sha256",
                self.archive_sha,
            ],
            runner=runner,
            stdout=io.StringIO(),
            stderr=stderr,
        )
        self.assertEqual(exit_code, 2)
        failed = json.loads(receipt_path.read_text())
        self.assertEqual(failed["payload"]["status"], "FAIL")
        self.assertFalse(
            failed["payload"]["evidence"]["declares_ready_for_72h_soak"]
        )
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)

    def test_reboot_boundary_never_executes_reboot_and_proves_boot_change(self) -> None:
        runner = FakeRunner(self.bundle)
        controller = self.controller(runner)
        controller.deploy(self.bundle)
        boundary = controller.reboot_boundary(self.bundle)
        self.assertFalse(boundary["payload"]["evidence"]["automatic_reboot_executed"])
        before_count = len(runner.commands)
        runner.boot_id = BOOT_B
        verified = controller.verify_reboot(self.bundle, boundary)
        self.assertTrue(verified["payload"]["evidence"]["boot_identity_changed"])
        external = "\n".join(" ".join(argv) for argv, _ in runner.commands[:before_count])
        self.assertNotRegex(external, r"(?:systemctl|shutdown)\s+(?:--user\s+)?reboot")
        runner.boot_id = BOOT_A
        with self.assertRaisesRegex(deploy.DeploymentError, "has not changed"):
            controller.verify_reboot(self.bundle, boundary)

    def test_executed_rollback_and_exact_redeploy_preserve_pause_state(self) -> None:
        runner = FakeRunner(self.bundle)
        runner.pause_state = {
            "paused": True,
            "event_type": "pause",
            "sequence": 7,
            "event_sha256": "a" * 64,
        }
        controller = self.controller(runner)
        controller.deploy(self.bundle)
        rollback = controller.rollback(self.bundle)
        self.assertEqual(
            rollback["payload"]["evidence"]["service_state"],
            "none-service-stopped",
        )
        self.assertFalse(runner.container_running)
        redeployed = controller.redeploy(self.bundle, rollback)
        self.assertTrue(redeployed["payload"]["evidence"]["exact_release_restored"])
        self.assertTrue(runner.container_running)
        self.assertEqual(
            redeployed["payload"]["evidence"]["pause_state_sha256"],
            rollback["payload"]["evidence"]["pause_state_sha256"],
        )
        tampered = copy.deepcopy(rollback)
        tampered["payload"]["evidence"]["service_state"] = "active"
        before = len(runner.commands)
        with self.assertRaisesRegex(deploy.DeploymentError, "payload integrity"):
            controller.redeploy(self.bundle, tampered)
        self.assertEqual(len(runner.commands), before)


if __name__ == "__main__":
    unittest.main()
