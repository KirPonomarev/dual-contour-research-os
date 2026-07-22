from __future__ import annotations

import copy
import importlib.util
import json
import shutil
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = ROOT / "ops/release/image_e2e_harness.py"
SPEC = importlib.util.spec_from_file_location("r08a_image_e2e_harness", HARNESS_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("R08A harness cannot be imported")
harness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = harness
SPEC.loader.exec_module(harness)

IMAGE_ID = "sha256:" + "a" * 64
RELEASE_SHA = "b" * 40


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[list[str], bytes | None]] = []
        self.responses: dict[str, dict[str, object]] = {}
        self.container_id = "c" * 64
        self.image_architecture = "amd64"
        self.running_image = IMAGE_ID

    def run(
        self,
        arguments,
        *,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
    ):
        del timeout
        argv = list(arguments)
        self.commands.append((argv, input_bytes))
        if argv[:3] == ["docker", "image", "inspect"]:
            return harness.CommandResult(0, json.dumps([{
                "Id": IMAGE_ID,
                "Os": "linux",
                "Architecture": self.image_architecture,
                "Config": {
                    "User": "10001:10001",
                    "Entrypoint": ["python", "-m", "research_bridge.researchd"],
                    "Cmd": ["--config", "/run/research-os/researchd.json"],
                    "Labels": {"org.opencontainers.image.revision": RELEASE_SHA},
                },
            }]))
        if argv[:3] == ["docker", "container", "inspect"]:
            return harness.CommandResult(0, json.dumps([{
                "Id": self.container_id,
                "Config": {"Image": self.running_image, "User": "10001:10001"},
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "PortBindings": {},
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"],
                    "RestartPolicy": {"Name": "no"},
                },
                "State": {"Running": True},
            }]))
        if any(item.startswith("--name=research-os-r08a-contender-") for item in argv):
            return harness.CommandResult(3, "", "researchd runtime failed\n")
        if "--entrypoint=python" in argv:
            if input_bytes is None:
                return harness.CommandResult(4)
            request = json.loads(input_bytes)
            uid_arg = next(item for item in argv if item.startswith("--user="))
            uid = int(uid_arg.removeprefix("--user=").split(":", 1)[0])
            command = request["command"]
            allowed = {
                10001: {"status"},
                10002: {"submit_source_trigger"},
                10003: {"claim_next_proposal"},
            }
            if command not in allowed[uid]:
                return harness.CommandResult(0, "")
            key = request["idempotency_key"]
            if key not in self.responses:
                if command == "status":
                    result: dict[str, object] = {"paused": False}
                else:
                    result = {
                        "decision": "MATERIAL",
                        "reason_code": "novel-bounded-source",
                        "model_calls_consumed": 0,
                        "material_event": {
                            "object_id": "material-event:" + "d" * 64,
                            "payload": copy.deepcopy(
                                request["payload"]["source_trigger"]
                            ),
                        },
                    }
                self.responses[key] = {
                    "version": request["version"],
                    "request_id": request["request_id"],
                    "ok": True,
                    "command": command,
                    "result": result,
                }
            return harness.CommandResult(
                0, json.dumps(self.responses[key], sort_keys=True) + "\n"
            )
        return harness.CommandResult(0, "ok\n")


class ProductionImageE2EHarnessTests(unittest.TestCase):
    def subject(self) -> harness.ImageSubject:
        return harness.ImageSubject(IMAGE_ID, RELEASE_SHA)

    def test_frozen_input_graph_is_minimal_rootless_and_non_authoritative(self) -> None:
        hashes = harness.verify_frozen_inputs(ROOT)
        self.assertEqual(len(hashes), 10)
        self.assertIn("ops/release/Containerfile", hashes)
        container = (ROOT / "ops/release/Containerfile").read_text()
        self.assertNotIn("image_e2e_harness", container)
        self.assertNotIn("COPY .", container)
        required_provenance = {
            "model-role-evaluation-v2.json",
            "model-worker-ipc-extension-v1.json",
            "model-provider-routing-v1.json",
            "model-provider-routing-v2.json",
            "model-accounting-mode-v1.json",
            "model-null-content-vacuous-reconciliation-v1.json",
            "model-chief-null-content-vacuous-reconciliation-v1.json",
        }
        for name in required_provenance:
            self.assertIn(
                "COPY --chown=10001:10001 "
                f"provenance/{name} /opt/research-os/provenance/{name}",
                container,
            )
        self.assertEqual(
            container.count("COPY --chown=10001:10001 provenance/"), 9
        )
        self.assertIn(
            "provenance/model-worker-ipc-extension-v1.json",
            container,
        )
        self.assertIn(
            "provenance/model-worker-ipc-extension-v2.json",
            container,
        )
        dockerignore = (ROOT / ".dockerignore").read_text()
        for name in required_provenance:
            self.assertIn(f"!provenance/{name}", dockerignore)
        self.assertNotIn("!provenance/**", dockerignore)
        policy = json.loads(
            (ROOT / "ops/release/final-a1-runtime-policy.json").read_text()
        )
        self.assertEqual(policy["platform"], "linux/amd64")
        self.assertEqual(policy["network"], "none")
        self.assertFalse(policy["external_action_authority"])

    def test_matrix_uses_real_socket_clients_roles_single_writer_and_restart(self) -> None:
        runner = FakeRunner()
        instance = harness.ImageE2EHarness(
            self.subject(), root=ROOT, runner=runner, token="0123456789ab"
        )
        result = instance.run_matrix()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["af_unix_status"])
        self.assertTrue(result["source_materialized"])
        self.assertTrue(result["role_mismatch_rejected"])
        self.assertTrue(result["second_writer_rejected"])
        self.assertTrue(result["same_container_restart"])
        self.assertEqual(result["network"], "none")
        self.assertFalse(result["external_action_authority"])
        self.assertFalse(result["grants_authority"])

        commands = [argv for argv, _ in runner.commands]
        joined = "\n".join(" ".join(argv) for argv in commands)
        self.assertIn("--platform=linux/amd64", joined)
        self.assertIn("--network=none", joined)
        self.assertNotIn("--publish", joined)
        self.assertNotIn("docker.sock,target=", joined)
        self.assertIn("--user=10001:10001", joined)
        self.assertIn("--user=10002:10001", joined)
        self.assertIn("--user=10003:10001", joined)
        self.assertIn("chmod 0710 /var/lib/research-os", joined)
        self.assertIn("/var/lib/research-os/.runtime-initialized", joined)
        self.assertIn("socket.AF_UNIX", joined)
        self.assertIn("docker stop --time=10", joined)
        self.assertTrue(any("contender" in " ".join(argv) for argv in commands))
        client_frames = [body for argv, body in runner.commands if "--entrypoint=python" in argv]
        self.assertTrue(client_frames)
        self.assertTrue(all(frame and frame.endswith(b"\n") for frame in client_frames))
        source_frames = [
            json.loads(frame)
            for frame in client_frames
            if frame and b'"command":"submit_source_trigger"' in frame
        ]
        self.assertTrue(source_frames)
        self.assertTrue(
            source_frames[0]["payload"]["source_trigger"]["evidence_refs"]
        )

    def copied_root(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        shutil.copytree(ROOT / "ops", root / "ops")
        shutil.copy2(ROOT / ".dockerignore", root / ".dockerignore")
        return temporary, root

    def test_empty_policy_role_network_and_supervisor_drift_fail_closed(self) -> None:
        mutations = {
            "empty-policy": lambda root: self._mutate_json(
                root / "ops/release/researchd.config.template.json",
                lambda value: value.__setitem__("policy_snapshots", {}),
            ),
            "role-map": lambda root: self._mutate_json(
                root / "ops/release/researchd.config.template.json",
                lambda value: value["principal_roles"].__setitem__("10003", "collector"),
            ),
            "network": lambda root: self._mutate_json(
                root / "ops/release/final-a1-runtime-policy.json",
                lambda value: value.__setitem__("network", "bridge"),
            ),
            "supervisor": lambda root: (
                root / "ops/deploy/research-os-a1-final.service"
            ).write_text(
                (root / "ops/deploy/research-os-a1-final.service")
                .read_text()
                .replace("--restart=no", "--restart=always"),
                encoding="utf-8",
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                temporary, root = self.copied_root()
                with temporary:
                    mutate(root)
                    with self.assertRaises(harness.HarnessError):
                        harness.verify_frozen_inputs(root)

    @staticmethod
    def _mutate_json(path: Path, mutate) -> None:
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_image_and_running_container_identity_drift_fail_closed(self) -> None:
        wrong_arch = FakeRunner()
        wrong_arch.image_architecture = "arm64"
        with self.assertRaises(harness.HarnessError):
            harness.ImageE2EHarness(
                self.subject(), root=ROOT, runner=wrong_arch, token="0123456789ab"
            ).preflight()

        wrong_image = FakeRunner()
        wrong_image.running_image = "sha256:" + "f" * 64
        instance = harness.ImageE2EHarness(
            self.subject(), root=ROOT, runner=wrong_image, token="0123456789ab"
        )
        with self.assertRaises(harness.HarnessError):
            instance.start()
        instance.cleanup()

    def test_subject_and_request_bounds_reject_ambiguous_values(self) -> None:
        with self.assertRaises(harness.HarnessError):
            harness.ImageSubject("python:latest", RELEASE_SHA)
        with self.assertRaises(harness.HarnessError):
            harness.ImageSubject(IMAGE_ID, "main")
        instance = harness.ImageE2EHarness(
            self.subject(), root=ROOT, runner=FakeRunner(), token="0123456789ab"
        )
        with self.assertRaises(harness.HarnessError):
            instance.request(
                uid=0,
                request={"version": "1.1", "request_id": "r", "idempotency_key": "k", "command": "status", "payload": {}},
            )


if __name__ == "__main__":
    unittest.main()
