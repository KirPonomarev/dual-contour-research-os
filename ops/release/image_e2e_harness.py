#!/usr/bin/env python3
"""External exact-image harness for the production AF_UNIX boundary.

The harness never enters the production image and never supplies a Python
backend to researchd.  It starts the pinned image with the same immutable
inputs and container boundary as the final unit, then sends canonical protocol
frames from short-lived, network-disabled clients running as the frozen UIDs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
from typing import Any, Mapping, Protocol, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "ops/release/researchd.config.template.json"
POLICY = ROOT / "ops/release/final-a1-runtime-policy.json"
CONTAINERFILE = ROOT / "ops/release/Containerfile"
CORE_UNIT = ROOT / "ops/deploy/research-os-a1-final.service"
CONNECTED_UNIT = ROOT / "ops/deploy/research-os-connected-worker@.service"
CONNECTED_CONTAINERFILE = ROOT / "ops/connected-worker/Containerfile"
CONNECTED_INPUTS = ROOT / "ops/connected-worker/runbook-inputs.json"

_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
_GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
_TOKEN = re.compile(r"^[a-f0-9]{12}$")
_MAX_OUTPUT = 1_048_576
_SOCKET = "/var/lib/research-os/researchd.sock"

_CLIENT = r'''import json,socket,sys
frame=sys.stdin.buffer.read(65537)
if not frame or len(frame)>65536 or not frame.endswith(b"\n"):
    raise SystemExit(4)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.settimeout(5.0)
s.connect("/var/lib/research-os/researchd.sock")
s.sendall(frame)
data=bytearray()
while True:
    block=s.recv(16384)
    if not block:
        break
    data.extend(block)
    if len(data)>262144:
        raise SystemExit(5)
s.close()
sys.stdout.buffer.write(data)
'''


class HarnessError(RuntimeError):
    """The exact-image boundary or an executed check was not satisfied."""


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
            raise HarnessError("bounded container command failed") from exc
        if len(completed.stdout) > _MAX_OUTPUT or len(completed.stderr) > _MAX_OUTPUT:
            raise HarnessError("container command output exceeded its bound")
        try:
            return CommandResult(
                completed.returncode,
                completed.stdout.decode("utf-8", errors="strict"),
                completed.stderr.decode("utf-8", errors="strict"),
            )
        except UnicodeDecodeError as exc:
            raise HarnessError("container command output was not UTF-8") from exc


@dataclass(frozen=True)
class ImageSubject:
    image_id: str
    release_sha: str
    platform: str = "linux/amd64"

    def __post_init__(self) -> None:
        if _IMAGE_ID.fullmatch(self.image_id) is None:
            raise HarnessError("image subject must be an immutable sha256 ID")
        if _GIT_SHA.fullmatch(self.release_sha) is None:
            raise HarnessError("release subject must be an exact Git SHA")
        if self.platform != "linux/amd64":
            raise HarnessError("image subject platform is not frozen linux/amd64")


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise HarnessError("frozen harness input is not a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HarnessError("frozen harness input is not strict JSON") from exc
    if not isinstance(value, dict):
        raise HarnessError("frozen harness input must be an object")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_frozen_inputs(root: Path = ROOT) -> dict[str, str]:
    """Verify the complete public image/topology input set without mutation."""

    config_path = root / "ops/release/researchd.config.template.json"
    policy_path = root / "ops/release/final-a1-runtime-policy.json"
    container_path = root / "ops/release/Containerfile"
    core_unit_path = root / "ops/deploy/research-os-a1-final.service"
    connected_unit_path = root / "ops/deploy/research-os-connected-worker@.service"
    connected_container_path = root / "ops/connected-worker/Containerfile"
    connected_inputs_path = root / "ops/connected-worker/runbook-inputs.json"
    dockerignore_path = root / ".dockerignore"
    paths = (
        config_path,
        policy_path,
        container_path,
        core_unit_path,
        connected_unit_path,
        connected_container_path,
        connected_inputs_path,
        dockerignore_path,
    )
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise HarnessError("production image input set is incomplete")

    config = _load(config_path)
    policy = _load(policy_path)
    connected = _load(connected_inputs_path)
    if (
        config.get("schema_id") != "ResearchdServiceConfig"
        or config.get("schema_version") != "1.1.0"
        or config.get("runtime_root") != "/var/lib/research-os"
        or config.get("allowed_uids") != [10001, 10002, 10003]
        or config.get("principal_roles")
        != {"10001": "operator", "10002": "collector", "10003": "scout"}
        or config.get("approval_receipts") != {}
        or config.get("a1_enabled") is not True
        or not isinstance(config.get("policy_snapshots"), dict)
        or len(config["policy_snapshots"]) != 1
    ):
        raise HarnessError("production service configuration drifted")
    bindings = config.get("frozen_bindings")
    if not isinstance(bindings, dict):
        raise HarnessError("production service bindings are missing")
    policy_sha = bindings.get("policy_sha256")
    if not isinstance(policy_sha, str) or set(config["policy_snapshots"]) != {policy_sha}:
        raise HarnessError("production policy binding is empty or mixed")
    if (
        policy.get("platform") != "linux/amd64"
        or policy.get("user") != "10001:10001"
        or policy.get("network") != "none"
        or policy.get("published_ports") != []
        or policy.get("read_only_root_filesystem") is not True
        or policy.get("cap_drop") != ["ALL"]
        or policy.get("security_options") != ["no-new-privileges:true"]
        or policy.get("restart_policy") != "no"
        or policy.get("control_transport") != "AF_UNIX"
        or policy.get("external_action_authority") is not False
    ):
        raise HarnessError("production runtime policy drifted")

    container = container_path.read_text(encoding="utf-8")
    if any(
        required not in container
        for required in (
            "FROM python@sha256:",
            "COPY --chown=10001:10001 src/ /opt/research-os/src/",
            "COPY --chown=10001:10001 contracts/catalog.json /opt/research-os/contracts/catalog.json",
            "COPY --chown=10001:10001 contracts/a1/v1/ /opt/research-os/contracts/a1/v1/",
            "USER 10001:10001",
            'ENTRYPOINT ["python", "-m", "research_bridge.researchd"]',
            'CMD ["--config", "/run/research-os/researchd.json"]',
        )
    ) or "image_e2e_harness" in container:
        raise HarnessError("production image content boundary drifted")
    dockerignore = dockerignore_path.read_text(encoding="utf-8").splitlines()
    if dockerignore[:2] != ["**", "!src/"] or "!src/**" not in dockerignore:
        raise HarnessError("production build context is not deny-first")

    core_unit = core_unit_path.read_text(encoding="utf-8")
    connected_unit = connected_unit_path.read_text(encoding="utf-8")
    connected_container = connected_container_path.read_text(encoding="utf-8")
    core_required = (
        "--user=10001:10001",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--restart=no",
        "RestrictAddressFamilies=AF_UNIX",
        "Restart=on-failure",
    )
    if any(item not in core_unit for item in core_required):
        raise HarnessError("production core unit drifted")
    if core_unit.count("--restart=no") != 1 or "--publish" in core_unit:
        raise HarnessError("production core supervisor or network boundary drifted")
    connected_required = (
        "--user=10004:10001",
        "--network=research-os-provider-egress",
        "research-os-a1-runtime,target=/var/lib/research-os,readonly",
        "--restart=no",
        "Restart=no",
        "RestrictAddressFamilies=AF_UNIX",
    )
    if any(item not in connected_unit for item in connected_required):
        raise HarnessError("connected-worker topology drifted")
    if "docker.sock,target=" in connected_unit or "JobLedger" in connected_container:
        raise HarnessError("connected worker crossed the single-writer boundary")
    composition = connected.get("researchd_runtime_composition")
    if (
        not isinstance(composition, dict)
        or composition.get("add_allowed_uid") != 10004
        or composition.get("add_principal_role") != {"10004": "connected_worker"}
        or composition.get("rendered_config_in_Git") is not False
    ):
        raise HarnessError("connected-worker principal composition drifted")

    return {path.relative_to(root).as_posix(): _sha(path) for path in paths}


class ImageE2EHarness:
    def __init__(
        self,
        subject: ImageSubject,
        *,
        root: Path = ROOT,
        runner: Runner | None = None,
        token: str | None = None,
    ) -> None:
        self.subject = subject
        self.root = root.resolve()
        self.runner = runner or SubprocessRunner()
        self.token = token or secrets.token_hex(6)
        if _TOKEN.fullmatch(self.token) is None:
            raise HarnessError("harness token is invalid")
        self.core = f"research-os-r08a-{self.token}"
        self.contender = f"research-os-r08a-contender-{self.token}"
        self.runtime_volume = f"research-os-r08a-runtime-{self.token}"
        self.config_volume = f"research-os-r08a-config-{self.token}"
        self._started = False

    def _run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
        check: bool = True,
    ) -> CommandResult:
        result = self.runner.run(
            list(arguments), input_bytes=input_bytes, timeout=timeout
        )
        if check and result.returncode != 0:
            raise HarnessError("exact-image harness command failed")
        return result

    @staticmethod
    def _json_output(result: CommandResult, label: str) -> dict[str, Any]:
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise HarnessError(f"{label} was not JSON") from exc
        if not isinstance(value, dict):
            raise HarnessError(f"{label} was not an object")
        return value

    def preflight(self) -> dict[str, str]:
        hashes = verify_frozen_inputs(self.root)
        result = self._run(
            ["docker", "image", "inspect", self.subject.image_id]
        )
        try:
            decoded = json.loads(result.stdout)
            image = decoded[0]
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
            raise HarnessError("image inspection was invalid") from exc
        config = image.get("Config") if isinstance(image, dict) else None
        labels = config.get("Labels") if isinstance(config, dict) else None
        if (
            image.get("Id") != self.subject.image_id
            or image.get("Os") != "linux"
            or image.get("Architecture") != "amd64"
            or not isinstance(config, dict)
            or config.get("User") != "10001:10001"
            or config.get("Entrypoint") != ["python", "-m", "research_bridge.researchd"]
            or config.get("Cmd") != ["--config", "/run/research-os/researchd.json"]
            or not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.revision") != self.subject.release_sha
        ):
            raise HarnessError("image identity or entrypoint drifted")
        return hashes

    def start(self) -> None:
        self.preflight()
        for volume in (self.runtime_volume, self.config_volume):
            self._run(["docker", "volume", "create", volume])
        config_bytes = (
            self.root / "ops/release/researchd.config.template.json"
        ).read_bytes()
        self._run(
            [
                "docker", "run", "--rm", "-i", "--platform=linux/amd64",
                "--network=none", "--entrypoint=/bin/sh", "--user=0:0",
                f"--mount=type=volume,source={self.runtime_volume},target=/var/lib/research-os",
                f"--mount=type=volume,source={self.config_volume},target=/run/research-os",
                self.subject.image_id, "-eu", "-c",
                "chown 10001:10001 /var/lib/research-os /run/research-os; "
                "chmod 0710 /var/lib/research-os; chmod 0700 /run/research-os; "
                "umask 077; cat > /run/research-os/researchd.json; "
                "chown 10001:10001 /run/research-os/researchd.json; "
                "chmod 0600 /run/research-os/researchd.json",
            ],
            input_bytes=config_bytes,
        )
        self._run(
            [
                "docker", "container", "create", f"--name={self.core}",
                "--platform=linux/amd64", "--user=10001:10001", "--group-add=10001",
                "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=256",
                "--memory=2147483648", "--cpus=2", "--restart=no",
                "--env=RESEARCH_OS_ENVIRONMENT=pre-soak",
                "--env=RESEARCH_OS_EXTERNAL_ACTION_AUTHORITY=false",
                f"--label=org.research-os.release-sha={self.subject.release_sha}",
                f"--mount=type=volume,source={self.runtime_volume},target=/var/lib/research-os",
                f"--mount=type=volume,source={self.config_volume},target=/run/research-os,readonly",
                self.subject.image_id,
            ]
        )
        self._run(["docker", "start", self.core])
        self._run(
            [
                "docker", "exec", "--user=10001:10001", self.core, "python", "-c",
                "import os,stat,time; p='/var/lib/research-os/researchd.sock'; "
                "end=time.monotonic()+10; "
                "exec(\"while not os.path.exists(p) and time.monotonic()<end: time.sleep(.05)\"); "
                "s=os.stat(p); assert stat.S_ISSOCK(s.st_mode) and stat.S_IMODE(s.st_mode)==0o660",
            ],
            timeout=15.0,
        )
        self._started = True
        self._verify_container()

    def _inspect_container(self) -> dict[str, Any]:
        result = self._run(["docker", "container", "inspect", self.core])
        try:
            decoded = json.loads(result.stdout)
            value = decoded[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise HarnessError("container inspection was invalid") from exc
        if not isinstance(value, dict):
            raise HarnessError("container inspection was not an object")
        return value

    def _verify_container(self) -> str:
        value = self._inspect_container()
        config = value.get("Config")
        host = value.get("HostConfig")
        state = value.get("State")
        if not all(isinstance(item, dict) for item in (config, host, state)):
            raise HarnessError("container identity is incomplete")
        restart = host.get("RestartPolicy")
        security = host.get("SecurityOpt")
        if (
            config.get("Image") != self.subject.image_id
            or config.get("User") != "10001:10001"
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("PortBindings") not in (None, {})
            or host.get("CapDrop") != ["ALL"]
            or security != ["no-new-privileges:true"]
            or not isinstance(restart, dict)
            or restart.get("Name") != "no"
            or state.get("Running") is not True
        ):
            raise HarnessError("running container drifted from the frozen boundary")
        identity = value.get("Id")
        if not isinstance(identity, str) or not identity:
            raise HarnessError("running container identity is missing")
        return identity

    def request(
        self,
        *,
        uid: int,
        request: Mapping[str, object],
        expect_success: bool = True,
    ) -> dict[str, Any] | None:
        if not self._started:
            raise HarnessError("image harness is not started")
        if uid not in {10001, 10002, 10003}:
            raise HarnessError("request UID is outside the frozen role map")
        try:
            frame = json.dumps(
                dict(request), sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("ascii") + b"\n"
        except (TypeError, ValueError, UnicodeError) as exc:
            raise HarnessError("request is not canonical JSON data") from exc
        if len(frame) > 65_536:
            raise HarnessError("request exceeds the frozen IPC bound")
        result = self._run(
            [
                "docker", "run", "--rm", "-i", "--platform=linux/amd64",
                f"--user={uid}:10001", "--network=none", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                f"--mount=type=volume,source={self.runtime_volume},target=/var/lib/research-os,readonly",
                "--entrypoint=python", self.subject.image_id, "-c", _CLIENT,
            ],
            input_bytes=frame,
            timeout=15.0,
        )
        if not result.stdout:
            if expect_success:
                raise HarnessError("AF_UNIX request returned no success response")
            return None
        response = self._json_output(result, "AF_UNIX response")
        valid = (
            response.get("version") == request.get("version")
            and response.get("request_id") == request.get("request_id")
            and response.get("command") == request.get("command")
            and response.get("ok") is True
            and isinstance(response.get("result"), dict)
        )
        if expect_success and not valid:
            raise HarnessError("AF_UNIX success response is not request-bound")
        if not expect_success:
            raise HarnessError("role-mismatched AF_UNIX request unexpectedly succeeded")
        return response

    def source_happy_path(self) -> tuple[dict[str, object], dict[str, Any]]:
        key = f"r08a-source-{self.token}"
        content_sha = hashlib.sha256(key.encode("ascii")).hexdigest()
        observed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        request: dict[str, object] = {
                "version": "1.2",
                "request_id": f"request-{key}",
                "idempotency_key": key,
                "command": "submit_source_trigger",
                "payload": {
                    "source_trigger": {
                        "trigger_id": f"trigger:{key}",
                        "collector_id": "collector:uid:10002",
                        "source_ref": f"public:synthetic/{content_sha}",
                        "source_content_sha256": content_sha,
                        "observed_at": observed,
                        "summary": "Bounded sanitized production-image harness event.",
                        "evidence_refs": [],
                        "transport_idempotency_key": key,
                    }
                },
            }
        response = self.request(uid=10002, request=request)
        assert response is not None
        result = response["result"]
        if not isinstance(result, dict) or not isinstance(result.get("material_event"), dict):
            raise HarnessError("collector request did not materialize a production event")
        return request, response

    def role_mismatch_rejected(self) -> None:
        key = f"r08a-role-{self.token}"
        self.request(
            uid=10003,
            expect_success=False,
            request={
                "version": "1.2", "request_id": f"request-{key}",
                "idempotency_key": key, "command": "submit_source_trigger",
                "payload": {"source_trigger": {
                    "trigger_id": f"trigger:{key}",
                    "collector_id": "collector:uid:10002",
                    "source_ref": "public:synthetic/role-check",
                    "source_content_sha256": hashlib.sha256(key.encode()).hexdigest(),
                    "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "summary": "Role-bound request check.", "evidence_refs": [],
                    "transport_idempotency_key": key,
                }},
            },
        )

    def second_writer_rejected(self) -> None:
        result = self._run(
            [
                "docker", "run", "--rm", f"--name={self.contender}",
                "--platform=linux/amd64", "--user=10001:10001", "--network=none",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                f"--mount=type=volume,source={self.runtime_volume},target=/var/lib/research-os",
                f"--mount=type=volume,source={self.config_volume},target=/run/research-os,readonly",
                self.subject.image_id,
            ],
            timeout=15.0,
            check=False,
        )
        if result.returncode == 0:
            raise HarnessError("second writer unexpectedly acquired the runtime")

    def restart_verify(
        self,
        source_request: Mapping[str, object],
        expected_response: Mapping[str, object],
    ) -> None:
        identity = self._verify_container()
        self._run(["docker", "stop", "--time=10", self.core])
        self._run(["docker", "start", self.core])
        self._run(
            ["docker", "exec", "--user=10001:10001", self.core, "python", "-c",
             "import os,time; p='/var/lib/research-os/researchd.sock'; end=time.monotonic()+10; "
             "exec(\"while not os.path.exists(p) and time.monotonic()<end: time.sleep(.05)\"); assert os.path.exists(p)"],
            timeout=15.0,
        )
        if self._verify_container() != identity:
            raise HarnessError("same-container restart changed container identity")
        replay = self.request(uid=10002, request=source_request)
        if replay != expected_response:
            raise HarnessError("restart replay did not preserve the exact response")

    def cleanup(self) -> None:
        self._run(["docker", "rm", "--force", self.contender], check=False)
        self._run(["docker", "rm", "--force", self.core], check=False)
        for volume in (self.config_volume, self.runtime_volume):
            self._run(["docker", "volume", "rm", volume], check=False)
        self._started = False

    def run_matrix(self) -> dict[str, object]:
        hashes = self.preflight()
        try:
            self.start()
            status_request = {
                "version": "1.1", "request_id": f"request-status-{self.token}",
                "idempotency_key": f"read-status-{self.token}",
                "command": "status", "payload": {},
            }
            status = self.request(uid=10001, request=status_request)
            source_request, source = self.source_happy_path()
            self.role_mismatch_rejected()
            self.second_writer_rejected()
            material = source["result"]["material_event"]
            self.restart_verify(source_request, source)
            event_id = material.get("object_id")
            return {
                "status": "PASS",
                "release_sha": self.subject.release_sha,
                "image_id": self.subject.image_id,
                "platform": self.subject.platform,
                "input_hashes": hashes,
                "af_unix_status": isinstance(status, dict),
                "source_materialized": isinstance(event_id, str),
                "material_event_sha256": hashlib.sha256(str(event_id).encode()).hexdigest(),
                "role_mismatch_rejected": True,
                "second_writer_rejected": True,
                "same_container_restart": True,
                "network": "none",
                "external_action_authority": False,
                "grants_authority": False,
            }
        finally:
            self.cleanup()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the exact production-image AF_UNIX harness")
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--token")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = ImageE2EHarness(
            ImageSubject(args.image_id, args.release_sha),
            root=args.root,
            token=args.token,
        ).run_matrix()
    except HarnessError:
        print(json.dumps({"status": "FAIL"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
