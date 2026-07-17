from __future__ import annotations

import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "src"))

from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.ipc import decode_message, encode_message  # noqa: E402
from research_bridge.researchctl import run  # noqa: E402
from research_bridge.researchd import ResearchDaemon  # noqa: E402
from tests.test_stage1_reference_vertical import (  # noqa: E402
    INPUT_A,
    INPUT_B,
    INPUT_REFS,
    NOW,
    _authority,
    _authority_verifier,
)


RESPONSE_MAXIMUM_BYTES = 262_144


class ResearchctlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _one_response(
        self,
        *,
        result: dict[str, object] | None = None,
        close_without_response: bool = False,
        response_override: dict[str, object] | None = None,
    ) -> tuple[Path, concurrent.futures.Future[dict[str, object]], concurrent.futures.ThreadPoolExecutor]:
        endpoint = self.root / f"control-{len(list(self.root.glob('control-*')))}.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(endpoint))
        listener.listen(1)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

        def serve() -> dict[str, object]:
            try:
                connection, _ = listener.accept()
                with connection:
                    frame = bytearray()
                    while not frame.endswith(b"\n"):
                        block = connection.recv(4096)
                        if not block:
                            break
                        frame.extend(block)
                    request = decode_message(bytes(frame))
                    if close_without_response:
                        return request
                    response = response_override or {
                        "version": "1.1",
                        "request_id": request["request_id"],
                        "ok": True,
                        "command": request["command"],
                        "result": result or {"accepted": True},
                    }
                    connection.sendall(
                        encode_message(
                            response,
                            maximum_bytes=RESPONSE_MAXIMUM_BYTES,
                        )
                    )
                    return request
            finally:
                listener.close()

        return endpoint, executor.submit(serve), executor

    def _run(
        self,
        argv: list[str],
        *,
        stdin_text: str = "",
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = run(
            argv,
            stdin=io.StringIO(stdin_text),
            stdout=stdout,
            stderr=stderr,
        )
        return code, stdout.getvalue(), stderr.getvalue()

    def test_status_pause_resume_and_lookup_map_to_exact_protocol_1_1(self) -> None:
        cases = (
            (
                "status",
                ["status"],
                "status",
                {},
            ),
            (
                "pause",
                [
                    "pause",
                    "--reason",
                    "synthetic hold",
                    "--authority-ref",
                    "permit:synthetic-hold",
                    "--idempotency-key",
                    "pause-synthetic",
                ],
                "pause_global",
                {
                    "reason": "synthetic hold",
                    "authority_ref": "permit:synthetic-hold",
                },
            ),
            (
                "resume",
                [
                    "resume",
                    "--approval-ref",
                    "approval:synthetic-resume",
                    "--idempotency-key",
                    "resume-synthetic",
                ],
                "resume_global",
                {"approval_ref": "approval:synthetic-resume"},
            ),
            (
                "lookup",
                ["lookup", "--job-spec-ref", "job-synthetic"],
                "lookup",
                {"job_spec_ref": "job-synthetic"},
            ),
        )
        for label, command, wire_command, payload in cases:
            with self.subTest(command=label):
                endpoint, future, executor = self._one_response()
                try:
                    code, output, error = self._run(
                        [
                            "--socket",
                            str(endpoint),
                            "--request-id",
                            f"request-{label}",
                            *command,
                        ]
                    )
                    request = future.result(timeout=5)
                finally:
                    executor.shutdown(wait=True)
                self.assertEqual(code, 0)
                self.assertEqual(error, "")
                self.assertEqual(json.loads(output)["ok"], True)
                self.assertEqual(request["version"], "1.1")
                self.assertEqual(request["command"], wire_command)
                self.assertEqual(request["payload"], payload)

    def test_submit_reads_one_strict_exact_stdin_object(self) -> None:
        documents = {
            "job_spec": {"object_id": "job-synthetic"},
            "permit": {"object_id": "permit-synthetic"},
            "lease": {"object_id": "lease-synthetic"},
        }
        endpoint, future, executor = self._one_response()
        try:
            code, output, error = self._run(
                [
                    "--socket",
                    str(endpoint),
                    "--request-id",
                    "request-submit",
                    "submit",
                    "--idempotency-key",
                    "submit-synthetic",
                ],
                stdin_text=json.dumps(documents),
            )
            request = future.result(timeout=5)
        finally:
            executor.shutdown(wait=True)
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertTrue(output.endswith("\n"))
        self.assertEqual(request["command"], "submit")
        self.assertEqual(request["idempotency_key"], "submit-synthetic")
        self.assertEqual(request["payload"], documents)

    def test_local_input_transport_and_daemon_failures_have_frozen_exit_codes(self) -> None:
        missing = self.root / "missing.sock"
        invalid_inputs = (
            "",
            "[]",
            '{"job_spec":{},"permit":{},"lease":{},"extra":true}',
            '{"job_spec":{},"job_spec":{},"permit":{},"lease":{}}',
            "x" * 65_537,
        )
        for index, invalid in enumerate(invalid_inputs):
            with self.subTest(local=index):
                code, output, error = self._run(
                    [
                        "--socket",
                        str(missing),
                        "submit",
                        "--idempotency-key",
                        "submit-synthetic",
                    ],
                    stdin_text=invalid,
                )
                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertEqual(error, "local input rejected\n")
                self.assertNotIn(str(missing), error)

        code, output, error = self._run(
            ["--socket", str(missing), "status"]
        )
        self.assertEqual((code, output, error), (3, "", "local transport failed\n"))

        endpoint, future, executor = self._one_response(close_without_response=True)
        try:
            code, output, error = self._run(
                ["--socket", str(endpoint), "status"]
            )
            future.result(timeout=5)
        finally:
            executor.shutdown(wait=True)
        self.assertEqual((code, output, error), (4, "", "daemon rejected request\n"))

    def test_response_bound_is_independent_and_binding_is_verified(self) -> None:
        endpoint, future, executor = self._one_response(
            result={"synthetic": "x" * 70_000}
        )
        try:
            code, output, error = self._run(
                [
                    "--socket",
                    str(endpoint),
                    "--request-id",
                    "request-large-response",
                    "status",
                ]
            )
            future.result(timeout=5)
        finally:
            executor.shutdown(wait=True)
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertEqual(len(json.loads(output)["result"]["synthetic"]), 70_000)

        endpoint, future, executor = self._one_response(
            response_override={
                "version": "1.1",
                "request_id": "wrong-request",
                "ok": True,
                "command": "status",
                "result": {},
            }
        )
        try:
            code, output, error = self._run(
                [
                    "--socket",
                    str(endpoint),
                    "--request-id",
                    "request-expected",
                    "status",
                ]
            )
            future.result(timeout=5)
        finally:
            executor.shutdown(wait=True)
        self.assertEqual((code, output, error), (3, "", "local transport failed\n"))

    def test_real_daemon_submit_then_lookup_over_authenticated_af_unix(self) -> None:
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        store = ContentAddressedStore(runtime / "input-cas", quota_bytes=1_048_576)
        for index, (reference, payload) in enumerate(
            zip(INPUT_REFS, (INPUT_A, INPUT_B), strict=True)
        ):
            source = self.root / f"input-{index}.bin"
            source.write_bytes(payload)
            store.publish(
                source,
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                expected_size_bytes=len(payload),
            )
            self.assertEqual(
                reference,
                f"cas:sha256:{hashlib.sha256(payload).hexdigest()}",
            )
        job_spec, permit, lease = _authority("D0_PUBLIC")
        lease_payload = lease["payload"]
        job_payload = job_spec["payload"]
        assert isinstance(lease_payload, dict)
        assert isinstance(job_payload, dict)
        daemon = ResearchDaemon(
            runtime,
            authority=_authority_verifier(),
            allowed_uids={os.geteuid()},
            runner_identity=str(lease_payload["runner_identity"]),
            input_quota_bytes=1_048_576,
            checkpoint_quota_bytes=1_048_576,
            artifact_quota_bytes=1_048_576,
            maximum_input_bytes=1_048_576,
            clock=lambda: NOW,
        )
        daemon.start()
        documents = {"job_spec": job_spec, "permit": permit, "lease": lease}
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                served = executor.submit(daemon.serve_once)
                submit_code, submit_output, submit_error = self._run(
                    [
                        "--socket",
                        str(daemon.socket_path),
                        "--request-id",
                        "request-real-submit",
                        "submit",
                        "--idempotency-key",
                        str(job_payload["idempotency_key"]),
                    ],
                    stdin_text=json.dumps(documents),
                )
                served.result(timeout=5)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                served = executor.submit(daemon.serve_once)
                lookup_code, lookup_output, lookup_error = self._run(
                    [
                        "--socket",
                        str(daemon.socket_path),
                        "--request-id",
                        "request-real-lookup",
                        "lookup",
                        "--job-spec-ref",
                        str(job_spec["object_id"]),
                    ]
                )
                served.result(timeout=5)
        finally:
            daemon.close()

        self.assertEqual((submit_code, submit_error), (0, ""))
        self.assertEqual((lookup_code, lookup_error), (0, ""))
        self.assertEqual(
            json.loads(submit_output)["result"]["execution_receipt"],
            json.loads(lookup_output)["result"]["execution_receipt"],
        )


if __name__ == "__main__":
    unittest.main()
