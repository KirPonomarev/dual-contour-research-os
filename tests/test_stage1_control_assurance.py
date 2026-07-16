import ast
import concurrent.futures
import hashlib
import inspect
import json
import os
import socket
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from research_bridge.control import (  # noqa: E402
    ControlError,
    ControlRequest,
    ControlRouter,
)
from research_bridge.ipc import (  # noqa: E402
    IPCError,
    PeerCredentials,
    UnixControlServer,
    encode_message,
)
from research_bridge.ledger import JobLedger, LedgerError  # noqa: E402


AT = "2026-01-02T03:04:05Z"
ADMISSION_SHA256 = hashlib.sha256(b"synthetic-control-admission").hexdigest()
NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _claim(ledger: JobLedger, *, job_id: str = "job-control-synthetic") -> None:
    ledger.claim(
        job_id=job_id,
        attempt_id="attempt-control-synthetic",
        permit_id="permit-control-synthetic",
        runner_identity="offline-runner-synthetic",
        fencing_epoch=1,
        fencing_token="fence-control-synthetic",
        admitted_at=AT,
        admission_digest=ADMISSION_SHA256,
    )


def _request(
    command: str,
    payload: dict[str, object],
    *,
    request_id: str = "request-synthetic-001",
    idempotency_key: str = "control-synthetic-001",
) -> ControlRequest:
    return ControlRequest.from_mapping(
        {
            "version": "1.0",
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "command": command,
            "payload": payload,
        }
    )


class _RecordingBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def pause_snapshot(self) -> dict[str, object]:
        self.calls.append(("pause_snapshot", {}))
        return {"paused": False}

    def pause_global(self, **keywords: object) -> object:
        self.calls.append(("pause_global", dict(keywords)))
        return object()

    def resume_global(self, **keywords: object) -> object:
        self.calls.append(("resume_global", dict(keywords)))
        return object()


class LocalControlFrontDoorAssuranceTests(unittest.TestCase):
    def _server(
        self,
        backend: _RecordingBackend,
        *,
        peer_uid: int = 1001,
        allowed_uids: set[int] | None = None,
    ) -> UnixControlServer:
        router = ControlRouter(backend, clock=lambda: NOW)
        return UnixControlServer(
            Path(self.temporary_directory.name) / "synthetic-control.sock",
            router,
            allowed_uids={1001} if allowed_uids is None else allowed_uids,
            credential_resolver=lambda _: PeerCredentials(
                uid=peer_uid,
                gid=1001,
                pid=1234,
            ),
        )

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _assert_raw_request_denied_without_backend_call(
        self,
        raw_request: bytes,
        *,
        peer_uid: int = 1001,
    ) -> None:
        backend = _RecordingBackend()
        server = self._server(backend, peer_uid=peer_uid)
        client, connection = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            def send_request() -> None:
                client.sendall(raw_request)
                client.shutdown(socket.SHUT_WR)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                sent = executor.submit(send_request)
                with self.assertRaises((ControlError, IPCError)):
                    server.handle_connection(connection)
                sent.result(timeout=5)
            self.assertEqual(backend.calls, [])
        finally:
            connection.close()
            client.close()
            server.close()

    def test_malformed_and_oversized_messages_make_zero_backend_calls(self) -> None:
        malformed = (
            b"not-json\n",
            json.dumps(["not", "a", "mapping"]).encode("utf-8") + b"\n",
            json.dumps(
                {
                    "version": "1.0",
                    "request_id": "request-synthetic-001",
                    "idempotency_key": "control-synthetic-001",
                    "command": "status",
                }
            ).encode("utf-8")
            + b"\n",
            json.dumps(
                {
                    "version": "1.0",
                    "request_id": "request-synthetic-001",
                    "idempotency_key": "control-synthetic-001",
                    "command": "status",
                    "payload": {},
                    "unexpected": "synthetic",
                }
            ).encode("utf-8")
            + b"\n",
        )
        for index, raw_request in enumerate(malformed):
            with self.subTest(case=index):
                self._assert_raw_request_denied_without_backend_call(raw_request)

        self._assert_raw_request_denied_without_backend_call(b"x" * 65_537)

    def test_unknown_command_and_unauthorized_uid_make_zero_backend_calls(self) -> None:
        unknown = encode_message(
            {
                "version": "1.0",
                "request_id": "request-synthetic-unknown",
                "idempotency_key": "control-synthetic-unknown",
                "command": "unsupported_synthetic_command",
                "payload": {},
            }
        )
        self._assert_raw_request_denied_without_backend_call(unknown)

        status = encode_message(
            {
                "version": "1.0",
                "request_id": "request-synthetic-status",
                "idempotency_key": "control-synthetic-status",
                "command": "status",
                "payload": {},
            }
        )
        self._assert_raw_request_denied_without_backend_call(status, peer_uid=2002)

    def test_server_creates_only_a_unix_socket_with_mode_0660(self) -> None:
        backend = _RecordingBackend()
        socket_path = Path(self.temporary_directory.name) / "synthetic-control.sock"
        server = self._server(backend, peer_uid=os.getuid(), allowed_uids={os.getuid()})
        try:
            server.start()
            metadata = socket_path.stat()
            self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o660)
        finally:
            server.close()

        with self.assertRaises(IPCError):
            UnixControlServer(
                socket_path,
                ControlRouter(backend, clock=lambda: NOW),
                allowed_uids={os.getuid()},
                deadline_seconds=5.001,
            )

    def test_router_pause_replay_and_approval_bound_resume_compose_with_ledger(self) -> None:
        database = Path(self.temporary_directory.name) / "synthetic-router-ledger.sqlite3"
        ledger = JobLedger(database)
        router = ControlRouter(ledger, clock=lambda: NOW)
        try:
            pause = _request(
                "pause_global",
                {
                    "reason": "synthetic router hold",
                    "authority_ref": "permit:synthetic-router-authority",
                },
                idempotency_key="pause-synthetic-router",
            )
            first = router.dispatch(pause, peer_uid=1001)
            before_replay = ledger.event_count()
            replay = router.dispatch(pause, peer_uid=1001)
            self.assertTrue(first.ok)
            self.assertTrue(replay.ok)
            self.assertEqual(ledger.event_count(), before_replay)
            self.assertTrue(ledger.is_globally_paused())
            self.assertEqual(ledger.pause_snapshot()["actor"], "uid:1001")

            for index, payload in enumerate(({}, {"approval_ref": ""})):
                with self.subTest(payload=payload):
                    before_invalid_resume = ledger.event_count()
                    with self.assertRaises(ControlError):
                        request = _request(
                            "resume_global",
                            payload,
                            request_id=f"request-invalid-resume-{index}",
                            idempotency_key=f"resume-invalid-{index}",
                        )
                        router.dispatch(request, peer_uid=1001)
                    self.assertEqual(ledger.event_count(), before_invalid_resume)
                    self.assertTrue(ledger.is_globally_paused())

            resume = _request(
                "resume_global",
                {"approval_ref": "approval:synthetic-router-authority"},
                request_id="request-synthetic-resume",
                idempotency_key="resume-synthetic-router",
            )
            response = router.dispatch(resume, peer_uid=1001)
            self.assertTrue(response.ok)
            self.assertFalse(ledger.is_globally_paused())
            _claim(ledger, job_id="job-synthetic-after-router-resume")
            self.assertEqual(ledger.event_count("claim"), 1)
            self.assertTrue(ledger.verify_chain())
        finally:
            ledger.close()


class PersistentPauseAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = (
            Path(self.temporary_directory.name) / "synthetic-control-ledger.sqlite3"
        )
        self.ledger = JobLedger(self.database)

    def tearDown(self) -> None:
        self.ledger.close()
        self.temporary_directory.cleanup()

    def test_pause_survives_reopen_and_blocks_claim_without_claim_event(self) -> None:
        paused = self.ledger.pause_global(
            actor="uid:1001",
            reason="synthetic offline maintenance",
            authority_ref="permit:synthetic-pause-authority",
            idempotency_key="pause-synthetic-001",
            event_at=AT,
        )
        self.assertEqual(paused.event_type, "pause")
        self.assertTrue(self.ledger.is_globally_paused())
        self.assertEqual(self.ledger.event_count(), 1)
        tables = {
            row[0]
            for row in self.ledger._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
            if not row[0].startswith("sqlite_")
        }
        self.assertEqual(tables, {"bridge_job_ledger"})
        self.assertTrue(self.ledger.verify_chain())

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        self.assertTrue(self.ledger.is_globally_paused())
        before = self.ledger.event_count()
        with self.assertRaises(LedgerError):
            _claim(self.ledger)
        self.assertEqual(self.ledger.event_count(), before)
        self.assertEqual(self.ledger.event_count("claim"), 0)
        self.assertTrue(self.ledger.verify_chain())

    def test_duplicate_control_idempotency_key_adds_zero_events(self) -> None:
        keywords = {
            "actor": "uid:1001",
            "reason": "synthetic duplicate check",
            "authority_ref": "permit:synthetic-pause-authority",
            "idempotency_key": "pause-synthetic-duplicate",
            "event_at": AT,
        }
        first = self.ledger.pause_global(**keywords)
        before = self.ledger.event_count()

        duplicate = self.ledger.pause_global(**keywords)

        self.assertEqual(self.ledger.event_count(), before)
        self.assertEqual(self.ledger.event_count("pause"), 1)
        self.assertEqual(duplicate.event_sha256, first.event_sha256)
        self.assertTrue(self.ledger.verify_chain())

    def test_resume_requires_nonempty_approval_and_invalid_values_write_nothing(self) -> None:
        self.ledger.pause_global(
            actor="uid:1001",
            reason="synthetic approval check",
            authority_ref="permit:synthetic-pause-authority",
            idempotency_key="pause-synthetic-approval",
            event_at=AT,
        )
        before = self.ledger.event_count()

        for approval_ref in (None, "", "   "):
            with self.subTest(approval_ref=approval_ref):
                with self.assertRaises((LedgerError, TypeError)):
                    self.ledger.resume_global(
                        actor="uid:1001",
                        approval_ref=approval_ref,
                        idempotency_key="resume-synthetic-invalid",
                        event_at=AT,
                    )
                self.assertEqual(self.ledger.event_count(), before)
                self.assertTrue(self.ledger.is_globally_paused())

        self.assertTrue(self.ledger.verify_chain())

    def test_approval_bound_resume_unblocks_claim_and_chain_stays_valid(self) -> None:
        self.ledger.pause_global(
            actor="uid:1001",
            reason="synthetic resume check",
            authority_ref="permit:synthetic-pause-authority",
            idempotency_key="pause-synthetic-resume",
            event_at=AT,
        )
        resumed = self.ledger.resume_global(
            actor="uid:1001",
            approval_ref="approval:synthetic-resume-authority",
            idempotency_key="resume-synthetic-001",
            event_at=AT,
        )

        self.assertEqual(resumed.event_type, "resume")
        self.assertFalse(self.ledger.is_globally_paused())
        _claim(self.ledger)
        self.assertEqual(self.ledger.event_count("pause"), 1)
        self.assertEqual(self.ledger.event_count("resume"), 1)
        self.assertEqual(self.ledger.event_count("claim"), 1)
        self.assertEqual(self.ledger.event_count(), 3)
        self.assertTrue(self.ledger.verify_chain())

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        self.assertFalse(self.ledger.is_globally_paused())
        self.assertTrue(self.ledger.verify_chain())


class Stage1ControlStaticBoundaryTests(unittest.TestCase):
    def test_control_surface_is_stdlib_only_domain_neutral_and_unix_local(self) -> None:
        expected_exports = {
            "control.py": {
                "ControlError",
                "ControlRequest",
                "ControlResponse",
                "ControlRouter",
            },
            "ipc.py": {
                "IPCError",
                "PeerCredentials",
                "UnixControlServer",
                "encode_message",
                "decode_message",
                "resolve_peer_credentials",
            },
        }
        forbidden_imports = {
            "aiohttp",
            "cryptography",
            "fastapi",
            "ftplib",
            "flask",
            "http",
            "httpx",
            "pydantic",
            "requests",
            "smtplib",
            "starlette",
            "urllib",
            "urllib3",
        }
        forbidden_identifier_fragments = {
            "deploy",
            "domain_registry",
            "exchange",
            "exploit",
            "http",
            "inet",
            "live_trade",
            "order_submit",
            "publish",
            "registry_writer",
            "target_scan",
        }

        identifiers: set[str] = set()
        imported_roots: set[str] = set()
        for filename, exports in expected_exports.items():
            module_path = SRC / "research_bridge" / filename
            tree = ast.parse(module_path.read_text())
            module = __import__(f"research_bridge.{filename[:-3]}", fromlist=["*"])
            self.assertEqual(set(module.__all__), exports, filename)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_roots.update(
                        alias.name.split(".")[0] for alias in node.names
                    )
                elif isinstance(node, ast.ImportFrom) and node.level:
                    imported_roots.add("research_bridge")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported_roots.add(node.module.split(".")[0])
                elif isinstance(node, ast.Name):
                    identifiers.add(node.id.lower())
                elif isinstance(node, ast.Attribute):
                    identifiers.add(node.attr.lower())
                elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    identifiers.add(node.name.lower())

        non_stdlib = {
            root
            for root in imported_roots
            if root not in sys.stdlib_module_names and root != "research_bridge"
        }
        self.assertEqual(non_stdlib, set())
        self.assertTrue(imported_roots.isdisjoint(forbidden_imports))
        self.assertNotIn("af_inet", identifiers)
        self.assertNotIn("af_inet6", identifiers)
        violations = {
            identifier
            for identifier in identifiers
            if any(fragment in identifier for fragment in forbidden_identifier_fragments)
        }
        self.assertEqual(violations, set())

    def test_control_ledger_exposes_only_frozen_pause_interface(self) -> None:
        expected = {
            "pause_global": {
                "actor",
                "reason",
                "authority_ref",
                "idempotency_key",
                "event_at",
            },
            "resume_global": {
                "actor",
                "approval_ref",
                "idempotency_key",
                "event_at",
            },
        }
        for method_name, keyword_names in expected.items():
            signature = inspect.signature(getattr(JobLedger, method_name))
            self.assertEqual(
                {
                    name
                    for name, parameter in signature.parameters.items()
                    if name != "self" and parameter.kind is inspect.Parameter.KEYWORD_ONLY
                },
                keyword_names,
            )
        self.assertTrue(callable(getattr(JobLedger, "is_globally_paused", None)))
        self.assertTrue(callable(getattr(JobLedger, "pause_snapshot", None)))


if __name__ == "__main__":
    unittest.main()
