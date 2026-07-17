import concurrent.futures
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
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.control import (
    ControlError,
    ControlRequest,
    ControlResponse,
    ControlRouter,
)
from research_bridge.ipc import (
    IPCError,
    PeerCredentials,
    UnixControlServer,
    decode_message,
    encode_message,
    resolve_peer_credentials,
)
from tests.test_stage1_authority_policy import synthetic_authority  # noqa: E402


NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def trusted_authority():
    return synthetic_authority()


class RecordingBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.paused = False
        self.reason: str | None = None

    def pause_snapshot(self) -> dict[str, object]:
        self.calls.append(("pause_snapshot", {}))
        return {"paused": self.paused, "reason": self.reason, "generation": len(self.calls)}

    def pause_global(self, **kwargs: object) -> object:
        self.calls.append(("pause_global", dict(kwargs)))
        self.paused = True
        self.reason = str(kwargs["reason"])
        return object()

    def resume_global(self, **kwargs: object) -> object:
        self.calls.append(("resume_global", dict(kwargs)))
        self.paused = False
        self.reason = None
        return object()


def request(command: str, payload: dict[str, object]) -> ControlRequest:
    return ControlRequest(
        version="1.0",
        request_id=f"request-{command}",
        idempotency_key=f"idempotency-{command}",
        command=command,
        payload=payload,
    )


class ControlRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = RecordingBackend()
        self.router = ControlRouter(
            self.backend,
            authority=trusted_authority(),
            clock=lambda: NOW,
        )

    def test_only_literal_commands_and_shapes_are_accepted_before_backend_calls(self) -> None:
        valid_status = {
            "version": "1.0",
            "request_id": "request-status",
            "idempotency_key": "idempotency-status",
            "command": "status",
            "payload": {},
        }
        parsed = ControlRequest.from_mapping(valid_status)
        self.assertEqual(parsed.to_mapping(), valid_status)

        invalid = [
            {**valid_status, "actor": "uid:0"},
            {**valid_status, "version": "1.0.0"},
            {**valid_status, "command": "claim"},
            {**valid_status, "command": "pause_global", "payload": {}},
            {
                **valid_status,
                "command": "pause_global",
                "payload": {"reason": "synthetic", "authority_ref": "authority:a", "actor": "uid:0"},
            },
            {**valid_status, "command": "resume_global", "payload": {"approval_ref": ""}},
            {key: value for key, value in valid_status.items() if key != "request_id"},
        ]
        for value in invalid:
            with self.assertRaises(ControlError):
                ControlRequest.from_mapping(value)
        with self.assertRaises(ControlError):
            self.router.dispatch(valid_status, peer_uid=1000)  # type: ignore[arg-type]
        self.assertEqual(self.backend.calls, [])

    def test_status_pause_and_resume_use_verified_uid_and_current_snapshot(self) -> None:
        status = self.router.dispatch(request("status", {}), peer_uid=1200)
        self.assertIsInstance(status, ControlResponse)
        self.assertTrue(status.ok)
        self.assertFalse(status.result["paused"])
        self.assertEqual(self.backend.calls, [("pause_snapshot", {})])

        paused = self.router.dispatch(
            request(
                "pause_global",
                {"reason": "synthetic maintenance", "authority_ref": "authority:offline-a"},
            ),
            peer_uid=1200,
        )
        self.assertTrue(paused.result["paused"])
        self.assertEqual(
            self.backend.calls[-2:],
            [
                (
                    "pause_global",
                    {
                        "actor": "uid:1200",
                        "reason": "synthetic maintenance",
                        "authority_ref": "authority:offline-a",
                        "idempotency_key": "idempotency-pause_global",
                        "event_at": "2026-01-02T03:04:05Z",
                    },
                ),
                ("pause_snapshot", {}),
            ],
        )

        resumed = self.router.dispatch(
            request("resume_global", {"approval_ref": "approval:offline-a"}),
            peer_uid=1200,
        )
        self.assertFalse(resumed.result["paused"])
        self.assertEqual(
            self.backend.calls[-2:],
            [
                (
                    "resume_global",
                    {
                        "actor": "uid:1200",
                        "approval_ref": "approval:offline-a",
                        "idempotency_key": "idempotency-resume_global",
                        "event_at": "2026-01-02T03:04:05Z",
                    },
                ),
                ("pause_snapshot", {}),
            ],
        )

    def test_invalid_peer_or_clock_causes_zero_transition_calls(self) -> None:
        pause_request = request(
            "pause_global",
            {"reason": "synthetic maintenance", "authority_ref": "authority:offline-a"},
        )
        for invalid_uid in (True, -1, "1200"):
            with self.assertRaises(ControlError):
                self.router.dispatch(pause_request, peer_uid=invalid_uid)  # type: ignore[arg-type]
        self.assertEqual(self.backend.calls, [])

        invalid_clock_router = ControlRouter(
            self.backend,
            authority=trusted_authority(),
            clock=lambda: datetime(2026, 1, 2, 3, 4, 5),
        )
        with self.assertRaises(ControlError):
            invalid_clock_router.dispatch(pause_request, peer_uid=1200)
        self.assertEqual(self.backend.calls, [])


class IPCMessageTests(unittest.TestCase):
    def test_encoding_is_bounded_canonical_newline_json(self) -> None:
        response = ControlResponse(
            version="1.0",
            request_id="request-status",
            command="status",
            result={"paused": False},
        )
        encoded = encode_message(response)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded.count(b"\n"), 1)
        self.assertEqual(decode_message(encoded), response.to_mapping())
        self.assertEqual(
            json.loads(encoded),
            {"command": "status", "ok": True, "request_id": "request-status", "result": {"paused": False}, "version": "1.0"},
        )

    def test_decoding_rejects_bad_framing_duplicates_constants_and_oversize(self) -> None:
        invalid_frames = [
            b"{}",
            b"{}\n{}\n",
            b"{}\r\n",
            b"[]\n",
            b'{"key":1,"key":2}\n',
            b'{"key":NaN}\n',
            b"\xff\n",
            b"x" * 65_536 + b"\n",
        ]
        for frame in invalid_frames:
            with self.assertRaises(IPCError):
                decode_message(frame)
        with self.assertRaises(IPCError):
            encode_message({"value": "x" * 65_536})

    def test_operating_system_peer_credentials_are_available_on_unix_pair(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            credentials = resolve_peer_credentials(left)
        finally:
            left.close()
            right.close()
        self.assertEqual(credentials.uid, os.getuid())
        self.assertEqual(credentials.gid, os.getgid())


class UnixControlServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = RecordingBackend()
        self.router = ControlRouter(
            self.backend,
            authority=trusted_authority(),
            clock=lambda: NOW,
        )
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.temporary_directory.name) / "control.sock"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def server(self, *, uid: int, allowed_uids: set[int] | None = None) -> UnixControlServer:
        return UnixControlServer(
            self.socket_path,
            self.router,
            allowed_uids={uid} if allowed_uids is None else allowed_uids,
            credential_resolver=lambda _: PeerCredentials(uid=uid, gid=100),
        )

    def test_listener_is_af_unix_mode_0660_and_close_is_idempotent(self) -> None:
        server = self.server(uid=1000)
        server.close()
        server.start()
        socket_stat = os.lstat(self.socket_path)
        self.assertTrue(stat.S_ISSOCK(socket_stat.st_mode))
        self.assertEqual(stat.S_IMODE(socket_stat.st_mode), 0o660)
        self.assertEqual(server._listener.family, socket.AF_UNIX)
        server.close()
        server.close()
        self.assertFalse(self.socket_path.exists())

    def test_allowed_peer_is_dispatched_and_receives_one_response(self) -> None:
        server = self.server(uid=1200)
        server_side, client_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client_side.sendall(
                encode_message(
                    request(
                        "pause_global",
                        {"reason": "synthetic maintenance", "authority_ref": "authority:offline-a"},
                    ).to_mapping()
                )
            )
            response = server.handle_connection(server_side)
            wire_response = decode_message(client_side.recv(65_536))
        finally:
            server_side.close()
            client_side.close()
        self.assertTrue(response.result["paused"])
        self.assertEqual(wire_response, response.to_mapping())
        self.assertEqual(self.backend.calls[0][1]["actor"], "uid:1200")

    def test_unauthorized_or_unverified_peer_causes_zero_backend_calls(self) -> None:
        unauthorized = self.server(uid=1200, allowed_uids={1300})
        server_side, client_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with self.assertRaises(IPCError):
                unauthorized.handle_connection(server_side)
        finally:
            server_side.close()
            client_side.close()
        self.assertEqual(self.backend.calls, [])

        unverified = UnixControlServer(
            self.socket_path,
            self.router,
            allowed_uids={1200},
            credential_resolver=lambda _: (_ for _ in ()).throw(OSError("synthetic")),
        )
        server_side, client_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with self.assertRaises(IPCError):
                unverified.handle_connection(server_side)
        finally:
            server_side.close()
            client_side.close()
        self.assertEqual(self.backend.calls, [])

    def test_malformed_unknown_and_oversized_requests_cause_zero_backend_calls(self) -> None:
        frames = [
            b'{"version":"1.0"}\n',
            encode_message(
                {
                    "version": "1.0",
                    "request_id": "request-unknown",
                    "idempotency_key": "idempotency-unknown",
                    "command": "runner",
                    "payload": {},
                }
            ),
            b"x" * 65_537,
        ]
        for frame in frames:
            server = self.server(uid=1200)
            server_side, client_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    sender = executor.submit(client_side.sendall, frame)
                    with self.assertRaises((ControlError, IPCError)):
                        server.handle_connection(server_side)
                    sender.result(timeout=5)
            finally:
                server_side.close()
                client_side.close()
        self.assertEqual(self.backend.calls, [])

    def test_deadline_is_positive_and_never_above_five_seconds(self) -> None:
        for deadline in (0, -1, 5.0001, True):
            with self.assertRaises(IPCError):
                UnixControlServer(
                    self.socket_path,
                    self.router,
                    allowed_uids={1200},
                    deadline_seconds=deadline,
                )
        UnixControlServer(
            self.socket_path,
            self.router,
            allowed_uids={1200},
            deadline_seconds=5,
        ).close()


if __name__ == "__main__":
    unittest.main()
