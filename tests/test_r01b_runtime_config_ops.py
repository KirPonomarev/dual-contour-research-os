from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.admission import canonical_json_sha256  # noqa: E402
from research_bridge.control import ControlError, ControlRequest, ControlRouter  # noqa: E402
from research_bridge.ipc import PeerCredentials, UnixControlServer, encode_message  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    ResearchDaemon,
    _ServiceConfigError,
    _service_config_from_mapping,
)


CONFIG_PATH = ROOT / "ops/release/researchd.config.template.json"
POLICY_PROFILE_SHA256 = "50a3f629d8931262b7cd7109575ddb99f5fc8cacffec1985e1d5793e012dc3b4"
ZERO_SHA256 = "0" * 64
NOW = datetime(2026, 7, 19, 6, 0, tzinfo=timezone.utc)


def canonical_config() -> dict[str, object]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


class _Core:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def pause_snapshot(self) -> dict[str, object]:
        self.calls.append("status")
        return {"paused": False}


class _A1:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def submit_source_trigger(self, **_: object) -> dict[str, object]:
        self.calls.append("submit_source_trigger")
        return {"accepted": True}

    def claim_proposal(self, **_: object) -> dict[str, object]:
        self.calls.append("claim_proposal")
        return {"claimed": True}


class RuntimeConfigOpsTests(unittest.TestCase):
    def test_canonical_template_is_strict_a1_enabled_but_release_unbound(self) -> None:
        config = canonical_config()
        service = _service_config_from_mapping(config)
        bindings = dict(service.frozen_bindings or {})
        policy = next(iter(config["policy_snapshots"].values()))  # type: ignore[union-attr]
        payload = policy["payload"]
        self.assertTrue(service.a1_enabled)
        self.assertEqual(service.allowed_uids, (10001, 10002, 10003))
        self.assertEqual(
            dict(service.principal_roles),
            {10001: "operator", 10002: "collector", 10003: "scout"},
        )
        self.assertEqual(config["approval_receipts"], {})
        self.assertEqual(bindings["release_manifest_sha256"], ZERO_SHA256)
        self.assertEqual(payload["aggregate_sha256"], POLICY_PROFILE_SHA256)
        self.assertEqual(policy["classification"], "D1_INTERNAL_SANITIZED")
        self.assertGreaterEqual(
            datetime.fromisoformat(payload["valid_until"].replace("Z", "+00:00"))
            - datetime.fromisoformat(payload["valid_from"].replace("Z", "+00:00")),
            __import__("datetime").timedelta(days=14),
        )
        for ref in (*bindings["executor_capability_refs"], *bindings["evaluator_capability_refs"]):
            self.assertTrue((ROOT / ref).is_file())

    def test_empty_mixed_tampered_expired_and_bad_binding_configs_are_denied(self) -> None:
        cases: list[dict[str, object]] = []
        empty = canonical_config()
        empty["policy_snapshots"] = {}
        cases.append(empty)
        mixed = canonical_config()
        document = next(iter(mixed["policy_snapshots"].values()))  # type: ignore[union-attr]
        mixed["policy_snapshots"]["f" * 64] = copy.deepcopy(document)  # type: ignore[index]
        cases.append(mixed)
        tampered = canonical_config()
        next(iter(tampered["policy_snapshots"].values()))["issuer"]["id"] = "untrusted"  # type: ignore[index,union-attr]
        cases.append(tampered)
        expired = canonical_config()
        next(iter(expired["policy_snapshots"].values()))["payload"]["valid_until"] = "2026-07-18T00:00:00Z"  # type: ignore[index,union-attr]
        cases.append(expired)
        for field in ("core_catalog_sha256", "a1_catalog_sha256", "ipc_compatibility_profile_sha256"):
            bad = canonical_config()
            bad["frozen_bindings"][field] = "f" * 64  # type: ignore[index]
            cases.append(bad)
        for mutation in (
            lambda c: c["frozen_bindings"].update(executor_capability_refs=[]),  # type: ignore[union-attr]
            lambda c: c["a1_limits"]["cycle_limits"].update(max_model_calls=13),  # type: ignore[index,union-attr]
            lambda c: c.update(allowed_uids=[10001, 10001, 10003]),
            lambda c: c["principal_roles"].update({"10003": "collector"}),  # type: ignore[union-attr]
        ):
            bad = canonical_config()
            mutation(bad)
            cases.append(bad)
        for config in cases:
            with self.subTest(case=len(config)):
                with self.assertRaises(_ServiceConfigError):
                    _service_config_from_mapping(config)

    def test_verified_uid_role_matrix_denies_cross_role_and_missing_backend(self) -> None:
        config = canonical_config()
        service = _service_config_from_mapping(config)
        core, a1 = _Core(), _A1()
        router = ControlRouter(core, a1_backend=a1, authority=service.authority, clock=lambda: NOW)
        allowed = set(service.allowed_uids)

        def dispatch(uid: int, request: dict[str, object], *, with_backend: bool = True) -> object:
            selected = router if with_backend else ControlRouter(core, authority=service.authority, clock=lambda: NOW)
            server = UnixControlServer(
                "/tmp/unused-r01b.sock",
                selected,
                allowed_uids=allowed,
                principal_roles=service.principal_roles,
                credential_resolver=lambda _: PeerCredentials(uid=uid, gid=10001, pid=1),
            )
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                left.sendall(encode_message(request))
                left.shutdown(socket.SHUT_WR)
                return server.handle_connection(right)
            finally:
                left.close()
                right.close()
                server.close()

        status = {"version": "1.1", "request_id": "r01b-op", "idempotency_key": "r01b-op", "command": "status", "payload": {}}
        trigger = {"version": "1.2", "request_id": "r01b-collector", "idempotency_key": "r01b-collector", "command": "submit_source_trigger", "payload": {"source_trigger": {}}}
        claim = {"version": "1.2", "request_id": "r01b-scout", "idempotency_key": "r01b-scout", "command": "claim_proposal", "payload": {"material_event_ref": "material-event:r01b"}}
        self.assertEqual(dispatch(10001, status).command, "status")
        self.assertEqual(dispatch(10002, trigger).command, "submit_source_trigger")
        self.assertEqual(dispatch(10003, claim).command, "claim_proposal")
        with self.assertRaises(ControlError):
            dispatch(10002, status)
        with self.assertRaises(ControlError):
            dispatch(10003, trigger)
        with self.assertRaisesRegex(ControlError, "backend is unavailable"):
            dispatch(10002, trigger, with_backend=False)
        supplied_role = dict(trigger, role="operator")
        with self.assertRaises(ControlError):
            ControlRequest.from_mapping(supplied_role)

    def test_ai_off_legacy_config_starts_core_and_real_uid_status_socket(self) -> None:
        config = canonical_config()
        config = {key: value for key, value in config.items() if key not in {"a1_enabled", "principal_roles", "frozen_bindings", "a1_limits"}}
        config["schema_version"] = "1.0.0"
        config["allowed_uids"] = [os.geteuid()]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            root.mkdir(mode=0o700)
            config["runtime_root"] = str(root)
            service = _service_config_from_mapping(config)
            daemon = ResearchDaemon(
                root,
                authority=service.authority,
                allowed_uids=service.allowed_uids,
                principal_roles=service.principal_roles,
                a1_enabled=False,
                runner_identity=service.runner_identity,
            )
            daemon.start()
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(daemon.socket_path))
                client.sendall(encode_message({"version": "1.1", "request_id": "r01b-real", "idempotency_key": "r01b-real", "command": "status", "payload": {}}))
                client.shutdown(socket.SHUT_WR)
                response = daemon.serve_once()
                self.assertEqual(response.command, "status")
                client.close()
            finally:
                daemon.close()


if __name__ == "__main__":
    unittest.main()
