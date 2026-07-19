from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.control import ControlError  # noqa: E402
from research_bridge.discovery import _empty_durable_states  # noqa: E402
from research_bridge.ipc import PeerCredentials, encode_message  # noqa: E402
from research_bridge.ledger import JobLedger  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    ResearchDaemon,
    ResearchdError,
    _service_config_from_mapping,
)


CONFIG_PATH = ROOT / "ops/release/researchd.config.template.json"
NOW = datetime(2026, 7, 19, 6, 0, tzinfo=timezone.utc)
COLLECTOR_UID = 10002
SCOUT_UID = 10003
RELEASE_SHA256 = hashlib.sha256(b"r02c-frozen-release").hexdigest()


def _plain(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _source(key: str, *, suffix: str = "one", **overrides: object) -> dict[str, object]:
    trigger: dict[str, object] = {
        "trigger_id": f"trigger:{suffix}",
        "collector_id": "collector:uid:10002",
        "source_ref": f"public:r02c/{suffix}",
        "source_content_sha256": hashlib.sha256(suffix.encode()).hexdigest(),
        "observed_at": "2026-07-19T05:59:00Z",
        "summary": "Sanitized public synthetic assurance signal.",
        "evidence_refs": [f"public:evidence/{suffix}"],
        "transport_idempotency_key": key,
    }
    trigger.update(overrides)
    return trigger


class ProductionA1DurabilityAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.runtime = self.base / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.now = NOW
        self.peer_uid = COLLECTOR_UID
        self.daemons: list[ResearchDaemon] = []

    def tearDown(self) -> None:
        for daemon in reversed(self.daemons):
            daemon.close()
        self.temporary.cleanup()

    def _service(self):
        # The policy, issuers, limits, roles, and compatibility bindings all
        # come from the shipped production template and production parser.
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        config["runtime_root"] = str(self.runtime)
        config["frozen_bindings"]["release_manifest_sha256"] = RELEASE_SHA256
        return _service_config_from_mapping(config)

    def _daemon(self) -> ResearchDaemon:
        service = self._service()
        daemon = ResearchDaemon(
            self.runtime,
            authority=service.authority,
            allowed_uids=service.allowed_uids,
            principal_roles=service.principal_roles,
            a1_enabled=service.a1_enabled,
            frozen_bindings=service.frozen_bindings,
            a1_limits=service.a1_limits,
            runner_identity=service.runner_identity,
            input_quota_bytes=service.input_quota_bytes,
            checkpoint_quota_bytes=service.checkpoint_quota_bytes,
            artifact_quota_bytes=service.artifact_quota_bytes,
            maximum_input_bytes=service.maximum_input_bytes,
            deadline_seconds=service.deadline_seconds,
            clock=lambda: self.now,
            credential_resolver=lambda _: PeerCredentials(
                uid=self.peer_uid, gid=20000, pid=os.getpid()
            ),
        )
        self.daemons.append(daemon)
        return daemon

    def _request(
        self,
        daemon: ResearchDaemon,
        uid: int,
        command: str,
        key: str,
        payload: dict[str, object],
        *,
        extra: dict[str, object] | None = None,
    ):
        request: dict[str, object] = {
            "version": "1.2",
            "request_id": f"request:{key}",
            "idempotency_key": key,
            "command": command,
            "payload": payload,
        }
        if extra:
            request.update(extra)
        self.peer_uid = uid
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(daemon.socket_path))
        try:
            client.sendall(encode_message(request))
            client.shutdown(socket.SHUT_WR)
            return daemon.serve_once()
        finally:
            client.close()

    def _submit_source(self, daemon: ResearchDaemon, key: str, **overrides: object):
        return self._request(
            daemon,
            COLLECTOR_UID,
            "submit_source_trigger",
            key,
            {"source_trigger": _source(key, suffix=key, **overrides)},
        )

    def test_real_af_unix_collector_to_scout_wait_data_replay_and_reopen(self) -> None:
        daemon = self._daemon()
        daemon.start()
        self.assertEqual(type(daemon._a1_backend).__name__, "DurableDiscoveryService")

        before_wait = daemon._ledger.event_count()  # type: ignore[union-attr]
        wait = self._request(
            daemon, SCOUT_UID, "claim_next_proposal", "poll:empty", {}
        )
        self.assertEqual(wait.result["decision"], "WAIT_DATA")
        self.assertEqual(wait.result["model_calls_consumed"], 0)
        self.assertEqual(daemon._ledger.event_count(), before_wait)  # type: ignore[union-attr]

        accepted = self._submit_source(daemon, "source:one")
        self.assertEqual(accepted.result["decision"], "MATERIAL")
        self.assertEqual(accepted.result["model_calls_consumed"], 0)
        after_source = daemon._ledger.event_count()  # type: ignore[union-attr]
        claimed = self._request(
            daemon, SCOUT_UID, "claim_next_proposal", "claim:one", {}
        )
        self.assertEqual(claimed.result["decision"], "CLAIMED")
        self.assertEqual(claimed.result["claim"]["generation"], 1)
        after_claim = daemon._ledger.event_count()  # type: ignore[union-attr]

        daemon.close()
        reopened = self._daemon()
        reopened.start()
        replayed = self._submit_source(reopened, "source:one")
        self.assertEqual(_plain(replayed.result), _plain(accepted.result))
        self.assertEqual(reopened._ledger.event_count(), after_claim)  # type: ignore[union-attr]
        replayed_claim = self._request(
            reopened, SCOUT_UID, "claim_next_proposal", "claim:one", {}
        )
        self.assertEqual(_plain(replayed_claim.result), _plain(claimed.result))
        self.assertEqual(reopened._ledger.event_count(), after_claim)  # type: ignore[union-attr]
        self.assertGreater(after_claim, after_source)

    def test_genuine_v1_start_is_zero_write_then_first_authorized_transition_is_atomic_v2(self) -> None:
        ledger = JobLedger(self.runtime / "bridge-job-ledger.sqlite3")
        ledger._advance_a1_projections(
            projections=_empty_durable_states(state_version="durable-discovery-v1"),
            idempotency_key="r02c:genuine-v1",
            event_at="2026-07-19T05:58:00Z",
        )
        before_start = ledger.event_count()
        ledger.close()

        daemon = self._daemon()
        daemon.start()
        self.assertEqual(daemon._ledger.event_count(), before_start)  # type: ignore[union-attr]
        initial = daemon._ledger.projection_coverage()  # type: ignore[union-attr]
        self.assertEqual(
            {entry["state"]["state_version"] for entry in initial.values()},
            {"durable-discovery-v1"},
        )
        self._submit_source(daemon, "source:v1-upgrade")
        upgraded = daemon._ledger.projection_coverage()  # type: ignore[union-attr]
        sequences = {
            entry["last_applied_sequence"]
            for name, entry in upgraded.items()
            if name in {"material_events", "candidates", "admissions", "capabilities"}
        }
        self.assertEqual(len(sequences), 1)
        self.assertEqual(
            {
                entry["state"]["state_version"]
                for name, entry in upgraded.items()
                if name in {"material_events", "candidates", "admissions", "capabilities"}
            },
            {"durable-discovery-v2"},
        )
        self.assertEqual(daemon._ledger.event_count(), before_start + 1)  # type: ignore[union-attr]

    def test_mixed_and_corrupt_projection_state_fail_startup_closed(self) -> None:
        for case in ("mixed", "corrupt"):
            with self.subTest(case=case):
                root = self.base / case
                root.mkdir(mode=0o700)
                original = self.runtime
                self.runtime = root
                ledger = JobLedger(root / "bridge-job-ledger.sqlite3")
                states = _empty_durable_states(state_version="durable-discovery-v1")
                if case == "mixed":
                    states["candidates"] = copy.deepcopy(states["candidates"])
                    states["candidates"]["state_version"] = "durable-discovery-v2"
                ledger._advance_a1_projections(
                    projections=states,
                    idempotency_key=f"r02c:{case}",
                    event_at="2026-07-19T05:58:00Z",
                )
                ledger.close()
                if case == "corrupt":
                    connection = sqlite3.connect(root / "bridge-job-ledger.sqlite3")
                    connection.execute(
                        "UPDATE bridge_a1_projection_state SET state_json = ?, last_applied_sequence = last_applied_sequence + 1 WHERE projection_name = ?",
                        ('{"state_version":"corrupt"}', "material_events"),
                    )
                    connection.commit()
                    connection.close()
                daemon = self._daemon()
                with self.assertRaises(ResearchdError):
                    daemon.start()
                self.assertFalse(os.path.lexists(daemon.socket_path))
                self.runtime = original

    def test_provenance_private_live_transport_spoof_and_rate_are_denied(self) -> None:
        daemon = self._daemon()
        daemon.start()
        before = daemon._ledger.event_count()  # type: ignore[union-attr]
        denied = (
            {"source_ref": "private:r02c/secret"},
            {"source_ref": "live:r02c/action"},
            {"source_ref": "https://example.invalid/unpinned"},
            {"transport_idempotency_key": "wrong-transport"},
        )
        for index, override in enumerate(denied):
            with self.subTest(override=override):
                with self.assertRaises(ControlError):
                    self._submit_source(daemon, f"deny:{index}", **override)
        self.assertEqual(daemon._ledger.event_count(), before)  # type: ignore[union-attr]

        with self.assertRaises(ControlError):
            self._request(
                daemon,
                COLLECTOR_UID,
                "submit_source_trigger",
                "spoof:role",
                {"source_trigger": _source("spoof:role", suffix="spoof")},
                extra={"role": "scout"},
            )
        for index in range(12):
            self._submit_source(daemon, f"rate:{index}")
        count_at_limit = daemon._ledger.event_count()  # type: ignore[union-attr]
        with self.assertRaises(ControlError):
            self._submit_source(daemon, "rate:overflow")
        self.assertEqual(daemon._ledger.event_count(), count_at_limit)  # type: ignore[union-attr]

    def test_expired_claim_is_refenced_and_old_token_is_stale(self) -> None:
        daemon = self._daemon()
        daemon.start()
        self._submit_source(daemon, "source:lease")
        first = self._request(
            daemon, SCOUT_UID, "claim_next_proposal", "claim:first", {}
        ).result["claim"]
        self.now += timedelta(seconds=301)
        second = self._request(
            daemon, SCOUT_UID, "claim_next_proposal", "claim:second", {}
        ).result["claim"]
        self.assertEqual(second["generation"], 2)
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        with self.assertRaises(ControlError):
            self._request(
                daemon,
                SCOUT_UID,
                "ack_proposal",
                "ack:stale",
                {
                    "material_event_ref": first["material_event_ref"],
                    "claim_token": first["claim_token"],
                },
            )

    def test_second_writer_is_denied_and_close_releases_all_resources(self) -> None:
        daemon = self._daemon()
        daemon.start()
        contender = self._daemon()
        with self.assertRaises(ResearchdError):
            contender.start()
        self.assertTrue(daemon._ledger.verify_chain())  # type: ignore[union-attr]
        daemon.close()
        self.assertFalse(os.path.lexists(daemon.socket_path))
        self.assertIsNone(daemon._ledger)
        self.assertIsNone(daemon._a1_backend)


if __name__ == "__main__":
    unittest.main()
