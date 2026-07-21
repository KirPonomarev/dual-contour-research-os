from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.organism import build_manifest_from_files  # noqa: E402
from tests.test_s12_state_pulse import (  # noqa: E402
    ENVIRONMENT,
    SAMPLE_AT,
    STATE_AT,
    _capability,
    _manifest,
    _policy,
    _state,
    _thaw,
)
from research_bridge.organism import sample_pulse  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "runtime_monitor",
    ROOT / "ops" / "organism" / "runtime_monitor.py",
)
assert SPEC is not None and SPEC.loader is not None
runtime_monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime_monitor)

CYCLE_SPEC = importlib.util.spec_from_file_location(
    "runtime_monitor_cycle",
    ROOT / "ops" / "organism" / "runtime_monitor_cycle.py",
)
assert CYCLE_SPEC is not None and CYCLE_SPEC.loader is not None
runtime_monitor_cycle = importlib.util.module_from_spec(CYCLE_SPEC)
CYCLE_SPEC.loader.exec_module(runtime_monitor_cycle)

MonitorError = runtime_monitor.MonitorError
MonitorJournal = runtime_monitor.MonitorJournal
validate_policy = runtime_monitor.validate_policy
run_cycle = runtime_monitor_cycle.run_cycle
select_pulse_policy = runtime_monitor_cycle.select_pulse_policy


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _identity() -> dict[str, object]:
    return {
        "release_sha": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "config_sha256": "c" * 64,
        "policy_sha256": "d" * 64,
        "environment_ref": ENVIRONMENT,
    }


def _monitor_policy() -> dict[str, object]:
    return _load(ROOT / "ops" / "organism" / "runtime-monitor-policy.json")


def _sample(
    sample_id: str = "sample:healthy-one",
    *,
    observed_at: str = SAMPLE_AT,
    pulse: object | None = None,
) -> dict[str, object]:
    if pulse is None:
        pulse = sample_pulse(
            _state(), _manifest(), [_capability()], _policy(), sampled_at=observed_at
        )
    return {
        "schema_id": "RuntimeMonitorInput",
        "schema_version": "1.0.0",
        "sample_id": sample_id,
        "observed_at": observed_at,
        "pulse": pulse,
        "identity": _identity(),
        "runtime": {
            "heartbeat_at": observed_at,
            "wip_count": 0,
            "budget_reserved_units": 10,
            "budget_limit_units": 100,
            "storage_used_bytes": 10,
            "storage_quota_bytes": 100,
            "provider_state": "AVAILABLE",
            "ai_off": False,
            "active_core_writers": 1,
            "second_writer_attempts": 0,
            "research_state_sha256_before": "e" * 64,
            "research_state_sha256_after": "e" * 64,
        },
    }


class ObservabilityRecoveryControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "journal"

    def _journal(self) -> object:
        return MonitorJournal(self.root, _monitor_policy(), _identity())

    def test_healthy_samples_are_idempotent_and_counters_survive_restart(self) -> None:
        journal = self._journal()
        sample = _sample()
        observed = datetime.fromisoformat(SAMPLE_AT[:-1] + "+00:00")
        first = journal.record(sample, now=observed)
        retry = journal.record(sample, now=observed)
        self.assertEqual(retry, first)
        self.assertEqual(len(journal.records()), 1)
        self.assertEqual(first["payload"]["alerts"], [])
        self.assertEqual(
            first["payload"]["counters"],
            {
                "sample_count": 1,
                "alert_sample_count": 0,
                "green_samples": 1,
                "yellow_samples": 0,
                "red_samples": 0,
                "alert_counts": {},
            },
        )
        self.assertEqual(first["payload"]["monitor_research_state_writes"], 0)
        self.assertFalse(first["payload"]["grants_authority"])

        later = "2026-01-02T03:04:07Z"
        second = _sample("sample:healthy-two", observed_at=later)
        reopened = self._journal()
        recorded = reopened.record(
            second,
            now=datetime.fromisoformat(later[:-1] + "+00:00"),
        )
        self.assertEqual(recorded["payload"]["sequence"], 2)
        self.assertEqual(recorded["payload"]["counters"]["sample_count"], 2)
        self.assertEqual(recorded["payload"]["counters"]["green_samples"], 2)
        self.assertEqual(len(reopened.records()), 2)

    def test_fault_injection_alerts_every_required_runtime_dimension(self) -> None:
        stale_pulse = sample_pulse(
            _state(),
            _manifest(),
            [_capability(status="STALE", critical=True)],
            _policy(),
            sampled_at=SAMPLE_AT,
        )
        sample = _sample("sample:fault-matrix", pulse=stale_pulse)
        sample["identity"] = {**_identity(), "release_sha": "f" * 40}
        runtime = sample["runtime"]
        assert isinstance(runtime, dict)
        runtime.update(
            heartbeat_at="2026-01-02T02:50:00Z",
            wip_count=2,
            budget_reserved_units=101,
            storage_used_bytes=91,
            provider_state="UNAVAILABLE",
            active_core_writers=2,
            second_writer_attempts=1,
            research_state_sha256_after="0" * 64,
        )
        now = datetime.fromisoformat(SAMPLE_AT[:-1] + "+00:00") + timedelta(seconds=10)
        record = self._journal().record(sample, now=now)
        alerts = {item["code"]: item for item in record["payload"]["alerts"]}
        required = {
            "CLOCK_DRIFT",
            "HEARTBEAT_STALE",
            "IDENTITY_DRIFT",
            "PULSE_RED",
            "WIP_LIMIT_EXCEEDED",
            "BUDGET_LIMIT_EXCEEDED",
            "STORAGE_LIMIT",
            "PROVIDER_UNAVAILABLE",
            "SECOND_WRITER",
            "RESEARCH_STATE_CHANGED_DURING_SAMPLE",
        }
        self.assertTrue(required <= set(alerts))
        self.assertTrue(all(item["severity"] == "RED" for item in alerts.values()))
        self.assertEqual(
            sorted(record["payload"]["active_incident_refs"]),
            sorted(item["incident_ref"] for item in alerts.values()),
        )
        counters = record["payload"]["counters"]
        self.assertEqual(counters["red_samples"], 1)
        self.assertEqual(counters["alert_sample_count"], 1)
        self.assertEqual(counters["alert_counts"]["SECOND_WRITER"], 1)

    def test_unchanged_input_becomes_a_new_stale_tick_after_one_interval(self) -> None:
        journal = self._journal()
        sample = _sample("sample:stalled-producer")
        observed = datetime.fromisoformat(SAMPLE_AT[:-1] + "+00:00")
        first = journal.record(sample, now=observed)
        stale = journal.record(sample, now=observed + timedelta(seconds=181))
        self.assertEqual(first["payload"]["sequence"], 1)
        self.assertEqual(stale["payload"]["sequence"], 2)
        codes = {item["code"] for item in stale["payload"]["alerts"]}
        self.assertTrue({"CLOCK_DRIFT", "HEARTBEAT_STALE"} <= codes)
        self.assertEqual(stale["payload"]["counters"]["sample_count"], 2)
        self.assertEqual(stale["payload"]["counters"]["red_samples"], 1)

    def test_queue_pressure_is_alerted_and_ai_off_needs_no_provider(self) -> None:
        queue_state = _state(
            "GENERATING",
            queue={
                "runnable": 8,
                "waiting_authority": 0,
                "parked": 0,
                "oldest_event_at": STATE_AT,
            },
            ai_enabled=True,
        )
        queue_pulse = sample_pulse(
            queue_state, _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT
        )
        queue_record = self._journal().record(
            _sample("sample:queue-pressure", pulse=queue_pulse),
            now=datetime.fromisoformat(SAMPLE_AT[:-1] + "+00:00"),
        )
        self.assertIn(
            "QUEUE_DEGRADED",
            {item["code"] for item in queue_record["payload"]["alerts"]},
        )

        ai_time = "2026-01-02T03:04:07Z"
        ai_pulse = sample_pulse(
            _state(ai_enabled=False),
            _manifest(),
            [_capability()],
            _policy(),
            sampled_at=ai_time,
        )
        ai_sample = _sample("sample:ai-off", observed_at=ai_time, pulse=ai_pulse)
        ai_sample["runtime"]["ai_off"] = True
        ai_sample["runtime"]["provider_state"] = "AI_OFF"
        ai_record = self._journal().record(
            ai_sample,
            now=datetime.fromisoformat(ai_time[:-1] + "+00:00"),
        )
        codes = {item["code"] for item in ai_record["payload"]["alerts"]}
        self.assertNotIn("PROVIDER_UNAVAILABLE", codes)
        self.assertNotIn("AI_OFF_PROVIDER_STATE_MISMATCH", codes)

    def test_terminal_age_policy_is_selected_only_for_validated_terminal_lifecycle(self) -> None:
        active = _load(ROOT / "ops" / "organism" / "pulse-policy.json")
        terminal = _load(ROOT / "ops" / "organism" / "terminal-pulse-policy.json")
        parked = _state(
            "PARKED",
            queue={
                "runnable": 0,
                "waiting_authority": 0,
                "parked": 1,
                "oldest_event_at": STATE_AT,
            },
        )
        self.assertEqual(
            select_pulse_policy(parked, active, terminal)["policy_id"],
            "a1-safe-terminal-pulse-policy",
        )

        active_work = _state(
            "GENERATING",
            queue={
                "runnable": 1,
                "waiting_authority": 0,
                "parked": 0,
                "oldest_event_at": STATE_AT,
            },
        )
        self.assertEqual(
            select_pulse_policy(active_work, active, terminal)["policy_id"],
            "a1-read-only-pulse-policy",
        )

        parked_with_runnable_work = _state(
            "PARKED",
            queue={
                "runnable": 1,
                "waiting_authority": 0,
                "parked": 1,
                "oldest_event_at": STATE_AT,
            },
        )
        self.assertEqual(
            select_pulse_policy(parked_with_runnable_work, active, terminal)["policy_id"],
            "a1-safe-terminal-pulse-policy",
        )

        later = "2026-01-02T07:04:06Z"
        parked_pulse = sample_pulse(
            parked,
            _manifest(),
            [_capability()],
            select_pulse_policy(parked, active, terminal),
            sampled_at=later,
        )
        active_pulse = sample_pulse(
            active_work,
            _manifest(),
            [_capability()],
            select_pulse_policy(active_work, active, terminal),
            sampled_at=later,
        )
        self.assertEqual(parked_pulse["payload"]["traffic_light"], "YELLOW")
        self.assertEqual(active_pulse["payload"]["traffic_light"], "RED")

    def test_fresh_cycle_reads_a_consistent_backup_and_writes_only_monitor_journal(self) -> None:
        from research_bridge.ledger import JobLedger

        ledger_path = Path(self.temporary.name) / "runtime" / "bridge-job-ledger.sqlite3"
        ledger_path.parent.mkdir(mode=0o700)
        identity_path = Path(self.temporary.name) / "runtime-identity.json"
        identity_path.write_text(json.dumps(_identity()), encoding="utf-8")
        os.chmod(identity_path, 0o600)
        observed = datetime.fromisoformat(SAMPLE_AT[:-1] + "+00:00")

        with JobLedger(ledger_path) as live:
            before = live.event_count()
            record = run_cycle(
                ledger_path=ledger_path,
                repository_root=ROOT,
                manifest_source_path=ROOT / "ops" / "organism" / "component-declarations.json",
                deployment_projection_path=ROOT / "ops" / "organism" / "deployment-projection.json",
                active_pulse_policy_path=ROOT / "ops" / "organism" / "pulse-policy.json",
                terminal_pulse_policy_path=ROOT / "ops" / "organism" / "terminal-pulse-policy.json",
                monitor_policy_path=ROOT / "ops" / "organism" / "runtime-monitor-policy.json",
                expected_identity_path=identity_path,
                journal_root=self.root,
                now=observed,
                ai_off=False,
                provider_state="AVAILABLE",
                wip_count=1,
                active_core_writers=1,
                second_writer_attempts=0,
            )
            self.assertEqual(live.event_count(), before)

        codes = {item["code"] for item in record["payload"]["alerts"]}
        self.assertNotIn("RESEARCH_STATE_CHANGED_DURING_SAMPLE", codes)
        self.assertNotIn("CLOCK_DRIFT", codes)
        self.assertNotIn("HEARTBEAT_STALE", codes)
        self.assertEqual(record["payload"]["monitor_research_state_writes"], 0)
        self.assertFalse(record["payload"]["grants_authority"])
        self.assertEqual(len(MonitorJournal(self.root, _monitor_policy(), _identity()).records()), 1)

    def test_reused_sample_or_tampered_chain_fails_closed(self) -> None:
        journal = self._journal()
        observed = datetime.fromisoformat(SAMPLE_AT[:-1] + "+00:00")
        sample = _sample()
        journal.record(sample, now=observed)
        changed = _thaw(sample)
        assert isinstance(changed, dict)
        changed["runtime"]["wip_count"] = 1
        with self.assertRaisesRegex(MonitorError, "sample_id was reused"):
            journal.record(changed, now=observed)

        record_path = next(self.root.glob("*.json"))
        value = json.loads(record_path.read_text(encoding="utf-8"))
        value["payload"]["counters"]["sample_count"] = 99
        record_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(MonitorError, "chain or counters"):
            self._journal().records()

    def test_policy_topology_and_units_are_scheduled_but_non_authoritative(self) -> None:
        policy = validate_policy(_monitor_policy())
        self.assertFalse(policy["grants_authority"])
        self.assertEqual(policy["sample_interval_seconds"], 60)
        manifest = build_manifest_from_files(
            ROOT / "ops" / "organism" / "component-declarations.json",
            ROOT / "ops" / "organism" / "deployment-projection.json",
            issued_at="2026-07-19T16:15:00Z",
            repository_root=ROOT,
        )
        components = {
            item["component_id"]: item for item in manifest["payload"]["components"]
        }
        monitor = components["runtime-pulse-monitor"]
        self.assertEqual(monitor["access"]["network"], "NONE")
        self.assertEqual(monitor["access"]["write_refs"], ("monitor:owner-only-journal",))
        self.assertEqual(monitor["authority_ceiling"], "NON_AUTHORITATIVE_EVIDENCE_ONLY")

        monitor_service = (ROOT / "ops/deploy/research-os-runtime-monitor.service").read_text()
        monitor_timer = (ROOT / "ops/deploy/research-os-runtime-monitor.timer").read_text()
        backup_service = (ROOT / "ops/deploy/research-os-backup.service").read_text()
        backup_timer = (ROOT / "ops/deploy/research-os-backup.timer").read_text()
        self.assertIn("OnUnitActiveSec=60s", monitor_timer)
        self.assertIn("Persistent=true", monitor_timer)
        self.assertIn("WantedBy=timers.target", monitor_timer)
        self.assertIn("RESEARCH_OS_MONITOR_JOURNAL_VOLUME", monitor_service)
        self.assertIn("RESEARCH_OS_MONITOR_IDENTITY_VOLUME", monitor_service)
        self.assertIn("runtime_monitor_cycle.py", monitor_service)
        self.assertIn("target=/var/lib/research-os,readonly", monitor_service)
        self.assertIn("--network=none", monitor_service)
        self.assertIn("mode=0700,uid=10001,gid=10001", monitor_service)
        self.assertNotIn("PrivateDevices=yes", monitor_service)
        self.assertNotIn("PrivateTmp=yes", monitor_service)
        self.assertNotIn("source=%h/.config/research-os/runtime-identity.json", monitor_service)
        self.assertNotIn("researchd.sock", monitor_service)
        self.assertNotIn("bridge_job_ledger", monitor_service)
        self.assertIn("/release_backup_restore.py backup ", backup_service)
        for forbidden in (" restore ", " drill ", " delete ", " prune "):
            self.assertNotIn(forbidden, backup_service)
        self.assertIn("OnCalendar=*-*-* 03:15:00 UTC", backup_timer)
        self.assertIn("Persistent=true", backup_timer)
        self.assertIn("RandomizedDelaySec=900s", backup_timer)

        recovery = _load(ROOT / "ops/release/monitoring-recovery-policy.json")
        self.assertFalse(recovery["observation_windows_started"])
        self.assertFalse(recovery["external_action_authority"])
        self.assertFalse(recovery["backup"]["restore_scheduled"])
        self.assertEqual(recovery["supervisor"]["research_state_writers"], 1)


if __name__ == "__main__":
    unittest.main()
