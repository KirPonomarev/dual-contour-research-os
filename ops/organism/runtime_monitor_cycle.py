#!/usr/bin/env python3
"""Generate and record one fresh, read-only runtime monitoring sample.

The cycle reads a consistent SQLite backup through a read-only volume mount,
projects organism state from that disposable backup, selects a terminal-aware
Pulse policy only for validated PARKED/WAIT_AUTHORITY lifecycle, and writes only
to the dedicated monitor journal.  It never opens the live ledger through
``JobLedger`` and never calls a provider.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.ledger import JobLedger, LedgerError  # noqa: E402
from research_bridge.organism import (  # noqa: E402
    OrganismManifestError,
    build_manifest_from_files,
    load_json_document,
    project_organism_state_from_ledger,
    sample_pulse,
    validate_pulse_policy,
)


_MONITOR_SPEC = importlib.util.spec_from_file_location(
    "runtime_monitor_cycle_recorder",
    Path(__file__).with_name("runtime_monitor.py"),
)
if _MONITOR_SPEC is None or _MONITOR_SPEC.loader is None:
    raise RuntimeError("runtime monitor recorder is unavailable")
_runtime_monitor = importlib.util.module_from_spec(_MONITOR_SPEC)
_MONITOR_SPEC.loader.exec_module(_runtime_monitor)

MonitorError = _runtime_monitor.MonitorError
MonitorJournal = _runtime_monitor.MonitorJournal


class MonitorCycleError(RuntimeError):
    """One stable, non-secret cycle failure."""


def _format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise MonitorCycleError("cycle clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise MonitorCycleError("runtime state hashing failed") from exc
    return digest.hexdigest()


def _consistent_backup(source: Path, destination: Path) -> str:
    if source.is_symlink() or not source.is_file():
        raise MonitorCycleError("live ledger path is invalid")
    try:
        source_uri = f"file:{source}?mode=ro"
        with closing(sqlite3.connect(source_uri, uri=True, isolation_level=None)) as live:
            live.execute("PRAGMA query_only = ON")
            with closing(sqlite3.connect(destination)) as snapshot:
                live.backup(snapshot)
                snapshot.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                snapshot.commit()
        os.chmod(destination, 0o600)
    except (OSError, sqlite3.Error) as exc:
        raise MonitorCycleError("consistent read-only ledger backup failed") from exc
    return _sha256(destination)


def select_pulse_policy(
    state: Mapping[str, object],
    active_policy: Mapping[str, object],
    terminal_policy: Mapping[str, object],
) -> Mapping[str, object]:
    """Use relaxed age only for a validated terminal lifecycle.

    Queue projections are append-only historical aggregates and may retain old
    runnable or authority-wait entries after the state projector has safely
    moved the current lifecycle to PARKED.  Active lifecycle values still use
    the short policy regardless of queue shape.
    """

    active = validate_pulse_policy(active_policy)
    terminal = validate_pulse_policy(terminal_policy)
    payload = state.get("payload")
    if not isinstance(payload, Mapping):
        raise MonitorCycleError("organism state payload is invalid")
    queue = payload.get("queue")
    if not isinstance(queue, Mapping):
        raise MonitorCycleError("organism state queue is invalid")
    lifecycle = payload.get("lifecycle_state")
    if lifecycle in {"PARKED", "WAIT_AUTHORITY"}:
        return terminal
    return active


def _runtime_sample(
    *,
    observed_at: str,
    pulse: Mapping[str, object],
    identity: Mapping[str, object],
    runtime_root: Path,
    research_state_sha256_before: str,
    research_state_sha256_after: str,
    ai_off: bool,
    provider_state: str,
    wip_count: int,
    active_core_writers: int,
    second_writer_attempts: int,
) -> dict[str, object]:
    try:
        storage = os.statvfs(runtime_root)
    except OSError as exc:
        raise MonitorCycleError("runtime storage counters are unavailable") from exc
    epoch_micros = int(
        datetime.fromisoformat(observed_at[:-1] + "+00:00").timestamp() * 1_000_000
    )
    return {
        "schema_id": "RuntimeMonitorInput",
        "schema_version": "1.0.0",
        "sample_id": f"runtime-sample:{epoch_micros}",
        "observed_at": observed_at,
        "pulse": pulse,
        "identity": dict(identity),
        "runtime": {
            "heartbeat_at": observed_at,
            "wip_count": wip_count,
            "budget_reserved_units": 0,
            "budget_limit_units": 1,
            "storage_used_bytes": (storage.f_blocks - storage.f_bavail) * storage.f_frsize,
            "storage_quota_bytes": storage.f_blocks * storage.f_frsize,
            "provider_state": provider_state,
            "ai_off": ai_off,
            "active_core_writers": active_core_writers,
            "second_writer_attempts": second_writer_attempts,
            "research_state_sha256_before": research_state_sha256_before,
            "research_state_sha256_after": research_state_sha256_after,
        },
    }


def run_cycle(
    *,
    ledger_path: Path,
    repository_root: Path,
    manifest_source_path: Path,
    deployment_projection_path: Path,
    active_pulse_policy_path: Path,
    terminal_pulse_policy_path: Path,
    monitor_policy_path: Path,
    expected_identity_path: Path,
    journal_root: Path,
    now: datetime,
    ai_off: bool,
    provider_state: str,
    wip_count: int,
    active_core_writers: int,
    second_writer_attempts: int,
) -> Mapping[str, object]:
    observed_at = _format_time(now)
    identity = load_json_document(expected_identity_path)
    environment_ref = identity.get("environment_ref")
    if not isinstance(environment_ref, str):
        raise MonitorCycleError("runtime identity environment is invalid")
    if ai_off and provider_state != "AI_OFF":
        raise MonitorCycleError("AI_OFF requires provider_state=AI_OFF")
    if not ai_off and provider_state == "AI_OFF":
        raise MonitorCycleError("AI_ON cannot claim provider_state=AI_OFF")

    with tempfile.TemporaryDirectory(prefix="runtime-monitor-cycle-") as temporary:
        temporary_root = Path(temporary)
        first = temporary_root / "source-before.sqlite3"
        working = temporary_root / "projection.sqlite3"
        second = temporary_root / "source-after.sqlite3"
        before_sha = _consistent_backup(ledger_path, first)
        shutil.copyfile(first, working)
        os.chmod(working, 0o600)

        manifest = build_manifest_from_files(
            manifest_source_path,
            deployment_projection_path,
            issued_at=observed_at,
            repository_root=repository_root,
        )
        with JobLedger(working) as ledger:
            state = project_organism_state_from_ledger(
                ledger,
                manifest,
                projected_at=observed_at,
                environment_ref=environment_ref,
                ai_enabled=not ai_off,
            )

        active_policy = load_json_document(active_pulse_policy_path)
        terminal_policy = load_json_document(terminal_pulse_policy_path)
        selected_policy = select_pulse_policy(state, active_policy, terminal_policy)
        pulse = sample_pulse(
            state,
            manifest,
            (),
            selected_policy,
            sampled_at=observed_at,
        )
        after_sha = _consistent_backup(ledger_path, second)

    sample = _runtime_sample(
        observed_at=observed_at,
        pulse=pulse,
        identity=identity,
        runtime_root=ledger_path.parent,
        research_state_sha256_before=before_sha,
        research_state_sha256_after=after_sha,
        ai_off=ai_off,
        provider_state=provider_state,
        wip_count=wip_count,
        active_core_writers=active_core_writers,
        second_writer_attempts=second_writer_attempts,
    )
    journal = MonitorJournal(
        journal_root,
        load_json_document(monitor_policy_path),
        identity,
    )
    return journal.record(sample, now=now)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and record one fresh runtime Pulse")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--manifest-source", required=True)
    parser.add_argument("--deployment-projection", required=True)
    parser.add_argument("--active-pulse-policy", required=True)
    parser.add_argument("--terminal-pulse-policy", required=True)
    parser.add_argument("--monitor-policy", required=True)
    parser.add_argument("--expected-identity", required=True)
    parser.add_argument("--journal-root", required=True)
    parser.add_argument("--provider-state", choices=("AVAILABLE", "UNAVAILABLE", "UNKNOWN", "AI_OFF"), default="AVAILABLE")
    parser.add_argument("--ai-off", action="store_true")
    parser.add_argument("--wip-count", type=int, default=1)
    parser.add_argument("--active-core-writers", type=int, default=1)
    parser.add_argument("--second-writer-attempts", type=int, default=0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        record = run_cycle(
            ledger_path=Path(args.ledger),
            repository_root=Path(args.repository_root),
            manifest_source_path=Path(args.manifest_source),
            deployment_projection_path=Path(args.deployment_projection),
            active_pulse_policy_path=Path(args.active_pulse_policy),
            terminal_pulse_policy_path=Path(args.terminal_pulse_policy),
            monitor_policy_path=Path(args.monitor_policy),
            expected_identity_path=Path(args.expected_identity),
            journal_root=Path(args.journal_root),
            now=datetime.now(timezone.utc),
            ai_off=args.ai_off,
            provider_state=args.provider_state,
            wip_count=args.wip_count,
            active_core_writers=args.active_core_writers,
            second_writer_attempts=args.second_writer_attempts,
        )
        payload = record["payload"]
        assert isinstance(payload, Mapping)
        alerts = payload["alerts"]
        assert isinstance(alerts, list)
        severities = {str(alert["severity"]) for alert in alerts}
        status = "RED" if "RED" in severities else "YELLOW" if "YELLOW" in severities else "GREEN"
        print(json.dumps({
            "status": status,
            "sequence": payload["sequence"],
            "alert_count": len(alerts),
            "record_ref": record["object_id"],
        }, sort_keys=True, separators=(",", ":")))
        return 1 if status == "RED" else 0
    except (
        LedgerError,
        MonitorCycleError,
        MonitorError,
        OrganismManifestError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as exc:
        print(f"runtime_monitor_cycle=FAIL:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
