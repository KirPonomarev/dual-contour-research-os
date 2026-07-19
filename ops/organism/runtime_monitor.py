#!/usr/bin/env python3
"""Read-only Pulse evaluator with an owner-only immutable monitoring journal.

The monitor never opens the research ledger, CAS, provider store, or control
socket.  It validates one already-issued Pulse plus sanitized host counters and
writes only to its dedicated monitoring directory.  Records are hash chained,
restart-replayed, idempotent by sample identity, and non-authoritative.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.organism import validate_pulse_sample  # noqa: E402


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_RE = re.compile(r"^[a-f0-9]{40}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[-:][a-z0-9]+)*$")
_POLICY_KEYS = {
    "schema_id", "schema_version", "policy_id", "sample_interval_seconds",
    "clock_skew_alert_seconds", "heartbeat_stale_seconds", "wip_limit",
    "storage_warn_percent", "storage_red_percent", "budget_warn_percent",
    "maximum_records", "backup_schedule_ref", "grants_authority",
}
_IDENTITY_KEYS = {
    "release_sha", "image_digest", "config_sha256", "policy_sha256",
    "environment_ref",
}
_RUNTIME_KEYS = {
    "heartbeat_at", "wip_count", "budget_reserved_units", "budget_limit_units",
    "storage_used_bytes", "storage_quota_bytes", "provider_state", "ai_off",
    "active_core_writers", "second_writer_attempts",
    "research_state_sha256_before", "research_state_sha256_after",
}
_INPUT_KEYS = {
    "schema_id", "schema_version", "sample_id", "observed_at", "pulse",
    "identity", "runtime",
}
_DOCUMENT_KEYS = {
    "schema_id", "schema_version", "object_id", "issued_at", "issuer",
    "contour", "classification", "payload", "integrity",
}
_PAYLOAD_KEYS = {
    "sequence", "sample_id", "sample_sha256", "observed_at", "recorded_at", "pulse_ref",
    "pulse_traffic_light", "identity_sha256", "alerts", "active_incident_refs",
    "counters", "previous_record_sha256", "monitor_research_state_writes",
    "grants_authority",
}
_COUNTER_KEYS = {
    "sample_count", "alert_sample_count", "green_samples", "yellow_samples",
    "red_samples", "alert_counts",
}
_GENESIS = "0" * 64


class MonitorError(RuntimeError):
    """One stable, non-secret monitoring validation failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MonitorError("non-canonical monitoring data") from exc


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise MonitorError(f"{label} shape is invalid")
    return {str(key): item for key, item in value.items()}


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise MonitorError(f"{label} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise MonitorError(f"{label} must be RFC3339 UTC") from exc
    if parsed.tzinfo is None:
        raise MonitorError(f"{label} must be RFC3339 UTC")
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise MonitorError("monitor clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > 2**53 - 1:
        raise MonitorError(f"{label} is invalid")
    return value


def _strict_json(path: Path) -> dict[str, object]:
    raw = Path(path)
    if raw.is_symlink() or not raw.is_file():
        raise MonitorError("monitor input file is invalid")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise MonitorError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MonitorError("monitor input file is invalid") from exc
    if not isinstance(value, dict):
        raise MonitorError("monitor input must be an object")
    return value


def validate_policy(value: Mapping[str, object]) -> dict[str, object]:
    policy = _exact(value, _POLICY_KEYS, "monitor policy")
    if (
        policy["schema_id"] != "RuntimeMonitorPolicy"
        or policy["schema_version"] != "1.0.0"
        or policy["grants_authority"] is not False
        or not isinstance(policy["policy_id"], str)
        or _ID_RE.fullmatch(policy["policy_id"]) is None
        or not isinstance(policy["backup_schedule_ref"], str)
        or not policy["backup_schedule_ref"].startswith("systemd:")
    ):
        raise MonitorError("monitor policy identity is invalid")
    for name, minimum in (
        ("sample_interval_seconds", 1), ("clock_skew_alert_seconds", 1),
        ("heartbeat_stale_seconds", 1), ("wip_limit", 1),
        ("storage_warn_percent", 1), ("storage_red_percent", 2),
        ("budget_warn_percent", 1), ("maximum_records", 1),
    ):
        policy[name] = _integer(policy[name], f"policy.{name}", minimum=minimum)
    if not (
        policy["storage_warn_percent"] < policy["storage_red_percent"] <= 100
        and policy["budget_warn_percent"] < 100
        and policy["maximum_records"] <= 1_000_000
    ):
        raise MonitorError("monitor policy thresholds are invalid")
    return policy


def validate_identity(value: Mapping[str, object]) -> dict[str, object]:
    identity = _exact(value, _IDENTITY_KEYS, "runtime identity")
    if not isinstance(identity["release_sha"], str) or _GIT_RE.fullmatch(identity["release_sha"]) is None:
        raise MonitorError("release identity is invalid")
    for name in ("config_sha256", "policy_sha256"):
        if not isinstance(identity[name], str) or _SHA256_RE.fullmatch(identity[name]) is None:
            raise MonitorError(f"{name} is invalid")
    image = identity["image_digest"]
    if not isinstance(image, str) or not image.startswith("sha256:") or _SHA256_RE.fullmatch(image[7:]) is None:
        raise MonitorError("image identity is invalid")
    environment = identity["environment_ref"]
    if not isinstance(environment, str) or not environment.startswith("profile:"):
        raise MonitorError("environment identity is invalid")
    return identity


def validate_monitor_input(value: Mapping[str, object]) -> dict[str, object]:
    sample = _exact(value, _INPUT_KEYS, "monitor input")
    if sample["schema_id"] != "RuntimeMonitorInput" or sample["schema_version"] != "1.0.0":
        raise MonitorError("monitor input identity is invalid")
    if not isinstance(sample["sample_id"], str) or _ID_RE.fullmatch(sample["sample_id"]) is None:
        raise MonitorError("sample_id is invalid")
    _time(sample["observed_at"], "observed_at")
    sample["pulse"] = validate_pulse_sample(sample["pulse"])  # type: ignore[arg-type]
    sample["identity"] = validate_identity(sample["identity"])  # type: ignore[arg-type]
    runtime = _exact(sample["runtime"], _RUNTIME_KEYS, "runtime counters")
    _time(runtime["heartbeat_at"], "runtime.heartbeat_at")
    for name in (
        "wip_count", "budget_reserved_units", "budget_limit_units", "storage_used_bytes",
        "storage_quota_bytes", "active_core_writers", "second_writer_attempts",
    ):
        runtime[name] = _integer(runtime[name], f"runtime.{name}")
    if runtime["budget_limit_units"] == 0 or runtime["storage_quota_bytes"] == 0:
        raise MonitorError("runtime limits must be positive")
    if runtime["provider_state"] not in {"AVAILABLE", "UNAVAILABLE", "UNKNOWN", "AI_OFF"}:
        raise MonitorError("provider_state is invalid")
    if not isinstance(runtime["ai_off"], bool):
        raise MonitorError("ai_off must be boolean")
    for name in ("research_state_sha256_before", "research_state_sha256_after"):
        if not isinstance(runtime[name], str) or _SHA256_RE.fullmatch(runtime[name]) is None:
            raise MonitorError(f"runtime.{name} is invalid")
    sample["runtime"] = runtime
    return sample


def _alert(code: str, severity: str, identity_sha256: str) -> dict[str, str]:
    material = {"code": code, "identity_sha256": identity_sha256}
    return {
        "code": code,
        "severity": severity,
        "incident_ref": "incident:runtime-monitor:" + _digest(material),
    }


def evaluate_alerts(
    sample: Mapping[str, object],
    policy: Mapping[str, object],
    expected_identity: Mapping[str, object],
    *,
    now: datetime,
) -> list[dict[str, str]]:
    value = validate_monitor_input(sample)
    limits = validate_policy(policy)
    expected = validate_identity(expected_identity)
    observed = value["identity"]
    runtime = value["runtime"]
    pulse = value["pulse"]
    assert isinstance(observed, Mapping) and isinstance(runtime, Mapping) and isinstance(pulse, Mapping)
    payload = pulse["payload"]
    assert isinstance(payload, Mapping)
    identity_sha = _digest(expected)
    alerts: dict[str, dict[str, str]] = {}

    def add(code: str, severity: str) -> None:
        alerts[code] = _alert(code, severity, identity_sha)

    observed_at = _time(value["observed_at"], "observed_at")
    if now.tzinfo is None:
        raise MonitorError("monitor clock must be timezone-aware")
    clock_skew = abs(int((now.astimezone(timezone.utc) - observed_at).total_seconds()))
    if clock_skew > limits["clock_skew_alert_seconds"]:
        add("CLOCK_DRIFT", "RED")
    heartbeat_age = int(
        (
            now.astimezone(timezone.utc)
            - _time(runtime["heartbeat_at"], "heartbeat_at")
        ).total_seconds()
    )
    if heartbeat_age < 0 or heartbeat_age > limits["heartbeat_stale_seconds"]:
        add("HEARTBEAT_STALE", "RED")
    if observed != expected or payload.get("environment_ref") != expected["environment_ref"]:
        add("IDENTITY_DRIFT", "RED")
    traffic = payload.get("traffic_light")
    if traffic == "RED":
        add("PULSE_RED", "RED")
    elif traffic == "YELLOW":
        add("PULSE_YELLOW", "YELLOW")
    if any(code in payload.get("reason_codes", ()) for code in ("QUEUE_STUCK", "QUEUE_PRESSURE")):
        add("QUEUE_DEGRADED", "RED" if "QUEUE_STUCK" in payload.get("reason_codes", ()) else "YELLOW")
    if runtime["wip_count"] > limits["wip_limit"]:
        add("WIP_LIMIT_EXCEEDED", "RED")
    budget_percent = 100 * runtime["budget_reserved_units"] // runtime["budget_limit_units"]
    if budget_percent > 100:
        add("BUDGET_LIMIT_EXCEEDED", "RED")
    elif budget_percent >= limits["budget_warn_percent"]:
        add("BUDGET_PRESSURE", "YELLOW")
    storage_percent = 100 * runtime["storage_used_bytes"] // runtime["storage_quota_bytes"]
    if storage_percent >= limits["storage_red_percent"]:
        add("STORAGE_LIMIT", "RED")
    elif storage_percent >= limits["storage_warn_percent"]:
        add("STORAGE_PRESSURE", "YELLOW")
    if runtime["ai_off"] is True:
        if runtime["provider_state"] != "AI_OFF":
            add("AI_OFF_PROVIDER_STATE_MISMATCH", "RED")
    elif runtime["provider_state"] != "AVAILABLE":
        add("PROVIDER_UNAVAILABLE", "RED")
    if runtime["active_core_writers"] != 1 or runtime["second_writer_attempts"] != 0:
        add("SECOND_WRITER", "RED")
    if runtime["research_state_sha256_before"] != runtime["research_state_sha256_after"]:
        add("RESEARCH_STATE_CHANGED_DURING_SAMPLE", "RED")
    return [alerts[code] for code in sorted(alerts)]


class MonitorJournal:
    """Hash-chained, monitoring-only record store with restart replay."""

    def __init__(self, root: Path, policy: Mapping[str, object], expected_identity: Mapping[str, object]) -> None:
        self.root = Path(root)
        self.policy = validate_policy(policy)
        self.expected_identity = validate_identity(expected_identity)
        if self.root.is_symlink():
            raise MonitorError("monitor root cannot be a symlink")
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            mode = stat.S_IMODE(self.root.stat().st_mode)
        except OSError as exc:
            raise MonitorError("monitor root is unavailable") from exc
        if mode & 0o077:
            raise MonitorError("monitor root must be owner-only")

    def record(self, sample: Mapping[str, object], *, now: datetime) -> Mapping[str, object]:
        value = validate_monitor_input(sample)
        input_sha = _digest(value)
        if now.tzinfo is None:
            raise MonitorError("monitor clock must be timezone-aware")
        recorded_at = _format_time(now)
        bucket = int(now.astimezone(timezone.utc).timestamp()) // self.policy["sample_interval_seconds"]
        journal_sample_id = f"{value['sample_id']}:monitor-bucket-{bucket}"
        lock_path = self.root / ".monitor.lock"
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise MonitorError("monitor lock is unavailable") from exc
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            records = self._load_records()
            for record in records:
                payload = record["payload"]
                assert isinstance(payload, Mapping)
                if payload["sample_id"] != journal_sample_id:
                    continue
                if payload["sample_sha256"] != input_sha:
                    raise MonitorError("sample_id was reused with different input")
                return record
            if len(records) >= self.policy["maximum_records"]:
                raise MonitorError("monitor journal capacity reached")
            alerts = evaluate_alerts(
                value, self.policy, self.expected_identity, now=now
            )
            previous = records[-1] if records else None
            counters = self._next_counters(previous, alerts)
            pulse = value["pulse"]
            assert isinstance(pulse, Mapping)
            pulse_payload = pulse["payload"]
            assert isinstance(pulse_payload, Mapping)
            previous_sha = (
                previous["integrity"]["record_sha256"]  # type: ignore[index]
                if previous is not None
                else _GENESIS
            )
            payload = {
                "sequence": len(records) + 1,
                "sample_id": journal_sample_id,
                "sample_sha256": input_sha,
                "observed_at": value["observed_at"],
                "recorded_at": recorded_at,
                "pulse_ref": pulse["object_id"],
                "pulse_traffic_light": pulse_payload["traffic_light"],
                "identity_sha256": _digest(self.expected_identity),
                "alerts": alerts,
                "active_incident_refs": sorted(alert["incident_ref"] for alert in alerts),
                "counters": counters,
                "previous_record_sha256": previous_sha,
                "monitor_research_state_writes": 0,
                "grants_authority": False,
            }
            record_sha = _digest(payload)
            document = {
                "schema_id": "RuntimeMonitorRecord",
                "schema_version": "1.0.0",
                "object_id": f"runtime-monitor-record:{record_sha}",
                "issued_at": recorded_at,
                "issuer": "read-only-runtime-monitor",
                "contour": "governance",
                "classification": "D1_INTERNAL_SANITIZED",
                "payload": payload,
                "integrity": {
                    "record_sha256": record_sha,
                    "parent_refs": [
                        f"monitor-record:sha256:{previous_sha}",
                        str(pulse["object_id"]),
                        f"runtime-input:sha256:{input_sha}",
                    ],
                },
            }
            self._write_record(document)
            return document
        finally:
            os.close(descriptor)

    def records(self) -> tuple[Mapping[str, object], ...]:
        return tuple(self._load_records())

    @staticmethod
    def _next_counters(previous: Mapping[str, object] | None, alerts: Sequence[Mapping[str, str]]) -> dict[str, object]:
        if previous is None:
            counters: dict[str, object] = {
                "sample_count": 0, "alert_sample_count": 0, "green_samples": 0,
                "yellow_samples": 0, "red_samples": 0, "alert_counts": {},
            }
        else:
            source = previous["payload"]["counters"]  # type: ignore[index]
            counters = json.loads(_canonical(source))
        counters["sample_count"] += 1  # type: ignore[operator]
        severities = {alert["severity"] for alert in alerts}
        if alerts:
            counters["alert_sample_count"] += 1  # type: ignore[operator]
        severity = "RED" if "RED" in severities else "YELLOW" if "YELLOW" in severities else "GREEN"
        counters[f"{severity.lower()}_samples"] += 1  # type: ignore[operator]
        alert_counts = counters["alert_counts"]
        assert isinstance(alert_counts, dict)
        for alert in alerts:
            code = alert["code"]
            alert_counts[code] = alert_counts.get(code, 0) + 1
        return counters

    def _load_records(self) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        previous_sha = _GENESIS
        expected_counters: dict[str, object] | None = None
        paths = sorted(self.root.glob("[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-*.json"))
        if set(paths) != set(self.root.glob("*.json")):
            raise MonitorError("monitor journal contains an unexpected record")
        for sequence, path in enumerate(paths, start=1):
            if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise MonitorError("monitor record mode is invalid")
            document = _exact(_strict_json(path), _DOCUMENT_KEYS, "monitor record")
            if (
                document["schema_id"] != "RuntimeMonitorRecord"
                or document["schema_version"] != "1.0.0"
                or document["issuer"] != "read-only-runtime-monitor"
                or document["contour"] != "governance"
                or document["classification"] != "D1_INTERNAL_SANITIZED"
            ):
                raise MonitorError("monitor record identity is invalid")
            payload = _exact(document["payload"], _PAYLOAD_KEYS, "monitor record payload")
            alerts = payload["alerts"]
            if not isinstance(alerts, list) or any(
                not isinstance(alert, Mapping) or set(alert) != {"code", "severity", "incident_ref"}
                for alert in alerts
            ):
                raise MonitorError("monitor alerts are invalid")
            if any(
                not isinstance(alert["code"], str)
                or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", alert["code"]) is None
                or alert["severity"] not in {"YELLOW", "RED"}
                or not isinstance(alert["incident_ref"], str)
                or alert["incident_ref"] != _alert(
                    alert["code"], alert["severity"], str(payload["identity_sha256"])
                )["incident_ref"]
                for alert in alerts
            ):
                raise MonitorError("monitor alert identity is invalid")
            counters = _exact(payload["counters"], _COUNTER_KEYS, "monitor counters")
            expected_counters = self._next_counters(records[-1] if records else None, alerts)  # type: ignore[arg-type]
            record_sha = _digest(payload)
            integrity = document["integrity"]
            if not isinstance(integrity, Mapping) or set(integrity) != {"record_sha256", "parent_refs"}:
                raise MonitorError("monitor record integrity is invalid")
            if (
                payload["sequence"] != sequence
                or payload["previous_record_sha256"] != previous_sha
                or counters != expected_counters
                or not isinstance(payload["sample_sha256"], str)
                or _SHA256_RE.fullmatch(payload["sample_sha256"]) is None
                or not isinstance(payload["identity_sha256"], str)
                or _SHA256_RE.fullmatch(payload["identity_sha256"]) is None
                or payload["pulse_traffic_light"] not in {"GREEN", "YELLOW", "RED"}
                or payload["active_incident_refs"]
                != sorted(alert["incident_ref"] for alert in alerts)
                or document["issued_at"] != payload["recorded_at"]
                or integrity["record_sha256"] != record_sha
                or document["object_id"] != f"runtime-monitor-record:{record_sha}"
                or path.name != f"{sequence:08d}-{record_sha}.json"
                or payload["monitor_research_state_writes"] != 0
                or payload["grants_authority"] is not False
            ):
                raise MonitorError("monitor record chain or counters are invalid")
            expected_parents = [
                f"monitor-record:sha256:{previous_sha}",
                str(payload["pulse_ref"]),
                f"runtime-input:sha256:{payload['sample_sha256']}",
            ]
            if integrity["parent_refs"] != expected_parents:
                raise MonitorError("monitor record parent refs are invalid")
            previous_sha = record_sha
            document["payload"] = payload
            records.append(document)
        return records

    def _write_record(self, document: Mapping[str, object]) -> None:
        sequence = document["payload"]["sequence"]  # type: ignore[index]
        record_sha = document["integrity"]["record_sha256"]  # type: ignore[index]
        final = self.root / f"{sequence:08d}-{record_sha}.json"
        temporary = self.root / f".{sequence:08d}-{record_sha}.tmp"
        data = _canonical(document) + b"\n"
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                remaining = memoryview(data)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise MonitorError("monitor record write failed")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.link(temporary, final)
            os.unlink(temporary)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, MonitorError) as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            if isinstance(exc, MonitorError):
                raise
            raise MonitorError("monitor record commit failed") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record one sanitized runtime Pulse")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--expected-identity", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--journal-root", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        sample = _strict_json(Path(args.input))
        _time(sample.get("observed_at"), "observed_at")
        journal = MonitorJournal(
            Path(args.journal_root),
            _strict_json(Path(args.policy)),
            _strict_json(Path(args.expected_identity)),
        )
        record = journal.record(sample, now=datetime.now(timezone.utc))
        payload = record["payload"]
        assert isinstance(payload, Mapping)
        print(json.dumps({
            "status": "RECORDED",
            "sequence": payload["sequence"],
            "alert_count": len(payload["alerts"]),  # type: ignore[arg-type]
            "record_ref": record["object_id"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except MonitorError as exc:
        print(f"runtime_monitor=FAIL:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
