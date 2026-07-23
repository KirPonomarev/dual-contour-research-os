#!/usr/bin/env python3
"""Strict read-only BridgeObservationReadiness/1.0.0 projection.

This tool projects Bridge-owned observation readiness from sanitized public
Bridge inputs only. It never grants authority, never promotes, never writes,
never starts timers, never consumes Market/Security/domain health inputs, and
never claims long-window completion.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_RE = re.compile(r"^[a-f0-9]{40}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[A-Za-z0-9][A-Za-z0-9._:@/+%-]{0,1023}$")
_FORBIDDEN_FIELDS = {"domain_health", "market", "security"}
_REQUEST_KEYS = {
    "schema_id",
    "schema_version",
    "now",
    "release_ref",
    "runtime_ref",
    "policy_ref",
    "observation_policy_sha256",
}
_RELEASE_KEYS = {
    "schema_id",
    "schema_version",
    "release_ref",
    "release_sha",
    "runtime_ref",
    "runtime_policy_sha256",
    "observation_policy_ref",
    "observation_policy_sha256",
    "valid_until",
}
_RUNTIME_KEYS = {
    "schema_id",
    "schema_version",
    "runtime_ref",
    "release_sha",
    "runtime_policy_sha256",
    "observation_policy_sha256",
    "input_sha256",
    "valid_until",
}
_MONITOR_KEYS = {
    "schema_id",
    "schema_version",
    "runtime_ref",
    "release_sha",
    "observation_policy_sha256",
    "monitor_input_sha256",
    "valid_until",
}
_SIGNAL_KEYS = {
    "schema_id",
    "schema_version",
    "signal_ref",
    "ready_for_observation",
    "facts",
    "valid_until",
}
_REQUIRED_INPUTS = (
    "bridge_release_identity",
    "bridge_runtime_binding",
    "bridge_monitor_projection",
)
_OPTIONAL_INPUTS = ("bridge_readiness_signal",)
_NONBLOCKING_FACT_KEYS = {"OPERATIONALLY_PROVEN", "long_windows_complete"}
_FALSE = object()


class BridgeObservationReadinessError(RuntimeError):
    """A stable fail-closed validation failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BridgeObservationReadinessError("document is not canonical JSON data") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise BridgeObservationReadinessError(f"{label} shape is invalid")
    return json.loads(_canonical(value))


def _checked(call: object, *args: object) -> object:
    if not callable(call):
        raise BridgeObservationReadinessError("validator is not callable")
    try:
        return call(*args)
    except BridgeObservationReadinessError:
        return _FALSE


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BridgeObservationReadinessError(f"{label} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BridgeObservationReadinessError(f"{label} must be RFC3339 UTC") from exc
    if parsed.tzinfo is None:
        raise BridgeObservationReadinessError(f"{label} must be RFC3339 UTC")
    return parsed.astimezone(timezone.utc)


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise BridgeObservationReadinessError(f"{label} must be SHA-256")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_RE.fullmatch(value) is None:
        raise BridgeObservationReadinessError(f"{label} must be a git SHA")
    return value


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise BridgeObservationReadinessError(f"{label} must be a normalized reference")
    lowered = value.lower()
    if any(marker in lowered for marker in ("credential", "secret", "raw-response", "runtime-db", "/home/", "/var/lib/")):
        raise BridgeObservationReadinessError(f"{label} crosses the public evidence boundary")
    return value


def _forbidden_scan(value: object, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise BridgeObservationReadinessError(f"{label} keys must be strings")
            if key in _FORBIDDEN_FIELDS:
                raise BridgeObservationReadinessError(f"{label} contains forbidden domain field {key}")
            _forbidden_scan(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _forbidden_scan(item, f"{label}[{index}]")


def _load(path: Path) -> dict[str, object]:
    raw = Path(path)
    if raw.is_symlink() or not raw.is_file():
        raise BridgeObservationReadinessError("JSON input is not a regular file")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise BridgeObservationReadinessError("JSON input contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BridgeObservationReadinessError("JSON input is invalid") from exc
    if not isinstance(value, dict):
        raise BridgeObservationReadinessError("JSON input must be an object")
    return value


def evaluate(request: object) -> dict[str, object]:
    _forbidden_scan(request, "request envelope")
    document = _exact(request, {"request", "inputs"}, "request envelope")
    meta = _exact(document["request"], _REQUEST_KEYS, "request")
    if meta["schema_id"] != "BridgeObservationReadinessRequest" or meta["schema_version"] != "1.0.0":
        raise BridgeObservationReadinessError("request identity is invalid")
    now = _time(meta["now"], "request.now")
    release_ref = _ref(meta["release_ref"], "request.release_ref")
    runtime_ref = _ref(meta["runtime_ref"], "request.runtime_ref")
    policy_ref = _ref(meta["policy_ref"], "request.policy_ref")
    policy_sha = _sha(meta["observation_policy_sha256"], "request.observation_policy_sha256")

    inputs = document["inputs"]
    if not isinstance(inputs, Mapping):
        raise BridgeObservationReadinessError("inputs must be an object")
    allowed = set(_REQUIRED_INPUTS + _OPTIONAL_INPUTS)
    if not set(inputs) <= allowed:
        raise BridgeObservationReadinessError("inputs contain an unexpected input name")

    reasons: set[str] = set()
    parsed: dict[str, dict[str, object]] = {}
    bindings: dict[str, dict[str, str]] = {}
    release_sha: str | None = None
    for name in _REQUIRED_INPUTS:
        if name not in inputs:
            reasons.add("MISSING_INPUT")
            continue
        if name == "bridge_release_identity":
            keys = _RELEASE_KEYS
            schema_id = "BridgeReleaseIdentity"
        elif name == "bridge_runtime_binding":
            keys = _RUNTIME_KEYS
            schema_id = "BridgeRuntimeBinding"
        else:
            keys = _MONITOR_KEYS
            schema_id = "BridgeMonitorProjection"
        try:
            item = _exact(inputs[name], keys, f"inputs.{name}")
        except BridgeObservationReadinessError:
            reasons.add("MALFORMED_INPUT")
            continue
        if item["schema_id"] != schema_id or item["schema_version"] != "1.0.0":
            reasons.add("MALFORMED_INPUT")
            continue
        valid = True
        if name == "bridge_release_identity":
            checked_release_ref = _checked(_ref, item["release_ref"], "inputs.bridge_release_identity.release_ref")
            checked_runtime_ref = _checked(_ref, item["runtime_ref"], "inputs.bridge_release_identity.runtime_ref")
            checked_policy_ref = _checked(_ref, item["observation_policy_ref"], "inputs.bridge_release_identity.observation_policy_ref")
            checked_runtime_policy_sha = _checked(_sha, item["runtime_policy_sha256"], "inputs.bridge_release_identity.runtime_policy_sha256")
            if checked_release_ref is _FALSE or checked_runtime_ref is _FALSE or checked_policy_ref is _FALSE or checked_runtime_policy_sha is _FALSE:
                reasons.add("MALFORMED_INPUT")
                valid = False
            elif checked_release_ref != release_ref:
                reasons.add("RELEASE_IDENTITY_MISMATCH")
                valid = False
            if checked_runtime_ref is not _FALSE and checked_runtime_ref != runtime_ref:
                reasons.add("RUNTIME_IDENTITY_MISMATCH")
                valid = False
            if checked_policy_ref is not _FALSE and checked_policy_ref != policy_ref:
                reasons.add("POLICY_REF_MISMATCH")
                valid = False
        else:
            checked_runtime_ref = _checked(_ref, item["runtime_ref"], f"inputs.{name}.runtime_ref")
            if checked_runtime_ref is _FALSE:
                reasons.add("MALFORMED_INPUT")
                valid = False
            elif checked_runtime_ref != runtime_ref:
                reasons.add("RUNTIME_IDENTITY_MISMATCH")
                valid = False
            if name == "bridge_runtime_binding":
                if _checked(_sha, item["input_sha256"], "inputs.bridge_runtime_binding.input_sha256") is _FALSE:
                    reasons.add("MALFORMED_INPUT")
                    valid = False
            else:
                if _checked(_sha, item["monitor_input_sha256"], "inputs.bridge_monitor_projection.monitor_input_sha256") is _FALSE:
                    reasons.add("MALFORMED_INPUT")
                    valid = False
        checked_valid_until = _checked(_time, item["valid_until"], f"inputs.{name}.valid_until")
        checked_policy_sha = _checked(_sha, item["observation_policy_sha256"], f"inputs.{name}.observation_policy_sha256")
        checked_item_release_sha = _checked(_git_sha, item["release_sha"], f"inputs.{name}.release_sha")
        if checked_valid_until is _FALSE or checked_policy_sha is _FALSE or checked_item_release_sha is _FALSE:
            reasons.add("MALFORMED_INPUT")
            valid = False
        elif checked_valid_until <= now:
            reasons.add("STALE_INPUT")
            valid = False
        if checked_policy_sha is not _FALSE and checked_policy_sha != policy_sha:
            reasons.add("POLICY_HASH_MISMATCH")
            valid = False
        if checked_item_release_sha is not _FALSE:
            if name == "bridge_release_identity":
                release_sha = checked_item_release_sha
            elif release_sha is not None and checked_item_release_sha != release_sha:
                reasons.add("RELEASE_IDENTITY_MISMATCH")
                valid = False
        if valid:
            parsed[name] = item
            if name == "bridge_release_identity":
                bindings["release"] = {"role": "release", "ref": release_ref, "input_sha256": canonical_sha256(item)}
            elif name == "bridge_runtime_binding":
                bindings["runtime"] = {"role": "runtime", "ref": runtime_ref, "input_sha256": canonical_sha256(item)}
            else:
                bindings["monitor"] = {"role": "monitor", "ref": runtime_ref, "input_sha256": canonical_sha256(item)}

    signal: dict[str, object] | None = None
    signal_ok = False
    if "bridge_readiness_signal" in inputs:
        try:
            signal = _exact(inputs["bridge_readiness_signal"], _SIGNAL_KEYS, "inputs.bridge_readiness_signal")
        except BridgeObservationReadinessError:
            reasons.add("MALFORMED_INPUT")
            signal = None
        if signal is not None:
            if signal["schema_id"] != "BridgeReadinessSignal" or signal["schema_version"] != "1.0.0":
                reasons.add("MALFORMED_INPUT")
                signal = None
        if signal is not None:
            checked_signal_ref = _checked(_ref, signal["signal_ref"], "inputs.bridge_readiness_signal.signal_ref")
            checked_signal_valid_until = _checked(_time, signal["valid_until"], "inputs.bridge_readiness_signal.valid_until")
            if checked_signal_ref is _FALSE or not isinstance(signal["ready_for_observation"], bool) or checked_signal_valid_until is _FALSE:
                reasons.add("MALFORMED_INPUT")
                signal = None
            else:
                facts = signal["facts"]
                if not isinstance(facts, Mapping) or not set(facts) <= _NONBLOCKING_FACT_KEYS:
                    reasons.add("MALFORMED_INPUT")
                    signal = None
                elif any(not isinstance(facts[name], bool) for name in facts):
                    reasons.add("MALFORMED_INPUT")
                    signal = None
                elif checked_signal_valid_until <= now:
                    reasons.add("STALE_INPUT")
                    signal = None
                else:
                    signal_ok = True
                    bindings["signal"] = {
                        "role": "signal",
                        "ref": checked_signal_ref,
                        "input_sha256": canonical_sha256(signal),
                    }

    valid_until_candidates = [
        _time(parsed[name]["valid_until"], f"inputs.{name}.valid_until")
        for name in parsed
        if "valid_until" in parsed[name]
    ]
    if signal_ok and signal is not None:
        valid_until_candidates.append(_time(signal["valid_until"], "inputs.bridge_readiness_signal.valid_until"))
    valid_until = min(valid_until_candidates).isoformat(timespec="seconds").replace("+00:00", "Z") if valid_until_candidates else None

    result = "UNKNOWN"
    if signal_ok and signal is not None and signal["ready_for_observation"] is False:
        if not reasons:
            result = "FALSE"
        reasons.add("EXPLICIT_NEGATIVE_READINESS")
    if not reasons:
        result = "TRUE"

    return {
        "schema_id": "BridgeObservationReadiness",
        "schema_version": "1.0.0",
        "generated_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "valid_until": valid_until,
        "result": result,
        "reason_codes": sorted(reasons),
        "observation_policy_sha256": policy_sha,
        "release_sha": release_sha,
        "input_bindings": sorted(bindings.values(), key=lambda binding: binding["role"]),
        "authority_granted": False,
        "promotion_allowed": False,
        "canonical_write_allowed": False,
        "live_action_allowed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate BridgeObservationReadiness/1.0.0")
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate_command = commands.add_parser("evaluate")
    evaluate_command.add_argument("--request", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command != "evaluate":
            raise BridgeObservationReadinessError("command is unsupported")
        result = evaluate(_load(Path(args.request)))
    except BridgeObservationReadinessError as exc:
        fail_closed = {
            "schema_id": "BridgeObservationReadiness",
            "schema_version": "1.0.0",
            "result": "UNKNOWN",
            "reason_codes": ["MALFORMED_INPUT"],
            "error": str(exc),
            "authority_granted": False,
            "promotion_allowed": False,
            "canonical_write_allowed": False,
            "live_action_allowed": False,
        }
        print(json.dumps(fail_closed, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
