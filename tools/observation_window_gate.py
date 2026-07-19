#!/usr/bin/env python3
"""Validate post-Product-Done observation window documents without starting work."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_RE = re.compile(r"^[a-f0-9]{40}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[A-Za-z0-9][A-Za-z0-9._:@/+%-]{0,1023}$")
_WINDOW_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_POLICY_KEYS = {
    "schema_id", "schema_version", "policy_id", "window_sequence", "counter_fields",
    "zero_tolerance_fields", "fingerprint_fields", "windows", "privacy",
    "timers_started", "grants_authority",
}
_WINDOW_KEYS = {
    "duration_seconds", "bucket_seconds", "minimum_checkpoints",
    "minimum_pulse_samples", "minimum_monitor_records", "minimum_bounded_jobs",
    "minimum_research_cycles", "minimum_provider_calls", "minimum_backups",
    "minimum_restart_checks", "minimum_nonzero_job_buckets",
    "minimum_nonzero_cycle_buckets", "minimum_nonzero_provider_buckets",
    "provider_calls_must_be_zero", "previous_window",
}
_PRIVACY_KEYS = {
    "public_documents", "private_evidence_location_in_public_document",
    "raw_logs_in_public_document", "runtime_database_in_public_document",
    "provider_response_in_public_document",
}
_FINGERPRINT_FIELDS = {
    "release_sha", "tree_sha", "image_digests", "config_sha256", "policy_sha256",
    "provider_sha256", "schema_sha256", "sbom_sha256", "environment_ref",
}
_COUNTER_FIELDS = {
    "pulse_samples", "monitor_records", "bounded_jobs", "research_cycles",
    "provider_calls", "backup_successes", "restart_checks", "runtime_resets",
    "unknown_provider_results", "reconciled_provider_results", "canonical_writes",
    "live_actions", "authority_breaches", "privacy_violations",
    "second_writer_events", "fingerprint_drift_events", "counter_resets_unexplained",
}
_ZERO_FIELDS = {
    "canonical_writes", "live_actions", "authority_breaches", "privacy_violations",
    "second_writer_events", "fingerprint_drift_events", "counter_resets_unexplained",
}
_DOCUMENT_KEYS = {
    "schema_id", "schema_version", "object_id", "issued_at", "issuer", "contour",
    "classification", "payload", "integrity",
}
_START_KEYS = {
    "window_id", "policy_sha256", "threshold_sha256", "product_done_ref",
    "product_done_at", "deployment_ref", "previous_closeout_ref", "fingerprint",
    "fingerprint_sha256", "planned_start_at", "planned_end_at", "baseline_counters",
    "active_incident_refs", "proofs", "private_evidence_manifest_sha256",
    "grants_authority",
}
_CHECKPOINT_KEYS = {
    "window_start_ref", "window_id", "policy_sha256", "fingerprint_sha256",
    "checkpoint_index", "observed_at", "elapsed_seconds", "counters",
    "opened_incident_refs", "closed_incident_refs", "active_incident_refs", "reset_refs",
    "monitor_chain_head_ref", "private_evidence_manifest_sha256", "grants_authority",
}
_CLOSEOUT_KEYS = {
    "window_start_ref", "window_id", "policy_sha256", "threshold_sha256",
    "fingerprint_sha256", "started_at", "ended_at", "duration_seconds", "counters",
    "checkpoint_refs", "workload_buckets", "opened_incident_refs",
    "closed_incident_refs", "active_incident_refs", "reset_refs", "proofs",
    "private_evidence_manifest_sha256", "status", "grants_authority",
}
_PROOF_KEYS = {"proof_ref", "subject_fingerprint_sha256", "valid_until"}
_BUCKET_KEYS = {
    "bucket_index", "started_at", "ended_at", "bounded_jobs", "research_cycles",
    "provider_calls",
}
_PREFIX = {
    "ObservationWindowStart": "observation-window-start",
    "ObservationWindowCheckpoint": "observation-window-checkpoint",
    "ObservationWindowCloseout": "observation-window-closeout",
}


class WindowGateError(RuntimeError):
    """A stable window-policy or receipt validation failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WindowGateError("document is not canonical JSON data") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise WindowGateError(f"{label} shape is invalid")
    return json.loads(_canonical(value))


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > 2**53 - 1:
        raise WindowGateError(f"{label} is invalid")
    return value


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WindowGateError(f"{label} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WindowGateError(f"{label} must be RFC3339 UTC") from exc
    if parsed.tzinfo is None:
        raise WindowGateError(f"{label} must be RFC3339 UTC")
    return parsed.astimezone(timezone.utc)


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise WindowGateError(f"{label} must be SHA-256")
    return value


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise WindowGateError(f"{label} must be a normalized reference")
    lowered = value.lower()
    if any(marker in lowered for marker in ("credential", "secret", "raw-response", "runtime-db", "/home/", "/var/lib/")):
        raise WindowGateError(f"{label} crosses the public evidence boundary")
    return value


def _refs(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise WindowGateError(f"{label} must be an array")
    refs = [_ref(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(refs) != len(set(refs)):
        raise WindowGateError(f"{label} contains duplicates")
    return refs


def _load(path: Path) -> dict[str, object]:
    raw = Path(path)
    if raw.is_symlink() or not raw.is_file():
        raise WindowGateError("JSON input is not a regular file")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise WindowGateError("JSON input contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WindowGateError("JSON input is invalid") from exc
    if not isinstance(value, dict):
        raise WindowGateError("JSON input must be an object")
    return value


def validate_policy(value: Mapping[str, object]) -> dict[str, object]:
    policy = _exact(value, _POLICY_KEYS, "window policy")
    if (
        policy["schema_id"] != "ObservationWindowPolicy"
        or policy["schema_version"] != "1.0.0"
        or policy["policy_id"] != "post-product-done-sequential-windows-v1"
        or policy["timers_started"] is not False
        or policy["grants_authority"] is not False
    ):
        raise WindowGateError("window policy identity or authority is invalid")
    sequence = policy["window_sequence"]
    if sequence != ["SUBSTRATE_24H", "PROVIDER_48H", "INTEGRATED_7D", "FINAL_14D"]:
        raise WindowGateError("window sequence is invalid")
    if (
        not isinstance(policy["counter_fields"], list)
        or set(policy["counter_fields"]) != _COUNTER_FIELDS
        or len(policy["counter_fields"]) != len(_COUNTER_FIELDS)
    ):
        raise WindowGateError("counter field policy is invalid")
    if not isinstance(policy["zero_tolerance_fields"], list) or set(policy["zero_tolerance_fields"]) != _ZERO_FIELDS:
        raise WindowGateError("zero-tolerance field policy is invalid")
    if not isinstance(policy["fingerprint_fields"], list) or set(policy["fingerprint_fields"]) != _FINGERPRINT_FIELDS:
        raise WindowGateError("fingerprint field policy is invalid")
    privacy = _exact(policy["privacy"], _PRIVACY_KEYS, "privacy policy")
    if (
        privacy["public_documents"] != "SANITIZED_COUNTERS_HASHES_AND_REFS_ONLY"
        or any(privacy[name] is not False for name in _PRIVACY_KEYS if name != "public_documents")
    ):
        raise WindowGateError("privacy policy is invalid")
    windows = policy["windows"]
    if not isinstance(windows, Mapping) or set(windows) != set(sequence):
        raise WindowGateError("window threshold coverage is invalid")
    previous: str | None = None
    for window_id in sequence:
        rule = _exact(windows[window_id], _WINDOW_KEYS, f"window rule {window_id}")
        for name in _WINDOW_KEYS - {"provider_calls_must_be_zero", "previous_window"}:
            rule[name] = _integer(rule[name], f"{window_id}.{name}", minimum=1 if name not in {"minimum_provider_calls", "minimum_nonzero_provider_buckets"} else 0)
        if rule["duration_seconds"] % rule["bucket_seconds"] != 0:
            raise WindowGateError("window duration is not divisible into frozen buckets")
        buckets = rule["duration_seconds"] // rule["bucket_seconds"]
        for name in ("minimum_nonzero_job_buckets", "minimum_nonzero_cycle_buckets", "minimum_nonzero_provider_buckets"):
            if rule[name] > buckets:
                raise WindowGateError("nonzero bucket threshold exceeds bucket count")
        if not isinstance(rule["provider_calls_must_be_zero"], bool):
            raise WindowGateError("provider zero-call policy is invalid")
        if rule["previous_window"] != previous:
            raise WindowGateError("window predecessor policy is invalid")
        previous = window_id
        windows[window_id] = rule
    policy["windows"] = windows
    return policy


def _fingerprint(value: object) -> dict[str, object]:
    fingerprint = _exact(value, _FINGERPRINT_FIELDS, "release fingerprint")
    for name in ("release_sha", "tree_sha"):
        if not isinstance(fingerprint[name], str) or _GIT_RE.fullmatch(fingerprint[name]) is None:
            raise WindowGateError(f"fingerprint.{name} is invalid")
    images = fingerprint["image_digests"]
    if not isinstance(images, list) or not images or len(images) != len(set(images)) or any(
        not isinstance(item, str) or not item.startswith("sha256:") or _SHA256_RE.fullmatch(item[7:]) is None
        for item in images
    ):
        raise WindowGateError("fingerprint image digests are invalid")
    for name in ("config_sha256", "policy_sha256", "provider_sha256", "schema_sha256", "sbom_sha256"):
        _sha(fingerprint[name], f"fingerprint.{name}")
    _ref(fingerprint["environment_ref"], "fingerprint.environment_ref")
    return fingerprint


def _counters(value: object) -> dict[str, int]:
    raw = _exact(value, _COUNTER_FIELDS, "window counters")
    return {name: _integer(raw[name], f"counter.{name}") for name in sorted(_COUNTER_FIELDS)}


def _proofs(value: object, fingerprint_sha256: str, required_until: datetime) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise WindowGateError("current proof list is required")
    result: list[dict[str, object]] = []
    refs: set[str] = set()
    for index, raw in enumerate(value):
        proof = _exact(raw, _PROOF_KEYS, f"proof[{index}]")
        ref = _ref(proof["proof_ref"], f"proof[{index}].proof_ref")
        if ref in refs:
            raise WindowGateError("proof refs must be unique")
        refs.add(ref)
        if _sha(proof["subject_fingerprint_sha256"], "proof subject") != fingerprint_sha256:
            raise WindowGateError("proof subject differs from frozen release fingerprint")
        if _time(proof["valid_until"], "proof valid_until") < required_until:
            raise WindowGateError("proof expires before the window closes")
        result.append(proof)
    return result


def _document(value: Mapping[str, object], schema_id: str, payload_keys: set[str]) -> tuple[dict[str, object], dict[str, object]]:
    document = _exact(value, _DOCUMENT_KEYS, schema_id)
    if (
        document["schema_id"] != schema_id
        or document["schema_version"] != "1.0.0"
        or document["issuer"] != "observation-window-controller"
        or document["contour"] != "governance"
        or document["classification"] != "D1_INTERNAL_SANITIZED"
    ):
        raise WindowGateError(f"{schema_id} identity is invalid")
    _time(document["issued_at"], "document.issued_at")
    payload = _exact(document["payload"], payload_keys, f"{schema_id} payload")
    digest = canonical_sha256(payload)
    integrity = _exact(document["integrity"], {"payload_sha256", "parent_refs"}, "document integrity")
    if _sha(integrity["payload_sha256"], "payload_sha256") != digest:
        raise WindowGateError("document payload integrity is invalid")
    prefix = _PREFIX[schema_id]
    if document["object_id"] != f"{prefix}:{digest}":
        raise WindowGateError("document object identity is invalid")
    _refs(integrity["parent_refs"], "integrity.parent_refs")
    return document, payload


def validate_start(
    value: Mapping[str, object],
    policy: Mapping[str, object],
    *,
    previous_closeout: Mapping[str, object] | None = None,
    _skip_previous_document: bool = False,
) -> dict[str, object]:
    rules = validate_policy(policy)
    document, payload = _document(value, "ObservationWindowStart", _START_KEYS)
    window_id = payload["window_id"]
    if not isinstance(window_id, str) or _WINDOW_RE.fullmatch(window_id) is None or window_id not in rules["windows"]:
        raise WindowGateError("start window_id is invalid")
    policy_sha = canonical_sha256(rules)
    if _sha(payload["policy_sha256"], "start policy_sha256") != policy_sha:
        raise WindowGateError("start does not bind the frozen policy")
    rule = rules["windows"][window_id]
    if payload["threshold_sha256"] != canonical_sha256(rule):
        raise WindowGateError("start does not freeze the exact window thresholds")
    fingerprint = _fingerprint(payload["fingerprint"])
    fingerprint_sha = canonical_sha256(fingerprint)
    if payload["fingerprint_sha256"] != fingerprint_sha:
        raise WindowGateError("start fingerprint digest is invalid")
    start = _time(payload["planned_start_at"], "planned_start_at")
    end = _time(payload["planned_end_at"], "planned_end_at")
    product_done = _time(payload["product_done_at"], "product_done_at")
    if product_done > start or end - start != timedelta(seconds=rule["duration_seconds"]):
        raise WindowGateError("window starts before Product Done or has the wrong duration")
    _ref(payload["product_done_ref"], "product_done_ref")
    _ref(payload["deployment_ref"], "deployment_ref")
    if document["issued_at"] != payload["planned_start_at"]:
        raise WindowGateError("start issuance does not equal timer start")
    baseline = _counters(payload["baseline_counters"])
    if any(baseline[name] != 0 for name in _ZERO_FIELDS):
        raise WindowGateError("zero-tolerance counter is nonzero before start")
    if _refs(payload["active_incident_refs"], "active_incident_refs"):
        raise WindowGateError("window cannot start with an active incident")
    _proofs(payload["proofs"], fingerprint_sha, end)
    _sha(payload["private_evidence_manifest_sha256"], "private evidence manifest")
    if payload["grants_authority"] is not False:
        raise WindowGateError("window start cannot grant authority")

    required_previous = rule["previous_window"]
    previous_ref = payload["previous_closeout_ref"]
    if required_previous is None:
        if previous_ref is not None or previous_closeout is not None:
            raise WindowGateError("first window cannot claim a predecessor")
    else:
        if previous_ref is None:
            raise WindowGateError("window predecessor closeout is required")
        _ref(previous_ref, "previous_closeout_ref")
        if not _skip_previous_document:
            if previous_closeout is None:
                raise WindowGateError("window predecessor closeout is required")
            prior = validate_closeout(previous_closeout, rules, start_document=None, checkpoints=None, structural_only=True)
            prior_payload = prior["payload"]
            if (
                previous_ref != prior["object_id"]
                or prior_payload["window_id"] != required_previous
                or prior_payload["fingerprint_sha256"] != fingerprint_sha
                or _time(prior_payload["ended_at"], "previous ended_at") > start
            ):
                raise WindowGateError("window predecessor is not sequential and release-identical")

    expected_parents = {
        payload["product_done_ref"], payload["deployment_ref"],
        *[proof["proof_ref"] for proof in payload["proofs"]],
        *([previous_ref] if previous_ref is not None else []),
    }
    if set(document["integrity"]["parent_refs"]) != expected_parents:
        raise WindowGateError("start parent refs are incomplete")
    document["payload"] = payload
    return document


def _prior_state(
    start_payload: Mapping[str, object],
    previous: Mapping[str, object] | None,
    start_ref: str,
) -> tuple[dict[str, int], set[str], set[str], set[str], int, datetime, str | None]:
    if previous is None:
        return (
            _counters(start_payload["baseline_counters"]), set(), set(), set(), 0,
            _time(start_payload["planned_start_at"], "planned_start_at"), None,
        )
    document, payload = _document(previous, "ObservationWindowCheckpoint", _CHECKPOINT_KEYS)
    counters = _counters(payload["counters"])
    opened = set(_refs(payload["opened_incident_refs"], "previous opened"))
    closed = set(_refs(payload["closed_incident_refs"], "previous closed"))
    active = set(_refs(payload["active_incident_refs"], "previous active"))
    resets = set(_refs(payload["reset_refs"], "previous resets"))
    baseline = _counters(start_payload["baseline_counters"])
    observed = _time(payload["observed_at"], "previous observed_at")
    start_time = _time(start_payload["planned_start_at"], "planned_start_at")
    if (
        payload["window_start_ref"] != start_ref
        or payload["window_id"] != start_payload["window_id"]
        or payload["policy_sha256"] != start_payload["policy_sha256"]
        or payload["fingerprint_sha256"] != start_payload["fingerprint_sha256"]
        or payload["elapsed_seconds"] != int((observed - start_time).total_seconds())
        or any(counters[name] != 0 for name in _ZERO_FIELDS)
        or not closed <= opened
        or active != opened - closed
        or counters["runtime_resets"] - baseline["runtime_resets"] != len(resets)
        or payload["grants_authority"] is not False
    ):
        raise WindowGateError("previous checkpoint is not intrinsically valid")
    return (
        counters, opened, closed, resets, _integer(payload["checkpoint_index"], "checkpoint_index", minimum=1),
        observed, str(document["object_id"]),
    )


def validate_checkpoint(
    value: Mapping[str, object],
    policy: Mapping[str, object],
    start_document: Mapping[str, object],
    *,
    previous_checkpoint: Mapping[str, object] | None = None,
    previous_closeout: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rules = validate_policy(policy)
    start = validate_start(
        start_document,
        rules,
        previous_closeout=previous_closeout,
        _skip_previous_document=False,
    )
    start_payload = start["payload"]
    document, payload = _document(value, "ObservationWindowCheckpoint", _CHECKPOINT_KEYS)
    if (
        payload["window_start_ref"] != start["object_id"]
        or payload["window_id"] != start_payload["window_id"]
        or payload["policy_sha256"] != start_payload["policy_sha256"]
        or payload["fingerprint_sha256"] != start_payload["fingerprint_sha256"]
        or payload["grants_authority"] is not False
    ):
        raise WindowGateError("checkpoint binding is invalid")
    prior_counters, prior_opened, prior_closed, prior_resets, prior_index, prior_time, prior_ref = _prior_state(
        start_payload, previous_checkpoint, str(start["object_id"])
    )
    index = _integer(payload["checkpoint_index"], "checkpoint_index", minimum=1)
    observed = _time(payload["observed_at"], "checkpoint observed_at")
    start_time = _time(start_payload["planned_start_at"], "planned_start_at")
    end_time = _time(start_payload["planned_end_at"], "planned_end_at")
    if index != prior_index + 1 or not prior_time < observed <= end_time:
        raise WindowGateError("checkpoint order or time is invalid")
    elapsed = _integer(payload["elapsed_seconds"], "elapsed_seconds")
    if elapsed != int((observed - start_time).total_seconds()):
        raise WindowGateError("checkpoint elapsed_seconds is invalid")
    counters = _counters(payload["counters"])
    if any(counters[name] < prior_counters[name] for name in _COUNTER_FIELDS):
        raise WindowGateError("checkpoint counter underflow is invalid")
    if any(counters[name] != 0 for name in _ZERO_FIELDS):
        raise WindowGateError("checkpoint violates a zero-tolerance metric")
    opened = set(_refs(payload["opened_incident_refs"], "opened_incident_refs"))
    closed = set(_refs(payload["closed_incident_refs"], "closed_incident_refs"))
    active = set(_refs(payload["active_incident_refs"], "active_incident_refs"))
    resets = set(_refs(payload["reset_refs"], "reset_refs"))
    if not prior_opened <= opened or not prior_closed <= closed or not prior_resets <= resets:
        raise WindowGateError("checkpoint loses incident or reset history")
    if not closed <= opened or active != opened - closed:
        raise WindowGateError("checkpoint active incident set is inconsistent")
    if counters["runtime_resets"] - prior_counters["runtime_resets"] != len(resets - prior_resets):
        raise WindowGateError("checkpoint reset counter and refs disagree")
    _ref(payload["monitor_chain_head_ref"], "monitor_chain_head_ref")
    _sha(payload["private_evidence_manifest_sha256"], "private evidence manifest")
    expected_parents = {start["object_id"], payload["monitor_chain_head_ref"], *([prior_ref] if prior_ref else [])}
    if set(document["integrity"]["parent_refs"]) != expected_parents:
        raise WindowGateError("checkpoint parent refs are incomplete")
    document["payload"] = payload
    return document


def validate_closeout(
    value: Mapping[str, object],
    policy: Mapping[str, object],
    start_document: Mapping[str, object] | None,
    checkpoints: Sequence[Mapping[str, object]] | None,
    *,
    structural_only: bool = False,
    previous_closeout: Mapping[str, object] | None = None,
) -> dict[str, object]:
    rules = validate_policy(policy)
    document, payload = _document(value, "ObservationWindowCloseout", _CLOSEOUT_KEYS)
    window_id = payload["window_id"]
    if window_id not in rules["windows"] or payload["status"] != "PASS" or payload["grants_authority"] is not False:
        raise WindowGateError("closeout identity, status or authority is invalid")
    _sha(payload["policy_sha256"], "closeout policy_sha256")
    _sha(payload["threshold_sha256"], "closeout threshold_sha256")
    _sha(payload["fingerprint_sha256"], "closeout fingerprint_sha256")
    _counters(payload["counters"])
    _refs(payload["checkpoint_refs"], "checkpoint_refs")
    _refs(payload["opened_incident_refs"], "opened_incident_refs")
    _refs(payload["closed_incident_refs"], "closed_incident_refs")
    _refs(payload["active_incident_refs"], "active_incident_refs")
    _refs(payload["reset_refs"], "reset_refs")
    _sha(payload["private_evidence_manifest_sha256"], "private evidence manifest")
    if structural_only:
        rule = rules["windows"][window_id]
        started = _time(payload["started_at"], "closeout started_at")
        ended = _time(payload["ended_at"], "closeout ended_at")
        if (
            payload["policy_sha256"] != canonical_sha256(rules)
            or payload["threshold_sha256"] != canonical_sha256(rule)
            or payload["duration_seconds"] != rule["duration_seconds"]
            or ended - started != timedelta(seconds=rule["duration_seconds"])
        ):
            raise WindowGateError("structural predecessor closeout is not policy-bound")
        document["payload"] = payload
        return document
    if start_document is None or checkpoints is None:
        raise WindowGateError("closeout requires its start and checkpoints")
    start = validate_start(
        start_document,
        rules,
        previous_closeout=previous_closeout,
        _skip_previous_document=False,
    )
    start_payload = start["payload"]
    if (
        payload["window_start_ref"] != start["object_id"]
        or payload["window_id"] != start_payload["window_id"]
        or payload["policy_sha256"] != start_payload["policy_sha256"]
        or payload["threshold_sha256"] != start_payload["threshold_sha256"]
        or payload["fingerprint_sha256"] != start_payload["fingerprint_sha256"]
        or payload["started_at"] != start_payload["planned_start_at"]
        or payload["ended_at"] != start_payload["planned_end_at"]
    ):
        raise WindowGateError("closeout differs from the frozen start")
    rule = rules["windows"][window_id]
    started = _time(payload["started_at"], "closeout started_at")
    ended = _time(payload["ended_at"], "closeout ended_at")
    duration = _integer(payload["duration_seconds"], "duration_seconds", minimum=1)
    if duration != rule["duration_seconds"] or ended - started != timedelta(seconds=duration):
        raise WindowGateError("closeout duration is incomplete")
    prior: Mapping[str, object] | None = None
    validated: list[dict[str, object]] = []
    for checkpoint in checkpoints:
        current = validate_checkpoint(
            checkpoint,
            rules,
            start,
            previous_checkpoint=prior,
            previous_closeout=previous_closeout,
        )
        validated.append(current)
        prior = current
    if len(validated) < rule["minimum_checkpoints"] or not validated:
        raise WindowGateError("closeout has insufficient checkpoint coverage")
    if validated[-1]["payload"]["observed_at"] != payload["ended_at"]:
        raise WindowGateError("last checkpoint does not close the exact interval")
    refs = [item["object_id"] for item in validated]
    if payload["checkpoint_refs"] != refs:
        raise WindowGateError("closeout checkpoint refs are incomplete or reordered")
    last = validated[-1]["payload"]
    for name in ("counters", "opened_incident_refs", "closed_incident_refs", "active_incident_refs", "reset_refs"):
        if payload[name] != last[name]:
            raise WindowGateError("closeout state differs from its last checkpoint")
    if payload["active_incident_refs"] or set(payload["opened_incident_refs"]) != set(payload["closed_incident_refs"]):
        raise WindowGateError("closeout has an unresolved incident")
    counters = _counters(payload["counters"])
    baseline = _counters(start_payload["baseline_counters"])
    delta = {name: counters[name] - baseline[name] for name in _COUNTER_FIELDS}
    minima = {
        "pulse_samples": rule["minimum_pulse_samples"],
        "monitor_records": rule["minimum_monitor_records"],
        "bounded_jobs": rule["minimum_bounded_jobs"],
        "research_cycles": rule["minimum_research_cycles"],
        "provider_calls": rule["minimum_provider_calls"],
        "backup_successes": rule["minimum_backups"],
        "restart_checks": rule["minimum_restart_checks"],
    }
    if any(delta[name] < minimum for name, minimum in minima.items()):
        raise WindowGateError("closeout workload is vacuous or below frozen thresholds")
    if rule["provider_calls_must_be_zero"] and delta["provider_calls"] != 0:
        raise WindowGateError("provider-independent window contains provider calls")
    if delta["unknown_provider_results"] > delta["reconciled_provider_results"]:
        raise WindowGateError("closeout leaves provider accounting unresolved")
    buckets = payload["workload_buckets"]
    expected_count = rule["duration_seconds"] // rule["bucket_seconds"]
    if not isinstance(buckets, list) or len(buckets) != expected_count:
        raise WindowGateError("closeout workload buckets are incomplete")
    job_total = cycle_total = provider_total = 0
    nonzero_jobs = nonzero_cycles = nonzero_provider = 0
    for index, raw in enumerate(buckets, start=1):
        bucket = _exact(raw, _BUCKET_KEYS, f"workload bucket {index}")
        expected_start = started + timedelta(seconds=(index - 1) * rule["bucket_seconds"])
        expected_end = expected_start + timedelta(seconds=rule["bucket_seconds"])
        if (
            bucket["bucket_index"] != index
            or _time(bucket["started_at"], "bucket started_at") != expected_start
            or _time(bucket["ended_at"], "bucket ended_at") != expected_end
        ):
            raise WindowGateError("workload bucket chronology is invalid")
        jobs = _integer(bucket["bounded_jobs"], "bucket bounded_jobs")
        cycles = _integer(bucket["research_cycles"], "bucket research_cycles")
        calls = _integer(bucket["provider_calls"], "bucket provider_calls")
        job_total += jobs
        cycle_total += cycles
        provider_total += calls
        nonzero_jobs += int(jobs > 0)
        nonzero_cycles += int(cycles > 0)
        nonzero_provider += int(calls > 0)
    if (job_total, cycle_total, provider_total) != (delta["bounded_jobs"], delta["research_cycles"], delta["provider_calls"]):
        raise WindowGateError("workload buckets do not conserve counters")
    if (
        nonzero_jobs < rule["minimum_nonzero_job_buckets"]
        or nonzero_cycles < rule["minimum_nonzero_cycle_buckets"]
        or nonzero_provider < rule["minimum_nonzero_provider_buckets"]
    ):
        raise WindowGateError("workload is not distributed across the frozen interval")
    _proofs(payload["proofs"], payload["fingerprint_sha256"], ended)
    expected_parents = {start["object_id"], *refs, *[proof["proof_ref"] for proof in payload["proofs"]]}
    if set(document["integrity"]["parent_refs"]) != expected_parents:
        raise WindowGateError("closeout parent refs are incomplete")
    document["payload"] = payload
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate post-Product-Done observation documents")
    commands = parser.add_subparsers(dest="command", required=True)
    policy = commands.add_parser("validate-policy")
    policy.add_argument("--policy", required=True)
    start = commands.add_parser("validate-start")
    start.add_argument("--policy", required=True)
    start.add_argument("--start", required=True)
    start.add_argument("--previous-closeout")
    checkpoint = commands.add_parser("validate-checkpoint")
    checkpoint.add_argument("--policy", required=True)
    checkpoint.add_argument("--start", required=True)
    checkpoint.add_argument("--checkpoint", required=True)
    checkpoint.add_argument("--previous-checkpoint")
    checkpoint.add_argument("--previous-closeout")
    closeout = commands.add_parser("validate-closeout")
    closeout.add_argument("--policy", required=True)
    closeout.add_argument("--start", required=True)
    closeout.add_argument("--checkpoint", action="append", required=True)
    closeout.add_argument("--closeout", required=True)
    closeout.add_argument("--previous-closeout")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = _load(Path(args.policy))
        if args.command == "validate-policy":
            value = validate_policy(policy)
            identity = value["policy_id"]
        elif args.command == "validate-start":
            previous = _load(Path(args.previous_closeout)) if args.previous_closeout else None
            value = validate_start(_load(Path(args.start)), policy, previous_closeout=previous)
            identity = value["object_id"]
        elif args.command == "validate-checkpoint":
            previous = _load(Path(args.previous_checkpoint)) if args.previous_checkpoint else None
            previous_closeout = _load(Path(args.previous_closeout)) if args.previous_closeout else None
            value = validate_checkpoint(
                _load(Path(args.checkpoint)), policy, _load(Path(args.start)),
                previous_checkpoint=previous, previous_closeout=previous_closeout,
            )
            identity = value["object_id"]
        else:
            previous_closeout = _load(Path(args.previous_closeout)) if args.previous_closeout else None
            value = validate_closeout(
                _load(Path(args.closeout)), policy, _load(Path(args.start)),
                [_load(Path(path)) for path in args.checkpoint],
                previous_closeout=previous_closeout,
            )
            identity = value["object_id"]
        print(f"observation_window_gate=GREEN:{identity}")
        return 0
    except WindowGateError as exc:
        print(f"observation_window_gate=FAIL:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
