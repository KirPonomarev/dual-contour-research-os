from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "provenance" / "observation-window-policy-v1.json"
TOOL_PATH = ROOT / "tools" / "observation_window_gate.py"

SPEC = importlib.util.spec_from_file_location("observation_window_gate", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

WindowGateError = gate.WindowGateError
canonical_sha256 = gate.canonical_sha256
validate_checkpoint = gate.validate_checkpoint
validate_closeout = gate.validate_closeout
validate_policy = gate.validate_policy
validate_start = gate.validate_start


def _time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _policy() -> dict[str, object]:
    value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _document(schema_id: str, issued_at: str, payload: dict[str, object], parents: list[str]) -> dict[str, object]:
    digest = canonical_sha256(payload)
    prefix = {
        "ObservationWindowStart": "observation-window-start",
        "ObservationWindowCheckpoint": "observation-window-checkpoint",
        "ObservationWindowCloseout": "observation-window-closeout",
    }[schema_id]
    return {
        "schema_id": schema_id,
        "schema_version": "1.0.0",
        "object_id": f"{prefix}:{digest}",
        "issued_at": issued_at,
        "issuer": "observation-window-controller",
        "contour": "governance",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {"payload_sha256": digest, "parent_refs": parents},
    }


def _rebind(document: dict[str, object]) -> None:
    payload = document["payload"]
    assert isinstance(payload, dict)
    digest = canonical_sha256(payload)
    prefix = {
        "ObservationWindowStart": "observation-window-start",
        "ObservationWindowCheckpoint": "observation-window-checkpoint",
        "ObservationWindowCloseout": "observation-window-closeout",
    }[str(document["schema_id"])]
    document["object_id"] = f"{prefix}:{digest}"
    integrity = document["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = digest


def _fingerprint(policy: dict[str, object]) -> dict[str, object]:
    return {
        "release_sha": "1" * 40,
        "tree_sha": "2" * 40,
        "image_digests": ["sha256:" + "3" * 64],
        "config_sha256": "4" * 64,
        "policy_sha256": canonical_sha256(policy),
        "provider_sha256": "5" * 64,
        "schema_sha256": "6" * 64,
        "sbom_sha256": "7" * 64,
        "environment_ref": "environment:synthetic-release",
    }


def _zero_counters() -> dict[str, int]:
    policy = validate_policy(_policy())
    return {str(name): 0 for name in policy["counter_fields"]}


def _substrate_graph(*, zero_work: bool = False) -> tuple[
    dict[str, object], dict[str, object], list[dict[str, object]], dict[str, object]
]:
    policy = validate_policy(_policy())
    rule = policy["windows"]["SUBSTRATE_24H"]
    assert isinstance(rule, dict)
    started = datetime(2026, 7, 20, tzinfo=timezone.utc)
    ended = started + timedelta(seconds=int(rule["duration_seconds"]))
    fingerprint = _fingerprint(policy)
    fingerprint_sha = canonical_sha256(fingerprint)
    proof = {
        "proof_ref": "proof:current-synthetic-release",
        "subject_fingerprint_sha256": fingerprint_sha,
        "valid_until": _time(ended + timedelta(days=1)),
    }
    baseline = _zero_counters()
    start_payload: dict[str, object] = {
        "window_id": "SUBSTRATE_24H",
        "policy_sha256": canonical_sha256(policy),
        "threshold_sha256": canonical_sha256(rule),
        "product_done_ref": "receipt:product-done-synthetic",
        "product_done_at": _time(started - timedelta(minutes=1)),
        "deployment_ref": "deployment:synthetic-release",
        "previous_closeout_ref": None,
        "fingerprint": fingerprint,
        "fingerprint_sha256": fingerprint_sha,
        "planned_start_at": _time(started),
        "planned_end_at": _time(ended),
        "baseline_counters": baseline,
        "active_incident_refs": [],
        "proofs": [proof],
        "private_evidence_manifest_sha256": "8" * 64,
        "grants_authority": False,
    }
    start = _document(
        "ObservationWindowStart",
        _time(started),
        start_payload,
        ["receipt:product-done-synthetic", "deployment:synthetic-release", proof["proof_ref"]],
    )

    checkpoints: list[dict[str, object]] = []
    previous_ref: str | None = None
    for index in range(1, 25):
        counters = _zero_counters()
        if not zero_work:
            counters["pulse_samples"] = 48 * index
            counters["monitor_records"] = 48 * index
            counters["bounded_jobs"] = index // 6
            counters["research_cycles"] = min(2, index // 6)
            counters["backup_successes"] = int(index >= 12)
            counters["restart_checks"] = int(index >= 18)
            counters["runtime_resets"] = int(index >= 24)
        observed = started + timedelta(hours=index)
        reset_refs = ["reset:synthetic-one"] if counters["runtime_resets"] else []
        payload: dict[str, object] = {
            "window_start_ref": start["object_id"],
            "window_id": "SUBSTRATE_24H",
            "policy_sha256": canonical_sha256(policy),
            "fingerprint_sha256": fingerprint_sha,
            "checkpoint_index": index,
            "observed_at": _time(observed),
            "elapsed_seconds": index * 3600,
            "counters": counters,
            "opened_incident_refs": [],
            "closed_incident_refs": [],
            "active_incident_refs": [],
            "reset_refs": reset_refs,
            "monitor_chain_head_ref": f"monitor:chain-{index:04d}",
            "private_evidence_manifest_sha256": "9" * 64,
            "grants_authority": False,
        }
        parents = [start["object_id"], payload["monitor_chain_head_ref"]]
        if previous_ref is not None:
            parents.append(previous_ref)
        checkpoint = _document("ObservationWindowCheckpoint", _time(observed), payload, parents)
        checkpoints.append(checkpoint)
        previous_ref = str(checkpoint["object_id"])

    final_counters = copy.deepcopy(checkpoints[-1]["payload"]["counters"])
    buckets: list[dict[str, object]] = []
    for index in range(1, 5):
        bucket_start = started + timedelta(hours=(index - 1) * 6)
        buckets.append({
            "bucket_index": index,
            "started_at": _time(bucket_start),
            "ended_at": _time(bucket_start + timedelta(hours=6)),
            "bounded_jobs": 0 if zero_work else 1,
            "research_cycles": 0 if zero_work or index > 2 else 1,
            "provider_calls": 0,
        })
    closeout_payload: dict[str, object] = {
        "window_start_ref": start["object_id"],
        "window_id": "SUBSTRATE_24H",
        "policy_sha256": canonical_sha256(policy),
        "threshold_sha256": canonical_sha256(rule),
        "fingerprint_sha256": fingerprint_sha,
        "started_at": _time(started),
        "ended_at": _time(ended),
        "duration_seconds": int(rule["duration_seconds"]),
        "counters": final_counters,
        "checkpoint_refs": [item["object_id"] for item in checkpoints],
        "workload_buckets": buckets,
        "opened_incident_refs": [],
        "closed_incident_refs": [],
        "active_incident_refs": [],
        "reset_refs": [] if zero_work else ["reset:synthetic-one"],
        "proofs": [proof],
        "private_evidence_manifest_sha256": "a" * 64,
        "status": "PASS",
        "grants_authority": False,
    }
    parents = [start["object_id"], *closeout_payload["checkpoint_refs"], proof["proof_ref"]]
    closeout = _document("ObservationWindowCloseout", _time(ended), closeout_payload, parents)
    return policy, start, checkpoints, closeout


class ObservationWindowGateAssuranceTests(unittest.TestCase):
    def test_exact_non_vacuous_graph_passes_without_starting_a_timer(self) -> None:
        policy, start, checkpoints, closeout = _substrate_graph()
        self.assertFalse(policy["timers_started"])
        self.assertEqual(validate_start(start, policy)["object_id"], start["object_id"])
        self.assertEqual(
            validate_closeout(closeout, policy, start, checkpoints)["object_id"],
            closeout["object_id"],
        )

    def test_zero_work_and_short_interval_are_rejected(self) -> None:
        policy, start, checkpoints, closeout = _substrate_graph(zero_work=True)
        with self.assertRaisesRegex(WindowGateError, "vacuous|threshold"):
            validate_closeout(closeout, policy, start, checkpoints)

        policy, start, checkpoints, closeout = _substrate_graph()
        closeout["payload"]["duration_seconds"] -= 1
        _rebind(closeout)
        with self.assertRaisesRegex(WindowGateError, "duration"):
            validate_closeout(closeout, policy, start, checkpoints)

    def test_stale_fingerprint_and_retrospective_thresholds_are_rejected(self) -> None:
        policy, start, _, _ = _substrate_graph()
        start["payload"]["fingerprint"]["provider_sha256"] = "b" * 64
        _rebind(start)
        with self.assertRaisesRegex(WindowGateError, "fingerprint"):
            validate_start(start, policy)

        policy, start, _, _ = _substrate_graph()
        changed_policy = copy.deepcopy(policy)
        changed_policy["windows"]["SUBSTRATE_24H"]["minimum_bounded_jobs"] += 1
        with self.assertRaisesRegex(WindowGateError, "frozen policy"):
            validate_start(start, changed_policy)

    def test_counter_underflow_and_reset_mismatch_are_rejected(self) -> None:
        policy, start, checkpoints, _ = _substrate_graph()
        current = copy.deepcopy(checkpoints[1])
        current["payload"]["counters"]["pulse_samples"] = 1
        _rebind(current)
        with self.assertRaisesRegex(WindowGateError, "underflow"):
            validate_checkpoint(current, policy, start, previous_checkpoint=checkpoints[0])

        current = copy.deepcopy(checkpoints[1])
        current["payload"]["counters"]["runtime_resets"] = 1
        _rebind(current)
        with self.assertRaisesRegex(WindowGateError, "reset counter"):
            validate_checkpoint(current, policy, start, previous_checkpoint=checkpoints[0])

    def test_incident_proof_distribution_and_zero_tolerance_boundaries(self) -> None:
        policy, start, checkpoints, closeout = _substrate_graph()
        closeout["payload"]["active_incident_refs"] = ["incident:still-open"]
        closeout["payload"]["opened_incident_refs"] = ["incident:still-open"]
        _rebind(closeout)
        with self.assertRaisesRegex(WindowGateError, "state differs|unresolved"):
            validate_closeout(closeout, policy, start, checkpoints)

        policy, start, _, _ = _substrate_graph()
        start["payload"]["proofs"][0]["valid_until"] = start["payload"]["planned_start_at"]
        _rebind(start)
        with self.assertRaisesRegex(WindowGateError, "expires"):
            validate_start(start, policy)

        policy, start, checkpoints, closeout = _substrate_graph()
        closeout["payload"]["workload_buckets"][0]["bounded_jobs"] = 4
        for bucket in closeout["payload"]["workload_buckets"][1:]:
            bucket["bounded_jobs"] = 0
        _rebind(closeout)
        with self.assertRaisesRegex(WindowGateError, "distributed"):
            validate_closeout(closeout, policy, start, checkpoints)

        policy, start, checkpoints, _ = _substrate_graph()
        current = copy.deepcopy(checkpoints[0])
        current["payload"]["counters"]["canonical_writes"] = 1
        _rebind(current)
        with self.assertRaisesRegex(WindowGateError, "zero-tolerance"):
            validate_checkpoint(current, policy, start)

    def test_public_reference_boundary_and_sequential_predecessor_are_enforced(self) -> None:
        policy, start, _, _ = _substrate_graph()
        start["payload"]["deployment_ref"] = "runtime-db:private-location"
        start["integrity"]["parent_refs"][1] = "runtime-db:private-location"
        _rebind(start)
        with self.assertRaisesRegex(WindowGateError, "public evidence boundary"):
            validate_start(start, policy)

        policy, _, _, predecessor = _substrate_graph()
        rule = policy["windows"]["PROVIDER_48H"]
        previous_end = datetime.fromisoformat(predecessor["payload"]["ended_at"].replace("Z", "+00:00"))
        fingerprint = _fingerprint(policy)
        fingerprint_sha = canonical_sha256(fingerprint)
        end = previous_end + timedelta(seconds=int(rule["duration_seconds"]))
        proof = {
            "proof_ref": "proof:provider-window",
            "subject_fingerprint_sha256": fingerprint_sha,
            "valid_until": _time(end + timedelta(days=1)),
        }
        payload = {
            "window_id": "PROVIDER_48H",
            "policy_sha256": canonical_sha256(policy),
            "threshold_sha256": canonical_sha256(rule),
            "product_done_ref": "receipt:product-done-synthetic",
            "product_done_at": _time(previous_end - timedelta(days=1)),
            "deployment_ref": "deployment:synthetic-release",
            "previous_closeout_ref": predecessor["object_id"],
            "fingerprint": fingerprint,
            "fingerprint_sha256": fingerprint_sha,
            "planned_start_at": _time(previous_end),
            "planned_end_at": _time(end),
            "baseline_counters": _zero_counters(),
            "active_incident_refs": [],
            "proofs": [proof],
            "private_evidence_manifest_sha256": "b" * 64,
            "grants_authority": False,
        }
        later_start = _document(
            "ObservationWindowStart",
            _time(previous_end),
            payload,
            [payload["product_done_ref"], payload["deployment_ref"], payload["previous_closeout_ref"], proof["proof_ref"]],
        )
        self.assertEqual(
            validate_start(later_start, policy, previous_closeout=predecessor)["object_id"],
            later_start["object_id"],
        )
        with self.assertRaisesRegex(WindowGateError, "predecessor closeout"):
            validate_start(later_start, policy)

    def test_cli_policy_and_start_use_the_same_rules(self) -> None:
        policy, start, _, _ = _substrate_graph()
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            start_path = Path(temporary) / "start.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            start_path.write_text(json.dumps(start), encoding="utf-8")
            policy_result = subprocess.run(
                ["python3", str(TOOL_PATH), "validate-policy", "--policy", str(policy_path)],
                check=False, capture_output=True, text=True,
            )
            start_result = subprocess.run(
                [
                    "python3", str(TOOL_PATH), "validate-start", "--policy", str(policy_path),
                    "--start", str(start_path),
                ],
                check=False, capture_output=True, text=True,
            )
        self.assertEqual(policy_result.returncode, 0, policy_result.stderr)
        self.assertEqual(start_result.returncode, 0, start_result.stderr)
        self.assertIn("observation_window_gate=GREEN", policy_result.stdout)
        self.assertIn("observation_window_gate=GREEN", start_result.stdout)


if __name__ == "__main__":
    unittest.main()
