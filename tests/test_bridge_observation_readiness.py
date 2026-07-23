from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "bridge_observation_readiness.py"
POLICY_PATH = ROOT / "provenance" / "observation-window-policy-v1.json"

SPEC = importlib.util.spec_from_file_location("bridge_observation_readiness", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
bor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bor)

BridgeObservationReadinessError = bor.BridgeObservationReadinessError
canonical_sha256 = bor.canonical_sha256
evaluate = bor.evaluate


def _time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _policy() -> dict[str, object]:
    value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _request(now: datetime, valid_until: datetime, *, policy: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "request": {
            "schema_id": "BridgeObservationReadinessRequest",
            "schema_version": "1.0.0",
            "now": _time(now),
            "release_ref": "release:bridge-observation-readiness-v1",
            "runtime_ref": "runtime:bridge-observation-readiness-v1",
            "policy_ref": "policy:observation-window-v1",
            "observation_policy_sha256": canonical_sha256(policy if policy is not None else _policy()),
        },
        "inputs": {
            "bridge_release_identity": {
                "schema_id": "BridgeReleaseIdentity",
                "schema_version": "1.0.0",
                "release_ref": "release:bridge-observation-readiness-v1",
                "release_sha": "9d4f0aecfb84ecb46e1ed8bbdf38fe1d94403696",
                "runtime_ref": "runtime:bridge-observation-readiness-v1",
                "runtime_policy_sha256": "44159ebee95cfd1800f5ab93fb057c29a480c30bd8e68568e21185087d8c0fa9",
                "observation_policy_ref": "policy:observation-window-v1",
                "observation_policy_sha256": canonical_sha256(policy if policy is not None else _policy()),
                "valid_until": _time(valid_until),
            },
            "bridge_runtime_binding": {
                "schema_id": "BridgeRuntimeBinding",
                "schema_version": "1.0.0",
                "runtime_ref": "runtime:bridge-observation-readiness-v1",
                "release_sha": "9d4f0aecfb84ecb46e1ed8bbdf38fe1d94403696",
                "runtime_policy_sha256": "44159ebee95cfd1800f5ab93fb057c29a480c30bd8e68568e21185087d8c0fa9",
                "observation_policy_sha256": canonical_sha256(policy if policy is not None else _policy()),
                "input_sha256": "0" * 64,
                "valid_until": _time(valid_until),
            },
            "bridge_monitor_projection": {
                "schema_id": "BridgeMonitorProjection",
                "schema_version": "1.0.0",
                "runtime_ref": "runtime:bridge-observation-readiness-v1",
                "release_sha": "9d4f0aecfb84ecb46e1ed8bbdf38fe1d94403696",
                "observation_policy_sha256": canonical_sha256(policy if policy is not None else _policy()),
                "monitor_input_sha256": "1" * 64,
                "valid_until": _time(valid_until),
            },
        },
    }


def _expected_bindings(request: dict[str, object], *, include_signal: bool) -> list[dict[str, object]]:
    inputs = request["inputs"]
    assert isinstance(inputs, dict)
    bindings = [
        {
            "role": "release",
            "ref": inputs["bridge_release_identity"]["release_ref"],
            "input_sha256": canonical_sha256(inputs["bridge_release_identity"]),
        },
        {
            "role": "runtime",
            "ref": inputs["bridge_runtime_binding"]["runtime_ref"],
            "input_sha256": canonical_sha256(inputs["bridge_runtime_binding"]),
        },
        {
            "role": "monitor",
            "ref": inputs["bridge_monitor_projection"]["runtime_ref"],
            "input_sha256": canonical_sha256(inputs["bridge_monitor_projection"]),
        },
    ]
    if include_signal:
        bindings.append(
            {
                "role": "signal",
                "ref": inputs["bridge_readiness_signal"]["signal_ref"],
                "input_sha256": canonical_sha256(inputs["bridge_readiness_signal"]),
            }
        )
    return sorted(bindings, key=lambda binding: str(binding["role"]))


def _explicit_signal(now: datetime, valid_until: datetime, *, ready_for_observation: bool, facts: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "schema_id": "BridgeReadinessSignal",
        "schema_version": "1.0.0",
        "signal_ref": "signal:bridge-observation-readiness",
        "ready_for_observation": ready_for_observation,
        "facts": facts if facts is not None else {},
        "valid_until": _time(valid_until),
    }


class BridgeObservationReadinessTests(unittest.TestCase):
    def _assert_authority_false(self, result: dict[str, object]) -> None:
        for name in ("authority_granted", "promotion_allowed", "canonical_write_allowed", "live_action_allowed"):
            self.assertIs(result[name], False)
        self.assertEqual(result["release_sha"], "9d4f0aecfb84ecb46e1ed8bbdf38fe1d94403696")

    def test_all_exact_current_bridge_inputs_pass_true(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=1))
        result = evaluate(request)
        self.assertEqual(result["result"], "TRUE")
        self.assertEqual(result["valid_until"], request["inputs"]["bridge_release_identity"]["valid_until"])
        self.assertEqual(result["reason_codes"], [])
        self._assert_authority_false(result)
        self.assertEqual(result["input_bindings"], _expected_bindings(request, include_signal=False))

    def test_nonblocking_operational_facts_do_not_block_true(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=2))
        request["inputs"]["bridge_readiness_signal"] = _explicit_signal(
            now,
            now + timedelta(hours=3),
            ready_for_observation=True,
            facts={"OPERATIONALLY_PROVEN": False, "long_windows_complete": False},
        )
        result = evaluate(request)
        self.assertEqual(result["result"], "TRUE")
        self.assertEqual(result["reason_codes"], [])
        self._assert_authority_false(result)
        self.assertEqual(result["input_bindings"], _expected_bindings(request, include_signal=True))

    def test_explicit_negative_bridge_signal_is_false(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=2))
        request["inputs"]["bridge_readiness_signal"] = _explicit_signal(
            now,
            now + timedelta(hours=1),
            ready_for_observation=False,
            facts={"OPERATIONALLY_PROVEN": False, "long_windows_complete": False},
        )
        result = evaluate(request)
        self.assertEqual(result["result"], "FALSE")
        self.assertEqual(result["reason_codes"], ["EXPLICIT_NEGATIVE_READINESS"])
        self.assertEqual(result["valid_until"], request["inputs"]["bridge_readiness_signal"]["valid_until"])
        self._assert_authority_false(result)
        self.assertEqual(result["input_bindings"], _expected_bindings(request, include_signal=True))

    def test_missing_required_input_is_unknown(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=1))
        del request["inputs"]["bridge_monitor_projection"]
        result = evaluate(request)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("MISSING_INPUT", result["reason_codes"])
        self.assertEqual(result["release_sha"], "9d4f0aecfb84ecb46e1ed8bbdf38fe1d94403696")
        self._assert_authority_false(result)

    def test_stale_or_expired_input_is_unknown(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now - timedelta(seconds=1))
        result = evaluate(request)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("STALE_INPUT", result["reason_codes"])
        self.assertEqual(result["input_bindings"], [])
        self._assert_authority_false(result)

    def test_hash_release_runtime_shape_and_duplicate_key_fail_closed(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)

        bad = _request(now, now + timedelta(hours=1))
        bad["request"]["observation_policy_sha256"] = "f" * 64
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("POLICY_HASH_MISMATCH", result["reason_codes"])

        bad = _request(now, now + timedelta(hours=1))
        bad["inputs"]["bridge_runtime_binding"]["release_sha"] = "a" * 40
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("RELEASE_IDENTITY_MISMATCH", result["reason_codes"])

        bad = _request(now, now + timedelta(hours=1))
        bad["inputs"]["bridge_monitor_projection"]["release_sha"] = "a" * 40
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("RELEASE_IDENTITY_MISMATCH", result["reason_codes"])

        bad = _request(now, now + timedelta(hours=1))
        bad["inputs"]["bridge_runtime_binding"]["runtime_ref"] = "runtime:other"
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("RUNTIME_IDENTITY_MISMATCH", result["reason_codes"])

        bad = _request(now, now + timedelta(hours=1))
        bad["inputs"]["bridge_release_identity"]["unexpected"] = True
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("MALFORMED_INPUT", result["reason_codes"])

        bad = _request(now, now + timedelta(hours=1))
        bad["inputs"]["bridge_runtime_binding"]["input_sha256"] = "x" * 64
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertEqual(result["reason_codes"], ["MALFORMED_INPUT"])

        bad = _request(now, now + timedelta(hours=1))
        bad["inputs"]["bridge_monitor_projection"]["valid_until"] = "not-a-time"
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertEqual(result["reason_codes"], ["MALFORMED_INPUT"])

        bad = _request(now, now + timedelta(hours=1))
        bad["inputs"]["bridge_monitor_projection"]["release_sha"] = 7
        result = evaluate(bad)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertEqual(result["reason_codes"], ["MALFORMED_INPUT"])

        with tempfile.TemporaryDirectory() as temporary:
            duplicate_path = Path(temporary) / "duplicate.json"
            duplicate_path.write_text(
                '{"request": {}, "inputs": {}, "inputs": {}}',
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, str(TOOL_PATH), "evaluate", "--request", str(duplicate_path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        receipt = json.loads(completed.stderr)
        self.assertEqual(receipt["result"], "UNKNOWN")
        self.assertIn("MALFORMED_INPUT", receipt["reason_codes"])

    def test_market_security_domain_fields_are_rejected(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        for field in ("domain_health", "market", "security"):
            bad = _request(now, now + timedelta(hours=1))
            bad["request"][field] = "RED"
            with self.assertRaises(BridgeObservationReadinessError):
                evaluate(bad)

            bad = _request(now, now + timedelta(hours=1))
            bad["inputs"]["bridge_release_identity"][field] = "RED"
            with self.assertRaises(BridgeObservationReadinessError):
                evaluate(bad)

            bad = _request(now, now + timedelta(hours=1))
            bad["inputs"]["bridge_readiness_signal"] = _explicit_signal(
                now,
                now + timedelta(hours=1),
                ready_for_observation=False,
                facts={field: "RED"},
            )
            with self.assertRaises(BridgeObservationReadinessError):
                evaluate(bad)

    def test_minimum_ttl_sorted_reason_codes_and_authority_booleans(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=5))
        request["inputs"]["bridge_runtime_binding"]["valid_until"] = _time(now + timedelta(hours=1))
        request["inputs"]["bridge_readiness_signal"] = _explicit_signal(
            now,
            now + timedelta(hours=2),
            ready_for_observation=False,
        )
        result = evaluate(request)
        self.assertEqual(result["result"], "FALSE")
        self.assertEqual(result["valid_until"], request["inputs"]["bridge_runtime_binding"]["valid_until"])
        self.assertEqual(result["reason_codes"], sorted(result["reason_codes"]))
        self.assertEqual(len(result["reason_codes"]), len(set(result["reason_codes"])))
        self._assert_authority_false(result)

    def test_cross_bound_runtime_and_monitor_release_sha_mismatch_is_unknown(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        for name in ("bridge_runtime_binding", "bridge_monitor_projection"):
            request = _request(now, now + timedelta(hours=1))
            request["inputs"][name]["release_sha"] = "a" * 40
            result = evaluate(request)
            self.assertEqual(result["result"], "UNKNOWN")
            self.assertEqual(result["reason_codes"], ["RELEASE_IDENTITY_MISMATCH"])
            self.assertEqual(result["release_sha"], request["inputs"]["bridge_release_identity"]["release_sha"])
            self._assert_authority_false(result)

    def test_valid_until_equal_to_now_is_stale(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now)
        result = evaluate(request)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertEqual(result["reason_codes"], ["STALE_INPUT"])
        self._assert_authority_false(result)

    def test_invalid_required_value_and_negative_signal_precedence_is_unknown(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=2))
        request["inputs"]["bridge_runtime_binding"]["release_sha"] = "a" * 40
        request["inputs"]["bridge_readiness_signal"] = _explicit_signal(
            now,
            now + timedelta(hours=1),
            ready_for_observation=False,
        )
        result = evaluate(request)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertEqual(result["reason_codes"], ["EXPLICIT_NEGATIVE_READINESS", "RELEASE_IDENTITY_MISMATCH"])
        self._assert_authority_false(result)

    def test_negative_signal_with_only_release_sha_binding_is_unknown(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=1))
        request["inputs"]["bridge_readiness_signal"] = _explicit_signal(
            now,
            now + timedelta(hours=1),
            ready_for_observation=False,
        )
        del request["inputs"]["bridge_runtime_binding"]["input_sha256"]
        result = evaluate(request)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertIn("MALFORMED_INPUT", result["reason_codes"])
        self.assertIn("EXPLICIT_NEGATIVE_READINESS", result["reason_codes"])
        self._assert_authority_false(result)

    def test_malformed_signal_does_not_shorten_ttl_or_make_false(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        request = _request(now, now + timedelta(hours=3))
        request["inputs"]["bridge_readiness_signal"] = _explicit_signal(
            now,
            now + timedelta(seconds=1),
            ready_for_observation=False,
        )
        request["inputs"]["bridge_readiness_signal"]["ready_for_observation"] = "no"
        result = evaluate(request)
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertEqual(result["reason_codes"], ["MALFORMED_INPUT"])
        self.assertEqual(result["valid_until"], request["inputs"]["bridge_release_identity"]["valid_until"])
        self._assert_authority_false(result)

    def test_cli_success_is_strict_json_and_fail_closed_on_bad_input(self) -> None:
        now = datetime(2026, 7, 20, 0, 0, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            request_path = Path(temporary) / "request.json"
            request_path.write_text(
                json.dumps(_request(now, now + timedelta(hours=1)), sort_keys=True),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, str(TOOL_PATH), "evaluate", "--request", str(request_path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["result"], "TRUE")
        self.assertEqual(payload["schema_id"], "BridgeObservationReadiness")
        self.assertEqual(payload["schema_version"], "1.0.0")
        self._assert_authority_false(payload)


if __name__ == "__main__":
    unittest.main()
