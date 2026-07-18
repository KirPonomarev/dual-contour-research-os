from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.ledger import JobLedger  # noqa: E402
from research_bridge.organism import (  # noqa: E402
    OrganismStateError,
    build_manifest_from_files,
    build_organism_manifest,
    canonical_json_sha256,
    load_json_document,
    project_organism_state,
    project_organism_state_from_ledger,
    sample_pulse,
    validate_organism_state,
    validate_pulse_policy,
    validate_pulse_sample,
)
from tests.test_a1_storage_v2 import AT, projection_states  # noqa: E402
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS, feedback_kwargs  # noqa: E402


ENVIRONMENT = "profile:linux-ci"
STATE_AT = "2026-01-02T03:04:05Z"
SAMPLE_AT = "2026-01-02T03:04:06Z"


def _manifest():
    return build_manifest_from_files(
        ROOT / "ops" / "organism" / "component-declarations.json",
        ROOT / "ops" / "organism" / "deployment-projection.json",
        issued_at="2026-07-18T16:00:00Z",
        repository_root=ROOT,
    )


def _policy() -> dict[str, object]:
    return load_json_document(ROOT / "ops" / "organism" / "pulse-policy.json")


def _capability(
    *,
    capability_id: str = "A1_DURABLE_FEEDBACK",
    status: str = "PASS_FOR_FROZEN_SCOPE",
    environment_ref: str = ENVIRONMENT,
    critical: bool = True,
) -> dict[str, object]:
    return {
        "capability_id": capability_id,
        "status": status,
        "environment_ref": environment_ref,
        "critical": critical,
        "reason_codes": [] if status == "PASS_FOR_FROZEN_SCOPE" else ["PROOF_STALE"],
        "proof_ref": f"capability-proof:{capability_id.lower()}",
    }


def _facts(
    lifecycle: str,
    *,
    queue: dict[str, object] | None = None,
    ai_enabled: bool = True,
    shadow_taint: str = "SHADOW_UNAPPLIED",
    reason_codes: list[str] | None = None,
    updated_at: str = STATE_AT,
) -> dict[str, object]:
    if queue is None:
        queue = {"runnable": 0, "waiting_authority": 0, "parked": 0, "oldest_event_at": None}
    if reason_codes is None:
        reason_codes = [f"STATE_{lifecycle}"]
    return {
        "ledger_sequence": 7,
        "lifecycle_state": lifecycle,
        "state_ref": f"state:{lifecycle.lower()}",
        "reason_codes": reason_codes,
        "queue": queue,
        "shadow_taint": shadow_taint,
        "ai_enabled": ai_enabled,
        "source": "FROZEN_CONTROLLER_SNAPSHOT",
        "proof_refs": ["proof:synthetic-state"],
        "environment_ref": ENVIRONMENT,
        "updated_at": updated_at,
    }


def _state(lifecycle: str = "WAIT_DATA", **overrides: object):
    return project_organism_state(
        _facts(lifecycle, **overrides), _manifest(), projected_at=SAMPLE_AT
    )


def _thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _resign(document: object) -> dict[str, object]:
    value = _thaw(document)
    assert isinstance(value, dict)
    payload = value["payload"]
    assert isinstance(payload, dict)
    digest = canonical_json_sha256(payload)
    prefix = "organism-state" if value["schema_id"] == "OrganismState" else "pulse-sample"
    value["object_id"] = f"{prefix}:{digest}"
    value["integrity"]["payload_sha256"] = digest  # type: ignore[index]
    return value


class StatePulseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "state.sqlite3"

    def _ledger(self) -> JobLedger:
        ledger = JobLedger(self.database)
        ledger.append_a1_bundle(
            objects=BASE_DOCUMENTS,
            projections=projection_states("state-pulse"),
            idempotency_key="state-pulse-base",
            event_at=AT,
        )
        return ledger

    def test_all_lifecycle_states_have_explicit_durable_semantics(self) -> None:
        cases = {
            "WAIT_DATA": {},
            "REJECTED": {},
            "GENERATING": {
                "queue": {"runnable": 1, "waiting_authority": 0, "parked": 0, "oldest_event_at": STATE_AT}
            },
            "ADMITTED_A1": {},
            "RUNNING": {},
            "LEARNED": {"shadow_taint": "NONE", "reason_codes": ["DOMAIN_APPLIED"]},
            "WAIT_AUTHORITY": {
                "queue": {"runnable": 0, "waiting_authority": 1, "parked": 0, "oldest_event_at": STATE_AT}
            },
            "PARKED": {
                "queue": {"runnable": 0, "waiting_authority": 0, "parked": 1, "oldest_event_at": STATE_AT}
            },
        }
        for lifecycle, values in cases.items():
            with self.subTest(lifecycle=lifecycle):
                state = _state(lifecycle, **values)
                self.assertEqual(state["payload"]["lifecycle_state"], lifecycle)
                self.assertFalse(state["payload"]["grants_authority"])
                self.assertEqual(validate_organism_state(state)["object_id"], state["object_id"])

    def test_invalid_lifecycle_queue_learning_and_ai_off_claims_fail_closed(self) -> None:
        with self.assertRaisesRegex(OrganismStateError, "GENERATING requires"):
            _state("GENERATING")
        with self.assertRaisesRegex(OrganismStateError, "WAIT_AUTHORITY requires"):
            _state("WAIT_AUTHORITY")
        with self.assertRaisesRegex(OrganismStateError, "PARKED requires"):
            _state("PARKED")
        with self.assertRaisesRegex(OrganismStateError, "LEARNED requires"):
            _state("LEARNED")
        with self.assertRaisesRegex(OrganismStateError, "AI_OFF"):
            _state(
                "GENERATING",
                ai_enabled=False,
                queue={"runnable": 1, "waiting_authority": 0, "parked": 0, "oldest_event_at": STATE_AT},
            )

    def test_wait_authority_survives_restart_with_same_state_id(self) -> None:
        ledger = self._ledger()
        ledger.append_feedback_bundle(
            **feedback_kwargs(  # type: ignore[arg-type]
                next_event_candidate=None,
                parked_gap_refs=[],
                idempotency_key="state-wait-authority",
            )
        )
        before = project_organism_state_from_ledger(
            ledger, _manifest(), projected_at=SAMPLE_AT, environment_ref=ENVIRONMENT, ai_enabled=True
        )
        self.assertEqual(before["payload"]["lifecycle_state"], "WAIT_AUTHORITY")
        ledger.close()
        with JobLedger(self.database) as reopened:
            after = project_organism_state_from_ledger(
                reopened, _manifest(), projected_at=SAMPLE_AT, environment_ref=ENVIRONMENT, ai_enabled=True
            )
            self.assertEqual(after, before)
            self.assertEqual(after["object_id"], before["object_id"])

    def test_exhausted_feedback_is_explicitly_parked_after_restart(self) -> None:
        ledger = self._ledger()
        candidate = deepcopy(feedback_kwargs()["next_event_candidate"])
        candidate["remaining_energy"] = 0  # type: ignore[index]
        ledger.append_feedback_bundle(
            **feedback_kwargs(  # type: ignore[arg-type]
                next_event_candidate=candidate,
                parked_gap_refs=[],
                idempotency_key="state-parked",
            )
        )
        ledger.close()
        with JobLedger(self.database) as reopened:
            state = project_organism_state_from_ledger(
                reopened, _manifest(), projected_at=SAMPLE_AT, environment_ref=ENVIRONMENT, ai_enabled=True
            )
            self.assertEqual(state["payload"]["lifecycle_state"], "PARKED")
            self.assertGreater(state["payload"]["queue"]["parked"], 0)

    def test_empty_durable_ledger_is_wait_data_and_ai_off_keeps_core_healthy(self) -> None:
        with JobLedger(self.database) as ledger:
            state = project_organism_state_from_ledger(
                ledger, _manifest(), projected_at=SAMPLE_AT, environment_ref=ENVIRONMENT, ai_enabled=False
            )
            pulse = sample_pulse(state, _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT)
            self.assertEqual(state["payload"]["lifecycle_state"], "WAIT_DATA")
            self.assertEqual(pulse["payload"]["traffic_light"], "GREEN")
            self.assertEqual(pulse["payload"]["health_state"], "AI_OFF_CORE_OPERATIONAL")
            self.assertIn("AI_OFF_CORE_OPERATIONAL", pulse["payload"]["reason_codes"])

    def test_wait_data_and_rejected_are_healthy_but_explicit(self) -> None:
        expected = {"WAIT_DATA": "HEALTHY_WAIT_DATA", "REJECTED": "HEALTHY_REJECTED"}
        for lifecycle, health in expected.items():
            with self.subTest(lifecycle=lifecycle):
                state = _state(lifecycle)
                pulse = sample_pulse(state, _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT)
                self.assertEqual(pulse["payload"]["traffic_light"], "GREEN")
                self.assertEqual(pulse["payload"]["health_state"], health)
                self.assertIn(lifecycle, " ".join(pulse["payload"]["reason_codes"]))

    def test_wait_authority_and_parked_never_report_green(self) -> None:
        cases = {
            "WAIT_AUTHORITY": {"runnable": 0, "waiting_authority": 1, "parked": 0, "oldest_event_at": STATE_AT},
            "PARKED": {"runnable": 0, "waiting_authority": 0, "parked": 1, "oldest_event_at": STATE_AT},
        }
        for lifecycle, queue in cases.items():
            with self.subTest(lifecycle=lifecycle):
                pulse = sample_pulse(
                    _state(lifecycle, queue=queue), _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT
                )
                self.assertEqual(pulse["payload"]["traffic_light"], "YELLOW")
                self.assertEqual(pulse["payload"]["health_state"], lifecycle)

    def test_stale_failed_or_environment_mismatched_capability_is_never_green(self) -> None:
        cases = (
            (_capability(status="STALE", critical=True), "RED"),
            (_capability(status="FAILED", critical=False), "YELLOW"),
            (_capability(environment_ref="profile:other", critical=True), "RED"),
        )
        for capability, traffic in cases:
            with self.subTest(capability=capability):
                pulse = sample_pulse(
                    _state(), _manifest(), [capability], _policy(), sampled_at=SAMPLE_AT
                )
                self.assertEqual(pulse["payload"]["traffic_light"], traffic)
                self.assertNotEqual(pulse["payload"]["traffic_light"], "GREEN")

    def test_missing_capability_evidence_is_yellow_not_green(self) -> None:
        pulse = sample_pulse(_state(), _manifest(), [], _policy(), sampled_at=SAMPLE_AT)
        self.assertEqual(pulse["payload"]["traffic_light"], "YELLOW")
        self.assertIn("CAPABILITY_EVIDENCE_ABSENT", pulse["payload"]["reason_codes"])

    def test_state_freshness_transitions_green_yellow_red(self) -> None:
        state = _state(updated_at=STATE_AT)
        for sampled_at, traffic in (
            ("2026-01-02T03:04:06Z", "GREEN"),
            ("2026-01-02T03:10:45Z", "YELLOW"),
            ("2026-01-02T03:19:05Z", "RED"),
        ):
            with self.subTest(sampled_at=sampled_at):
                pulse = sample_pulse(state, _manifest(), [_capability()], _policy(), sampled_at=sampled_at)
                self.assertEqual(pulse["payload"]["traffic_light"], traffic)

    def test_queue_count_and_age_transition_yellow_red(self) -> None:
        cases = (
            (8, "2026-01-02T03:04:06Z", "YELLOW"),
            (32, "2026-01-02T03:04:06Z", "RED"),
            (1, "2026-01-02T03:14:05Z", "YELLOW"),
            (1, "2026-01-02T03:34:05Z", "RED"),
        )
        for count, sampled_at, traffic in cases:
            with self.subTest(count=count, sampled_at=sampled_at):
                state = _state(
                    "GENERATING",
                    queue={"runnable": count, "waiting_authority": 0, "parked": 0, "oldest_event_at": STATE_AT},
                )
                pulse = sample_pulse(state, _manifest(), [_capability()], _policy(), sampled_at=sampled_at)
                self.assertEqual(pulse["payload"]["traffic_light"], traffic)

    def test_same_inputs_have_same_ids_and_observation_is_zero_write(self) -> None:
        ledger = self._ledger()
        ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
        changes = ledger._connection.total_changes
        state_a = project_organism_state_from_ledger(
            ledger, _manifest(), projected_at=SAMPLE_AT, environment_ref=ENVIRONMENT, ai_enabled=True
        )
        state_b = project_organism_state_from_ledger(
            ledger, _manifest(), projected_at=SAMPLE_AT, environment_ref=ENVIRONMENT, ai_enabled=True
        )
        pulse_a = sample_pulse(state_a, _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT)
        pulse_b = sample_pulse(state_b, _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT)
        self.assertEqual(state_a["object_id"], state_b["object_id"])
        self.assertEqual(pulse_a["object_id"], pulse_b["object_id"])
        self.assertEqual(ledger._connection.total_changes, changes)
        ledger.close()

    def test_manifest_state_and_pulse_are_separate_immutable_objects(self) -> None:
        state = _state()
        before = _thaw(state)
        pulse = sample_pulse(state, _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT)
        self.assertEqual(_thaw(state), before)
        self.assertNotEqual(state["object_id"], pulse["object_id"])
        self.assertFalse(pulse["payload"]["side_effects"])
        self.assertFalse(pulse["payload"]["grants_authority"])
        with self.assertRaises(TypeError):
            pulse["payload"]["traffic_light"] = "GREEN"  # type: ignore[index]

    def test_misleading_resigned_green_pulse_and_authority_state_fail_closed(self) -> None:
        stale = sample_pulse(
            _state(), _manifest(), [_capability(status="STALE")], _policy(), sampled_at=SAMPLE_AT
        )
        forged = _thaw(stale)
        assert isinstance(forged, dict)
        forged["payload"]["traffic_light"] = "GREEN"  # type: ignore[index]
        with self.assertRaisesRegex(OrganismStateError, "misleading"):
            validate_pulse_sample(_resign(forged))

        state = _thaw(_state())
        assert isinstance(state, dict)
        state["payload"]["grants_authority"] = True  # type: ignore[index]
        with self.assertRaisesRegex(OrganismStateError, "cannot grant authority"):
            validate_organism_state(_resign(state))

    def test_pulse_rejects_manifest_mismatch_and_duplicate_capabilities(self) -> None:
        state = _state()
        source = json.loads((ROOT / "ops" / "organism" / "component-declarations.json").read_text())
        source["source_id"] = "different-organism-source"
        projection = json.loads((ROOT / "ops" / "organism" / "deployment-projection.json").read_text())
        different = build_organism_manifest(
            source,
            projection,
            issued_at="2026-07-18T16:01:00Z",
            repository_root=ROOT,
        )
        with self.assertRaisesRegex(OrganismStateError, "different manifest"):
            sample_pulse(state, different, [_capability()], _policy(), sampled_at=SAMPLE_AT)
        with self.assertRaisesRegex(OrganismStateError, "unique"):
            sample_pulse(
                state, _manifest(), [_capability(), _capability()], _policy(), sampled_at=SAMPLE_AT
            )

    def test_pulse_policy_is_versioned_and_fail_closed(self) -> None:
        policy = validate_pulse_policy(_policy())
        self.assertLess(policy["freshness_warn_seconds"], policy["freshness_red_seconds"])
        invalid = _policy()
        invalid["queue_warn_count"] = invalid["queue_red_count"]
        with self.assertRaisesRegex(OrganismStateError, "requires"):
            validate_pulse_policy(invalid)

        pulse = _thaw(sample_pulse(_state(), _manifest(), [_capability()], _policy(), sampled_at=SAMPLE_AT))
        assert isinstance(pulse, dict)
        pulse["payload"]["policy_limits"]["freshness_warn_seconds"] = 1  # type: ignore[index]
        with self.assertRaisesRegex(OrganismStateError, "policy digest"):
            validate_pulse_sample(_resign(pulse))

    def test_queue_requires_honest_oldest_event_time(self) -> None:
        with self.assertRaisesRegex(OrganismStateError, "requires oldest_event_at"):
            _state(
                "GENERATING",
                queue={"runnable": 1, "waiting_authority": 0, "parked": 0, "oldest_event_at": None},
            )


if __name__ == "__main__":
    unittest.main()
