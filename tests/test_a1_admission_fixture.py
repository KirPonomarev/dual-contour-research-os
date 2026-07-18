from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.admission import (  # noqa: E402
    A1AdmissionError,
    A1AdmissionKernel,
    canonical_json_sha256,
)


CONTRACT_ROOT = ROOT / "contracts"
A1_CATALOG_SHA256 = hashlib.sha256(
    (CONTRACT_ROOT / "a1" / "v1" / "catalog.json").read_bytes()
).hexdigest()
CORE_CATALOG_SHA256 = hashlib.sha256(
    (CONTRACT_ROOT / "catalog.json").read_bytes()
).hexdigest()

NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40
POLICY_SHA256 = "3" * 64
CONTEXT_SHA256 = "4" * 64
RELEASE_SHA256 = "5" * 64
SOURCE_SHA256 = "6" * 64


def _kernel() -> A1AdmissionKernel:
    return A1AdmissionKernel(
        CONTRACT_ROOT,
        expected_a1_catalog_sha256=A1_CATALOG_SHA256,
        expected_core_catalog_sha256=CORE_CATALOG_SHA256,
    )


def _energy(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "wall_seconds": 120,
        "cpu_seconds": 120,
        "memory_mib": 256,
        "output_bytes": 1_000_000,
        "tokens": 2_000,
        "cost_units": 10,
    }
    value.update(overrides)
    return value


def _trigger(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "trigger_id": "trigger-public-001",
        "collector_id": "collector-public-fixture",
        "source_ref": "https://public.example/research/item-001",
        "source_content_sha256": SOURCE_SHA256,
        "observed_at": "2026-07-18T11:59:00Z",
        "summary": "Public synthetic research signal.",
        "evidence_refs": ["public-evidence:item-001"],
        "transport_idempotency_key": "transport-public-001",
    }
    value.update(overrides)
    return value


def _materialize(
    kernel: A1AdmissionKernel,
    trigger: dict[str, object] | None = None,
    **overrides: object,
):
    keywords: dict[str, object] = {
        "issued_at": NOW,
        "policy_sha256": POLICY_SHA256,
        "context_sha256": CONTEXT_SHA256,
        "classification": "D0",
        "ledger_revision": 7,
        "root_energy": _energy(),
        "remaining_energy": _energy(),
        "allowed_collectors": ["collector-public-fixture"],
        "allowed_source_prefixes": ["https://public.example/research/"],
    }
    keywords.update(overrides)
    return kernel.materialize_source_trigger(trigger or _trigger(), **keywords)


def _candidate(
    *,
    payload_overrides: dict[str, object] | None = None,
    document_overrides: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "candidate_id": "candidate-public-001",
        "event_ref": "material-event:public-001",
        "root_event_ref": "material-event:public-001",
        "draft_revision": 1,
        "experiment_type": "synthetic-fixture-check",
        "estimand": "Difference between deterministic fixture output and zero.",
        "null_hypothesis": "The deterministic fixture produces no difference.",
        "falsifier": "Observed output is byte-identical to the null fixture.",
        "stop_condition": "Stop after one registered offline fixture execution.",
        "scope": "Public synthetic offline fixture only.",
        "expected_output": "One synthetic ValidationReceipt.",
        "evidence_refs": ["public-evidence:item-001"],
        "evidence_independence_groups": [["public-evidence:item-001"]],
        "executor_family": "registered-offline-l0",
        "resource_request": {
            "wall_seconds": 60,
            "cpu_seconds": 60,
            "memory_mib": 128,
            "output_bytes": 100_000,
            "tokens": 1_000,
            "cost_units": 2,
        },
        "data_classes": ["synthetic"],
        "network_required": False,
        "holdout_access_requested": False,
        "canonical_write_requested": False,
        "private_api_requested": False,
        "live_execution_requested": False,
        "vcs_identity": {
            "repository_id": "dual-contour-research-os",
            "head_sha": HEAD_SHA,
            "base_sha": BASE_SHA,
            "worktree_clean": True,
            "contract_catalog_sha256": CORE_CATALOG_SHA256,
            "a1_catalog_sha256": A1_CATALOG_SHA256,
            "release_manifest_sha256": RELEASE_SHA256,
        },
        "policy_sha256": POLICY_SHA256,
        "context_sha256": CONTEXT_SHA256,
        "shadow_taint": "NONE",
        "model_call_refs": ["model-call:fixture-worker-001"],
        "critique_refs": ["model-call:fixture-critic-001"],
    }
    if payload_overrides:
        payload.update(deepcopy(payload_overrides))
    document: dict[str, object] = {
        "schema_id": "CandidateSpecDraft",
        "schema_version": "1.0.0",
        "object_id": "candidate-public-001",
        "issued_at": "2026-07-18T11:58:00Z",
        "issuer": "proposal-ingestor",
        "contour": "bridge",
        "classification": "D0",
        "payload": payload,
        "integrity": {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": canonical_json_sha256(payload),
            "parent_refs": ["material-event:public-001"],
        },
    }
    if document_overrides:
        document.update(deepcopy(document_overrides))
    if payload_overrides and "integrity" not in (document_overrides or {}):
        document["integrity"] = {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": canonical_json_sha256(payload),
            "parent_refs": ["material-event:public-001"],
        }
    return document


def _snapshot(
    kernel: A1AdmissionKernel,
    candidate: dict[str, object],
    **overrides: object,
):
    keywords: dict[str, object] = {
        "ledger_revision": 9,
        "as_of": NOW,
        "current_head_sha": HEAD_SHA,
        "base_sha": BASE_SHA,
        "worktree_clean": True,
        "release_manifest_sha256": RELEASE_SHA256,
        "context_sha256": CONTEXT_SHA256,
        "available_cost_units": 50,
        "available_tokens": 50_000,
        "cycle_admitted": 0,
        "daily_admitted": 0,
        "wip_available": True,
        "active_reservations": [],
        "executor_capability_refs": ["capability:executor-fixture"],
        "evaluator_capability_refs": ["capability:evaluator-fixture"],
        "model_route_proof_ref": "capability:model-route-fixture",
    }
    keywords.update(overrides)
    return kernel.freeze_admission_snapshot(candidate, **keywords)


class A1AdmissionFixtureTests(unittest.TestCase):
    def test_kernel_is_bound_to_exact_frozen_catalogs(self) -> None:
        kernel = _kernel()
        self.assertEqual(kernel.catalog_sha256, A1_CATALOG_SHA256)
        self.assertEqual(kernel.core_catalog_sha256, CORE_CATALOG_SHA256)
        with self.assertRaises(A1AdmissionError):
            A1AdmissionKernel(
                CONTRACT_ROOT,
                expected_a1_catalog_sha256="0" * 64,
                expected_core_catalog_sha256=CORE_CATALOG_SHA256,
            )

    def test_material_event_mints_all_trusted_fields(self) -> None:
        result = _materialize(_kernel())
        self.assertEqual(result.decision, "MATERIAL")
        self.assertEqual(result.reason_code, "MATERIAL")
        self.assertEqual(result.model_calls_consumed, 0)
        event = result.material_event
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["issuer"], "trusted-event-minter")
        self.assertEqual(event["contour"], "bridge")
        self.assertEqual(event["classification"], "D0")
        payload = event["payload"]
        self.assertEqual(payload["origin_class"], "EXOGENOUS")
        self.assertEqual(payload["event_kind"], "SOURCE_DISCOVERY")
        self.assertEqual(payload["causal_depth"], 0)
        self.assertEqual(payload["shadow_taint"], "NONE")
        self.assertEqual(payload["created_from_ledger_sequence"], 7)
        self.assertEqual(
            event["integrity"]["payload_sha256"],
            canonical_json_sha256(payload),
        )

    def test_materiality_non_material_paths_consume_zero_model_calls(self) -> None:
        kernel = _kernel()
        exact = _materialize(kernel).exact_key_sha256
        cases = (
            (
                "REJECTED_POLICY",
                {"trigger": _trigger(collector_id="unknown-collector")},
            ),
            ("WAIT_DATA", {"trigger": _trigger(evidence_refs=[])}),
            ("DUPLICATE_EXACT", {"seen_exact_sha256": [exact]}),
            ("NON_MATERIAL", {"suppressed_event_kinds": ["SOURCE_DISCOVERY"]}),
            ("WAIT_BUDGET", {"budget_available": False}),
        )
        for expected, options in cases:
            with self.subTest(expected=expected):
                trigger = options.pop("trigger", None)
                result = _materialize(kernel, trigger, **options)
                self.assertEqual(result.decision, expected)
                self.assertEqual(result.reason_code, expected)
                self.assertEqual(result.model_calls_consumed, 0)
                self.assertIsNone(result.material_event)

    def test_untrusted_trigger_cannot_supply_trusted_fields(self) -> None:
        for field, value in (
            ("issuer", "collector"),
            ("classification", "D0"),
            ("event_kind", "SOURCE_DISCOVERY"),
            ("policy_sha256", POLICY_SHA256),
            ("root_event_ref", "attacker-root"),
            ("budget", 999),
        ):
            with self.subTest(field=field):
                with self.assertRaises(A1AdmissionError):
                    _materialize(_kernel(), _trigger(**{field: value}))

    def test_materiality_fails_closed_on_energy_or_data_class_violation(self) -> None:
        with self.assertRaises(A1AdmissionError):
            _materialize(
                _kernel(),
                root_energy=_energy(tokens=10),
                remaining_energy=_energy(tokens=11),
            )
        with self.assertRaises(A1AdmissionError):
            _materialize(_kernel(), classification="D2")

    def test_valid_candidate_is_deterministic_and_non_authoritative(self) -> None:
        kernel = _kernel()
        candidate = _candidate()
        snapshot = _snapshot(kernel, candidate)
        first = kernel.evaluate_candidate(candidate, snapshot)
        second = kernel.evaluate_candidate(deepcopy(candidate), snapshot)
        self.assertEqual(first.decision, "ADMIT")
        self.assertEqual(first.decision_key_sha256, second.decision_key_sha256)
        self.assertEqual(first.to_mapping(), second.to_mapping())
        self.assertFalse(first.grants_execution_authority)
        receipt = first.to_mapping()
        self.assertEqual(receipt["payload"]["reason_codes"], ["ADMITTED_A1"])
        self.assertEqual(receipt["payload"]["budget_action"], "RESERVED")
        self.assertNotEqual(receipt["object_id"], receipt["payload"]["receipt_id"])
        self.assertNotEqual(
            receipt["payload"]["transport_idempotency_key"],
            receipt["payload"]["receipt_id"],
        )

    def test_changed_ledger_revision_produces_new_snapshot_and_receipt(self) -> None:
        kernel = _kernel()
        candidate = _candidate()
        first_snapshot = _snapshot(kernel, candidate, ledger_revision=9)
        second_snapshot = _snapshot(kernel, candidate, ledger_revision=10)
        self.assertNotEqual(first_snapshot.sha256, second_snapshot.sha256)
        self.assertNotEqual(
            kernel.evaluate_candidate(candidate, first_snapshot).decision_key_sha256,
            kernel.evaluate_candidate(candidate, second_snapshot).decision_key_sha256,
        )

    def test_hard_denies_are_deterministic_receipts(self) -> None:
        cases = (
            ("holdout_access_requested", "HOLDOUT_ACCESS_DENIED"),
            ("private_api_requested", "PRIVATE_API_DENIED"),
            ("live_execution_requested", "LIVE_EXECUTION_DENIED"),
            ("canonical_write_requested", "CANONICAL_WRITE_DENIED"),
            ("network_required", "UNKNOWN_VALIDATION_FAILURE"),
        )
        kernel = _kernel()
        for field, reason in cases:
            with self.subTest(field=field):
                candidate = _candidate(payload_overrides={field: True})
                decision = kernel.evaluate_candidate(
                    candidate, _snapshot(kernel, candidate)
                )
                self.assertEqual(decision.decision, "REJECT")
                self.assertEqual(
                    decision.to_mapping()["payload"]["reason_codes"], [reason]
                )
                self.assertFalse(decision.grants_execution_authority)

    def test_stale_and_mixed_vcs_fail_closed(self) -> None:
        kernel = _kernel()
        candidate = _candidate()
        stale = kernel.evaluate_candidate(
            candidate,
            _snapshot(kernel, candidate, current_head_sha="9" * 40),
        )
        self.assertEqual(stale.decision, "REJECT")
        self.assertEqual(
            stale.to_mapping()["payload"]["reason_codes"], ["STALE_VCS_IDENTITY"]
        )

        mixed_candidate = _candidate(
            payload_overrides={
                "vcs_identity": {
                    **candidate["payload"]["vcs_identity"],
                    "contract_catalog_sha256": "8" * 64,
                }
            }
        )
        mixed = kernel.evaluate_candidate(
            mixed_candidate, _snapshot(kernel, mixed_candidate)
        )
        self.assertEqual(mixed.decision, "REJECT")
        self.assertEqual(
            mixed.to_mapping()["payload"]["reason_codes"], ["MIXED_VCS_IDENTITY"]
        )
        self.assertEqual(mixed.to_mapping()["payload"]["public_reason_codes"], [])

    def test_budget_taint_and_missing_capability_park(self) -> None:
        kernel = _kernel()
        cases = (
            (
                _candidate(
                    payload_overrides={
                        "resource_request": {
                            "wall_seconds": 7_201,
                            "cpu_seconds": 60,
                            "memory_mib": 128,
                            "output_bytes": 100_000,
                            "tokens": 1_000,
                            "cost_units": 2,
                        }
                    }
                ),
                {},
                "BUDGET_EXHAUSTED",
            ),
            (
                _candidate(payload_overrides={"shadow_taint": "SHADOW_UNAPPLIED"}),
                {},
                "SHADOW_TAINT_RESTRICTED",
            ),
            (_candidate(), {"executor_capability_refs": []}, "BUDGET_EXHAUSTED"),
        )
        for candidate, snapshot_options, reason in cases:
            with self.subTest(reason=reason):
                decision = kernel.evaluate_candidate(
                    candidate, _snapshot(kernel, candidate, **snapshot_options)
                )
                self.assertEqual(decision.decision, "PARK")
                self.assertEqual(
                    decision.to_mapping()["payload"]["reason_codes"], [reason]
                )

    def test_invalid_and_circular_evidence_fail_closed(self) -> None:
        kernel = _kernel()
        with self.assertRaises(A1AdmissionError):
            _snapshot(
                kernel,
                _candidate(
                    payload_overrides={
                        "evidence_refs": [],
                        "evidence_independence_groups": [["public-evidence:item-001"]],
                    }
                ),
            )
        with self.assertRaises(A1AdmissionError):
            _snapshot(
                kernel,
                _candidate(
                    payload_overrides={
                        "evidence_refs": ["candidate-public-001"],
                        "evidence_independence_groups": [["candidate-public-001"]],
                    }
                ),
            )
        with self.assertRaises(A1AdmissionError):
            _snapshot(
                kernel,
                _candidate(
                    payload_overrides={
                        "evidence_refs": ["public-evidence:item-001"],
                        "evidence_independence_groups": [["public-evidence:other"]],
                    }
                ),
            )

    def test_resource_schema_minimum_and_active_reservations_are_enforced(self) -> None:
        kernel = _kernel()
        invalid = _candidate(
            payload_overrides={
                "resource_request": {
                    "wall_seconds": 60,
                    "cpu_seconds": 60,
                    "memory_mib": 63,
                    "output_bytes": 100_000,
                    "tokens": 1_000,
                    "cost_units": 2,
                }
            }
        )
        with self.assertRaises(A1AdmissionError):
            _snapshot(kernel, invalid)

        candidate = _candidate()
        saturated = kernel.evaluate_candidate(
            candidate,
            _snapshot(
                kernel,
                candidate,
                cycle_admitted=3,
                active_reservations=["budget-reservation:active-001"],
            ),
        )
        self.assertEqual(saturated.decision, "PARK")
        self.assertEqual(
            saturated.to_mapping()["payload"]["reason_codes"],
            ["BUDGET_EXHAUSTED"],
        )

    def test_outputs_are_deeply_immutable_and_copyable(self) -> None:
        kernel = _kernel()
        material = _materialize(kernel)
        assert material.material_event is not None
        with self.assertRaises(TypeError):
            material.material_event["payload"]["event_kind"] = "CHANGED"

        candidate = _candidate()
        snapshot = _snapshot(kernel, candidate)
        with self.assertRaises(TypeError):
            snapshot.payload["budget_state"]["available_tokens"] = 0
        snapshot_copy = snapshot.to_mapping()
        snapshot_copy["budget_state"]["available_tokens"] = 0
        self.assertEqual(snapshot.to_mapping()["budget_state"]["available_tokens"], 50_000)

        decision = kernel.evaluate_candidate(candidate, snapshot)
        with self.assertRaises(TypeError):
            decision.receipt["payload"]["decision"] = "REJECT"
        receipt_copy = decision.to_mapping()
        receipt_copy["payload"]["decision"] = "REJECT"
        self.assertEqual(decision.to_mapping()["payload"]["decision"], "ADMIT")

    def test_unknown_fields_and_mutated_integrity_fail_closed(self) -> None:
        kernel = _kernel()
        with self.assertRaises(A1AdmissionError):
            _snapshot(
                kernel,
                _candidate(document_overrides={"unknown": "value"}),
            )
        candidate = _candidate()
        candidate["payload"]["estimand"] = "mutated without resealing"
        with self.assertRaises(A1AdmissionError):
            _snapshot(kernel, candidate)


if __name__ == "__main__":
    unittest.main()
