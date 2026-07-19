from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest

from tools.method_card import MethodTransferPolicy, issue_method_card
from tools.recipient_shadow import RecipientShadowPolicy, ShadowObservation, evaluate_recipient_shadow


ROOT = Path(__file__).resolve().parents[1]
METHOD_PROFILE_SHA = "ecbf5578f85d50b9cdf53f5bead12f00a27c9500474faf50860d952408188628"
SHADOW_PROFILE_SHA = "4e55fad9e3b8db6d20dd1bfcf7d24565ca7c5f340992e6a0181016845e830d6e"
AT = "2026-07-19T01:05:00Z"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _method() -> tuple[dict[str, object], dict[str, object]]:
    draft = {
        "method_id": "bounded-replication-v1", "method_family": "REPLICATION", "objective_class": "ROBUSTNESS_CHECK",
        "input_contract_refs": ["contract:EvidenceSidecar:v1"], "output_contract_refs": ["contract:ReplicationAssessment:v1"],
        "precondition_codes": ["D0_D1_ONLY"], "invariant_codes": ["NO_RECIPIENT_WRITE"], "failure_mode_codes": ["NEGATIVE_TRANSFER"],
        "evaluation_protocol_ref": "protocol:replication-matrix-v1", "provenance_refs": ["public:synthetic-method-fixture-v1"],
        "eligible_recipient_classes": ["SECURITY_RESEARCH"], "source_shadow_taint": "NONE",
    }
    payload = {
        "draft_sha256": _digest(draft), "source_domain": "market", "source_classification": "D1_INTERNAL_SANITIZED", "source_shadow_taint": "NONE",
        "scan_profile_sha256": METHOD_PROFILE_SHA, "reviewed_field_paths": sorted(draft), "forbidden_match_count": 0,
        "method_family": draft["method_family"], "eligible_recipient_classes": draft["eligible_recipient_classes"], "expires_at": "2026-07-20T01:05:00Z",
        "raw_evidence_included": False, "targets_included": False, "strategies_included": False, "holdout_included": False, "secret_prompts_included": False, "grants_authority": False,
    }
    digest = _digest(payload)
    receipt = {
        "schema_id": "DeclassificationReceipt", "schema_version": "1.0.0", "object_id": "declassification-receipt:sha256:" + digest,
        "issued_at": "2026-07-19T01:01:00Z", "issuer": {"id": "synthetic-domain-writer", "authority_class": "domain-declassification-authority"},
        "contour": "market", "classification": "D1_INTERNAL_SANITIZED", "payload": payload,
        "integrity": {"payload_sha256": digest, "parent_refs": ["draft:sha256:" + payload["draft_sha256"]]},
    }
    policy = MethodTransferPolicy(ROOT / "provenance/method-card-declassification-v1.json", expected_sha256=METHOD_PROFILE_SHA)
    return issue_method_card(policy, draft, receipt, issued_at=AT), receipt


def _observations(card_id: str, treatment_deltas: tuple[int, ...] = (20, 30, 40, 50)) -> tuple[list[ShadowObservation], list[ShadowObservation]]:
    cases = ("CASE_EDGE", "CASE_NEGATIVE", "CASE_STANDARD", "CASE_STRESS")
    benchmark = "6696c070a869fc21f1706d1b47f7bd65ca4ad14a088aac21624ca371a77e9412"
    control = [ShadowObservation(case, "CONTROL", 500, benchmark, "a" * 64, "b" * 64, card_id) for case in cases]
    treatment = [ShadowObservation(case, "TREATMENT", 500 + delta, benchmark, "a" * 64, "b" * 64, card_id) for case, delta in zip(cases, treatment_deltas)]
    return control, treatment


class S36RecipientShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.method_policy = MethodTransferPolicy(ROOT / "provenance/method-card-declassification-v1.json", expected_sha256=METHOD_PROFILE_SHA)
        self.policy = RecipientShadowPolicy(ROOT / "provenance/recipient-shadow-evaluation-v1.json", expected_sha256=SHADOW_PROFILE_SHA)
        self.card, self.receipt = _method()

    def evaluate(self, control: list[ShadowObservation], treatment: list[ShadowObservation]):
        return evaluate_recipient_shadow(self.policy, self.method_policy, self.card, self.receipt, recipient_class="SECURITY_RESEARCH", control=control, treatment=treatment, at=AT)

    def test_positive_effect_is_scoped_deterministic_and_not_adopted(self) -> None:
        control, treatment = _observations(self.card["object_id"])
        first = self.evaluate(control, treatment)
        second = self.evaluate(list(reversed(control)), list(reversed(treatment)))
        self.assertEqual(first, second)
        self.assertEqual(first.status, "POSITIVE_SHADOW_EFFECT_NOT_ADOPTED")
        self.assertEqual((first.mean_delta_milli, first.interval_min_milli, first.interval_max_milli), (35, 20, 50))
        self.assertEqual(first.recipient_registry_writes, 0)
        self.assertFalse(first.canonical_adoption)
        self.assertFalse(first.grants_authority)

    def test_zero_interval_is_not_established(self) -> None:
        control, treatment = _observations(self.card["object_id"], (0, 20, 30, 40))
        report = self.evaluate(control, treatment)
        self.assertEqual(report.status, "NOT_ESTABLISHED")
        self.assertEqual(report.rollback_proposal["status"], "WAIT_AUTHORITY")

    def test_negative_transfer_creates_reusable_failure_and_rollback_proposal(self) -> None:
        control, treatment = _observations(self.card["object_id"], (20, -5, 30, 40))
        report = self.evaluate(control, treatment)
        self.assertEqual(report.status, "NEGATIVE_TRANSFER")
        self.assertTrue(report.failure_memory["reusable"])
        self.assertEqual(report.rollback_proposal["action"], "REMOVE_METHOD_FROM_RECIPIENT_SHADOW")
        self.assertFalse(report.rollback_proposal["applied"])

    def test_poison_cannot_promote_even_with_large_effect(self) -> None:
        control, treatment = _observations(self.card["object_id"], (300, 300, 300, 300))
        treatment[2] = replace(treatment[2], poison_present=True)
        report = self.evaluate(control, treatment)
        self.assertEqual(report.status, "REJECTED_POISONED_MEMORY")
        self.assertTrue(report.failure_memory["reusable"])
        self.assertFalse(report.canonical_adoption)

    def test_context_confound_and_recipient_write_fail_closed(self) -> None:
        control, treatment = _observations(self.card["object_id"])
        treatment[0] = replace(treatment[0], recipient_snapshot_sha256="c" * 64)
        self.assertEqual(self.evaluate(control, treatment).status, "REJECTED_CONFOUND")
        control, treatment = _observations(self.card["object_id"])
        treatment[0] = replace(treatment[0], recipient_write_count=1)
        report = self.evaluate(control, treatment)
        self.assertEqual(report.status, "REJECTED_BOUNDARY")
        self.assertEqual(report.recipient_registry_writes, 0)


if __name__ == "__main__":
    unittest.main()
