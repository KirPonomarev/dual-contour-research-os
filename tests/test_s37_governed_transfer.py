from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from tests.test_s36_recipient_shadow import _method, _observations
from tools.governed_transfer import (
    GovernedTransferPolicy,
    build_capability_proof,
    build_transfer_request,
    validate_transfer_request,
)
from tools.method_card import MethodTransferPolicy
from tools.recipient_shadow import RecipientShadowPolicy, evaluate_recipient_shadow


ROOT = Path(__file__).resolve().parents[1]
METHOD_SHA = "ecbf5578f85d50b9cdf53f5bead12f00a27c9500474faf50860d952408188628"
SHADOW_SHA = "4e55fad9e3b8db6d20dd1bfcf7d24565ca7c5f340992e6a0181016845e830d6e"
TRANSFER_SHA = "5d895f221d6a2971dd9341c1dbf9bd74dcd21c0f5d2b129df9dce974ccd194e9"
NOW = "2026-07-19T01:20:00Z"


class S37GovernedTransferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.method_policy = MethodTransferPolicy(ROOT / "provenance/method-card-declassification-v1.json", expected_sha256=METHOD_SHA)
        self.shadow_policy = RecipientShadowPolicy(ROOT / "provenance/recipient-shadow-evaluation-v1.json", expected_sha256=SHADOW_SHA)
        self.policy = GovernedTransferPolicy(ROOT / "provenance/governed-method-transfer-v1.json", expected_sha256=TRANSFER_SHA)
        self.card, self.receipt = _method()
        control, treatment = _observations(self.card["object_id"])
        self.report = evaluate_recipient_shadow(self.shadow_policy, self.method_policy, self.card, self.receipt, recipient_class="SECURITY_RESEARCH", control=control, treatment=treatment, at=NOW)
        self.request = build_transfer_request(self.policy, self.card, self.receipt, self.report, request_id="transfer-request-0001", nonce="nonce-transfer-0001", issued_at="2026-07-19T01:15:00Z", expires_at="2026-07-19T02:15:00Z")

    def validate(self, request=None, **kwargs):
        return validate_transfer_request(self.policy, self.method_policy, self.card, self.receipt, self.report, request or self.request, now=kwargs.pop("now", NOW), **kwargs)

    def test_valid_chain_stops_at_human_domain_authority(self) -> None:
        decision = self.validate()
        self.assertEqual(decision.status, "WAIT_HUMAN_DOMAIN_AUTHORITY")
        self.assertEqual(decision.capability_status, "METHOD_TRANSFER_PASS_FOR_FROZEN_SCOPE")
        self.assertFalse(decision.promotion_receipt_issued)
        self.assertFalse(decision.promotion_applied)
        self.assertEqual(decision.recipient_registry_writes, 0)
        self.assertFalse(decision.grants_authority)

    def test_replay_and_expiry_are_denied(self) -> None:
        replay = self.validate(consumed_request_ids={"transfer-request-0001"})
        self.assertEqual(replay.status, "REJECTED_REPLAY")
        expired = self.validate(now="2026-07-19T02:15:00Z")
        self.assertEqual(expired.status, "REJECTED_EXPIRED")

    def test_chain_tamper_and_promotion_reference_are_denied(self) -> None:
        for field, value in (("method_card_id", "method-card:sha256:" + "0" * 64), ("shadow_report_sha256", "0" * 64), ("promotion_receipt_ref", "forged:promotion"), ("grants_authority", True)):
            forged = deepcopy(self.request)
            forged["payload"][field] = value
            self.assertEqual(self.validate(forged).status, "REJECTED_CHAIN")

    def test_negative_shadow_cannot_enter_authority_corridor(self) -> None:
        control, treatment = _observations(self.card["object_id"], (20, -5, 30, 40))
        negative = evaluate_recipient_shadow(self.shadow_policy, self.method_policy, self.card, self.receipt, recipient_class="SECURITY_RESEARCH", control=control, treatment=treatment, at=NOW)
        request = build_transfer_request(self.policy, self.card, self.receipt, negative, request_id="transfer-request-0002", nonce="nonce-transfer-0002", issued_at="2026-07-19T01:15:00Z", expires_at="2026-07-19T02:15:00Z")
        decision = validate_transfer_request(self.policy, self.method_policy, self.card, self.receipt, negative, request, now=NOW)
        self.assertEqual(decision.status, "REJECTED_CHAIN")

    def test_capability_proof_is_scoped_and_non_authoritative(self) -> None:
        proof = build_capability_proof(self.policy, self.validate(), subject_sha="64a911e4bd6bc03a4ab0e29be373fa3a3352c705", issued_at="2026-07-19T01:20:00Z", expires_at="2026-08-02T01:20:00Z", evidence_refs=["receipt:integration-s35-method-card-20260719", "receipt:integration-s36-recipient-shadow-20260719"])
        self.assertEqual(proof["payload"]["status"], "METHOD_TRANSFER_PASS_FOR_FROZEN_SCOPE")
        self.assertEqual(proof["payload"]["authority_state"], "WAIT_HUMAN_DOMAIN_AUTHORITY")
        self.assertFalse(proof["payload"]["promotion_receipt_issued"])
        self.assertFalse(proof["payload"]["promotion_applied"])
        self.assertFalse(proof["payload"]["scientific_truth_transfer"])
        self.assertFalse(proof["payload"]["grants_authority"])
        encoded = json.dumps(proof["payload"], sort_keys=True, separators=(",", ":")).encode()
        import hashlib
        self.assertEqual(proof["integrity"]["payload_sha256"], hashlib.sha256(encoded).hexdigest())
        frozen = json.loads((ROOT / "docs/receipts/capability/e5-method-transfer.json").read_text())
        frozen_encoded = json.dumps(frozen["payload"], sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(frozen["integrity"]["payload_sha256"], hashlib.sha256(frozen_encoded).hexdigest())
        self.assertEqual(frozen["payload"]["status"], "METHOD_TRANSFER_PASS_FOR_FROZEN_SCOPE")
        self.assertEqual(frozen["payload"]["authority_state"], "WAIT_HUMAN_DOMAIN_AUTHORITY")
        self.assertFalse(frozen["payload"]["promotion_applied"])


if __name__ == "__main__":
    unittest.main()
