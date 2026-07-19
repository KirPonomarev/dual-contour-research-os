from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

from tools.method_card import (
    MethodTransferError,
    MethodTransferPolicy,
    issue_method_card,
    recipient_eligibility,
    validate_method_card,
)


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "provenance" / "method-card-declassification-v1.json"
PROFILE_SHA = "ecbf5578f85d50b9cdf53f5bead12f00a27c9500474faf50860d952408188628"
AT = "2026-07-19T01:00:00Z"


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _draft() -> dict[str, object]:
    return {
        "method_id": "bounded-replication-v1",
        "method_family": "REPLICATION",
        "objective_class": "ROBUSTNESS_CHECK",
        "input_contract_refs": ["contract:EvidenceSidecar:v1"],
        "output_contract_refs": ["contract:ReplicationAssessment:v1"],
        "precondition_codes": ["D0_D1_ONLY", "FROZEN_INPUTS"],
        "invariant_codes": ["NO_DOMAIN_PAYLOAD", "NO_RECIPIENT_WRITE"],
        "failure_mode_codes": ["CORRELATED_SOURCE", "UNDERPOWERED"],
        "evaluation_protocol_ref": "protocol:replication-matrix-v1",
        "provenance_refs": ["public:synthetic-method-fixture-v1"],
        "eligible_recipient_classes": ["GENERIC_RESEARCH", "SECURITY_RESEARCH"],
        "source_shadow_taint": "NONE",
    }


def _receipt(draft: dict[str, object], **overrides: object) -> dict[str, object]:
    payload = {
        "draft_sha256": _digest(draft),
        "source_domain": "market",
        "source_classification": "D1_INTERNAL_SANITIZED",
        "source_shadow_taint": "NONE",
        "scan_profile_sha256": PROFILE_SHA,
        "reviewed_field_paths": sorted(draft),
        "forbidden_match_count": 0,
        "method_family": draft["method_family"],
        "eligible_recipient_classes": draft["eligible_recipient_classes"],
        "expires_at": "2026-07-20T01:00:00Z",
        "raw_evidence_included": False,
        "targets_included": False,
        "strategies_included": False,
        "holdout_included": False,
        "secret_prompts_included": False,
        "grants_authority": False,
    }
    payload.update(overrides)
    digest = _digest(payload)
    return {
        "schema_id": "DeclassificationReceipt", "schema_version": "1.0.0",
        "object_id": "declassification-receipt:sha256:" + digest,
        "issued_at": "2026-07-19T00:55:00Z",
        "issuer": {"id": "synthetic-market-domain-writer", "authority_class": "domain-declassification-authority"},
        "contour": payload["source_domain"], "classification": payload["source_classification"],
        "payload": payload,
        "integrity": {"payload_sha256": digest, "parent_refs": ["draft:sha256:" + payload["draft_sha256"]]},
    }


class S35MethodCardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = MethodTransferPolicy(PROFILE, expected_sha256=PROFILE_SHA)

    def test_declassified_card_is_metadata_only_and_shadow_eligible(self) -> None:
        draft = _draft()
        receipt = _receipt(draft)
        before = json.dumps(receipt, sort_keys=True)
        card = issue_method_card(self.policy, draft, receipt, issued_at=AT)
        self.assertEqual(card["payload"]["transfer_status"], "DECLASSIFIED_METHOD_ONLY")
        self.assertIs(card["payload"]["no_raw_payload"], True)
        self.assertIs(card["payload"]["grants_authority"], False)
        self.assertNotIn("evidence", card["payload"])
        self.assertEqual(before, json.dumps(receipt, sort_keys=True))
        eligible = recipient_eligibility(
            self.policy, card, receipt, recipient_class="SECURITY_RESEARCH", at=AT
        )
        self.assertEqual(eligible.status, "ELIGIBLE_FOR_RECIPIENT_SHADOW_ONLY")
        self.assertFalse(eligible.recipient_write)
        self.assertFalse(eligible.grants_authority)
        denied = recipient_eligibility(
            self.policy, card, receipt, recipient_class="MARKET_RESEARCH", at=AT
        )
        self.assertEqual(denied.status, "INELIGIBLE")

    def test_shadow_unapplied_cannot_become_method_card(self) -> None:
        draft = _draft()
        draft["source_shadow_taint"] = "SHADOW_UNAPPLIED"
        with self.assertRaisesRegex(MethodTransferError, "shadow taint denied"):
            issue_method_card(self.policy, draft, _receipt(draft), issued_at=AT)

    def test_d2_d3_and_domain_authority_spoof_fail_closed(self) -> None:
        draft = _draft()
        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            receipt = _receipt(draft, source_classification=classification)
            with self.assertRaisesRegex(MethodTransferError, "binding or authority"):
                issue_method_card(self.policy, draft, receipt, issued_at=AT)
        spoof = _receipt(draft)
        spoof["issuer"]["authority_class"] = "bridge"
        with self.assertRaisesRegex(MethodTransferError, "binding or authority"):
            issue_method_card(self.policy, draft, spoof, issued_at=AT)

    def test_raw_target_holdout_prompt_and_metadata_leaks_fail_closed(self) -> None:
        draft = _draft()
        for field in (
            "raw_evidence_included", "targets_included", "strategies_included",
            "holdout_included", "secret_prompts_included",
        ):
            receipt = _receipt(draft, **{field: True})
            with self.assertRaisesRegex(MethodTransferError, "binding or authority"):
                issue_method_card(self.policy, draft, receipt, issued_at=AT)
        for leaked in (
            "public:https://example.invalid/raw", "public:/Users/operator/private",
            "public:10.0.0.1", "public:person@example.invalid", "public:sk-secretvalue",
        ):
            poisoned = _draft()
            poisoned["provenance_refs"] = [leaked]
            with self.assertRaises(MethodTransferError):
                issue_method_card(self.policy, poisoned, _receipt(poisoned), issued_at=AT)

    def test_receipt_draft_expiry_and_card_tamper_fail_closed(self) -> None:
        draft = _draft()
        receipt = _receipt(draft)
        mismatch = _receipt(draft, draft_sha256="0" * 64)
        with self.assertRaisesRegex(MethodTransferError, "binding or authority"):
            issue_method_card(self.policy, draft, mismatch, issued_at=AT)
        expired = _receipt(draft, expires_at="2026-07-19T00:59:59Z")
        with self.assertRaisesRegex(MethodTransferError, "binding or authority"):
            issue_method_card(self.policy, draft, expired, issued_at=AT)
        card = issue_method_card(self.policy, draft, receipt, issued_at=AT)
        forged = deepcopy(card)
        forged["payload"]["grants_authority"] = True
        with self.assertRaisesRegex(MethodTransferError, "binding or authority"):
            validate_method_card(self.policy, forged, declassification_receipt=receipt, at=AT)

    def test_additive_contract_catalog_is_frozen_and_core_unchanged(self) -> None:
        result = subprocess.run(
            ["python3", "tools/validate_e5_contracts.py"], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("e5_contract_validation=GREEN", result.stdout)
        self.assertEqual(
            hashlib.sha256((ROOT / "contracts" / "catalog.json").read_bytes()).hexdigest(),
            "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50",
        )


if __name__ == "__main__":
    unittest.main()
