import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "receipts" / "source-freeze" / "s3-security-ingestion-safe-map.json"
REUSE = ROOT / "docs" / "receipts" / "reuse" / "s3-security-ingestion-safe-map.json"
STAGE = ROOT / "stages" / "s3-security-ingestion-safe-map-authority"
WORKER_STAGE = ROOT / "stages" / "s3-security-ingestion-safe-map"
AUTHORITY_RECEIPT = ROOT / "docs" / "receipts" / "integration" / "s3-security-ingestion-safe-map-authority.json"
WORKER_RECEIPT = ROOT / "docs" / "receipts" / "integration" / "s3-security-ingestion-safe-map.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def payload_sha256(receipt: dict) -> str:
    encoded = json.dumps(receipt["payload"], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class Stage3AuthorityTests(unittest.TestCase):
    def test_source_and_reuse_are_integrity_bound(self) -> None:
        source = load(SOURCE)
        reuse = load(REUSE)
        self.assertEqual(source["schema_id"], "SourceFreezeReceipt")
        self.assertEqual(reuse["schema_id"], "ReuseDecisionReceipt")
        self.assertEqual(source["integrity"]["payload_sha256"], payload_sha256(source))
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        self.assertEqual(source["payload"]["selected_source_sha"], "abc45b938ddef24aa9d2cb874dfa7f6bd7273ae8")
        self.assertEqual(reuse["payload"]["code_sha256"], "77f907b54cecc8e2dcbadb28b2907e953dd1b005994c10713900c30ee0cc8de7")
        self.assertEqual(reuse["payload"]["license_spdx"], "Proprietary-Internal-Owned")

    def test_authority_and_worker_scope_are_exact(self) -> None:
        envelope = load(STAGE / "stage-envelope.json")
        lease = load(STAGE / "ownership-lease.json")
        self.assertEqual(envelope["base_sha"], "c3d6f215ad653db358e7875474de3c436bcf6e4c")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertFalse(lease["delegation_allowed"])
        worker = envelope["authorized_worker_stage"]
        self.assertEqual(worker["agent_id"], "agent-4")
        self.assertEqual(worker["private_base_sha"], "abc45b938ddef24aa9d2cb874dfa7f6bd7273ae8")
        self.assertEqual(worker["write_set"], [
            "research-os/evolution/fixtures/stage3-public-source-safe-map-v1.json",
            "tools/security_bridge_stage3_intake.py",
            "tests/test_security_bridge_stage3_intake.py",
        ])
        self.assertFalse(worker["push_authority"])

    def test_contract_is_slice_only_and_fail_closed(self) -> None:
        envelope = load(STAGE / "stage-envelope.json")
        contract = envelope["security_intake_contract"]
        self.assertEqual(contract["stage_exit_authorized"], "slice-only")
        self.assertFalse(contract["declares_dual_contour_pre_soak_green"])
        self.assertFalse(contract["declares_ready_for_72h_soak"])
        self.assertIn("red-or-operational-atoms-remain-quarantined-and-produce-no-live-action", contract["invariants"])
        self.assertIn("cross-contour-D2-D3-read-or-Market-data-access", envelope["forbidden_scope"])

    def test_public_authority_is_sanitized(self) -> None:
        text = "\n".join(path.read_text() for path in [SOURCE, REUSE, STAGE / "stage-envelope.json", STAGE / "ownership-lease.json"])
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/Volumes/", text)
        self.assertNotIn("api_key", text.lower())
        self.assertNotIn("access_token", text.lower())
        self.assertNotIn("cookie_value", text.lower())
        self.assertIn("network-fetch-crawl-scan-live-target-test", text)
        self.assertIn("cross-contour-D2-D3-read", text)

    def test_exact_head_ci_receipt_binds_worker_lease(self) -> None:
        receipt = load(AUTHORITY_RECEIPT)
        envelope = load(WORKER_STAGE / "stage-envelope.json")
        lease = load(WORKER_STAGE / "ownership-lease.json")
        self.assertEqual(receipt["integrity"]["payload_sha256"], payload_sha256(receipt))
        self.assertEqual(receipt["payload"]["head_sha"], "782f4efbcdfa0124fef3de59482d419624b6913c")
        self.assertEqual(receipt["payload"]["audit_results"]["public_exact_head_ci"], "https://github.com/KirPonomarev/dual-contour-research-os/actions/runs/29615959973")
        self.assertFalse(receipt["payload"]["audit_results"]["live_or_connected_authority"])
        self.assertFalse(receipt["payload"]["audit_results"]["cross_contour_read_authorized"])
        self.assertEqual(envelope["public_authority_sha"], receipt["payload"]["head_sha"])
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertFalse(envelope["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_worker_receipt_proves_ingestion_and_safe_map_without_expansion(self) -> None:
        receipt = load(WORKER_RECEIPT)
        self.assertEqual(receipt["integrity"]["payload_sha256"], payload_sha256(receipt))
        self.assertEqual(receipt["payload"]["head_sha"], "b86de273bc1fd5b1816b4fb31b7ab45a1c652e07")
        audit = receipt["payload"]["audit_results"]
        self.assertEqual(audit["focused_stage3_intake_tests"], 16)
        self.assertEqual(audit["bounded_stage1_stage3_regression_tests"], 22)
        self.assertEqual(audit["safe_map_entry_count"], 3)
        self.assertEqual(audit["safe_map_ready_count"], 2)
        self.assertEqual(audit["safe_map_quarantine_count"], 1)
        self.assertEqual(audit["red_atoms_eligible_for_live_action"], 0)
        self.assertEqual(audit["red_atoms_eligible_for_hypothesis"], 0)
        self.assertEqual(audit["network_calls"], 0)
        self.assertEqual(audit["registry_writes"], 0)
        self.assertEqual(audit["cross_contour_reads"], 0)
        self.assertTrue(audit["exact_replay_deterministic"])
        self.assertTrue(audit["completes_stage3_public_source_ingestion"])
        self.assertTrue(audit["completes_stage3_safe_map"])
        self.assertFalse(audit["scientific_outcome_applied"])
        self.assertFalse(audit["public_source_body_or_safe_map_payload_in_public_repo"])
        self.assertFalse(audit["declares_dual_contour_pre_soak_green"])
        self.assertFalse(audit["live_or_connected_authority"])

        text = WORKER_RECEIPT.read_text()
        self.assertNotIn("Every protected object operation", text)
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/Volumes/", text)


if __name__ == "__main__":
    unittest.main()
