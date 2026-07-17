import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "receipts" / "source-freeze" / "s3-security-ingestion-safe-map.json"
REUSE = ROOT / "docs" / "receipts" / "reuse" / "s3-security-ingestion-safe-map.json"
STAGE = ROOT / "stages" / "s3-security-ingestion-safe-map-authority"


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


if __name__ == "__main__":
    unittest.main()
