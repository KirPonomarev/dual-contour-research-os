import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPTS = ROOT / "docs" / "receipts" / "integration"


REQUIRED_STAGE1_RECEIPTS = [
    "s1-admission-kernel",
    "s1-ledger-durability",
    "s1-control-ipc",
    "s1-pause-ledger",
    "s1-trusted-ingestion",
    "s1-validation-boundary",
    "s1-budget-profile",
    "s1-budget-attempt-lifecycle",
    "s1-final-checkpoint-reopen-recovery",
    "s1-terminal-execution-receipt-lookup",
    "s1-researchd-researchctl-single-writer",
    "s1-researchd-service-entrypoint",
    "s1-auth-policy-boundary",
    "s1-permit-nonce-ledger",
    "s1-pause-epoch-fencing",
    "s1-market-offline-reference-e2e",
    "s1-security-offline-reference-e2e",
]


def load_receipt(name: str) -> dict:
    return json.loads((RECEIPTS / f"{name}.json").read_text())


def payload_sha256(receipt: dict) -> str:
    payload = json.dumps(receipt["payload"], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


class SkeletonGreenAuditTests(unittest.TestCase):
    def test_skeleton_green_receipt_is_integrity_bound_and_non_expansive(self) -> None:
        receipt = load_receipt("s1-skeleton-green-audit")
        self.assertEqual(receipt["schema_id"], "IntegrationReceipt")
        self.assertEqual(receipt["integrity"]["payload_sha256"], payload_sha256(receipt))
        audit = receipt["payload"]["audit_results"]
        self.assertTrue(audit["stage1_skeleton_green"])
        self.assertEqual(audit["declared_exit"], "SKELETON_GREEN")
        self.assertEqual(audit["remaining_stage1_gate"], "none")
        self.assertFalse(audit["pre_soak_green"])
        self.assertFalse(audit["ready_for_72h_soak"])
        self.assertFalse(audit["mvp_green"])
        self.assertFalse(audit["deployment_authority"])
        self.assertFalse(audit["live_or_connected_authority"])

    def test_skeleton_green_requires_all_stage1_receipts_and_two_domain_e2es(self) -> None:
        skeleton = load_receipt("s1-skeleton-green-audit")
        required = skeleton["payload"]["audit_results"]["required_integration_receipts"]
        self.assertEqual(required, REQUIRED_STAGE1_RECEIPTS)
        self.assertIn(
            "integration:integration-s1-market-offline-reference-e2e-20260717",
            skeleton["integrity"]["parent_refs"],
        )
        self.assertIn(
            "integration:integration-s1-security-offline-reference-e2e-20260717",
            skeleton["integrity"]["parent_refs"],
        )
        for name in required:
            receipt = load_receipt(name)
            self.assertEqual(receipt["integrity"]["payload_sha256"], payload_sha256(receipt), name)
            audit = receipt["payload"]["audit_results"]
            self.assertEqual(audit["contract_gate"], "green", name)
            self.assertEqual(audit["privacy_secret_scan"], "green", name)
            self.assertFalse(audit["source_mutation"], name)

    def test_skeleton_green_ci_and_head_are_exact_public_commit(self) -> None:
        receipt = load_receipt("s1-skeleton-green-audit")
        payload = receipt["payload"]
        self.assertEqual(payload["base_sha"], payload["head_sha"])
        self.assertEqual(payload["head_sha"], payload["integration_commit_sha"])
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{payload['head_sha']}^{{commit}}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"git:{payload['head_sha']}", receipt["integrity"]["parent_refs"])
        self.assertEqual(
            payload["remote_ci_ref"],
            "https://github.com/KirPonomarev/dual-contour-research-os/actions/runs/29604377316",
        )


if __name__ == "__main__":
    unittest.main()
