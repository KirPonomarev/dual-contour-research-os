from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs" / "receipts" / "A1_CONTRACTS_FROZEN.json"


class A1FreezeReceiptTests(unittest.TestCase):
    def test_freeze_verifier_is_green(self) -> None:
        result = subprocess.run(
            ["python3", "tools/verify_a1_freeze_receipt.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("a1_freeze_receipt=GREEN", result.stdout)

    def test_receipt_is_scope_limited(self) -> None:
        receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        denied = set(receipt["scope"]["does_not_allow"])
        self.assertIn("autonomous-canonical-mutation", denied)
        self.assertIn("live-trading", denied)
        self.assertIn("live-security-execution", denied)
        self.assertIn("bridge-write-of-domain-scientific-truth", denied)
        self.assertIn("deployment", denied)

    def test_freeze_is_bound_to_successful_exact_head_ci(self) -> None:
        receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        ci = receipt["exact_head_ci"]
        self.assertEqual(ci["head_sha"], receipt["frozen_bundle_head_sha"])
        self.assertEqual(ci["conclusion"], "success")
        self.assertTrue(ci["url"].endswith(str(ci["run_id"])))

    def test_verifier_fails_closed_on_catalog_drift(self) -> None:
        source = (ROOT / "tools" / "verify_a1_freeze_receipt.py").read_text(encoding="utf-8")
        self.assertIn('fail(f"hash_mismatch:{field}")', source)
        self.assertIn('fail("catalog_status")', source)
        self.assertIn('fail("scope_denies")', source)


if __name__ == "__main__":
    unittest.main()
