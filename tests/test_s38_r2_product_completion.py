from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProductCompletionTests(unittest.TestCase):
    def test_canonical_status_is_current_without_operational_overclaim(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        corridor = (ROOT / "docs/ADR/0003-a1-autonomous-research-corridor.md").read_text(encoding="utf-8")
        completion = (ROOT / "docs/PRODUCT_COMPLETION.md").read_text(encoding="utf-8")
        combined = "\n".join((readme, architecture, corridor, completion))

        self.assertNotIn("A1 runtime corridor is not yet implemented", combined)
        self.assertIn("PRODUCT_IMPLEMENTATION_COMPLETE_CANDIDATE", readme)
        self.assertIn("OPERATIONAL_PROOF_PENDING", readme)
        self.assertIn("PRODUCT_IMPLEMENTATION_COMPLETE / OPERATIONALLY_UNPROVEN", completion)
        self.assertIn("14-day burn-in", completion)
        self.assertIn("at least 200 bounded jobs", completion)
        self.assertIn("AUTONOMOUS_CANONICAL_MUTATION=false", completion)
        self.assertIn("LIVE_TRADING=false", completion)

    def test_product_document_references_only_existing_evidence_classes(self) -> None:
        required = (
            "contracts/catalog.json",
            "contracts/a1/v1/catalog.json",
            "contracts/e5/v1/catalog.json",
            "docs/receipts/release/s38-final-release-manifest.json",
            "docs/receipts/integration/s38-final-release-freeze.json",
            "docs/receipts/integration/s38-r1-final-deployment-rebind.json",
            "docs/receipts/integration/s39-r1-predecessor-probe-fix.json",
        )
        for relative in required:
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_product_completion_audit_is_integrity_bound_and_non_authoritative(self) -> None:
        path = ROOT / "docs/receipts/product/s38-r2-product-completion-audit.json"
        receipt = json.loads(path.read_text(encoding="utf-8"))
        payload = receipt["payload"]
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(receipt["integrity"]["payload_sha256"], digest)
        self.assertEqual(payload["status"], "PRODUCT_IMPLEMENTATION_AUDIT_PASS")
        self.assertFalse(payload["operationally_proven"])
        self.assertFalse(payload["final_done"])
        self.assertFalse(payload["grants_authority"])
        self.assertEqual(payload["remaining_stage_ids"], ["S39", "S40", "S41", "S42"])
        for relative, expected in payload["file_sha256"].items():
            with self.subTest(relative=relative):
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, expected)
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{payload['audit_base_sha']}^{{commit}}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
