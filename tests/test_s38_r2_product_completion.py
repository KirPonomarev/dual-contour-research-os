from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_PRODUCT_SUBJECT = "37f671269adc5a15c6f6571c0cf1731eccb3fc38"


def git_file_at(subject: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{subject}:{relative}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode(encoding="utf-8", errors="replace"))
    return result.stdout


class ProductCompletionTests(unittest.TestCase):
    def test_live_status_requires_repair_and_denies_the_superseded_release(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        corridor = (ROOT / "docs/ADR/0003-a1-autonomous-research-corridor.md").read_text(encoding="utf-8")
        completion = (ROOT / "docs/PRODUCT_COMPLETION.md").read_text(encoding="utf-8")
        combined = "\n".join((readme, architecture, corridor, completion))

        self.assertNotIn("A1 runtime corridor is not yet implemented", combined)
        self.assertIn("`SUPERSEDED_REPAIR_REQUIRED + PRODUCT_REPAIR_IN_PROGRESS`", readme)
        self.assertIn("Status: `SUPERSEDED_REPAIR_REQUIRED`", completion)
        self.assertIn("SUPERSEDED_REPAIR_REQUIRED / DEPLOYMENT_DENIED", completion)
        self.assertIn("replacement release", combined)
        self.assertNotIn("OPERATIONAL_PROOF_PENDING", readme)
        self.assertNotIn(
            "PRODUCT_IMPLEMENTATION_COMPLETE / OPERATIONALLY_UNPROVEN", completion
        )
        self.assertIn("14-day/200-job final burn-in", completion)
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
            "docs/receipts/release/r00-superseded-release.json",
        )
        for relative in required:
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_historical_product_audit_is_verified_at_its_git_subject(self) -> None:
        relative_path = "docs/receipts/product/s38-r2-product-completion-audit.json"
        path = ROOT / relative_path
        receipt = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            path.read_bytes(),
            git_file_at(HISTORICAL_PRODUCT_SUBJECT, relative_path),
        )
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
                historical = git_file_at(HISTORICAL_PRODUCT_SUBJECT, relative)
                actual = hashlib.sha256(historical).hexdigest()
                self.assertEqual(actual, expected)
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{HISTORICAL_PRODUCT_SUBJECT}^{{commit}}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
