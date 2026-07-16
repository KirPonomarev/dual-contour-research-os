import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPTS = ROOT / "docs" / "receipts" / "integration"


class IntegrationReceiptTests(unittest.TestCase):
    def test_receipts_are_integrity_bound_and_refer_to_commits(self) -> None:
        paths = sorted(RECEIPTS.glob("*.json"))
        self.assertGreaterEqual(len(paths), 3)
        for path in paths:
            receipt = json.loads(path.read_text())
            self.assertEqual(receipt["schema_id"], "IntegrationReceipt")
            payload = receipt["payload"]
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(receipt["integrity"]["payload_sha256"], hashlib.sha256(encoded).hexdigest(), path.name)
            for field in ("base_sha", "integration_commit_sha"):
                result = subprocess.run(
                    ["git", "cat-file", "-e", f"{payload[field]}^{{commit}}"],
                    cwd=ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, f"{path.name}:{field}")
            self.assertRegex(payload["head_sha"], re.compile(r"^[0-9a-f]{40}$"))
            self.assertIn(f"git:{payload['head_sha']}", receipt["integrity"]["parent_refs"])
            self.assertTrue(payload["remote_ci_ref"].startswith("https://github.com/KirPonomarev/dual-contour-research-os/actions/runs/"))
            self.assertEqual(payload["audit_results"]["contract_gate"], "green")
            self.assertEqual(payload["audit_results"]["privacy_secret_scan"], "green")
            self.assertFalse(payload["audit_results"]["source_mutation"])


if __name__ == "__main__":
    unittest.main()
