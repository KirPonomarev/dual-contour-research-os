import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from verify_release_identity import inspect


class ReleaseIdentityTests(unittest.TestCase):
    def test_canonical_release_identity_is_exact_and_not_a_deploy_gate(self) -> None:
        result = inspect(ROOT)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["sbom_package_count"], 107)
        self.assertFalse(result["declares_ready_for_72h_soak"])
        self.assertFalse(result["external_action_authority"])

    def copied(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative in ("docs/receipts/release", "docs/receipts/integration", "ops/release", "contracts"):
            shutil.copytree(ROOT / relative, root / relative)
        return temporary, root

    def test_manifest_payload_tamper_is_rejected(self) -> None:
        temporary, root = self.copied()
        with temporary:
            path = root / "docs/receipts/release/s4-release-manifest.json"
            value = json.loads(path.read_text())
            value["payload"]["config_sha256"] = "0" * 64
            path.write_text(json.dumps(value), encoding="utf-8")
            failures = inspect(root, check_git=False)["failures"]
            self.assertIn("manifest.payload_integrity", failures)
            self.assertIn("manifest.binding", failures)

    def test_config_drift_breaks_release_binding(self) -> None:
        temporary, root = self.copied()
        with temporary:
            path = root / "ops/release/researchd.config.template.json"
            value = json.loads(path.read_text())
            value["deadline_seconds"] = 4
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertIn("manifest.binding", inspect(root, check_git=False)["failures"])

    def test_sbom_image_or_package_removal_is_rejected(self) -> None:
        temporary, root = self.copied()
        with temporary:
            path = root / "docs/receipts/release/s4-release-sbom.spdx.json"
            value = json.loads(path.read_text())
            value["packages"] = value["packages"][1:]
            path.write_text(json.dumps(value), encoding="utf-8")
            failures = inspect(root, check_git=False)["failures"]
            self.assertIn("sbom.shape", failures)
            self.assertIn("sbom.identities", failures)


if __name__ == "__main__":
    unittest.main()
