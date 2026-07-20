from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import physical_release_control as control


class ExactEngineImageMappingTests(unittest.TestCase):
    def test_public_f10_evidence_binds_portable_and_engine_identities(self) -> None:
        receipt = json.loads(
            (ROOT / "docs/receipts/release/f10-disposable-linux-release-e2e-sanitized.json").read_text(
                encoding="utf-8"
            )
        )
        identity = receipt["payload"]["release_identity"]
        self.assertEqual(identity["portable_image_id"], control.IMAGE_ID)
        self.assertEqual(identity["local_exact_image_id"], control.ENGINE_IMAGE_ID)
        self.assertNotEqual(control.IMAGE_ID, control.ENGINE_IMAGE_ID)

    def test_rendered_bundle_uses_engine_id_without_relabeling_portable_id(self) -> None:
        bundle = control._render_bundle({"carrier_path": "/owner-only/exact-r17-carrier.tar"})
        self.assertEqual(bundle.image_id, control.ENGINE_IMAGE_ID)
        self.assertIn(control.ENGINE_IMAGE_ID.encode("ascii"), bundle.unit_bytes)
        self.assertNotIn(control.IMAGE_ID.encode("ascii"), bundle.unit_bytes)
        self.assertEqual(bundle.archive_sha256, control.CARRIER_SHA256)
        self.assertEqual(bundle.release_sha, control.RUNTIME_RELEASE_SHA)


if __name__ == "__main__":
    unittest.main()
