import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ContractBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads((ROOT / "contracts" / "catalog.json").read_text())

    def test_validator_cannot_apply_outcome(self) -> None:
        spec = self.catalog["contracts"]["ValidationReceipt"]
        self.assertEqual(spec["writer"], "pinned-validator")
        self.assertEqual(spec["authority"], "proposed-outcome-only")

    def test_domain_writer_owns_canonical_link(self) -> None:
        spec = self.catalog["contracts"]["DomainTrialLinkReceipt"]
        self.assertEqual(spec["writer"], "domain-registry-writer")

    def test_sensitive_checkpoint_is_reference_only(self) -> None:
        fields = self.catalog["contracts"]["CheckpointManifest"]["required_payload"]
        self.assertIn("payload_ref", fields)
        self.assertIn("payload_stored_in_domain_vault", fields)

    def test_generated_schemas_are_strict(self) -> None:
        for path in (ROOT / "contracts" / "v1").glob("*.schema.json"):
            schema = json.loads(path.read_text())
            self.assertFalse(schema["additionalProperties"], path.name)
            self.assertFalse(schema["properties"]["payload"]["additionalProperties"], path.name)


if __name__ == "__main__":
    unittest.main()
