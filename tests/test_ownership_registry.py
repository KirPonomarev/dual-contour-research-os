import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from validate_contracts import live_repository_paths, ownership_failures


class OwnershipRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads((ROOT / "ownership" / "registry.json").read_text())
        cls.live_paths = live_repository_paths()

    def test_current_registry_covers_every_live_path_exactly_once(self) -> None:
        self.assertEqual(ownership_failures(self.registry, self.live_paths), [])

    def test_amendment_receipts_form_a_chain_to_current_registry(self) -> None:
        amendments = [
            json.loads(path.read_text())
            for path in sorted(
                (ROOT / "docs" / "receipts").glob("OWNERSHIP_REGISTRY_AMENDMENT*.json")
            )
        ]
        current = hashlib.sha256((ROOT / "ownership" / "registry.json").read_bytes()).hexdigest()
        frozen = json.loads((ROOT / "docs" / "receipts" / "CONTRACTS_FROZEN.json").read_text())
        cursor = frozen["ownership_registry_sha256"]
        while cursor != current:
            candidates = [
                value
                for value in amendments
                if value["previous_ownership_registry_sha256"] == cursor
            ]
            self.assertEqual(len(candidates), 1)
            amendment = candidates[0]
            self.assertEqual(amendment["status"], "OWNERSHIP_REGISTRY_AMENDED")
            cursor = amendment["current_ownership_registry_sha256"]
        self.assertEqual(cursor, current)

    def test_reuse_receipt_is_schema_shaped_and_integrity_bound(self) -> None:
        receipt = json.loads(
            (
                ROOT
                / "docs"
                / "receipts"
                / "reuse"
                / "e0-ownership-registry-amendment.json"
            ).read_text()
        )
        schema = json.loads(
            (ROOT / "contracts" / "v1" / "ReuseDecisionReceipt.schema.json").read_text()
        )
        payload = json.dumps(receipt["payload"], sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(set(receipt), set(schema["properties"]))
        self.assertEqual(
            set(receipt["payload"]),
            set(schema["properties"]["payload"]["properties"]),
        )
        self.assertEqual(receipt["integrity"]["payload_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(receipt["payload"]["license_spdx"], "NOASSERTION")

    def test_nonexistent_canonical_directory_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["canonical_owners"]["src/research_bridge/not-a-live-directory/**"] = "agent-1"
        failures = ownership_failures(candidate, self.live_paths)
        self.assertIn(
            "canonical_pattern_matches_no_live_path:src/research_bridge/not-a-live-directory/**",
            failures,
        )

    def test_live_reserved_path_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["reserved_future_paths"]["src/research_bridge/control.py"] = "agent-1"
        failures = ownership_failures(candidate, self.live_paths)
        self.assertIn("reserved_path_is_live:src/research_bridge/control.py", failures)

    def test_overlapping_owner_patterns_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.registry)
        candidate["canonical_owners"]["src/research_bridge/*.py"] = "agent-1"
        failures = ownership_failures(candidate, self.live_paths)
        self.assertTrue(
            any(value.startswith("ownership_overlap:src/research_bridge/") for value in failures),
            failures,
        )

    def test_unowned_live_path_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.registry)
        del candidate["canonical_owners"]["src/research_bridge/control.py"]
        failures = ownership_failures(candidate, self.live_paths)
        self.assertIn("unowned_live_path:src/research_bridge/control.py", failures)


if __name__ == "__main__":
    unittest.main()
