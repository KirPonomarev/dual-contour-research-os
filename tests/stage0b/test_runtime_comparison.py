import json
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "inventory" / "runtime-comparison" / "comparison.json"
DRAFT = ROOT / "docs" / "drafts" / "stage0b" / "runtime-comparison.md"


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


class RuntimeComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        cls.draft = DRAFT.read_text(encoding="utf-8")

    def test_inventory_is_draft_evidence_not_canonical_receipt(self) -> None:
        self.assertEqual(self.inventory["status"], "draft_evidence_for_agent0")
        self.assertNotIn("selected_mode", self.inventory)
        self.assertEqual(
            self.inventory["next_action"].split()[0:2],
            ["Agent", "0"],
        )
        self.assertIn("not a `ReuseDecisionReceipt`", self.draft)

    def test_sources_require_freeze_and_public_release_authorization(self) -> None:
        for candidate in self.inventory["candidates"].values():
            self.assertTrue(candidate["source_freeze_required"])
            self.assertTrue(candidate["public_release_authorization_required"])
        self.assertFalse(
            self.inventory["evidence_status"]["source_freeze_receipts_present"]
        )

    def test_single_runtime_owner_and_validator_boundary_are_explicit(self) -> None:
        decision = self.inventory["draft_decision"]
        self.assertEqual(decision["single_runtime_owner"], "bridge_job_ledger")
        self.assertIn("validation_stays_external", decision["validator_result"])
        self.assertIn(
            "domain_registry_writer_is_only_scientific_outcome_writer",
            self.inventory["mandatory_conformance_gaps"],
        )

    def test_incomplete_cas_is_rejected(self) -> None:
        cas = next(
            row for row in self.inventory["comparison"]
            if row["capability"] == "cas_and_staging"
        )
        self.assertEqual(cas["owned_control_runtime"], "reject_as_complete_solution")
        self.assertEqual(cas["recommended_mode"], "minimal_bridge_glue")

    def test_sensitive_checkpoints_are_reference_only(self) -> None:
        gaps = self.inventory["mandatory_conformance_gaps"]
        tests = self.inventory["minimal_acceptance_tests"]
        self.assertIn("d2_d3_payloads_remain_domain_vault_refs_only", gaps)
        self.assertIn("d2_d3_bytes_are_rejected_and_vault_refs_are_accepted", tests)

    def test_public_inventory_contains_no_host_absolute_paths(self) -> None:
        local_uri_prefix = "file:" + "//"
        for value in _strings(self.inventory):
            self.assertFalse(value.startswith("/"), value)
            self.assertNotIn(local_uri_prefix, value)
        self.assertNotIn("](/", self.draft)
        self.assertNotIn(local_uri_prefix, self.draft)

    def test_evidence_counts_and_frozen_catalog_are_bound(self) -> None:
        evidence = self.inventory["evidence_status"]
        self.assertEqual(
            evidence["contracts_catalog_sha256"],
            "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50",
        )
        self.assertEqual(evidence["owned_control_runtime_focused_tests"]["passed"], 36)
        self.assertEqual(evidence["owned_durable_runtime_focused_tests"]["passed"], 36)


if __name__ == "__main__":
    unittest.main()
