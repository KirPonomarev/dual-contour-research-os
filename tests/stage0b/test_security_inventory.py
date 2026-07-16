import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "inventory" / "security" / "runtime-components.json"
FREEZE = ROOT / "inventory" / "security" / "source-freeze-candidate.json"
DRAFT = ROOT / "docs" / "drafts" / "stage0b" / "security-runtime.md"
PUBLIC_ARTIFACTS = (INVENTORY, FREEZE, DRAFT)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


class SecurityInventoryTests(unittest.TestCase):
    def test_inventory_is_sanitized_candidate_with_unique_components(self) -> None:
        payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "READY_FOR_AGENT0_REVIEW")
        self.assertFalse(payload["source"]["remote_url_published"])
        self.assertFalse(payload["evidence_status"]["source_repository_mutated"])
        self.assertFalse(payload["evidence_status"]["code_copied"])
        self.assertEqual(payload["evidence_status"]["focused_test_result"]["tests_passed"], 87)
        component_ids = [item["component_id"] for item in payload["components"]]
        self.assertEqual(len(component_ids), 9)
        self.assertEqual(len(component_ids), len(set(component_ids)))
        self.assertIn("ReuseDecisionReceipt", payload["next_action"])

    def test_anchors_are_relative_content_addressed_and_allowlisted(self) -> None:
        payload = json.loads(INVENTORY.read_text(encoding="utf-8"))
        allowed_prefixes = ("tools/", "tests/", "research-os/kernel/")
        for anchor in payload["anchors"].values():
            path = anchor["relative_path"]
            self.assertFalse(Path(path).is_absolute())
            self.assertTrue(path.startswith(allowed_prefixes), path)
            self.assertNotIn("programs/", path)
            self.assertRegex(anchor["sha256"], SHA256_RE)
            self.assertRegex(anchor["git_blob_sha1"], GIT_SHA1_RE)
        anchor_ids = set(payload["anchors"])
        for component in payload["components"]:
            self.assertTrue(component["portability_gaps"])
            self.assertLessEqual(set(component["source_anchor_ids"]), anchor_ids)
            self.assertLessEqual(set(component["test_anchor_ids"]), anchor_ids)
        for contract in payload["contract_candidates"]:
            self.assertFalse(Path(contract["relative_path"]).is_absolute())
            self.assertTrue(contract["relative_path"].startswith("research-os/kernel/"))
            self.assertRegex(contract["sha256"], SHA256_RE)

    def test_source_freeze_candidate_is_aggregate_only_and_balanced(self) -> None:
        payload = json.loads(FREEZE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "CANDIDATE_NOT_CANONICAL")
        self.assertIsNone(payload["source"]["upstream"])
        self.assertFalse(payload["source"]["remote_url_published"])
        self.assertEqual(payload["working_tree"]["tracked_changes"]["entry_count"], 0)
        self.assertEqual(payload["working_tree"]["untracked"]["top_level_status_entry_count"], 15)
        self.assertEqual(payload["working_tree"]["untracked"]["expanded_file_count"], 496)
        categories = payload["working_tree"]["category_dispositions"]
        totals = payload["working_tree"]["disposition_totals"]
        self.assertEqual(sum(item["top_level_entry_count"] for item in categories), 15)
        self.assertEqual(totals["parked_for_review"] + totals["excluded"], 15)
        self.assertEqual(totals["selected_for_import"], 0)
        self.assertRegex(payload["working_tree"]["tracked_changes"]["path_status_manifest_sha256"], SHA256_RE)
        self.assertRegex(payload["working_tree"]["untracked"]["relative_path_manifest_sha256"], SHA256_RE)

    def test_required_artifact_metadata_is_present(self) -> None:
        for path in (INVENTORY, FREEZE):
            payload = json.loads(path.read_text(encoding="utf-8"))
            for field in ("status", "source", "scope_boundary", "evidence_status", "owner_agent_role", "next_action"):
                self.assertIn(field, payload, f"{path.name}: {field}")
        draft = DRAFT.read_text(encoding="utf-8")
        for label in ("Status:", "Source or target:", "Scope boundary:", "Evidence status:", "Owner/agent role:", "Next action:"):
            self.assertIn(label, draft)

    def test_public_artifacts_contain_no_local_paths_urls_or_secret_shapes(self) -> None:
        forbidden = (
            re.compile(r"/(?:Users|Volumes|home)/"),
            re.compile(r"[A-Za-z]:\\\\"),
            re.compile(r"(?:https?|file)://", re.IGNORECASE),
            re.compile(r"git@[^\s]+"),
            re.compile(r"authorization\s*:\s*bearer", re.IGNORECASE),
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            re.compile(r"(?:api[_-]?key|password|access[_-]?token)\s*[=:]", re.IGNORECASE),
        )
        for path in PUBLIC_ARTIFACTS:
            text = path.read_text(encoding="utf-8")
            for pattern in forbidden:
                self.assertIsNone(pattern.search(text), f"{path.name}: {pattern.pattern}")


if __name__ == "__main__":
    unittest.main()
