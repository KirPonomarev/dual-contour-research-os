import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "inventory" / "market"


def load_json(name: str) -> dict:
    return json.loads((INVENTORY / name).read_text(encoding="utf-8"))


def walk_strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)
    elif isinstance(value, str):
        yield value


class MarketInventoryTests(unittest.TestCase):
    def test_repository_candidate_is_noncanonical_and_hash_sanitized(self):
        candidate = load_json("canonical-repository-candidate.json")
        self.assertEqual(candidate["status"], "draft_for_agent0")
        self.assertFalse(candidate["authority"])
        self.assertEqual(candidate["classification"], "D0_PUBLIC")
        self.assertEqual(candidate["constraints"]["canonical_receipt_writer"], "agent-0")
        repository = candidate["repository"]
        for key in (
            "remote_identity_sha256",
            "logical_remote_sha256",
            "inspected_branch_ref_sha256",
            "upstream_ref_sha256",
            "head_tree_manifest_sha256",
        ):
            self.assertRegex(repository[key], r"^[a-f0-9]{64}$")
        self.assertEqual(repository["head_sha"], repository["upstream_sha"])
        self.assertEqual((repository["ahead"], repository["behind"]), (0, 0))
        self.assertFalse(candidate["selection"]["worktree_bytes_selected"])
        self.assertFalse(candidate["selection"]["bridge_authority"])

    def test_source_freeze_parks_all_dirty_worktree_entries(self):
        candidate = load_json("source-freeze-candidate.json")
        self.assertEqual(candidate["status"], "draft_for_agent0")
        self.assertFalse(candidate["authority"])
        self.assertEqual(candidate["classification"], "D0_PUBLIC")
        payload = candidate["payload"]
        self.assertEqual(payload["head_sha"], payload["selected_source_sha"])
        self.assertEqual(payload["selected_source_mode"], "committed_head_only")
        dispositions = payload["path_dispositions"]
        self.assertEqual(sum(item["count"] for item in dispositions), 31)
        self.assertTrue(all(item["disposition"].startswith("parked_not_selected") for item in dispositions))
        for key in ("tracked_diff_sha256", "untracked_manifest_sha256", "dirty_manifest_sha256"):
            self.assertRegex(payload[key], r"^[a-f0-9]{64}$")

    def test_all_required_capability_families_are_inventory_candidates(self):
        inventory = load_json("reusable-capabilities.json")
        self.assertEqual(inventory["classification"], "D0_PUBLIC")
        required = {
            "append_only_ledger",
            "storage_lifecycle",
            "trial_registry",
            "backtest_primitives",
            "chronological_replay",
            "dataset_integrity",
            "evidence_routing_quality",
            "preregistration",
            "soak_recovery",
            "validator_adapters",
        }
        capabilities = {item["capability_id"]: item for item in inventory["capabilities"]}
        self.assertEqual(set(capabilities), required)
        for item in capabilities.values():
            self.assertGreater(item["matched_files"], 0)
            self.assertGreater(item["test_matches"], 0)
            self.assertEqual(item["matched_files"], item["non_test_matches"] + item["test_matches"])
            self.assertRegex(item["evidence_manifest_sha256"], r"^[a-f0-9]{64}$")
            self.assertEqual(item["canonical_owner"], "market-domain")
        self.assertFalse(inventory["admission"]["new_code_authorized"])
        self.assertFalse(inventory["admission"]["source_copy_authorized"])
        self.assertTrue(inventory["admission"]["requires_agent0_reuse_decision_receipt"])

    def test_public_inventory_contains_no_absolute_local_locator(self):
        for path in INVENTORY.glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            for value in walk_strings(payload):
                self.assertFalse(Path(value).is_absolute(), msg=f"absolute locator in {path.name}")
                self.assertNotIn("file:", value.lower())
                self.assertNotIn("private_url", value.lower())


if __name__ == "__main__":
    unittest.main()
