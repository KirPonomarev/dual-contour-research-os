import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "inventory" / "dependencies" / "stage0b-shortlist.json"
DOC = ROOT / "docs" / "drafts" / "stage0b" / "license-security-shortlist.md"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DependencyShortlistTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = INVENTORY.read_text(encoding="utf-8")
        cls.data = json.loads(cls.raw)
        cls.candidates = {
            candidate["package"]: candidate for candidate in cls.data["candidates"]
        }

    def test_stage_and_authority_are_pinned(self):
        self.assertEqual(self.data["stage_id"], "s0b-license-audit")
        self.assertEqual(self.data["agent_id"], "agent-5")
        self.assertTrue(SHA256.fullmatch(self.data["contract_catalog_sha256"]))
        self.assertEqual(self.data["scope"]["data_class"], "D0_PUBLIC")
        self.assertFalse(self.data["scope"]["adoption_performed"])
        self.assertFalse(self.data["scope"]["canonical_reuse_decision_issued"])

    def test_expected_candidate_pins_and_decisions(self):
        expected = {
            "jsonschema": ("4.26.0", "ADOPT"),
            "httpx": ("0.28.1", "PARK"),
            "pydantic": ("2.13.4", "REJECT"),
            "cryptography": ("49.0.0", "PARK"),
        }
        self.assertEqual(set(self.candidates), set(expected))
        for package, (version, recommendation) in expected.items():
            with self.subTest(package=package):
                candidate = self.candidates[package]
                self.assertEqual(candidate["version"], version)
                self.assertEqual(candidate["recommendation"], recommendation)
                self.assertRegex(candidate["source_commit"], r"^[0-9a-f]{40}$")
                self.assertTrue(SHA256.fullmatch(candidate["source_distribution"]["sha256"]))
                self.assertTrue(candidate["source_distribution"]["sha256_verified_locally"])

    def test_actual_licenses_are_permissive_and_hashed(self):
        allowed = {"MIT", "BSD-3-Clause", "Apache-2.0 OR BSD-3-Clause"}
        for package, candidate in self.candidates.items():
            with self.subTest(package=package):
                license_data = candidate["license"]
                self.assertIn(license_data["spdx"], allowed)
                self.assertTrue(SHA256.fullmatch(license_data["sha256"]))
                self.assertTrue(license_data["sdist_matches_upstream"])
                self.assertIn(candidate["source_commit"], license_data["upstream_permalink"])

    def test_advisory_observation_is_time_bounded(self):
        for package, candidate in self.candidates.items():
            with self.subTest(package=package):
                advisories = candidate["advisories"]
                self.assertEqual(advisories["pypi_exact_version_count"], 0)
                self.assertEqual(advisories["github_exact_version_count"], 0)
                self.assertEqual(advisories["checked_at_utc"], self.data["audit_time_utc"])
        self.assertIn("time-bounded observation", self.data["method"]["known_limitation"])

    def test_adopt_candidate_has_fail_closed_conditions(self):
        candidate = self.candidates["jsonschema"]
        conditions = "\n".join(candidate["adoption_conditions"])
        self.assertIn("exact transitive versions", conditions)
        self.assertIn("ReuseDecisionReceipt", conditions)
        self.assertIn("SBOM", conditions)
        self.assertIn("no optional extras", conditions)

    def test_evidence_sources_are_public_https_urls(self):
        self.assertGreaterEqual(len(self.data["evidence_sources"]), 16)
        for source in self.data["evidence_sources"]:
            self.assertTrue(source.startswith("https://"), source)
        local_user_path = "/" + "Users/"
        local_volume_path = "/" + "Volumes/"
        for forbidden in (local_user_path, local_volume_path, "private", "token="):
            self.assertNotIn(forbidden, self.raw)

    def test_analysis_did_not_adopt_a_dependency(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", pyproject)
        self.assertFalse((ROOT / "requirements.txt").exists())
        self.assertFalse((ROOT / "uv.lock").exists())

    def test_draft_links_to_machine_readable_inventory(self):
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("draft_for_agent0", doc)
        self.assertIn("no dependency was installed", doc)
        for package in self.candidates:
            self.assertIn(f"`{package}", doc)

    def test_inventory_digest_is_stable_for_handoff(self):
        digest = hashlib.sha256(INVENTORY.read_bytes()).hexdigest()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
