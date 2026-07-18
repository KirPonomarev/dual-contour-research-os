from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
A1 = ROOT / "contracts" / "a1" / "v1"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class A1ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load(A1 / "catalog.json")
        cls.profiles = {
            name: load(A1 / entry["ref"])
            for name, entry in cls.catalog["profile_manifest"].items()
        }

    def test_validator_is_green(self) -> None:
        result = subprocess.run(
            ["python3", "tools/validate_a1_contracts.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("A1 contracts: GREEN", result.stdout)

    def test_contract_set_is_exact_and_additive(self) -> None:
        self.assertEqual(self.catalog["status"], "frozen")
        self.assertEqual(
            set(self.catalog["contracts"]),
            {"MaterialEvent", "CandidateSpecDraft", "AdmissionReceipt", "CapabilityProofReceipt"},
        )
        core_hash = hashlib.sha256((ROOT / "contracts" / "catalog.json").read_bytes()).hexdigest()
        self.assertEqual(self.catalog["core_catalog_sha256"], core_hash)

    def test_generated_schemas_are_deterministic_and_strict(self) -> None:
        result = subprocess.run(
            ["python3", "tools/generate_a1_contracts.py", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in self.catalog["contracts"]:
            schema = load(A1 / f"{name}.schema.json")
            self.assertFalse(schema["additionalProperties"])
            self.assertFalse(schema["properties"]["payload"]["additionalProperties"])
            self.assertFalse(schema["properties"]["integrity"]["additionalProperties"])

    def test_profile_manifest_hashes_are_exact(self) -> None:
        for entry in self.catalog["profile_manifest"].values():
            actual = hashlib.sha256((A1 / entry["ref"]).read_bytes()).hexdigest()
            self.assertEqual(entry["sha256"], actual)

    def test_writer_matrix_never_grants_execution_or_domain_truth(self) -> None:
        matrix = self.profiles["writer_issuer_matrix"]
        for row in matrix["objects"].values():
            self.assertFalse(row["may_grant_execution"])
            self.assertFalse(row["may_write_domain_truth"])
        self.assertIn("HypothesisCard", matrix["domain_owned_frozen_contracts"])
        self.assertIn("ProtocolSnapshot", matrix["domain_owned_frozen_contracts"])

    def test_object_receipt_and_transport_identity_are_separate(self) -> None:
        rules = self.profiles["writer_issuer_matrix"]["identity_rules"]
        self.assertEqual(
            set(rules),
            {"object_id", "receipt_id", "transport_idempotency_key", "rule"},
        )
        fields = set(self.catalog["contracts"]["AdmissionReceipt"]["payload_required"])
        self.assertIn("receipt_id", fields)
        self.assertIn("transport_idempotency_key", fields)

    def test_candidate_is_falsifiable_and_frozen(self) -> None:
        required = set(self.catalog["contracts"]["CandidateSpecDraft"]["payload_required"])
        self.assertTrue(
            {"estimand", "null_hypothesis", "falsifier", "stop_condition", "evidence_refs", "evidence_independence_groups", "vcs_identity"}
            <= required
        )

    def test_admission_binds_snapshot_and_ledger_revision(self) -> None:
        required = set(self.catalog["contracts"]["AdmissionReceipt"]["payload_required"])
        self.assertTrue(
            {"admission_snapshot_sha256", "ledger_revision", "decision_key_sha256", "algorithm_version"}
            <= required
        )

    def test_shadow_taint_is_in_event_and_candidate(self) -> None:
        for name in ("MaterialEvent", "CandidateSpecDraft"):
            prop = self.catalog["contracts"][name]["payload_properties"]["shadow_taint"]
            self.assertEqual(set(prop["enum"]), {"NONE", "SHADOW_UNAPPLIED"})

    def test_capability_proof_is_scope_bound_and_non_authoritative(self) -> None:
        props = self.catalog["contracts"]["CapabilityProofReceipt"]["payload_properties"]
        self.assertEqual(props["grants_authority"], {"const": False})
        self.assertIn("PASS_FOR_FROZEN_SCOPE", props["status"]["enum"])
        self.assertNotIn("PASS", props["status"]["enum"])

    def test_policy_fails_closed(self) -> None:
        policy = self.profiles["a1_sandbox_policy"]
        self.assertEqual(policy["policy_mode"], "deny-unless-proven")
        self.assertEqual(policy["default_decision"], "REJECT")
        for deny in ("private-api", "true-unseen-holdout", "live-trading", "live-security-execution", "canonical-write"):
            self.assertIn(deny, policy["hard_denies"])

    def test_unknown_model_call_is_conservative(self) -> None:
        semantics = self.profiles["a1_sandbox_policy"]["budget_semantics"]
        self.assertTrue(semantics["reservation_required_before_external_call"])
        self.assertFalse(semantics["unknown_outcome_auto_retry"])
        self.assertFalse(semantics["unknown_outcome_auto_release"])
        self.assertTrue(semantics["reconciliation_required"])

    def test_model_roles_have_no_authority(self) -> None:
        invariants = self.profiles["model_role_registry"]["invariants"]
        self.assertTrue(invariants["model_outputs_are_untrusted"])
        self.assertTrue(invariants["models_cannot_admit_candidates"])
        self.assertTrue(invariants["models_cannot_issue_permits"])
        self.assertTrue(invariants["models_cannot_mutate_canonical_state"])
        self.assertTrue(invariants["consensus_is_not_evidence"])

    def test_collector_and_scout_cannot_mint_material_events(self) -> None:
        roles = self.profiles["ipc_compatibility"]["roles"]
        self.assertFalse(roles["collector"]["may_mint_material_event"])
        self.assertFalse(roles["scout"]["may_mint_material_event"])
        self.assertEqual(roles["collector"]["versions"], ["1.2"])

    def test_reason_codes_are_bounded_and_not_model_controlled(self) -> None:
        reasons = self.profiles["reason_codes"]
        self.assertEqual(reasons["parser_bounds"]["unknown_code_behavior"], "REJECT")
        self.assertTrue(reasons["rules"]["model_may_not_create_or_override_codes"])
        for code, entry in reasons["codes"].items():
            self.assertLessEqual(len(code), 64)
            self.assertLessEqual(len(entry["public_message"]), 240)


if __name__ == "__main__":
    unittest.main()
