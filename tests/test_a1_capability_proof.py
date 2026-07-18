from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from capability_proof import (  # noqa: E402
    CapabilityProofError,
    assess_capability_proof,
    canonical_json_sha256,
    issue_e1a_fixture_proof,
    validate_capability_proof,
)


RECEIPT_PATH = ROOT / "docs" / "receipts" / "capability" / "e1a-discovery-admission-fixture.json"
SUBJECT = "git:ca7f31b6ebce575af818f34209a2613835efd3e7"
CODE_SHA = "6c7bd4bd4925974e200d29d91d4da830331941f36ec568a3bc4e3852a91fca4e"
CONFIG_SHA = "d9c541e507188cfdb5af4750a6697751c13621122d5aa81d085c91a85156d8ba"
POLICY_SHA = "50a3f629d8931262b7cd7109575ddb99f5fc8cacffec1985e1d5793e012dc3b4"
SCHEMA_SHA = "c5b21d5b2036c9001375e9251d91186c324c8d09bb3497d3233169c89cf09122"
ENVIRONMENT_REF = "profile:environment-compatibility-v1:52f5d7c8715b3027164a2b284ca912357fd2b8f4bf6f2f2ab356e032370d50e7"


def _receipt() -> dict[str, object]:
    return json.loads(RECEIPT_PATH.read_text())


def _thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _assess(receipt: dict[str, object], **overrides: str):
    values = {
        "now": "2026-07-18T14:06:00Z",
        "subject_ref": SUBJECT,
        "code_sha256": CODE_SHA,
        "config_sha256": CONFIG_SHA,
        "policy_sha256": POLICY_SHA,
        "schema_sha256": SCHEMA_SHA,
        "environment_compatibility_ref": ENVIRONMENT_REF,
    }
    values.update(overrides)
    return assess_capability_proof(receipt, **values)


class CapabilityProofTests(unittest.TestCase):
    def test_static_receipt_is_exactly_reproduced_by_scoped_issuer(self) -> None:
        receipt = _receipt()
        issued = issue_e1a_fixture_proof(
            receipt["payload"],
            issued_at=receipt["issued_at"],
            classification=receipt["classification"],
        )
        self.assertEqual(_thaw(issued), receipt)
        validated = validate_capability_proof(receipt)
        self.assertEqual(validated["object_id"], receipt["object_id"])

    def test_receipt_matches_frozen_contract_shape_and_integrity(self) -> None:
        receipt = _receipt()
        catalog = json.loads((ROOT / "contracts" / "a1" / "v1" / "catalog.json").read_text())
        self.assertEqual(
            set(receipt["payload"]),
            set(catalog["contracts"]["CapabilityProofReceipt"]["payload_required"]),
        )
        self.assertEqual(receipt["integrity"]["payload_sha256"], canonical_json_sha256(receipt["payload"]))
        self.assertEqual(receipt["issuer"], "independent-assurance-issuer")
        self.assertFalse(receipt["payload"]["grants_authority"])

    def test_current_frozen_scope_passes_without_overclaim(self) -> None:
        receipt = _receipt()
        assessment = _assess(receipt)
        self.assertEqual(assessment.status, "PASS_FOR_FROZEN_SCOPE")
        self.assertEqual(assessment.invalidation_reasons, ())
        scope = receipt["payload"]["scope"]
        self.assertEqual(scope["proof_state"], "SHADOW_PASS_WITH_FIXTURE_MODEL")
        self.assertEqual(scope["real_provider"], "UNPROVEN")
        for field in ("canonical_mutation", "live_trading", "live_security_execution"):
            self.assertEqual(scope[field], "DENIED")
        self.assertEqual(scope["domain_application"], "SHADOW_UNAPPLIED")

    def test_mixed_head_is_stale(self) -> None:
        assessment = _assess(_receipt(), subject_ref="git:" + "0" * 40)
        self.assertEqual(assessment.status, "STALE")
        self.assertEqual(assessment.invalidation_reasons, ("subject-head-drift",))

    def test_expired_or_not_yet_valid_proof_is_stale(self) -> None:
        for now in ("2026-07-18T14:04:59Z", "2026-07-25T14:05:00Z"):
            with self.subTest(now=now):
                assessment = _assess(_receipt(), now=now)
                self.assertEqual(assessment.status, "STALE")
                self.assertIn("proof-expiry", assessment.invalidation_reasons)

    def test_each_relevant_dependency_drift_invalidates_only_its_scope(self) -> None:
        cases = {
            "code_sha256": "code-hash-drift",
            "config_sha256": "config-hash-drift",
            "policy_sha256": "policy-hash-drift",
            "schema_sha256": "schema-hash-drift",
            "environment_compatibility_ref": "environment-compatibility-drift",
        }
        for field, reason in cases.items():
            with self.subTest(field=field):
                replacement = "0" * 64 if field.endswith("sha256") else "profile:changed"
                assessment = _assess(_receipt(), **{field: replacement})
                self.assertEqual(assessment.status, "STALE")
                self.assertEqual(assessment.invalidation_reasons, (reason,))

    def test_integrity_scope_and_authority_tampering_fail_closed(self) -> None:
        mutations = []
        tampered = _receipt()
        tampered["payload"]["grants_authority"] = True
        mutations.append(tampered)
        tampered = _receipt()
        tampered["payload"]["scope"]["real_provider"] = "PROVEN"
        tampered["integrity"]["payload_sha256"] = canonical_json_sha256(tampered["payload"])
        mutations.append(tampered)
        tampered = _receipt()
        tampered["payload"]["negative_probe_refs"].remove("probe:writer-spoof-denied")
        tampered["integrity"]["payload_sha256"] = canonical_json_sha256(tampered["payload"])
        mutations.append(tampered)
        tampered = _receipt()
        tampered["payload"]["invalidation_conditions"].remove("proof-expiry")
        tampered["integrity"]["payload_sha256"] = canonical_json_sha256(tampered["payload"])
        mutations.append(tampered)
        for value in mutations:
            with self.subTest(mutation=value["payload"]):
                with self.assertRaises(CapabilityProofError):
                    validate_capability_proof(value)

    def test_subject_commit_and_evidence_chain_exist(self) -> None:
        receipt = _receipt()
        subject_sha = receipt["payload"]["subject_ref"].removeprefix("git:")
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{subject_sha}^{{commit}}"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(result.returncode, 0)
        for name in (
            "s01-e1a-admission-complete.json",
            "s02-scout-ipc-assurance.json",
            "s03-synthetic-domain-assurance.json",
        ):
            self.assertTrue((ROOT / "docs" / "receipts" / "integration" / name).is_file())

    def test_environment_profile_hash_and_limits_are_exact(self) -> None:
        path = ROOT / "contracts" / "a1" / "v1" / "profiles" / "environment_compatibility_v1.json"
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), ENVIRONMENT_REF.rsplit(":", 1)[1])
        profile = json.loads(path.read_text())
        self.assertIn("production-containment", profile["environments"]["macos-development"]["not_proof_of"])
        self.assertIn("vps-runtime-health", profile["environments"]["linux-ci"]["not_proof_of"])

    def test_later_path_activations_do_not_widen_the_e1a_capability_proof(self) -> None:
        registry = json.loads((ROOT / "ownership" / "registry.json").read_text())
        self.assertEqual(registry["canonical_owners"]["src/research_bridge/organism.py"], "agent-5")
        self.assertNotIn("src/research_bridge/organism.py", registry["reserved_future_paths"])
        self.assertTrue((ROOT / "src" / "research_bridge" / "organism.py").is_file())
        self.assertEqual(registry["canonical_owners"]["src/research_bridge/model_broker.py"], "agent-1")
        self.assertNotIn("src/research_bridge/model_broker.py", registry["reserved_future_paths"])
        self.assertTrue((ROOT / "src" / "research_bridge" / "model_broker.py").is_file())
        receipt_text = json.dumps(_receipt(), sort_keys=True).lower()
        self.assertNotIn("organism", receipt_text)
        self.assertNotIn("model_broker", receipt_text)


if __name__ == "__main__":
    unittest.main()
