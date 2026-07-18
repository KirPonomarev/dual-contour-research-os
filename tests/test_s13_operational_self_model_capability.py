from __future__ import annotations

from copy import deepcopy
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
    issue_durable_feedback_proof,
    issue_e1a_fixture_proof,
    issue_operational_self_model_proof,
    validate_capability_proof,
)


RECEIPT_PATH = ROOT / "docs" / "receipts" / "capability" / "e1c-operational-self-model-offline.json"
SUBJECT_SHA = "77f9860d13a80dcf9c277d27f0c2daf4a15ae9f2"
SUBJECT = f"git:{SUBJECT_SHA}"
CODE_SHA = "829eb5b9a6523cf782779df1172e9201d7409d8f16af89b011e0fb9467aafad9"
CONFIG_SHA = "bf69090e209e76c49a8dd7662bf67492c81f87e147a38291d02adf94767110aa"
POLICY_SHA = "0727ef9c26a19ef6ef2d89e358e3d0c2785eda3402efc796092a66c856a9bf89"
SCHEMA_SHA = "5038820e8edba6584c3668773e37078e3395026d58bfcdbbc05772298b233334"
ENVIRONMENT_REF = "profile:environment-compatibility-v1:52f5d7c8715b3027164a2b284ca912357fd2b8f4bf6f2f2ab356e032370d50e7"


def _receipt() -> dict[str, object]:
    return json.loads(RECEIPT_PATH.read_text())


def _thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _resign(receipt: dict[str, object]) -> dict[str, object]:
    value = deepcopy(receipt)
    payload = value["payload"]
    assert isinstance(payload, dict)
    digest = canonical_json_sha256(payload)
    value["object_id"] = f"capability-proof:{digest}"
    value["integrity"]["payload_sha256"] = digest  # type: ignore[index]
    return value


def _assess(receipt: dict[str, object], **overrides: str):
    values = {
        "now": "2026-07-18T16:30:00Z",
        "subject_ref": SUBJECT,
        "code_sha256": CODE_SHA,
        "config_sha256": CONFIG_SHA,
        "policy_sha256": POLICY_SHA,
        "schema_sha256": SCHEMA_SHA,
        "environment_compatibility_ref": ENVIRONMENT_REF,
    }
    values.update(overrides)
    return assess_capability_proof(receipt, **values)


def _git_bundle_hash(paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        raw = subprocess.check_output(["git", "show", f"{SUBJECT_SHA}:{path}"], cwd=ROOT)
        digest.update(path.encode() + b"\0")
        digest.update(raw)
    return digest.hexdigest()


class OperationalSelfModelCapabilityTests(unittest.TestCase):
    def test_static_receipt_is_exactly_reproduced_by_scoped_issuer(self) -> None:
        receipt = _receipt()
        issued = issue_operational_self_model_proof(
            receipt["payload"], issued_at=receipt["issued_at"], classification=receipt["classification"]
        )
        self.assertEqual(_thaw(issued), receipt)
        self.assertEqual(validate_capability_proof(receipt)["object_id"], receipt["object_id"])

    def test_scope_is_operational_non_anthropomorphic_and_zero_authority(self) -> None:
        receipt = _receipt()
        payload = receipt["payload"]
        scope = payload["scope"]
        self.assertEqual(payload["capability_id"], "OPERATIONAL_SELF_MODEL")
        self.assertEqual(scope["proof_state"], "OPERATIONAL_SELF_MODEL_PASS_WITH_DURABLE_OFFLINE_FIXTURES")
        self.assertEqual(scope["real_provider"], "UNPROVEN")
        self.assertEqual(scope["domain_application"], "SHADOW_UNAPPLIED")
        for field in ("canonical_mutation", "live_trading", "live_security_execution"):
            self.assertEqual(scope[field], "DENIED")
        self.assertFalse(payload["grants_authority"])
        forbidden_fields = {
            "consciousness", "sentience", "general_self_awareness", "human_equivalence",
            "self_granted_authority", "autonomous_canonical_authority",
        }
        self.assertTrue(forbidden_fields.isdisjoint(payload))
        self.assertTrue(forbidden_fields.isdisjoint(scope))

    def test_current_exact_frozen_scope_passes(self) -> None:
        assessment = _assess(_receipt())
        self.assertEqual(assessment.status, "PASS_FOR_FROZEN_SCOPE")
        self.assertEqual(assessment.invalidation_reasons, ())

    def test_each_bound_dimension_invalidates_independently(self) -> None:
        cases = {
            "subject_ref": ("git:" + "0" * 40, "subject-head-drift"),
            "code_sha256": ("0" * 64, "code-hash-drift"),
            "config_sha256": ("0" * 64, "config-hash-drift"),
            "policy_sha256": ("0" * 64, "policy-hash-drift"),
            "schema_sha256": ("0" * 64, "schema-hash-drift"),
            "environment_compatibility_ref": ("profile:environment-compatibility-v1:stale", "environment-compatibility-drift"),
        }
        for field, (replacement, reason) in cases.items():
            with self.subTest(field=field):
                assessment = _assess(_receipt(), **{field: replacement})
                self.assertEqual(assessment.status, "STALE")
                self.assertEqual(assessment.invalidation_reasons, (reason,))

    def test_expired_and_not_yet_valid_are_stale(self) -> None:
        for now in ("2026-07-18T16:24:59Z", "2026-07-25T16:25:00Z"):
            with self.subTest(now=now):
                assessment = _assess(_receipt(), now=now)
                self.assertEqual(assessment.status, "STALE")
                self.assertEqual(assessment.invalidation_reasons, ("proof-expiry",))

    def test_subject_hashes_recompute_from_exact_git_release(self) -> None:
        self.assertEqual(
            _git_bundle_hash(("src/research_bridge/organism.py", "src/research_bridge/ledger.py", "tools/capability_proof.py")),
            CODE_SHA,
        )
        self.assertEqual(
            _git_bundle_hash(("ops/organism/component-declarations.json", "ops/organism/deployment-projection.json")),
            CONFIG_SHA,
        )
        self.assertEqual(_git_bundle_hash(("ops/organism/pulse-policy.json",)), POLICY_SHA)
        self.assertEqual(_git_bundle_hash(("contracts/catalog.json", "contracts/a1/v1/catalog.json")), SCHEMA_SHA)

    def test_e1c_evidence_chain_and_subject_exist(self) -> None:
        for name in ("s11-manifest-topology.json", "s12-state-pulse.json"):
            self.assertTrue((ROOT / "docs" / "receipts" / "integration" / name).is_file(), name)
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{SUBJECT_SHA}^{{commit}}"], cwd=ROOT, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        basis = _receipt()["payload"]["proof_basis"]
        self.assertIn({"acceptance": "AC-ORGANISM", "result": "green-for-frozen-offline-scope"}, basis)

    def test_scope_provider_domain_live_and_authority_overclaims_fail_closed(self) -> None:
        mutations = (
            ("scope", "proof_state", "CONSCIOUS_AUTONOMOUS_SYSTEM"),
            ("scope", "real_provider", "PROVEN"),
            ("scope", "domain_application", "DOMAIN_APPLIED"),
            ("scope", "canonical_mutation", "ALLOWED"),
            ("payload", "grants_authority", True),
        )
        for container, field, value in mutations:
            with self.subTest(field=field):
                receipt = _receipt()
                payload = receipt["payload"]
                target = payload["scope"] if container == "scope" else payload
                target[field] = value
                with self.assertRaises(CapabilityProofError):
                    validate_capability_proof(_resign(receipt))

    def test_anthropomorphic_or_self_authority_proof_basis_fails_closed(self) -> None:
        mutations = (
            {"consciousness": True},
            {"claim": "the organism is sentient"},
            {"general_self_awareness": "proven"},
            {"claim": "grants itself authority"},
        )
        for claim in mutations:
            with self.subTest(claim=claim):
                receipt = _receipt()
                receipt["payload"]["proof_basis"].append(claim)
                with self.assertRaisesRegex(CapabilityProofError, "anthropomorphic or authority"):
                    validate_capability_proof(_resign(receipt))

    def test_scoped_issuers_reject_cross_capability_payloads(self) -> None:
        payload = _receipt()["payload"]
        for issuer in (issue_e1a_fixture_proof, issue_durable_feedback_proof):
            with self.subTest(issuer=issuer.__name__):
                with self.assertRaisesRegex(CapabilityProofError, "different capability"):
                    issuer(payload, issued_at="2026-07-18T16:25:00Z")
        prior = json.loads(
            (ROOT / "docs" / "receipts" / "capability" / "e1b-durable-feedback-offline.json").read_text()
        )
        with self.assertRaisesRegex(CapabilityProofError, "different capability"):
            issue_operational_self_model_proof(prior["payload"], issued_at=prior["issued_at"])


if __name__ == "__main__":
    unittest.main()
