from __future__ import annotations

from copy import deepcopy
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
    validate_capability_proof,
)


RECEIPT_PATH = ROOT / "docs" / "receipts" / "capability" / "e1b-durable-feedback-offline.json"
SUBJECT = "git:c49f0cba0d1f866da009788c72ccee005f93f150"
ENVIRONMENT_REF = (
    "profile:environment-compatibility-v1:"
    "52f5d7c8715b3027164a2b284ca912357fd2b8f4bf6f2f2ab356e032370d50e7"
)
INTEGRATION_RECEIPTS = (
    "s05-db-v2-global-order.json",
    "s06-authority-corridor.json",
    "s07-l0-validation.json",
    "s08-atomic-feedback.json",
    "s09-replay-capacity.json",
)


def _receipt() -> dict[str, object]:
    return json.loads(RECEIPT_PATH.read_text())


def _thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _assess(receipt: dict[str, object], **overrides: str):
    payload = receipt["payload"]
    assert isinstance(payload, dict)
    values = {
        "now": "2026-07-18T16:00:00Z",
        "subject_ref": SUBJECT,
        "code_sha256": payload["code_sha256"],
        "config_sha256": payload["config_sha256"],
        "policy_sha256": payload["policy_sha256"],
        "schema_sha256": payload["schema_sha256"],
        "environment_compatibility_ref": ENVIRONMENT_REF,
    }
    values.update(overrides)
    return assess_capability_proof(receipt, **values)  # type: ignore[arg-type]


def _resign(receipt: dict[str, object]) -> dict[str, object]:
    value = deepcopy(receipt)
    payload = value["payload"]
    assert isinstance(payload, dict)
    digest = canonical_json_sha256(payload)
    value["object_id"] = f"capability-proof:{digest}"
    integrity = value["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = digest
    return value


class DurableFeedbackCapabilityTests(unittest.TestCase):
    def test_static_receipt_is_exactly_reproduced_by_scoped_issuer(self) -> None:
        receipt = _receipt()
        issued = issue_durable_feedback_proof(
            receipt["payload"],
            issued_at=receipt["issued_at"],
            classification=receipt["classification"],
        )
        self.assertEqual(_thaw(issued), receipt)
        self.assertEqual(validate_capability_proof(receipt)["object_id"], receipt["object_id"])

    def test_contract_shape_integrity_and_zero_authority_are_frozen(self) -> None:
        receipt = _receipt()
        payload = receipt["payload"]
        self.assertEqual(payload["capability_id"], "A1_DURABLE_FEEDBACK")
        self.assertEqual(receipt["integrity"]["payload_sha256"], canonical_json_sha256(payload))
        self.assertFalse(payload["grants_authority"])
        scope = payload["scope"]
        self.assertEqual(scope["real_provider"], "UNPROVEN")
        self.assertEqual(scope["domain_application"], "SHADOW_UNAPPLIED")
        for field in ("canonical_mutation", "live_trading", "live_security_execution"):
            self.assertEqual(scope[field], "DENIED")

    def test_current_frozen_scope_passes(self) -> None:
        assessment = _assess(_receipt())
        self.assertEqual(assessment.status, "PASS_FOR_FROZEN_SCOPE")
        self.assertEqual(assessment.invalidation_reasons, ())

    def test_each_bound_dimension_invalidates_independently(self) -> None:
        cases = {
            "subject_ref": "subject-head-drift",
            "code_sha256": "code-hash-drift",
            "config_sha256": "config-hash-drift",
            "policy_sha256": "policy-hash-drift",
            "schema_sha256": "schema-hash-drift",
            "environment_compatibility_ref": "environment-compatibility-drift",
        }
        for field, reason in cases.items():
            with self.subTest(field=field):
                replacement = "git:" + "0" * 40 if field == "subject_ref" else "0" * 64
                if field == "environment_compatibility_ref":
                    replacement = "profile:environment-compatibility-v1:stale"
                assessment = _assess(_receipt(), **{field: replacement})
                self.assertEqual(assessment.status, "STALE")
                self.assertEqual(assessment.invalidation_reasons, (reason,))

    def test_expired_and_not_yet_valid_proofs_are_stale(self) -> None:
        for now in ("2026-07-18T15:49:59Z", "2026-07-25T15:50:00Z"):
            with self.subTest(now=now):
                assessment = _assess(_receipt(), now=now)
                self.assertEqual(assessment.status, "STALE")
                self.assertEqual(assessment.invalidation_reasons, ("proof-expiry",))

    def test_scope_and_authority_overclaims_fail_closed_even_when_resigned(self) -> None:
        mutations = (
            ("scope", "real_provider", "PROVEN"),
            ("scope", "domain_application", "DOMAIN_APPLIED"),
            ("scope", "canonical_mutation", "ALLOWED"),
            ("payload", "grants_authority", True),
        )
        for container, field, value in mutations:
            with self.subTest(field=field):
                receipt = _receipt()
                payload = receipt["payload"]
                assert isinstance(payload, dict)
                target = payload["scope"] if container == "scope" else payload
                assert isinstance(target, dict)
                target[field] = value
                with self.assertRaises(CapabilityProofError):
                    validate_capability_proof(_resign(receipt))

    def test_missing_required_negative_probe_fails_closed(self) -> None:
        receipt = _receipt()
        probes = receipt["payload"]["negative_probe_refs"]
        assert isinstance(probes, list)
        probes.remove("probe:canonical-live-authority-absent")
        with self.assertRaises(CapabilityProofError):
            validate_capability_proof(_resign(receipt))

    def test_scoped_issuers_reject_cross_capability_payloads(self) -> None:
        payload = _receipt()["payload"]
        with self.assertRaisesRegex(CapabilityProofError, "different capability"):
            issue_e1a_fixture_proof(payload, issued_at="2026-07-18T15:50:00Z")
        fixture = json.loads(
            (ROOT / "docs" / "receipts" / "capability" / "e1a-discovery-admission-fixture.json").read_text()
        )
        with self.assertRaisesRegex(CapabilityProofError, "different capability"):
            issue_durable_feedback_proof(fixture["payload"], issued_at=fixture["issued_at"])

    def test_bound_integration_evidence_and_subject_exist(self) -> None:
        for name in INTEGRATION_RECEIPTS:
            self.assertTrue((ROOT / "docs" / "receipts" / "integration" / name).is_file(), name)
        subject = SUBJECT.removeprefix("git:")
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{subject}^{{commit}}"], cwd=ROOT, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_receipt_does_not_claim_runtime_organism_or_provider_proof(self) -> None:
        receipt_text = RECEIPT_PATH.read_text()
        self.assertNotIn('"real_provider": "PROVEN"', receipt_text)
        self.assertNotIn('"domain_application": "DOMAIN_APPLIED"', receipt_text)
        self.assertNotIn('"grants_authority": true', receipt_text)


if __name__ == "__main__":
    unittest.main()
