from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import e3_aggregate_gate as gate  # noqa: E402
from capability_proof import (  # noqa: E402
    CapabilityProofError,
    assess_capability_proof,
    canonical_json_sha256,
    issue_e2_autonomous_research_proof,
    issue_e3_evolution_proof,
    validate_capability_proof,
)


RECEIPT = ROOT / "docs" / "receipts" / "capability" / "e3-evolution-shadow.json"


def receipt() -> dict[str, object]:
    return json.loads(RECEIPT.read_text())


def resign(value: dict[str, object]) -> dict[str, object]:
    result = deepcopy(value)
    payload = result["payload"]
    assert isinstance(payload, dict)
    digest = canonical_json_sha256(payload)
    result["object_id"] = f"capability-proof:{digest}"
    result["integrity"]["payload_sha256"] = digest  # type: ignore[index]
    return result


def thaw(value: object) -> object:
    if hasattr(value, "items"):
        return {str(key): thaw(child) for key, child in value.items()}  # type: ignore[union-attr]
    if isinstance(value, tuple):
        return [thaw(child) for child in value]
    return value


class E3AggregateGateTests(unittest.TestCase):
    def test_exact_evidence_passes_only_scoped_shadow_evolution(self) -> None:
        evidence = gate.validate_e3_evidence(ROOT)
        self.assertEqual(evidence["status"], "EVOLUTION_E3_SHADOW_PASS_FOR_FROZEN_SCOPE")
        self.assertEqual(evidence["mutation_proposal_status"], "MUTATION_PROPOSAL_LOOP_PASS")
        self.assertEqual(evidence["evolution_loop_status"], "EVOLUTION_LOOP_SHADOW_PASS")
        self.assertEqual(evidence["meta_evolution_status"], "META_EVOLUTION_PROPOSAL_ONLY")
        self.assertEqual(evidence["rollback_status"], "DESCRIPTIVE_WAIT_AUTHORITY")
        gate.validate_historical_aggregate_receipt(ROOT, receipt())

    def test_static_receipt_is_deterministically_reproduced(self) -> None:
        value = receipt()
        issued = issue_e3_evolution_proof(
            value["payload"],
            issued_at=value["issued_at"],
            classification=value["classification"],
        )
        self.assertEqual(thaw(issued), value)

    def test_scope_never_claims_production_uplift_or_authority(self) -> None:
        payload = validate_capability_proof(receipt())["payload"]
        scope = payload["scope"]
        self.assertEqual(scope["uplift_scope"], "FROZEN_BENCHMARK_AND_SHADOW_NOT_PRODUCTION")
        self.assertEqual(scope["domain_application"], "SHADOW_UNAPPLIED")
        self.assertEqual(scope["rollback_status"], "DESCRIPTIVE_WAIT_AUTHORITY")
        self.assertTrue(scope["human_required_for_promotion"])
        for field in gate.FORBIDDEN_TRUE_FLAGS:
            self.assertFalse(scope[field], field)
        self.assertFalse(payload["grants_authority"])

    def test_any_exact_evidence_byte_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in gate.EVIDENCE_FILES:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            relative = next(iter(gate.EVIDENCE_FILES))
            target = root / relative
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(gate.E3AggregateError, "digest mismatch"):
                gate.validate_e3_evidence(root)

    def test_resealed_uplift_or_promotion_overclaim_fails(self) -> None:
        mutations = (
            (
                "docs/receipts/integration/s30-challenger-assurance.json",
                "zero_scalar_promotion_mutation_holdout_authority",
                "auto-promoted",
                "challenger evidence",
            ),
            (
                "docs/receipts/integration/s31-shadow-canary-assurance.json",
                "zero_write_execution_promotion_apply_authority",
                "applied",
                "shadow canary evidence",
            ),
        )
        for relative, field, replacement, error in mutations:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = dict(gate.EVIDENCE_FILES)
                for source in evidence:
                    target = root / source
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / source, target)
                target = root / relative
                value = json.loads(target.read_text())
                value["payload"]["audit_results"][field] = replacement
                value["integrity"]["payload_sha256"] = canonical_json_sha256(value["payload"])
                target.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
                evidence[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
                with patch.object(gate, "EVIDENCE_FILES", evidence), patch.object(
                    gate, "_is_ancestor", return_value=True
                ):
                    with self.assertRaisesRegex(gate.E3AggregateError, error):
                        gate.validate_e3_evidence(root)

    def test_mixed_subject_and_forbidden_scope_fail_closed(self) -> None:
        with self.assertRaisesRegex(gate.E3AggregateError, "exact head"):
            gate.validate_e3_evidence(ROOT, subject_ref="git:" + "0" * 40)
        for field in gate.FORBIDDEN_TRUE_FLAGS:
            with self.subTest(field=field):
                value = receipt()
                value["payload"]["scope"][field] = True
                with self.assertRaises((CapabilityProofError, gate.E3AggregateError)):
                    gate.validate_historical_aggregate_receipt(ROOT, resign(value))
        value = receipt()
        value["payload"]["scope"]["uplift_scope"] = "PRODUCTION_UPLIFT_ESTABLISHED"
        with self.assertRaises((CapabilityProofError, gate.E3AggregateError)):
            gate.validate_historical_aggregate_receipt(ROOT, resign(value))

    def test_currentness_invalidates_hash_drift_and_expiry(self) -> None:
        payload = receipt()["payload"]
        kwargs = {
            "now": "2026-07-19T00:00:00Z",
            "subject_ref": payload["subject_ref"],
            "code_sha256": payload["code_sha256"],
            "config_sha256": payload["config_sha256"],
            "policy_sha256": payload["policy_sha256"],
            "schema_sha256": payload["schema_sha256"],
            "environment_compatibility_ref": payload["environment_compatibility_ref"],
        }
        self.assertEqual(assess_capability_proof(receipt(), **kwargs).status, "PASS_FOR_FROZEN_SCOPE")
        stale = assess_capability_proof(receipt(), **{**kwargs, "policy_sha256": "0" * 64})
        self.assertEqual(stale.status, "STALE")
        self.assertIn("policy-hash-drift", stale.invalidation_reasons)
        expired = assess_capability_proof(
            receipt(), **{**kwargs, "now": "2026-07-26T00:00:00Z"}
        )
        self.assertEqual(expired.status, "STALE")
        self.assertIn("proof-expiry", expired.invalidation_reasons)

    def test_cross_capability_issuer_rejects_e3_payload(self) -> None:
        value = receipt()
        with self.assertRaisesRegex(CapabilityProofError, "different capability"):
            issue_e2_autonomous_research_proof(
                value["payload"], issued_at=value["issued_at"]
            )


if __name__ == "__main__":
    unittest.main()
