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

import e2_aggregate_gate as gate  # noqa: E402
from capability_proof import (  # noqa: E402
    CapabilityProofError,
    assess_capability_proof,
    canonical_json_sha256,
    issue_e2_autonomous_research_proof,
    validate_capability_proof,
)


RECEIPT = ROOT / "docs" / "receipts" / "capability" / "e2-autonomous-research-shadow.json"


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


class E2AggregateGateTests(unittest.TestCase):
    def test_exact_evidence_and_static_receipt_pass_four_shadow_capabilities(self) -> None:
        evidence = gate.validate_e2_evidence(ROOT)
        self.assertEqual(
            evidence["status"],
            "AUTONOMOUS_RESEARCH_E2_SHADOW_PASS_FOR_FROZEN_SCOPE",
        )
        self.assertEqual(
            evidence["agenda_status"],
            "AUTONOMOUS_RESEARCH_AGENDA_SHADOW_PASS",
        )
        self.assertEqual(
            evidence["portfolio_status"],
            "AUTONOMOUS_PORTFOLIO_SELECTION_SHADOW_PASS",
        )
        self.assertEqual(
            evidence["falsification_status"],
            "AUTONOMOUS_FALSIFICATION_SHADOW_PASS",
        )
        self.assertEqual(
            evidence["replication_status"],
            "AUTONOMOUS_REPLICATION_SHADOW_PASS",
        )
        # The immutable S28 receipt remains structurally valid after later
        # evolution stages, while its currentness is assessed separately and
        # correctly becomes STALE when the frozen code bundle changes.
        proof = validate_capability_proof(receipt())
        self.assertEqual(
            proof["payload"]["capability_id"],
            "AUTONOMOUS_RESEARCH_E2_SHADOW",
        )

    def test_static_receipt_is_deterministically_reproduced(self) -> None:
        value = receipt()
        issued = issue_e2_autonomous_research_proof(
            value["payload"],
            issued_at=value["issued_at"],
            classification=value["classification"],
        )
        self.assertEqual(thaw(issued), value)

    def test_scope_is_shadow_only_and_memory_claim_remains_not_established(self) -> None:
        payload = validate_capability_proof(receipt())["payload"]
        scope = payload["scope"]
        self.assertEqual(
            scope["memory_status"],
            "MEASUREMENT_SCOPED_POPULATION_UPLIFT_NOT_ESTABLISHED",
        )
        self.assertEqual(
            scope["replication_independence"],
            "PER_PAIR_FROZEN_SCOPE_NOT_GLOBAL",
        )
        self.assertEqual(scope["domain_application"], "SHADOW_UNAPPLIED")
        self.assertTrue(scope["human_required_for_promotion"])
        for field in gate.FORBIDDEN_TRUE_FLAGS:
            self.assertFalse(scope[field], field)
        self.assertFalse(payload["grants_authority"])

    def test_any_exact_evidence_tamper_fails_before_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in gate.EVIDENCE_FILES:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            relative = next(iter(gate.EVIDENCE_FILES))
            target = root / relative
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(gate.E2AggregateError, "digest mismatch"):
                gate.validate_e2_evidence(root)

    def test_council_cannot_be_laundered_into_evidence_after_resealing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = dict(gate.EVIDENCE_FILES)
            for relative in evidence:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            relative = "docs/receipts/integration/s25-council-assurance.json"
            target = root / relative
            value = json.loads(target.read_text())
            value["payload"]["audit_results"]["dissent_and_unanimity_non_evidentiary"] = "evidence"
            value["integrity"]["payload_sha256"] = canonical_json_sha256(value["payload"])
            target.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
            evidence[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
            with patch.object(gate, "EVIDENCE_FILES", evidence), patch.object(
                gate, "_is_ancestor", return_value=True
            ):
                with self.assertRaisesRegex(gate.E2AggregateError, "council evidence"):
                    gate.validate_e2_evidence(root)

    def test_replication_and_memory_overclaims_fail_after_resealing(self) -> None:
        mutations = (
            (
                "docs/receipts/integration/s26-replication-assurance.json",
                "correlated_source_overclaim_denial",
                "global-independent",
                "replication evidence",
            ),
            (
                "docs/receipts/integration/s27-memory-assurance.json",
                "calibration_without_calibrated_claim",
                "calibrated",
                "memory evidence",
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
                    with self.assertRaisesRegex(gate.E2AggregateError, error):
                        gate.validate_e2_evidence(root)

    def test_stale_or_mixed_subject_and_receipt_scope_fail_closed(self) -> None:
        with self.assertRaisesRegex(gate.E2AggregateError, "exact head"):
            gate.validate_e2_evidence(ROOT, subject_ref="git:" + "0" * 40)
        for field, replacement in (
            ("autonomous_canonical_mutation", True),
            ("deployment", True),
            ("live_trading", True),
            ("live_security_execution", True),
            ("memory_status", "MEMORY_UPLIFT_ESTABLISHED"),
            ("replication_independence", "GLOBAL_INDEPENDENCE"),
        ):
            with self.subTest(field=field):
                value = receipt()
                value["payload"]["scope"][field] = replacement
                with self.assertRaises((CapabilityProofError, gate.E2AggregateError)):
                    gate.validate_historical_aggregate_receipt(ROOT, resign(value))

    def test_currentness_invalidates_on_hash_drift_or_expiry(self) -> None:
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
        self.assertEqual(
            assess_capability_proof(receipt(), **kwargs).status,
            "PASS_FOR_FROZEN_SCOPE",
        )
        stale = assess_capability_proof(
            receipt(), **{**kwargs, "code_sha256": "0" * 64}
        )
        self.assertEqual(stale.status, "STALE")
        self.assertIn("code-hash-drift", stale.invalidation_reasons)
        expired = assess_capability_proof(
            receipt(), **{**kwargs, "now": "2026-07-26T00:00:00Z"}
        )
        self.assertEqual(expired.status, "STALE")
        self.assertIn("proof-expiry", expired.invalidation_reasons)

    def test_cross_capability_issuer_rejects_payload(self) -> None:
        prior = json.loads(
            (ROOT / "docs" / "receipts" / "capability" / "e1-evolution-kernel-v1-shadow.json").read_text()
        )
        with self.assertRaisesRegex(CapabilityProofError, "different capability"):
            issue_e2_autonomous_research_proof(
                prior["payload"], issued_at=prior["issued_at"]
            )


if __name__ == "__main__":
    unittest.main()
