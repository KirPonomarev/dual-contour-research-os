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

import e1_aggregate_gate as gate  # noqa: E402
from capability_proof import (  # noqa: E402
    CapabilityProofError,
    canonical_json_sha256,
    issue_evolution_kernel_v1_proof,
    validate_capability_proof,
)


RECEIPT = ROOT / "docs" / "receipts" / "capability" / "e1-evolution-kernel-v1-shadow.json"


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


class E1AggregateGateTests(unittest.TestCase):
    def test_exact_evidence_and_static_receipt_pass(self) -> None:
        evidence = gate.validate_e1_evidence(ROOT)
        self.assertEqual(evidence["status"], "EVOLUTION_KERNEL_V1_SHADOW_PASS_FOR_FROZEN_SCOPE")
        proof = gate.validate_aggregate_receipt(ROOT, receipt())
        self.assertEqual(proof["payload"]["capability_id"], "EVOLUTION_KERNEL_V1")

    def test_static_receipt_is_deterministically_reproduced(self) -> None:
        value = receipt()
        issued = issue_evolution_kernel_v1_proof(
            value["payload"], issued_at=value["issued_at"], classification=value["classification"]
        )

        def thaw(item: object) -> object:
            if hasattr(item, "items"):
                return {str(key): thaw(child) for key, child in item.items()}  # type: ignore[union-attr]
            if isinstance(item, tuple):
                return [thaw(child) for child in item]
            return item

        self.assertEqual(thaw(issued), value)

    def test_scope_keeps_autonomy_bounded_and_authority_false(self) -> None:
        payload = validate_capability_proof(receipt())["payload"]
        scope = payload["scope"]
        for field in (
            "autonomous_idea_generation", "autonomous_a1_sandbox_admission",
            "autonomous_bounded_testing", "autonomous_learning_memory",
            "human_required_for_promotion",
        ):
            self.assertTrue(scope[field], field)
        for field in gate.FORBIDDEN_TRUE_FLAGS:
            self.assertFalse(scope[field], field)
        self.assertFalse(payload["grants_authority"])
        self.assertEqual(scope["mandatory_gpt"], "WAIT_PROVIDER")
        self.assertEqual(scope["temporary_kimi"], "UNPROMOTED_NOT_ROUTABLE")
        self.assertEqual(scope["independence"], "NOT_ESTABLISHED")

    def test_any_exact_evidence_tamper_fails_before_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in gate.EVIDENCE_FILES:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            target = root / next(iter(gate.EVIDENCE_FILES))
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaisesRegex(gate.E1AggregateError, "digest mismatch"):
                gate.validate_e1_evidence(root)

    def test_provider_claim_laundering_fails_even_with_rebound_file_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = dict(gate.EVIDENCE_FILES)
            for relative in evidence:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            relative = "docs/receipts/integration/s18-provider-hostile.json"
            target = root / relative
            value = json.loads(target.read_text())
            value["payload"]["audit_results"]["gpt_bindings"] = "AVAILABLE"
            payload = value["payload"]
            value["integrity"]["payload_sha256"] = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            target.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
            evidence[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
            with patch.object(gate, "EVIDENCE_FILES", evidence), patch.object(gate, "_is_ancestor", return_value=True):
                with self.assertRaisesRegex(gate.E1AggregateError, "widens or launders"):
                    gate.validate_e1_evidence(root)

    def test_stale_or_mixed_aggregate_head_fails(self) -> None:
        with self.assertRaisesRegex(gate.E1AggregateError, "exact head"):
            gate.validate_e1_evidence(ROOT, subject_ref="git:" + "0" * 40)

    def test_scope_overclaims_fail_even_when_payload_is_resigned(self) -> None:
        mutations = {
            "autonomous_canonical_mutation": True,
            "deployment": True,
            "live_trading": True,
            "live_security_execution": True,
            "mandatory_gpt": "AVAILABLE",
            "temporary_kimi": "CANONICAL_ROUTE",
            "independence": "ESTABLISHED",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                value = receipt()
                value["payload"]["scope"][field] = replacement
                with self.assertRaises((CapabilityProofError, gate.E1AggregateError)):
                    gate.validate_aggregate_receipt(ROOT, resign(value))

    def test_cross_capability_issuer_rejects_payload(self) -> None:
        prior = json.loads(
            (ROOT / "docs" / "receipts" / "capability" / "e1c-operational-self-model-offline.json").read_text()
        )
        with self.assertRaisesRegex(CapabilityProofError, "different capability"):
            issue_evolution_kernel_v1_proof(prior["payload"], issued_at=prior["issued_at"])


if __name__ == "__main__":
    unittest.main()
