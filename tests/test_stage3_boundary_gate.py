from __future__ import annotations

import ast
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.execution import ExecutionError
from research_bridge.validation import ValidationBoundary, ValidationBoundaryError
from tests.test_stage1_execution import Fixture
from tests.test_stage1_validation import (
    POLICY_REF,
    PROTOCOL_REF,
    REGISTRY_ID,
    VALIDATOR_ID,
    VALIDATOR_SHA256,
    chain,
    reseal,
)


SRC = ROOT / "src" / "research_bridge"
CONTRACTS = ROOT / "contracts" / "v1"
LOCAL_LAB_RECEIPT = ROOT / "docs" / "receipts" / "integration" / "s3-security-local-lab-evidence.json"
BOUNDARY_RECEIPT = ROOT / "docs" / "receipts" / "integration" / "s3-security-boundary-gate.json"
STAGE3_GATE_RECEIPT = ROOT / "docs" / "receipts" / "integration" / "s3-dual-contour-pre-soak-green.json"
STAGE3_GATE = ROOT / "stages" / "s3-dual-contour-pre-soak-green"
BOUNDARY_REUSE = ROOT / "docs" / "receipts" / "reuse" / "s3-security-boundary-gate.json"
BOUNDARY_STAGE = ROOT / "stages" / "s3-security-boundary-gate"


class Stage3BoundaryGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.boundary = ValidationBoundary(
            expected_validator_id=VALIDATOR_ID,
            expected_validator_sha256=VALIDATOR_SHA256,
            expected_registry_identity=REGISTRY_ID,
        )

    def verify(self, receipts):
        return self.boundary.verify(
            *receipts,
            expected_protocol_ref=PROTOCOL_REF,
            expected_policy_ref=POLICY_REF,
        )

    def test_boundary_authority_is_integrity_bound_and_slice_only(self) -> None:
        reuse = json.loads(BOUNDARY_REUSE.read_text())
        envelope = json.loads((BOUNDARY_STAGE / "stage-envelope.json").read_text())
        lease = json.loads((BOUNDARY_STAGE / "ownership-lease.json").read_text())
        payload = json.dumps(reuse["payload"], sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(reuse["integrity"]["payload_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(envelope["base_sha"], "82061197b2d27b81b0493ad9635756f164bcf1b0")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(envelope["boundary_contract"]["required_directions"], ["security-to-market", "market-to-security"])
        self.assertFalse(envelope["boundary_contract"]["declares_dual_contour_pre_soak_green"])
        self.assertFalse(envelope["boundary_contract"]["declares_ready_for_72h_soak"])
        self.assertFalse(lease["delegation_allowed"])

    def test_both_cross_contour_receipt_directions_deny_without_projection(self) -> None:
        for origin, foreign in (("security", "market"), ("market", "security")):
            receipts = list(chain())
            for receipt in receipts:
                receipt["contour"] = origin
            self.assertEqual(self.verify(receipts).contour, origin)

            for mismatch_index in range(3):
                attempt = list(chain())
                for receipt in attempt:
                    receipt["contour"] = origin
                attempt[mismatch_index]["contour"] = foreign
                with self.subTest(origin=origin, foreign=foreign, mismatch_index=mismatch_index):
                    with self.assertRaisesRegex(ValidationBoundaryError, "receipt contours do not match"):
                        self.verify(attempt)

    def test_mixed_execution_contours_stop_before_runner_or_artifact_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Fixture(root)
            fixture.permit["contour"] = "market"

            with self.assertRaisesRegex(ExecutionError, "contours must match"):
                fixture.execute()

            self.assertEqual(fixture.calls, [])
            self.assertEqual(fixture.publication_arguments, [])
            self.assertIsNone(fixture.ingestor_envelope)
            self.assertIsNone(fixture.completion_arguments)

    def test_d2_d3_receipt_payloads_never_project(self) -> None:
        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            with self.subTest(classification=classification):
                with self.assertRaisesRegex(ValidationBoundaryError, "classification must be D0 or D1"):
                    self.verify(chain(classification=classification))

    def test_core_bridge_surface_has_no_external_live_target_authority(self) -> None:
        modules = ["admission.py", "execution.py", "ingestion.py", "validation.py"]
        forbidden_imports = {"ftplib", "http", "httpx", "requests", "smtplib", "subprocess", "urllib"}
        forbidden_names = {"exploit", "live_target", "publish_finding", "report_submit", "target_scan"}
        forbidden_text = ("AF_INET", "create_connection", "urlopen(", "http://", "https://")

        for filename in modules:
            source = (SRC / filename).read_text()
            tree = ast.parse(source)
            imported_roots = set()
            definitions = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_roots.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported_roots.add(node.module.split(".")[0])
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    definitions.add(node.name.lower())
            self.assertTrue(imported_roots.isdisjoint(forbidden_imports), filename)
            self.assertTrue(all(not any(fragment in name for fragment in forbidden_names) for name in definitions), filename)
            self.assertTrue(all(marker not in source for marker in forbidden_text), filename)

        contract_names = {path.stem.lower() for path in CONTRACTS.glob("*.schema.json")}
        for forbidden in ("liveaction", "livetarget", "findingpublication", "reportsubmission", "exploitexecution"):
            self.assertTrue(all(forbidden not in name.replace("_", "").replace("-", "") for name in contract_names))

    def test_private_stage3_receipt_is_bound_to_zero_side_effects(self) -> None:
        receipt = json.loads(LOCAL_LAB_RECEIPT.read_text())
        audit = receipt["payload"]["audit_results"]
        self.assertEqual(audit["network_calls"], 0)
        self.assertEqual(audit["registry_writes"], 0)
        self.assertEqual(audit["cross_contour_reads"], 0)
        self.assertFalse(audit["live_or_connected_authority"])
        self.assertFalse(audit["scientific_outcome_applied"])

    def test_boundary_receipt_and_final_stage3_gate_are_integrity_bound(self) -> None:
        boundary = json.loads(BOUNDARY_RECEIPT.read_text())
        gate = json.loads(STAGE3_GATE_RECEIPT.read_text())
        envelope = json.loads((STAGE3_GATE / "stage-envelope.json").read_text())
        lease = json.loads((STAGE3_GATE / "ownership-lease.json").read_text())
        for receipt in (boundary, gate):
            payload = json.dumps(receipt["payload"], sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(receipt["integrity"]["payload_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertTrue(boundary["payload"]["audit_results"]["completes_all_stage3_required_capabilities"])
        audit = gate["payload"]["audit_results"]
        self.assertEqual(audit["required_capability_count"], 9)
        self.assertTrue(all(audit["capabilities"].values()))
        self.assertEqual(audit["stage_exit"], "DUAL_CONTOUR_PRE_SOAK_GREEN")
        self.assertTrue(audit["declares_market_pre_soak_green"])
        self.assertTrue(audit["declares_dual_contour_pre_soak_green"])
        self.assertFalse(audit["declares_ready_for_72h_soak"])
        self.assertFalse(audit["exact_image_digest_frozen"])
        self.assertFalse(audit["encrypted_off_host_backup_claimed"])
        self.assertFalse(audit["deployment_authority"])
        self.assertFalse(audit["live_or_connected_authority"])
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertFalse(envelope["gate_contract"]["declares_ready_for_72h_soak"])
        self.assertFalse(lease["delegation_allowed"])


if __name__ == "__main__":
    unittest.main()
