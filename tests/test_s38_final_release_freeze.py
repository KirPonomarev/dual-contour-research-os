from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

from tools.verify_final_release_freeze import (
    FinalReleaseFreezeError,
    inspect,
    validate_inventory,
    validate_manifest,
    validate_packet,
)


ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> dict[str, object]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class S38FinalReleaseFreezeTests(unittest.TestCase):
    def test_final_candidate_is_exact_frozen_and_non_authoritative(self) -> None:
        result = inspect(ROOT)
        self.assertEqual(result["status"], "FINAL_CANDIDATE_FROZEN_WAIT_HUMAN_APPROVAL")
        self.assertEqual(result["candidate_release_sha"], "b2c2e6a8c4e0a364ef82e8e51540433aa91430d4")
        self.assertEqual(result["phase_receipts"], 16)
        self.assertEqual(result["critical_debt"], 0)
        self.assertFalse(result["deployment_allowed"])
        self.assertFalse(result["grants_authority"])

    def test_manifest_candidate_catalog_and_debt_tamper_fail_closed(self) -> None:
        manifest = _load("docs/receipts/release/s38-final-release-manifest.json")
        for field, value in (
            ("candidate_tree_sha", "0" * 40),
            ("unresolved_critical_debt", ["critical:fixture"]),
            ("deployment_allowed", True),
        ):
            forged = deepcopy(manifest)
            forged["payload"][field] = value
            forged["integrity"]["payload_sha256"] = hashlib.sha256(
                json.dumps(forged["payload"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            with self.assertRaises(FinalReleaseFreezeError):
                validate_manifest(ROOT, forged)

    def test_deployment_packet_requires_rebound_human_receipt(self) -> None:
        packet = _load("ops/deploy/s38-final-deployment-packet.json")
        self.assertEqual(packet["authority"]["status"], "WAIT_HUMAN_APPROVAL_REBIND_REQUIRED")
        self.assertIsNone(packet["authority"]["deployment_approval_receipt_ref"])
        for field in ("deployment_allowed", "VPS_mutation_allowed", "live_action_allowed", "grants_authority"):
            forged = deepcopy(packet)
            forged["authority"][field] = True
            payload = {key: value for key, value in forged.items() if key != "integrity"}
            forged["integrity"]["payload_sha256"] = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            with self.assertRaises(FinalReleaseFreezeError):
                validate_packet(ROOT, forged)

    def test_dependency_notice_license_and_sbom_inventory_is_exact(self) -> None:
        inventory = _load("docs/receipts/release/s38-dependency-notice-inventory.json")
        validate_inventory(ROOT, inventory)
        forged = deepcopy(inventory)
        forged["licenses"][0]["sha256"] = "0" * 64
        with self.assertRaises(FinalReleaseFreezeError):
            validate_inventory(ROOT, forged)

    def test_predecessor_release_identity_and_current_contracts_remain_green(self) -> None:
        result = subprocess.run(
            ["python3", "tools/verify_release_identity.py"], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        identity = json.loads(result.stdout)
        self.assertEqual(identity["status"], "PASS")
        self.assertFalse(identity["external_action_authority"])


if __name__ == "__main__":
    unittest.main()
