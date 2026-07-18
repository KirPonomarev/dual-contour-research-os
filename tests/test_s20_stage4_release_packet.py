from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import verify_stage4_release_packet as verifier  # noqa: E402


def packet() -> dict[str, object]:
    return json.loads(verifier.PACKET.read_text())


def resign(value: dict[str, object]) -> dict[str, object]:
    result = deepcopy(value)
    result["integrity"]["payload_sha256"] = verifier._payload_digest(result)  # type: ignore[index]
    return result


class Stage4IsolationReleasePacketTests(unittest.TestCase):
    def test_static_packet_unit_and_runbook_are_green(self) -> None:
        value = verifier.validate_packet()
        self.assertEqual(value["candidate"]["supervisor"], "systemd-user")

    def test_namespaces_are_disjoint_and_parallel_writers_forbidden(self) -> None:
        value = packet()
        predecessor = set(value["predecessor"]["mutable_namespaces"])
        candidate = set(value["candidate"]["mutable_namespaces"])
        self.assertTrue(predecessor.isdisjoint(candidate))
        self.assertFalse(value["cutover"]["concurrent_activation"])
        self.assertTrue(value["cutover"]["single_writer_required"])
        self.assertEqual(value["candidate"]["runtime_model"], "ONE_BRIDGE_PROCESS_ONE_LEDGER_ONE_WRITER_A1_ADDITIVE")

    def test_exactly_one_restart_supervisor(self) -> None:
        unit = (ROOT / "ops/deploy/research-os-a1-bridge.service").read_text()
        self.assertEqual(unit.count("--restart=no"), 1)
        self.assertNotIn("--restart=unless-stopped", unit)
        self.assertEqual(unit.count("Restart=on-failure"), 1)

    def test_same_release_r0_is_bounded_and_changed_release_waits_for_human(self) -> None:
        value = packet()
        recovery = value["recovery"]
        self.assertEqual(recovery["r0_scope"], "SAME_RELEASE_SAME_IMAGE_SAME_POLICY_SAME_CONFIG_SAME_SCHEMA_ONLY")
        self.assertTrue(recovery["changed_release_requires_human_approval"])
        self.assertTrue(value["authority"]["deployment_approval_receipt_required"])
        for key, allowed in value["authority"].items():
            if key.startswith("packet_grants_"):
                self.assertFalse(allowed, key)

    def test_resealed_namespace_or_authority_widening_fails(self) -> None:
        cases = (
            lambda value: value["candidate"].__setitem__("mutable_namespaces", ["research-os-bridge-runtime"]),
            lambda value: value["cutover"].__setitem__("concurrent_activation", True),
            lambda value: value["cutover"].__setitem__("single_writer_required", False),
            lambda value: value["recovery"].__setitem__("changed_release_requires_human_approval", False),
            lambda value: value["authority"].__setitem__("packet_grants_deployment", True),
        )
        for mutate in cases:
            with self.subTest(mutate=mutate):
                value = packet()
                mutate(value)
                with self.assertRaises(verifier.Stage4PacketError):
                    verifier.validate_packet(packet=resign(value))

    def test_unit_drift_or_second_supervisor_fails(self) -> None:
        original = ROOT / "ops/deploy/research-os-a1-bridge.service"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = root / "ops/deploy/research-os-a1-bridge.service"
            unit.parent.mkdir(parents=True)
            unit.write_text(original.read_text().replace("--restart=no", "--restart=unless-stopped"))
            manifest = root / "docs/receipts/release/s4-release-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes((ROOT / "docs/receipts/release/s4-release-manifest.json").read_bytes())
            runbook = root / "docs/STAGE4_A1_ISOLATION_RELEASE_RUNBOOK.md"
            runbook.parent.mkdir(parents=True, exist_ok=True)
            runbook.write_bytes((ROOT / "docs/STAGE4_A1_ISOLATION_RELEASE_RUNBOOK.md").read_bytes())
            value = packet()
            value["candidate"]["unit_sha256"] = hashlib.sha256(unit.read_bytes()).hexdigest()
            with patch.object(verifier.subprocess, "run", return_value=type("R", (), {"returncode": 0})()):
                with self.assertRaisesRegex(verifier.Stage4PacketError, "one supervisor"):
                    verifier.validate_packet(root, packet=resign(value))


if __name__ == "__main__":
    unittest.main()
