from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_deployment_readiness_packet as readiness  # noqa: E402


def packet() -> dict[str, object]:
    return json.loads(readiness.PACKET.read_text())


def resign(value: dict[str, object]) -> dict[str, object]:
    result = deepcopy(value)
    result["integrity"]["payload_sha256"] = readiness.payload_digest(result)  # type: ignore[index]
    return result


class DeploymentReadinessPacketTests(unittest.TestCase):
    def test_exact_static_packet_is_ready_for_review_not_deploy(self) -> None:
        value = readiness.validate()
        self.assertEqual(value["readiness"]["status"], "READY_FOR_HUMAN_REVIEW_NOT_READY_TO_DEPLOY")
        self.assertFalse(value["authority"]["packet_grants_external_action"])

    def test_backup_restore_are_explicit_drafts_without_secrets(self) -> None:
        value = packet()
        self.assertEqual(value["backup_draft"]["state"], "RUNTIME_EVIDENCE_REQUIRED")
        self.assertEqual(value["restore_draft"]["state"], "RUNTIME_EVIDENCE_REQUIRED")
        self.assertFalse(value["backup_draft"]["repository_locator_in_git"])
        self.assertFalse(value["backup_draft"]["credential_in_git"])

    def test_resealed_overclaims_and_authority_widening_fail(self) -> None:
        cases = (
            lambda v: v["backup_draft"].__setitem__("state", "VERIFIED"),
            lambda v: v["restore_draft"].__setitem__("state", "VERIFIED"),
            lambda v: v["restore_draft"].__setitem__("destructive_restore", True),
            lambda v: v["authority"].__setitem__("human_confirmation_required", False),
            lambda v: v["authority"].__setitem__("packet_grants_external_action", True),
            lambda v: v["readiness"].__setitem__("status", "READY_TO_DEPLOY"),
        )
        for mutate in cases:
            value = packet()
            mutate(value)
            with self.assertRaises(readiness.ReadinessError):
                readiness.validate(packet=resign(value))

    def test_release_isolation_and_tool_digest_drift_fail(self) -> None:
        for section, field in (("release", "manifest_sha256"), ("isolation", "packet_sha256"), ("backup_draft", "controller_sha256"), ("authority", "approval_issuer_sha256")):
            value = packet()
            value[section][field] = "0" * 64
            with self.assertRaisesRegex(readiness.ReadinessError, "drift"):
                readiness.validate(packet=resign(value))


if __name__ == "__main__":
    unittest.main()
