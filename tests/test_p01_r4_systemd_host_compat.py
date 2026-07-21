from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import physical_release_control as control


class SystemdHostCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.unit = (ROOT / "ops/deploy/research-os-a1-final.service").read_text(
            encoding="utf-8"
        )

    def test_capability_mutating_host_directives_are_not_rendered(self) -> None:
        for directive in (
            "PrivateDevices=yes",
            "ProtectClock=yes",
            "ProtectKernelLogs=yes",
            "ProtectKernelModules=yes",
        ):
            self.assertNotIn(directive, self.unit)

    def test_compatible_host_hardening_remains_required(self) -> None:
        for directive in (
            "NoNewPrivileges=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
            "ProtectControlGroups=yes",
            "ProtectKernelTunables=yes",
            "RestrictRealtime=yes",
            "RestrictSUIDSGID=yes",
            "SystemCallArchitectures=native",
        ):
            self.assertIn(directive, self.unit)

    def test_container_sandbox_is_unchanged(self) -> None:
        for option in (
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
        ):
            self.assertIn(option, self.unit)

    def test_frozen_unit_hash_matches_control_constant(self) -> None:
        unit_sha256 = hashlib.sha256(
            (ROOT / "ops/deploy/research-os-a1-final.service").read_bytes()
        ).hexdigest()
        self.assertEqual(unit_sha256, control.UNIT_SHA256)


if __name__ == "__main__":
    unittest.main()
