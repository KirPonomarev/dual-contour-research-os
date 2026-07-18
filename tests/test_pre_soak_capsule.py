from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(TOOLS))

import build_pre_soak_capsule as builder  # noqa: E402
from research_bridge.admission import canonical_json_sha256  # noqa: E402
from research_bridge.cas import ContentAddressedStore  # noqa: E402


RELEASE_MANIFEST = ROOT / "docs" / "receipts" / "release" / "s4-release-manifest.json"
MARKET_BYTES = b"public synthetic market pre-soak input\n"
SECURITY_BYTES = b"sanitized synthetic security pre-soak input\n"


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("fixture JSON is not an object")
    return value


def snapshot(root: Path) -> tuple[tuple[str, str, int], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size)
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file() and not path.is_symlink()
    )


class PreSoakCapsuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.market = self.base / "market-source.bin"
        self.security = self.base / "security-source.bin"
        self.market.write_bytes(MARKET_BYTES)
        self.security.write_bytes(SECURITY_BYTES)
        self.capsule = self.base / "capsule"
        self.observed = datetime.now(timezone.utc).replace(microsecond=0)
        self.result = builder.build_capsule(
            release_manifest_path=RELEASE_MANIFEST,
            market_input_path=self.market,
            market_classification="D0_PUBLIC",
            security_input_path=self.security,
            security_classification="D1_INTERNAL_SANITIZED",
            output=self.capsule,
            observed=self.observed,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_capsule_config_is_owner_only_nonempty_active_and_exactly_parseable(self) -> None:
        config_path = self.capsule / builder.CONFIG_NAME
        manifest_path = self.capsule / builder.MANIFEST_NAME
        self.assertEqual(stat.S_IMODE(os.lstat(self.capsule).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(config_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.lstat(manifest_path).st_mode), 0o600)
        self.assertEqual(os.lstat(config_path).st_uid, os.geteuid())

        config = load_json(config_path)
        self.assertEqual(config["runtime_root"], builder.DEPLOY_RUNTIME_ROOT)
        self.assertEqual(config["allowed_uids"], [builder.DEPLOY_UID])
        self.assertEqual(config["runner_identity"], builder.RUNNER_IDENTITY)
        policies = config["policy_snapshots"]
        approvals = config["approval_receipts"]
        self.assertIsInstance(policies, dict)
        self.assertIsInstance(approvals, dict)
        self.assertEqual(len(policies), 1)
        self.assertEqual(len(approvals), 1)
        policy_sha256, policy = next(iter(policies.items()))
        approval_ref, approval = next(iter(approvals.items()))
        self.assertEqual(policy_sha256, canonical_json_sha256(policy))
        self.assertEqual(approval_ref, approval["object_id"])

        service = builder._parse_host_authority_projection(config)
        self.assertEqual(service.runtime_root, builder.DEPLOY_RUNTIME_ROOT)
        self.assertEqual(service.allowed_uids, (os.geteuid(),))
        self.assertEqual(service.runner_identity, builder.RUNNER_IDENTITY)
        service.authority.verify_resume(approval_ref, now=self.observed)
        service.authority.verify_resume(approval_ref, now=self.observed + timedelta(hours=72))

    def test_manifest_binds_release_config_policy_inputs_and_every_other_file(self) -> None:
        manifest_path = self.capsule / builder.MANIFEST_NAME
        config_path = self.capsule / builder.CONFIG_NAME
        manifest = load_json(manifest_path)
        payload = manifest["payload"]
        integrity = manifest["integrity"]
        self.assertIsInstance(payload, dict)
        self.assertIsInstance(integrity, dict)
        self.assertEqual(integrity["payload_sha256"], canonical_json_sha256(payload))
        self.assertEqual(manifest["object_id"], "pre-soak-capsule-" + canonical_json_sha256(payload))
        self.assertEqual(payload["release_manifest_sha256"], builder.RELEASE_MANIFEST_SHA256)
        self.assertEqual(payload["release_sha"], builder.RELEASE_SHA)
        self.assertEqual(payload["image_digest"], builder.IMAGE_DIGEST)
        self.assertEqual(
            payload["runtime_config_sha256"],
            hashlib.sha256(config_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(payload["network_class"], "offline")
        self.assertIs(payload["external_action_authority"], False)

        expected_files = []
        for path in sorted(self.capsule.rglob("*"), key=lambda item: item.as_posix()):
            metadata = os.lstat(path)
            self.assertFalse(stat.S_ISLNK(metadata.st_mode))
            if not stat.S_ISREG(metadata.st_mode) or path == manifest_path:
                continue
            expected_files.append(
                {
                    "relative_path": path.relative_to(self.capsule).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": metadata.st_size,
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                }
            )
        self.assertEqual(payload["file_hashes"], expected_files)
        self.assertEqual(self.result["capsule_manifest_sha256"], hashlib.sha256(manifest_path.read_bytes()).hexdigest())

    def test_market_and_security_bytes_are_seeded_via_cas_but_not_disclosed(self) -> None:
        manifest = load_json(self.capsule / builder.MANIFEST_NAME)
        payload = manifest["payload"]
        self.assertIsInstance(payload, dict)
        inputs = payload["inputs"]
        self.assertIsInstance(inputs, dict)
        store = ContentAddressedStore(
            self.capsule / "runtime" / "input-cas",
            quota_bytes=builder.INPUT_QUOTA_BYTES,
        )
        expected = {
            "market": ("D0_PUBLIC", MARKET_BYTES),
            "security": ("D1_INTERNAL_SANITIZED", SECURITY_BYTES),
        }
        for contour, (classification, raw) in expected.items():
            record = inputs[contour]
            self.assertEqual(record["classification"], classification)
            self.assertEqual(record["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(record["cas_ref"], f"cas:sha256:{hashlib.sha256(raw).hexdigest()}")
            self.assertEqual(record["size_bytes"], len(raw))
            self.assertEqual(
                store.read_bytes(record["cas_ref"], maximum_size_bytes=builder.MAXIMUM_INPUT_BYTES),
                raw,
            )

        public_text = (self.capsule / builder.MANIFEST_NAME).read_text(encoding="utf-8")
        public_text += json.dumps(self.result, sort_keys=True)
        for forbidden in (
            str(self.market),
            str(self.security),
            MARKET_BYTES.decode().strip(),
            SECURITY_BYTES.decode().strip(),
            "D2_DOMAIN_CONFIDENTIAL",
            "D3_RESTRICTED",
        ):
            self.assertNotIn(forbidden, public_text)

    def test_cli_output_is_sanitized_and_existing_capsule_is_never_overwritten(self) -> None:
        output = self.base / "cli-capsule"
        command = [
            sys.executable,
            str(TOOLS / "build_pre_soak_capsule.py"),
            "--release-manifest",
            str(RELEASE_MANIFEST),
            "--market-input",
            str(self.market),
            "--market-classification",
            "D0_PUBLIC",
            "--security-input",
            str(self.security),
            "--security-classification",
            "D1_INTERNAL_SANITIZED",
            "--out",
            str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        for forbidden in (
            str(self.market),
            str(self.security),
            str(output),
            MARKET_BYTES.decode().strip(),
            SECURITY_BYTES.decode().strip(),
        ):
            self.assertNotIn(forbidden, completed.stdout)
        before = snapshot(output)
        repeated = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(repeated.returncode, 1)
        self.assertEqual(snapshot(output), before)

    def test_private_classification_symlink_tampered_release_and_oversize_fail_closed(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []
        cases.append(("private-classification", {"market_classification": "D2_DOMAIN_CONFIDENTIAL"}))

        linked = self.base / "linked-input"
        linked.symlink_to(self.market)
        cases.append(("symlink", {"market_input_path": linked}))

        tampered = self.base / "tampered-release.json"
        tampered.write_bytes(RELEASE_MANIFEST.read_bytes() + b" ")
        cases.append(("tampered-release", {"release_manifest_path": tampered}))

        oversized = self.base / "oversized.bin"
        oversized.write_bytes(b"x" * (builder.MAXIMUM_INPUT_BYTES + 1))
        cases.append(("oversized", {"security_input_path": oversized}))

        for index, (name, overrides) in enumerate(cases):
            with self.subTest(name=name):
                output = self.base / f"rejected-{index}"
                arguments: dict[str, object] = {
                    "release_manifest_path": RELEASE_MANIFEST,
                    "market_input_path": self.market,
                    "market_classification": "D0_PUBLIC",
                    "security_input_path": self.security,
                    "security_classification": "D1_INTERNAL_SANITIZED",
                    "output": output,
                    "observed": self.observed,
                }
                arguments.update(overrides)
                with self.assertRaises(builder.CapsuleError):
                    builder.build_capsule(**arguments)
                self.assertFalse(output.exists())

    def test_failure_after_output_creation_removes_only_the_new_capsule(self) -> None:
        output = self.base / "transactional-rejection"
        with mock.patch.object(
            builder,
            "_parse_host_authority_projection",
            side_effect=ValueError("synthetic parser rejection"),
        ):
            with self.assertRaises(ValueError):
                builder.build_capsule(
                    release_manifest_path=RELEASE_MANIFEST,
                    market_input_path=self.market,
                    market_classification="D0_PUBLIC",
                    security_input_path=self.security,
                    security_classification="D1_INTERNAL_SANITIZED",
                    output=output,
                    observed=self.observed,
                )
        self.assertFalse(output.exists())

    def test_builder_contains_no_network_or_runtime_execution_path(self) -> None:
        source = (TOOLS / "build_pre_soak_capsule.py").read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import urllib",
            "import requests",
            "subprocess",
            "ResearchDaemon(",
            ".start()",
            ".submit(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
