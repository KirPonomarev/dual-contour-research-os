from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(TOOLS))

import build_pre_soak_capsule as builder  # noqa: E402
import issue_l0_job_bundle as issuer  # noqa: E402
from research_bridge.admission import admit, canonical_json_sha256  # noqa: E402
from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.l0 import DeterministicL0Runner  # noqa: E402
from research_bridge.researchctl import _submit_payload  # noqa: E402


RELEASE_MANIFEST = ROOT / "docs" / "receipts" / "release" / "s4-release-manifest.json"
MARKET_BYTES = b"public synthetic market job input\n"
SECURITY_BYTES = b"sanitized synthetic security job input\n"


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("fixture JSON is not an object")
    return value


def parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class L0JobBundleIssuerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.market = self.base / "market.bin"
        self.security = self.base / "security.bin"
        self.market.write_bytes(MARKET_BYTES)
        self.security.write_bytes(SECURITY_BYTES)
        self.capsule = self.base / "capsule"
        self.observed = datetime.now(timezone.utc).replace(microsecond=0)
        builder.build_capsule(
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

    def _issue(self, contour: str, sequence: int, *, lifetime: int = 300) -> tuple[Path, dict[str, object]]:
        output = self.base / f"bundle-{contour}-{sequence}.json"
        issuer.issue_bundle(
            capsule=self.capsule,
            contour=contour,
            sequence=sequence,
            lifetime_seconds=lifetime,
            output=output,
            observed=self.observed,
        )
        return output, load_json(output)

    def test_market_and_security_bundles_pass_exact_admission_researchctl_and_l0(self) -> None:
        config_path = self.capsule / builder.CONFIG_NAME
        service = builder._parse_host_authority_projection(load_json(config_path))
        manifest = load_json(self.capsule / builder.MANIFEST_NAME)
        manifest_payload = manifest["payload"]
        self.assertIsInstance(manifest_payload, dict)
        input_records = manifest_payload["inputs"]
        self.assertIsInstance(input_records, dict)
        store = ContentAddressedStore(
            self.capsule / "runtime" / "input-cas",
            quota_bytes=builder.INPUT_QUOTA_BYTES,
        )

        expected = (
            ("market", 11, "D0_PUBLIC", MARKET_BYTES),
            ("security", 22, "D1_INTERNAL_SANITIZED", SECURITY_BYTES),
        )
        object_ids: set[str] = set()
        for contour, sequence, classification, raw in expected:
            with self.subTest(contour=contour):
                output, bundle = self._issue(contour, sequence)
                self.assertEqual(set(bundle), {"job_spec", "permit", "lease"})
                self.assertEqual(stat.S_IMODE(os.lstat(output).st_mode), 0o600)
                self.assertEqual(os.lstat(output).st_uid, os.geteuid())
                self.assertEqual(_submit_payload(io.StringIO(output.read_text(encoding="utf-8"))), bundle)

                job = bundle["job_spec"]
                permit = bundle["permit"]
                lease = bundle["lease"]
                self.assertIsInstance(job, dict)
                self.assertIsInstance(permit, dict)
                self.assertIsInstance(lease, dict)
                grant = admit(job, permit, lease, now=self.observed, authority=service.authority)
                self.assertEqual(grant.contour, contour)
                self.assertEqual(grant.classification, classification)
                self.assertEqual(grant.fencing_epoch, sequence)
                self.assertEqual(grant.runner_identity, builder.RUNNER_IDENTITY)
                self.assertEqual(grant.provider, "L0")
                self.assertEqual(grant.reservation_cost_units, 1)
                self.assertEqual(grant.scope_limit_cost_units, 1)

                job_payload = job["payload"]
                permit_payload = permit["payload"]
                lease_payload = lease["payload"]
                self.assertEqual(job["contour"], contour)
                self.assertEqual(job["classification"], classification)
                self.assertEqual(job_payload["protocol_ref"], builder.L0_PROTOCOL_REF)
                self.assertEqual(job_payload["code_ref"], f"sha256:{builder.L0_TEMPLATE_SHA256}")
                self.assertEqual(job_payload["image_digest"], builder.IMAGE_DIGEST)
                self.assertEqual(job_payload["runner_profile"], "L0")
                self.assertEqual(job_payload["network_policy"], "offline")
                self.assertEqual(job_payload["resource_limits"], {"cost_units": 1})
                self.assertEqual(job_payload["input_refs"], [input_records[contour]["cas_ref"]])
                self.assertEqual(permit_payload["job_spec_sha256"], canonical_json_sha256(job))
                self.assertEqual(permit_payload["input_sha256"], canonical_json_sha256(job_payload["input_refs"]))
                self.assertEqual(
                    permit_payload["policy_snapshot_sha256"],
                    manifest_payload["authority_policy_sha256"],
                )
                self.assertEqual(permit_payload["network_class"], "offline")
                self.assertEqual(permit_payload["max_uses"], 1)
                self.assertEqual(permit_payload["quotas"]["claims"], 1)
                self.assertEqual(permit_payload["quotas"]["provider"], "L0")
                self.assertEqual(lease_payload["fencing_epoch"], sequence)
                self.assertEqual(lease_payload["runner_identity"], builder.RUNNER_IDENTITY)
                self.assertIn(f"-{sequence}-", job["object_id"])
                object_ids.add(job["object_id"])

                permit_lifetime = parsed_time(permit_payload["expires_at"]) - parsed_time(permit_payload["not_before"])
                lease_lifetime = parsed_time(lease_payload["expires_at"]) - parsed_time(lease_payload["issued_at"])
                self.assertLessEqual(permit_lifetime.total_seconds(), 300)
                self.assertLessEqual(lease_lifetime.total_seconds(), 300)

                staging = self.base / f"staging-{contour}"
                staging.mkdir(mode=0o700)
                runner = DeterministicL0Runner(
                    lambda ref: store.read_bytes(ref, maximum_size_bytes=builder.MAXIMUM_INPUT_BYTES),
                    clock=lambda: self.observed,
                    runner_identity=builder.RUNNER_IDENTITY,
                )
                result = runner.run(job, lease, staging)
                self.assertEqual(result.code_sha256, builder.L0_TEMPLATE_SHA256)
                self.assertEqual(result.input_sha256, canonical_json_sha256(job_payload["input_refs"]))
                self.assertEqual(result.environment_digest, builder.IMAGE_DIGEST)
                self.assertEqual(result.resource_usage["input_bytes"], len(raw))
        self.assertEqual(len(object_ids), 2)

    def test_cli_stdout_has_no_paths_payload_nonce_or_fence(self) -> None:
        output = self.base / "cli-bundle.json"
        command = [
            sys.executable,
            str(TOOLS / "issue_l0_job_bundle.py"),
            "--capsule",
            str(self.capsule),
            "--contour",
            "market",
            "--sequence",
            "33",
            "--lifetime-seconds",
            "120",
            "--out",
            str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        bundle = load_json(output)
        permit = bundle["permit"]
        lease = bundle["lease"]
        nonce = permit["payload"]["nonce"]
        fence = lease["payload"]["fencing_token"]
        for forbidden in (
            str(self.capsule),
            str(output),
            str(self.market),
            str(self.security),
            MARKET_BYTES.decode().strip(),
            SECURITY_BYTES.decode().strip(),
            nonce,
            fence,
        ):
            self.assertNotIn(forbidden, completed.stdout)
        status = json.loads(completed.stdout)
        self.assertEqual(status["contour"], "market")
        self.assertEqual(status["sequence"], 33)
        self.assertIs(status["external_action_authority"], False)

    def test_invalid_contour_sequence_lifetime_and_capsule_output_are_rejected(self) -> None:
        cases = (
            ("contour", {"contour": "bridge"}),
            ("sequence", {"sequence": 0}),
            ("lifetime", {"lifetime_seconds": 301}),
            ("inside-capsule", {"output": self.capsule / "bundle.json"}),
        )
        for index, (name, overrides) in enumerate(cases):
            with self.subTest(name=name):
                output = self.base / f"rejected-{index}.json"
                arguments: dict[str, object] = {
                    "capsule": self.capsule,
                    "contour": "market",
                    "sequence": 100 + index,
                    "lifetime_seconds": 300,
                    "output": output,
                    "observed": self.observed,
                }
                arguments.update(overrides)
                with self.assertRaises((issuer.BundleError, builder.CapsuleError)):
                    issuer.issue_bundle(**arguments)
                self.assertFalse(output.exists())

    def test_issuer_rejects_host_uid_and_relative_runtime_root_profiles(self) -> None:
        config_path = self.capsule / builder.CONFIG_NAME
        original = config_path.read_bytes()
        manifest = load_json(self.capsule / builder.MANIFEST_NAME)
        manifest_payload = manifest["payload"]
        self.assertIsInstance(manifest_payload, dict)
        host_uid = os.geteuid()
        self.assertNotEqual(host_uid, builder.DEPLOY_UID)

        cases = (
            ("host-uid", "allowed_uids", [host_uid]),
            ("relative-root", "runtime_root", "runtime"),
        )
        for name, field, value in cases:
            with self.subTest(name=name):
                config = json.loads(original)
                config[field] = value
                encoded = builder._canonical_bytes(config)
                config_path.write_bytes(encoded)
                os.chmod(config_path, 0o600)
                context = dict(manifest_payload)
                context["runtime_config_sha256"] = hashlib.sha256(encoded).hexdigest()
                with self.assertRaises(issuer.BundleError):
                    issuer._config_context(self.capsule, context, self.observed)
                config_path.write_bytes(original)
                os.chmod(config_path, 0o600)

    def test_bundle_lifetime_must_fit_active_policy_and_approval_window(self) -> None:
        near_expiry = self.observed + timedelta(seconds=builder.AUTHORITY_VALID_SECONDS - 1)
        rejected = self.base / "authority-window-rejected.json"
        with self.assertRaises(issuer.BundleError):
            issuer.issue_bundle(
                capsule=self.capsule,
                contour="market",
                sequence=46,
                lifetime_seconds=300,
                output=rejected,
                observed=near_expiry,
            )
        self.assertFalse(rejected.exists())

        accepted = self.base / "authority-window-accepted.json"
        issuer.issue_bundle(
            capsule=self.capsule,
            contour="market",
            sequence=47,
            lifetime_seconds=1,
            output=accepted,
            observed=near_expiry,
        )
        bundle = load_json(accepted)
        permit = bundle["permit"]
        self.assertIsInstance(permit, dict)
        permit_payload = permit["payload"]
        self.assertIsInstance(permit_payload, dict)
        self.assertEqual(
            parsed_time(permit_payload["expires_at"]),
            self.observed + timedelta(seconds=builder.AUTHORITY_VALID_SECONDS),
        )

    def test_existing_output_and_tampered_capsule_fail_without_overwrite(self) -> None:
        output = self.base / "existing.json"
        output.write_text("preserve-me\n", encoding="utf-8")
        with self.assertRaises((issuer.BundleError, builder.CapsuleError)):
            issuer.issue_bundle(
                capsule=self.capsule,
                contour="market",
                sequence=44,
                lifetime_seconds=300,
                output=output,
                observed=self.observed,
            )
        self.assertEqual(output.read_text(encoding="utf-8"), "preserve-me\n")

        config = self.capsule / builder.CONFIG_NAME
        config.write_bytes(config.read_bytes() + b" ")
        os.chmod(config, 0o600)
        rejected = self.base / "tampered-rejected.json"
        with self.assertRaises(issuer.BundleError):
            issuer.issue_bundle(
                capsule=self.capsule,
                contour="security",
                sequence=45,
                lifetime_seconds=300,
                output=rejected,
                observed=self.observed,
            )
        self.assertFalse(rejected.exists())

    def test_issuer_has_validation_only_and_no_execution_or_contact_path(self) -> None:
        source = (TOOLS / "issue_l0_job_bundle.py").read_text(encoding="utf-8")
        for forbidden in (
            "import socket",
            "import urllib",
            "import requests",
            "subprocess",
            "DeterministicL0Runner",
            "ResearchDaemon",
            "researchctl",
            ".submit(",
            ".run(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
