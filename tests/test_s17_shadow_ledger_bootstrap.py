from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import model_provider_shadow as shadow  # noqa: E402
from research_bridge.ledger import JobLedger, LedgerError  # noqa: E402
from research_bridge.model_broker import ModelCallBroker  # noqa: E402
from tests.test_s15_model_registry_broker import AT, policy, registry, spec  # noqa: E402


EVENT_AT = "2026-07-18T11:59:59Z"


class ShadowLedgerBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "shadow.sqlite3"
        self.profile = shadow.ConnectedShadowProfile()

    def args(self, path: Path | None = None) -> argparse.Namespace:
        return argparse.Namespace(
            ledger=str(path or self.database), event_at=EVENT_AT
        )

    def initialize(self) -> dict[str, object]:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(shadow._init_ledger(self.args(), self.profile), 0)
        return json.loads(output.getvalue())

    def test_new_private_ledger_is_D0_fixture_only_non_authoritative_and_verified(self) -> None:
        result = self.initialize()
        self.assertEqual(result["status"], "INITIALIZED_PRIVATE_FIXTURE_LEDGER")
        self.assertEqual(result["event_sequence"], 1)
        self.assertEqual(result["classification"], "D0")
        self.assertTrue(result["fixture_only"])
        self.assertFalse(result["grants_authority"])
        self.assertEqual(result["trusted_material_events"], 0)
        self.assertEqual(result["network_calls"], 0)
        self.assertFalse(result["credential_access"])
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)
        with JobLedger(self.database) as ledger:
            self.assertEqual(ledger.event_count(), 1)
            self.assertTrue(ledger.verify_chain())
            self.assertTrue(ledger.verify_a1_coverage())
            document = ledger.read_a1_object(result["object_ids"][0])
        self.assertEqual(document["schema_id"], "CapabilityProofReceipt")
        self.assertEqual(document["classification"], "D0")
        self.assertEqual(document["contour"], "governance")
        self.assertTrue(document["payload"]["fixture_only"])
        self.assertFalse(document["payload"]["grants_authority"])
        self.assertEqual(document["payload"]["shadow_status"], "SHADOW_UNAPPLIED")

    def test_bootstrap_projections_allow_durable_model_reservation_after_reopen(self) -> None:
        self.initialize()
        with JobLedger(self.database) as ledger:
            broker = ModelCallBroker(
                registry=registry(), ledger=ledger, budget_policy=policy()
            )
            call = spec(key="s17-after-bootstrap")
            prepared = broker.prepare(call, event_at=AT)
            self.assertEqual(prepared.state, "RESERVED")
            self.assertTrue(ledger.verify_chain())
            self.assertTrue(ledger.verify_a1_coverage())

    def test_existing_ledger_is_rejected_before_mutation(self) -> None:
        self.initialize()
        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        with self.assertRaises(shadow.ShadowProviderError):
            shadow._init_ledger(self.args(), self.profile)
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), before)

    def test_repository_path_is_denied_and_failure_removes_partial_database(self) -> None:
        repo_path = ROOT / "forbidden-shadow.sqlite3"
        with self.assertRaises(shadow.ShadowProviderError):
            shadow._init_ledger(self.args(repo_path), self.profile)
        self.assertFalse(repo_path.exists())

        original = JobLedger.append_a1_bundle

        def fail_after_schema(self, **kwargs):  # type: ignore[no-untyped-def]
            raise LedgerError("synthetic bootstrap fault")

        with patch.object(JobLedger, "append_a1_bundle", fail_after_schema):
            with self.assertRaises(LedgerError):
                shadow._init_ledger(self.args(), self.profile)
        self.assertFalse(self.database.exists())
        self.assertIsNotNone(original)

    def test_bootstrap_does_not_access_environment_credentials_or_transport(self) -> None:
        secret = "synthetic-never-read"
        output = io.StringIO()
        with patch.dict(
            os.environ,
            {
                "DEEPSEEK_API_KEY": secret,
                "ZHIPU_API_KEY": secret,
                "OPENAI_API_KEY": secret,
            },
            clear=True,
        ):
            with patch.object(
                shadow, "_http_post", side_effect=AssertionError("network forbidden")
            ):
                with redirect_stdout(output):
                    self.assertEqual(
                        shadow._init_ledger(self.args(), self.profile), 0
                    )
        self.assertNotIn(secret, output.getvalue())
        self.assertFalse(json.loads(output.getvalue())["credential_access"])


if __name__ == "__main__":
    unittest.main()
