import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_RECEIPTS = ROOT / "docs" / "receipts" / "source-freeze"
REUSE_RECEIPTS = ROOT / "docs" / "receipts" / "reuse"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def payload_sha256(receipt: dict) -> str:
    encoded = json.dumps(receipt["payload"], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class Stage1AuthorityTests(unittest.TestCase):
    def test_source_freezes_are_schema_shaped_and_integrity_bound(self) -> None:
        schema = load(ROOT / "contracts" / "v1" / "SourceFreezeReceipt.schema.json")
        allowed = set(schema["properties"])
        payload_allowed = set(schema["properties"]["payload"]["properties"])
        for path in sorted(SOURCE_RECEIPTS.glob("s0b-*.json")):
            receipt = load(path)
            self.assertEqual(set(receipt), allowed, path.name)
            self.assertEqual(set(receipt["payload"]), payload_allowed, path.name)
            self.assertEqual(receipt["schema_id"], "SourceFreezeReceipt")
            self.assertEqual(receipt["schema_version"], "1.0.0")
            self.assertEqual(receipt["payload"]["selected_source_sha"], receipt["payload"]["head_sha"])
            self.assertEqual(receipt["integrity"]["payload_sha256"], payload_sha256(receipt))

    def test_freezes_publish_only_sanitized_aggregates(self) -> None:
        for path in sorted(SOURCE_RECEIPTS.glob("s0b-*.json")):
            text = path.read_text()
            self.assertNotIn("/Users/", text)
            self.assertNotIn("/Volumes/", text)
            for disposition in load(path)["payload"]["path_dispositions"]:
                self.assertEqual(set(disposition), {"category", "count", "disposition"})
                self.assertNotEqual(disposition["disposition"], "selected-for-import")

    def test_reuse_decisions_select_no_external_or_domain_source_bytes(self) -> None:
        expected_modes = {
            "s1-admission-kernel.json": "contract-first-clean-room-minimal-glue",
            "s1-control-ipc-pause.json": "internal-adapter-plus-stdlib-minimal-glue",
            "s1-ledger-durability.json": "clean-room-stdlib-adapter-single-ledger",
            "s1-trusted-storage.json": "clean-room-stdlib-owned-cas-ingestor",
            "s1-offline-execution.json": "clean-room-stdlib-inprocess-frozen-l0-and-researchd-finalizer",
            "s1-validation-boundary.json": "clean-room-stdlib-pure-receipt-verifier",
        }
        schema = load(ROOT / "contracts" / "v1" / "ReuseDecisionReceipt.schema.json")
        allowed = set(schema["properties"])
        payload_allowed = set(schema["properties"]["payload"]["properties"])
        for name, mode in expected_modes.items():
            receipt = load(REUSE_RECEIPTS / name)
            self.assertEqual(set(receipt), allowed)
            self.assertEqual(set(receipt["payload"]), payload_allowed)
            self.assertEqual(receipt["schema_id"], "ReuseDecisionReceipt")
            self.assertEqual(receipt["payload"]["selected_mode"], mode)
            self.assertEqual(receipt["payload"]["code_sha256"], EMPTY_SHA256)
            self.assertEqual(receipt["payload"]["license_spdx"], "NOASSERTION")
            self.assertEqual(receipt["integrity"]["payload_sha256"], payload_sha256(receipt))
            selected = [item["candidate"] for item in receipt["payload"]["candidates"] if item["disposition"] == "selected"]
            self.assertNotIn("jsonschema-4.26.0", selected)
            self.assertNotIn("market-runtime-source", selected)

    def test_authority_stage_is_exact_and_reversible(self) -> None:
        envelope = load(ROOT / "stages" / "s1-authority-freeze" / "stage-envelope.json")
        lease = load(ROOT / "stages" / "s1-authority-freeze" / "ownership-lease.json")
        self.assertEqual(envelope["base_sha"], "9f90e989611071290fa1d3ce2ed9937b2aa40972")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertTrue(envelope["executable_blocker"])
        self.assertTrue(envelope["acceptance_commands"])
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_control_authority_is_pinned_and_reversible(self) -> None:
        envelope = load(ROOT / "stages" / "s1-control-authority" / "stage-envelope.json")
        lease = load(ROOT / "stages" / "s1-control-authority" / "ownership-lease.json")
        self.assertEqual(envelope["base_sha"], "57f1ba40b9964b0be147151b72d1a3821493b916")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertIn("public-http", envelope["forbidden_scope"])
        self.assertEqual(envelope["dependency_hashes"]["external_dependencies"], "none")
        self.assertTrue(envelope["executable_blocker"])
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_storage_authority_is_pinned_and_excludes_payload_and_runner_authority(self) -> None:
        envelope = load(ROOT / "stages" / "s1-storage-authority" / "stage-envelope.json")
        lease = load(ROOT / "stages" / "s1-storage-authority" / "ownership-lease.json")
        receipt = load(REUSE_RECEIPTS / "s1-trusted-storage.json")
        self.assertEqual(envelope["base_sha"], "2343613cfe4c4a2fe5bd19d4caca43eeb3e40d22")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertIn("d2-or-d3-payload-storage", envelope["forbidden_scope"])
        self.assertIn("runner-or-container-execution", envelope["forbidden_scope"])
        self.assertEqual(envelope["dependency_hashes"]["external_dependencies"], "none")
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in receipt["payload"]["candidates"]
        }
        self.assertEqual(dispositions["stdlib-os-hashlib-json-pathlib"], "selected")
        self.assertEqual(
            dispositions["market-runtime-source"],
            "rejected-no-license-no-code-copy",
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_execution_authority_is_pinned_offline_and_receipt_last(self) -> None:
        envelope = load(ROOT / "stages" / "s1-execution-authority" / "stage-envelope.json")
        lease = load(ROOT / "stages" / "s1-execution-authority" / "ownership-lease.json")
        receipt = load(REUSE_RECEIPTS / "s1-offline-execution.json")
        self.assertEqual(envelope["base_sha"], "abf1595e33d8b04a08ae11412da9f120bd19d24e")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertIn("subprocess-socket-network-or-dynamic-code", envelope["forbidden_scope"])
        self.assertIn("d2-or-d3-payload-storage", envelope["forbidden_scope"])
        self.assertIn("checkpoint-or-receipt-before-prerequisite-durability", envelope["stop_conditions"])
        self.assertEqual(envelope["dependency_hashes"]["external_dependencies"], "none")
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in receipt["payload"]["candidates"]
        }
        self.assertEqual(dispositions["stdlib-hashlib-json-os-pathlib"], "selected")
        self.assertEqual(
            dispositions["subprocess-or-container-runner"],
            "parked-until-isolation-proof",
        )
        self.assertEqual(
            dispositions["market-runtime-source"],
            "rejected-no-license-no-code-copy",
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_validation_authority_is_read_only_domain_neutral_and_reversible(self) -> None:
        envelope = load(ROOT / "stages" / "s1-validation-authority" / "stage-envelope.json")
        lease = load(ROOT / "stages" / "s1-validation-authority" / "ownership-lease.json")
        receipt = load(REUSE_RECEIPTS / "s1-validation-boundary.json")
        self.assertEqual(envelope["base_sha"], "50b04b330fca620814e964a308dfbefb3ba6cd7e")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertIn("validator-implementation-or-execution", envelope["forbidden_scope"])
        self.assertIn("domain-registry-writer-call-or-mutation", envelope["forbidden_scope"])
        self.assertIn("d2-or-d3-payload-acceptance-or-storage", envelope["forbidden_scope"])
        self.assertEqual(envelope["dependency_hashes"]["external_dependencies"], "none")
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in receipt["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["stdlib-hashlib-hmac-json-datetime"],
            "selected",
        )
        self.assertEqual(
            dispositions["domain-validator-or-registry-writer-import"],
            "rejected-domain-owned-and-side-effecting",
        )
        self.assertEqual(
            dispositions["market-runtime-source"],
            "rejected-no-license-no-code-copy",
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])


if __name__ == "__main__":
    unittest.main()
