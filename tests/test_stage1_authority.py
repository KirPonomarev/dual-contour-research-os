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
            "s1-market-base-repair.json": "pinned-private-domain-ci-repair-no-public-code-copy",
            "s1-market-base-symlink-fix.json": "owner-local-minimal-fail-closed-glue-no-public-copy",
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

    def test_market_base_authority_refresh_is_sanitized_pinned_and_reversible(self) -> None:
        envelope = load(ROOT / "stages" / "s1-market-base-authority" / "stage-envelope.json")
        lease = load(ROOT / "stages" / "s1-market-base-authority" / "ownership-lease.json")
        source = load(SOURCE_RECEIPTS / "s1-market-base-repair.json")
        reuse = load(REUSE_RECEIPTS / "s1-market-base-repair.json")

        self.assertEqual(envelope["base_sha"], "653bee1ade357efa045610ef60f649ba6fa0537f")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(source["payload"]["head_sha"], source["payload"]["upstream_sha"])
        self.assertEqual(source["payload"]["head_sha"], source["payload"]["selected_source_sha"])
        self.assertEqual(sum(item["count"] for item in source["payload"]["path_dispositions"]), 31)
        self.assertTrue(
            all(item["disposition"] == "parked-not-selected" for item in source["payload"]["path_dispositions"])
        )
        self.assertEqual(source["integrity"]["payload_sha256"], payload_sha256(source))
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        self.assertEqual(reuse["payload"]["code_sha256"], EMPTY_SHA256)
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["market-runtime-source"],
            "rejected-public-copy-no-license",
        )
        self.assertEqual(
            dispositions["validation-bypass-or-continue-on-error"],
            "rejected-validation-weakening",
        )
        public_text = "\n".join(
            (
                (SOURCE_RECEIPTS / "s1-market-base-repair.json").read_text(),
                (REUSE_RECEIPTS / "s1-market-base-repair.json").read_text(),
                (ROOT / "stages" / "s1-market-base-authority" / "stage-envelope.json").read_text(),
                (ROOT / "stages" / "s1-market-base-authority" / "ownership-lease.json").read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("github.com/KirPonomarev/crypto-market-lab", public_text)
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_market_base_symlink_fix_authority_is_narrow_fail_closed_and_sanitized(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-market-base-repair-authority-amendment"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-market-base-repair-authority-amendment"
            / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-market-base-symlink-fix.json")

        self.assertEqual(envelope["base_sha"], "9ec7ece410bb5de64c912af2b8b4052b33b11fa4")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(
            envelope["authorized_worker_stage"]["write_set"],
            [
                "src/market_lab/unified_product_access.py",
                "tests/test_unified_product_access.py",
                "tests/test_paper_reality_loop_cli.py",
            ],
        )
        self.assertEqual(
            envelope["authorized_worker_stage"]["integrator_write_set"],
            [".github/workflows/ci.yml"],
        )
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        self.assertEqual(reuse["payload"]["code_sha256"], EMPTY_SHA256)
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["market-owned-unified-product-access-boundary"],
            "selected",
        )
        self.assertEqual(
            dispositions["validation-bypass-or-symlink-resolution-before-check"],
            "rejected-fail-open",
        )
        public_text = "\n".join(
            (
                (REUSE_RECEIPTS / "s1-market-base-symlink-fix.json").read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-base-repair-authority-amendment"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-base-repair-authority-amendment"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("github.com/KirPonomarev/crypto-market-lab", public_text)
        self.assertIn(
            "runtime-edit-outside-the-authorized-owner-boundary",
            envelope["forbidden_scope"],
        )
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
