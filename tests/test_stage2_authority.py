import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_RECEIPTS = ROOT / "docs" / "receipts" / "source-freeze"
REUSE_RECEIPTS = ROOT / "docs" / "receipts" / "reuse"
STAGES = ROOT / "stages"
INTEGRATION_RECEIPTS = ROOT / "docs" / "receipts" / "integration"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def payload_sha256(receipt: dict) -> str:
    encoded = json.dumps(
        receipt["payload"], sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


class Stage2AuthorityTests(unittest.TestCase):
    def test_market_dataset_source_freeze_and_reuse_are_integrity_bound(self) -> None:
        source = load(
            SOURCE_RECEIPTS / "s2-market-public-dataset-temporal-integrity.json"
        )
        reuse = load(REUSE_RECEIPTS / "s2-market-public-dataset-temporal-integrity.json")

        self.assertEqual(source["schema_id"], "SourceFreezeReceipt")
        self.assertEqual(reuse["schema_id"], "ReuseDecisionReceipt")
        self.assertEqual(source["integrity"]["payload_sha256"], payload_sha256(source))
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        self.assertEqual(
            source["payload"]["selected_source_sha"],
            "96da40a62ef021a6bc5fbe4820e388ee961899a7",
        )
        self.assertEqual(
            reuse["payload"]["selected_mode"],
            "owner-local-existing-public-ohlcv-and-temporal-integrity-adapters-minimal-glue-no-public-payload",
        )
        self.assertEqual(reuse["payload"]["code_sha256"], EMPTY_SHA256)
        self.assertEqual(reuse["payload"]["license_spdx"], "NOASSERTION")

    def test_market_dataset_authority_is_narrow_and_non_expansive(self) -> None:
        envelope = load(
            STAGES
            / "s2-market-public-dataset-temporal-integrity-authority"
            / "stage-envelope.json"
        )
        lease = load(
            STAGES
            / "s2-market-public-dataset-temporal-integrity-authority"
            / "ownership-lease.json"
        )

        self.assertEqual(envelope["base_sha"], "9d7f4e1637ecc7000a235d1b33c8afb0edfb8ff9")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(envelope["risk_class"], "cross-repository-market-pre-soak-dataset-integrity-slice")
        self.assertFalse(lease["delegation_allowed"])
        self.assertFalse(envelope["dataset_contract"]["declares_market_pre_soak_green"])
        self.assertEqual(envelope["dataset_contract"]["stage_exit_authorized"], "slice-only")
        self.assertIn("closed-candle-only", envelope["dataset_contract"]["temporal_invariants"])

        worker = envelope["authorized_worker_stage"]
        self.assertEqual(worker["agent_id"], "agent-3")
        self.assertEqual(worker["private_base_sha"], "96da40a62ef021a6bc5fbe4820e388ee961899a7")
        self.assertEqual(
            worker["write_set"],
            [
                "data/bridge_pre_soak/public_ohlcv/binance_spot_btcusdt_1h_2024-01-01_2024-01-02.csv",
                "data/bridge_pre_soak/public_ohlcv/binance_spot_btcusdt_1h_2024-01-01_2024-01-02.manifest.json",
                "src/market_lab/bridge_pre_soak_dataset.py",
                "tests/test_bridge_pre_soak_dataset.py",
            ],
        )
        self.assertFalse(worker["push_authority"])

    def test_market_dataset_authority_publishes_no_payload_or_live_authority(self) -> None:
        public_text = "\n".join(
            [
                (
                    SOURCE_RECEIPTS
                    / "s2-market-public-dataset-temporal-integrity.json"
                ).read_text(),
                (
                    REUSE_RECEIPTS
                    / "s2-market-public-dataset-temporal-integrity.json"
                ).read_text(),
                (
                    STAGES
                    / "s2-market-public-dataset-temporal-integrity-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    STAGES
                    / "s2-market-public-dataset-temporal-integrity-authority"
                    / "ownership-lease.json"
                ).read_text(),
            ]
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("api_key", public_text.lower())
        self.assertNotIn("secret_key", public_text.lower())
        self.assertNotIn("access_token", public_text.lower())
        self.assertIn("network-capture-inside-validator-tests-or-Bridge-runtime", public_text)
        self.assertIn("exchange-order-key-account-secret-D2-D3-payload-live-trading-paper-trading-publication-deployment-or-UI-authority", public_text)

    def test_market_dataset_worker_lease_is_exact_and_receipt_bound(self) -> None:
        receipt = load(
            INTEGRATION_RECEIPTS
            / "s2-market-public-dataset-temporal-integrity-authority.json"
        )
        envelope = load(
            STAGES / "s2-market-public-dataset-temporal-integrity" / "stage-envelope.json"
        )
        lease = load(
            STAGES / "s2-market-public-dataset-temporal-integrity" / "ownership-lease.json"
        )

        self.assertEqual(receipt["schema_id"], "IntegrationReceipt")
        self.assertEqual(receipt["integrity"]["payload_sha256"], payload_sha256(receipt))
        self.assertEqual(receipt["payload"]["head_sha"], "999c033849a9e86887c4d348b1aec635b92ff22c")
        self.assertFalse(receipt["payload"]["audit_results"]["declares_market_pre_soak_green"])
        self.assertFalse(receipt["payload"]["audit_results"]["public_dataset_payload_in_public_repo"])

        self.assertEqual(envelope["public_authority_sha"], receipt["payload"]["head_sha"])
        self.assertEqual(envelope["public_authority_ci"], "29605160866")
        self.assertEqual(envelope["dependency_hashes"]["authority_receipt"], receipt["integrity"]["payload_sha256"])
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertFalse(lease["delegation_allowed"])
        self.assertFalse(envelope["push_authority"])
        self.assertIn(
            "validation-receipt-proposes-a-scientific-domain-outcome-or-writes-a-registry",
            envelope["stop_conditions"],
        )


if __name__ == "__main__":
    unittest.main()
