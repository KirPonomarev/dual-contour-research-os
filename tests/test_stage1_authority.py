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
            "s1-market-clean-checkout-fixtures.json": "owner-local-synthetic-clean-checkout-fixtures-no-new-dependency",
            "s1-market-lineage-portability.json": "owner-local-manifest-derived-recursive-lineage-no-new-dependency",
            "s1-market-sanitized-count-fixture.json": "owner-private-sanitized-count-sufficient-statistics-no-public-payload",
            "s1-authority-policy-boundary.json": "owned-stdlib-pinned-authority-policy-fail-closed",
            "s1-budget-profile.json": "owned-stdlib-exact-fixed-charge-budget-profile-single-ledger-ready",
            "s1-budget-attempt-lifecycle.json": "owned-stdlib-single-ledger-embedded-budget-receipts-fixed-charge",
            "s1-final-checkpoint-reopen-recovery.json": "owned-stdlib-verified-final-checkpoint-same-attempt-replay-single-ledger",
            "s1-pause-epoch-fencing.json": "owned-stdlib-canonical-ledger-sequence-fence",
            "s1-market-ci-reality-loop-prerequisite.json": "existing-real-cli-synthetic-prerequisite-hard-gate-no-runtime-change",
            "s1-market-storage-accounting-portability.json": "owner-local-stdlib-conservative-byte-accounting-no-public-copy",
            "s1-permit-nonce-ledger.json": "owned-stdlib-canonical-ledger-permit-nonce-digest-unique-index",
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

    def test_budget_profile_authority_is_exact_and_ledger_excluding(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-budget-profile-authority" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-budget-profile-authority" / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-budget-profile.json")

        self.assertEqual(envelope["write_set"], lease["write_set"])
        worker = envelope["authorized_worker_stage"]
        self.assertEqual(
            worker["source_write_set"],
            ["src/research_bridge/admission.py", "src/research_bridge/l0.py"],
        )
        self.assertEqual(len(worker["test_write_set"]), 4)
        self.assertIn("ledger", worker["next_gate_exclusions"])
        profile = envelope["runtime_profile"]
        self.assertEqual(
            set(profile["permit_quotas_exact"]),
            {
                "accounting_policy_ref",
                "budget_scope_ref",
                "claims",
                "provider",
                "scope_limit",
                "trial_ref",
            },
        )
        self.assertEqual(profile["job_resource_limits_exact"], {"cost_units": "R"})
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        public_text = "\n".join(
            (
                (REUSE_RECEIPTS / "s1-budget-profile.json").read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-budget-profile-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-budget-profile-authority"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_budget_attempt_lifecycle_authority_is_single_ledger_and_atomic(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle-authority"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle-authority"
            / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-budget-attempt-lifecycle.json")

        self.assertEqual(envelope["write_set"], lease["write_set"])
        worker = envelope["authorized_worker_stage"]
        self.assertEqual(
            worker["source_write_set"],
            [
                "src/research_bridge/kernel.py",
                "src/research_bridge/ledger.py",
                "src/research_bridge/execution.py",
            ],
        )
        self.assertEqual(len(worker["test_write_set"]), 8)
        ledger = envelope["ledger_contract"]
        self.assertEqual(ledger["database_user_version"], 1)
        self.assertEqual(ledger["new_tables"], 0)
        self.assertEqual(ledger["new_columns"], 0)
        self.assertEqual(len(ledger["new_unique_expression_indexes"]), 3)
        self.assertEqual(
            envelope["budget_contract"]["reservation_location"],
            "claim.payload.budget_reservation",
        )
        self.assertEqual(
            envelope["budget_contract"]["settlement_location"],
            "complete.payload.settlement_receipt",
        )
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        public_text = "\n".join(
            (
                (REUSE_RECEIPTS / "s1-budget-attempt-lifecycle.json").read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-budget-attempt-lifecycle-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-budget-attempt-lifecycle-authority"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_budget_attempt_lifecycle_worker_lease_is_exact(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-budget-attempt-lifecycle" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-budget-attempt-lifecycle" / "ownership-lease.json"
        )

        self.assertEqual(
            envelope["public_authority_sha"],
            "641f18ab1f0d9f6ef385ccd286220e0007dcde69",
        )
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(len(envelope["write_set"]), 11)
        self.assertEqual(
            envelope["write_set"][:3],
            [
                "src/research_bridge/kernel.py",
                "src/research_bridge/ledger.py",
                "src/research_bridge/execution.py",
            ],
        )
        self.assertFalse(envelope["push_authority"])
        self.assertFalse(lease["delegation_allowed"])
        self.assertIn(
            "second-table-second-ledger-new-event-type-new-column-table-rebuild-or-nonempty-legacy-migration",
            envelope["forbidden_scope"],
        )

    def test_final_checkpoint_reopen_authority_is_narrow_and_reversible(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-final-checkpoint-reopen-recovery-authority"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-final-checkpoint-reopen-recovery-authority"
            / "ownership-lease.json"
        )
        reuse = load(
            REUSE_RECEIPTS / "s1-final-checkpoint-reopen-recovery.json"
        )

        self.assertEqual(envelope["write_set"], lease["write_set"])
        worker = envelope["authorized_worker_stage"]
        self.assertEqual(
            worker["source_write_set"],
            ["src/research_bridge/ledger.py", "src/research_bridge/execution.py"],
        )
        self.assertEqual(len(worker["test_write_set"]), 5)
        replay = envelope["replay_contract"]
        self.assertEqual(
            replay["scope"], "same-job-same-attempt-single-final-checkpoint-only"
        )
        self.assertEqual(len(replay["checkpoint_exact_bindings"]), 8)
        self.assertEqual(len(replay["complete_exact_bindings"]), 6)
        self.assertIn("persisted-checkpoint-event_at", replay["checkpoint_time_rule"])
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        self.assertIn(
            "no-byte-for-byte-ExecutionReceipt-terminal-lookup-claim-in-this-stage",
            envelope["preservation_contract"],
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_budget_attempt_lifecycle_semantic_amendment_is_exact_and_non_expansive(self) -> None:
        original = load(
            ROOT / "stages" / "s1-budget-attempt-lifecycle" / "stage-envelope.json"
        )
        amendment = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle"
            / "stage-envelope-amendment-1.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle"
            / "ownership-lease-amendment-1.json"
        )

        self.assertEqual(amendment["amends_stage_id"], original["stage_id"])
        self.assertEqual(amendment["write_set_expansion"], [])
        self.assertEqual(lease["write_set"], original["write_set"])
        self.assertEqual(
            amendment["semantic_freeze"]["ledger_versions"],
            {
                "reservation_ledger_version_before": "global-event-chain-head-sequence-before-claim-append-or-zero-at-genesis",
                "settlement_ledger_version_after": "sequence-assigned-to-the-same-atomic-complete-event",
                "database_user_version": "SQLite-schema-version-only-and-equals-one",
            },
        )
        self.assertEqual(
            len(amendment["semantic_freeze"]["replay"]["exact_caller_projection"]),
            17,
        )
        self.assertEqual(
            len(
                amendment["semantic_freeze"]["provider_accounting_attestation"][
                    "exact_keys"
                ]
            ),
            11,
        )
        self.assertTrue(
            amendment["semantic_freeze"]["provider_accounting_attestation"][
                "provider_unknown"
            ]
        )
        self.assertEqual(
            amendment["semantic_freeze"]["provider_accounting_attestation"][
                "released_amount"
            ],
            0,
        )
        self.assertIn(
            "cumulative-lifetime-scope-cap",
            amendment["semantic_freeze"]["capacity_semantics"],
        )
        self.assertFalse(amendment["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_budget_attempt_lifecycle_validation_amendment_is_exact_and_fail_closed(self) -> None:
        original = load(
            ROOT / "stages" / "s1-budget-attempt-lifecycle" / "stage-envelope.json"
        )
        amendment = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle"
            / "stage-envelope-amendment-2.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle"
            / "ownership-lease-amendment-2.json"
        )

        added = [
            "src/research_bridge/validation.py",
            "tests/test_stage1_validation.py",
            "tests/test_stage1_validation_assurance.py",
            "tests/test_stage1_reference_vertical.py",
        ]
        self.assertEqual(amendment["amends_stage_id"], original["stage_id"])
        self.assertEqual(amendment["added_write_set"], added)
        self.assertEqual(lease["write_set"], original["write_set"] + added)
        self.assertEqual(len(lease["write_set"]), 15)
        self.assertEqual(
            amendment["compatibility_contract"]["execution_parent_order"],
            [
                "CheckpointManifest.object_id",
                "ExecutionReceipt.payload.artifact_refs-in-order",
                "SettlementReceipt.object_id",
                "ledger:ExecutionReceipt.payload.event_chain_head",
            ],
        )
        self.assertEqual(
            amendment["compatibility_contract"]["validator_policy"],
            "require-exact-new-parent-chain-with-no-optional-legacy-or-reordered-form",
        )
        self.assertFalse(amendment["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_budget_attempt_lifecycle_replay_projection_correction_is_complete(self) -> None:
        amendment = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle"
            / "stage-envelope-amendment-3.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-budget-attempt-lifecycle"
            / "ownership-lease-amendment-3.json"
        )
        projection = amendment["semantic_correction"]["exact_caller_projection"]

        self.assertEqual(len(projection), 19)
        self.assertEqual(projection[-2:], ["contour", "classification"])
        self.assertEqual(len(projection), len(set(projection)))
        self.assertEqual(amendment["write_set_expansion"], [])
        self.assertEqual(len(lease["write_set"]), 15)
        assurance_limit = amendment["validator_assurance_limit"]
        self.assertIn(
            "syntactically-valid-settlement-object-id",
            assurance_limit["not_proven"],
        )
        self.assertIn(
            "versioned-contract-and-interface-change",
            assurance_limit["future_authority_required"],
        )
        self.assertFalse(amendment["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_budget_profile_worker_lease_is_exact_and_non_expansive(self) -> None:
        envelope = load(ROOT / "stages" / "s1-budget-profile" / "stage-envelope.json")
        lease = load(ROOT / "stages" / "s1-budget-profile" / "ownership-lease.json")

        self.assertEqual(
            envelope["public_authority_sha"],
            "4cc95d80d23e36ffdb20250f6203510299de8faf",
        )
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(len(envelope["write_set"]), 6)
        self.assertEqual(
            envelope["write_set"][:2],
            ["src/research_bridge/admission.py", "src/research_bridge/l0.py"],
        )
        self.assertFalse(envelope["push_authority"])
        self.assertFalse(lease["delegation_allowed"])
        self.assertIn(
            "BudgetReservation-SettlementReceipt-capacity-scan-reserve-settle-release-or-recovery-implementation",
            envelope["forbidden_scope"],
        )

    def test_budget_profile_worker_amendment_is_two_fixture_files_only(self) -> None:
        amendment = load(
            ROOT / "stages" / "s1-budget-profile" / "stage-envelope-amendment-1.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-budget-profile"
            / "ownership-lease-amendment-1.json"
        )
        original = load(ROOT / "stages" / "s1-budget-profile" / "stage-envelope.json")

        self.assertEqual(amendment["amends_stage_id"], original["stage_id"])
        self.assertEqual(
            amendment["added_write_set"],
            [
                "tests/test_stage1_execution_assurance.py",
                "tests/test_stage1_reference_vertical.py",
            ],
        )
        self.assertEqual(
            set(lease["write_set"]),
            set(original["write_set"]) | set(amendment["added_write_set"]),
        )
        self.assertEqual(len(lease["write_set"]), 8)
        self.assertTrue(all(path.startswith("tests/") for path in amendment["added_write_set"]))
        self.assertFalse(amendment["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_market_storage_accounting_authority_is_two_file_and_nonweakening(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-market-storage-accounting-authority"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-market-storage-accounting-authority"
            / "ownership-lease.json"
        )
        reuse = load(
            REUSE_RECEIPTS / "s1-market-storage-accounting-portability.json"
        )

        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(
            envelope["authorized_worker_stage"]["write_set"],
            ["src/market_lab/system_state.py", "tests/test_system_state.py"],
        )
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["derive-used-bytes-as-total-minus-available-free-bytes"],
            "selected",
        )
        self.assertEqual(
            dispositions["relax-snapshot-accounting-validation"],
            "rejected-validation-weakening",
        )
        public_text = "\n".join(
            (
                (REUSE_RECEIPTS / "s1-market-storage-accounting-portability.json").read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-storage-accounting-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-storage-accounting-authority"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("github.com/KirPonomarev/crypto-market-lab", public_text)
        self.assertIn(
            "snapshot-validator-relaxation-or-accounting-identity-removal",
            envelope["forbidden_scope"],
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_market_storage_accounting_worker_lease_is_exact(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-market-storage-accounting-portability"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-market-storage-accounting-portability"
            / "ownership-lease.json"
        )

        self.assertEqual(
            envelope["public_authority_sha"],
            "d61f409ceac186370e889e4265e18d42ed333c9c",
        )
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(
            envelope["write_set"],
            ["src/market_lab/system_state.py", "tests/test_system_state.py"],
        )
        self.assertFalse(lease["delegation_allowed"])
        self.assertFalse(envelope["push_authority"])
        self.assertIn("exact-head private remote CI", envelope["acceptance_commands"])

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

    def test_market_clean_checkout_authority_is_test_only_disjoint_and_nonweakening(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-market-clean-checkout-authority" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-market-clean-checkout-authority" / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-market-clean-checkout-fixtures.json")

        self.assertEqual(envelope["base_sha"], "0afc73836136df0e12cbb6ca3dbe9429ffdfd0df")
        self.assertEqual(
            envelope["candidate_market_base_sha"],
            "6299f65f92d8bc6964c423775a5cce1f2fdef58a",
        )
        self.assertEqual(envelope["write_set"], lease["write_set"])
        workers = envelope["authorized_worker_stages"]
        self.assertEqual([worker["agent_id"] for worker in workers], ["agent-3", "agent-5"])
        owned = [set(worker["write_set"]) for worker in workers]
        self.assertFalse(owned[0] & owned[1])
        self.assertTrue(all(path.startswith("tests/") for paths in owned for path in paths))
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["skip-xfail-marker-or-missing-fixture-early-return"],
            "rejected-validation-weakening",
        )
        public_text = "\n".join(
            (
                (REUSE_RECEIPTS / "s1-market-clean-checkout-fixtures.json").read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-clean-checkout-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-clean-checkout-authority"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("github.com/KirPonomarev/crypto-market-lab", public_text)
        self.assertIn(
            "existing-assertion-deletion-relaxation-or-value-change",
            envelope["forbidden_scope"],
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_market_lineage_portability_authority_is_recursive_and_nonbypassable(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-market-lineage-portability-authority"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-market-lineage-portability-authority"
            / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-market-lineage-portability.json")

        self.assertEqual(envelope["base_sha"], "635370ed2daba6073594289f0be29db61cbecf25")
        self.assertEqual(
            envelope["candidate_market_base_sha"],
            "6299f65f92d8bc6964c423775a5cce1f2fdef58a",
        )
        self.assertEqual(envelope["write_set"], lease["write_set"])
        worker = envelope["authorized_worker_stage"]
        self.assertEqual(worker["agent_id"], "agent-3")
        self.assertEqual(len(worker["source_write_set"]), 9)
        self.assertEqual(len(worker["test_write_set"]), 8)
        self.assertFalse(set(worker["source_write_set"]) & set(worker["test_write_set"]))
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["owned-manifest-derived-recursive-lineage-policy"],
            "selected",
        )
        self.assertEqual(
            dispositions["validator-callback-mock-or-prevalidated-result-injection"],
            "rejected-validation-bypass",
        )
        self.assertIn(
            "pinned-default-lineage-relaxation",
            envelope["forbidden_scope"],
        )
        public_text = "\n".join(
            (
                (REUSE_RECEIPTS / "s1-market-lineage-portability.json").read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-lineage-portability-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-lineage-portability-authority"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("github.com/KirPonomarev/crypto-market-lab", public_text)
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_market_count_fixture_authority_is_private_allowlisted_and_nonweakening(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-market-count-fixture-authority"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-market-count-fixture-authority"
            / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-market-sanitized-count-fixture.json")

        self.assertEqual(envelope["base_sha"], "0169161ce428fd6b77762766e7e508a208b8edd2")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        amendment = envelope["authorized_worker_amendment"]
        self.assertEqual(amendment["agent_id"], "agent-3")
        self.assertEqual(
            amendment["added_write_set"],
            ["tests/fixtures/ban_local_eventness_nonlinear_candidate_cluster_counts.json"],
        )
        self.assertEqual(len(amendment["allowed_fields"]), 12)
        self.assertNotIn("timestamp", amendment["allowed_fields"])
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["owner-sanctioned-count-only-private-test-fixture"],
            "selected",
        )
        self.assertEqual(
            dispositions["fixture-specific-expected-value-change"],
            "rejected-validation-weakening",
        )
        public_text = "\n".join(
            (
                (REUSE_RECEIPTS / "s1-market-sanitized-count-fixture.json").read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-count-fixture-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-count-fixture-authority"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("github.com/KirPonomarev/crypto-market-lab", public_text)
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_market_ci_reality_loop_authority_is_workflow_only_and_nonweakening(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-market-ci-reality-loop-authority"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-market-ci-reality-loop-authority"
            / "ownership-lease.json"
        )
        reuse = load(
            REUSE_RECEIPTS / "s1-market-ci-reality-loop-prerequisite.json"
        )

        self.assertEqual(
            envelope["base_sha"],
            "7829846c779b0c7abe3820077ca4173e6b7bc056",
        )
        self.assertEqual(
            envelope["candidate_market_base_sha"],
            "0d188866cbcd8ad86db049fd250d5490bedcc6d5",
        )
        self.assertEqual(envelope["write_set"], lease["write_set"])
        worker = envelope["authorized_worker_stage"]
        self.assertEqual(worker["agent_id"], "agent-5")
        self.assertEqual(worker["write_set"], [".github/workflows/ci.yml"])
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["existing-real-cli-temporary-prerequisite-conformance-test"],
            "selected",
        )
        self.assertEqual(
            dispositions["skip-continue-on-error-or-advisory-gate"],
            "rejected-validation-weakening",
        )
        public_text = "\n".join(
            (
                (
                    REUSE_RECEIPTS
                    / "s1-market-ci-reality-loop-prerequisite.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-ci-reality-loop-authority"
                    / "stage-envelope.json"
                ).read_text(),
                (
                    ROOT
                    / "stages"
                    / "s1-market-ci-reality-loop-authority"
                    / "ownership-lease.json"
                ).read_text(),
            )
        )
        self.assertNotIn("/Users/", public_text)
        self.assertNotIn("/Volumes/", public_text)
        self.assertNotIn("github.com/KirPonomarev/crypto-market-lab", public_text)
        self.assertIn(
            "skip-xfail-continue-on-error-shell-fallback-or-advisory-conversion",
            envelope["forbidden_scope"],
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_market_ci_reality_loop_worker_lease_is_exact(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-market-ci-reality-loop" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-market-ci-reality-loop" / "ownership-lease.json"
        )

        self.assertEqual(
            envelope["base_sha"],
            "0d188866cbcd8ad86db049fd250d5490bedcc6d5",
        )
        self.assertEqual(
            envelope["public_authority_sha"],
            "ce91ae309380869ed1d7eea59ddef3980273e162",
        )
        self.assertEqual(envelope["public_authority_ci"], "29573139853")
        self.assertEqual(envelope["write_set"], [".github/workflows/ci.yml"])
        self.assertEqual(lease["write_set"], envelope["write_set"])
        self.assertEqual(
            envelope["dependency_hashes"]["candidate_market_tree"],
            "776b5124e53a7dbc3b38fed0bef135fc035db74c",
        )
        self.assertIn(
            "skip-xfail-continue-on-error-shell-fallback-conditional-or-validation-bypass",
            envelope["forbidden_scope"],
        )
        self.assertFalse(envelope["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_auth_policy_authority_is_fail_closed_pinned_and_contract_preserving(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-auth-policy-authority" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-auth-policy-authority" / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-authority-policy-boundary.json")

        self.assertEqual(envelope["base_sha"], "90620ec0dabc547bd36829cf70784ba4d300b242")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        worker = envelope["authorized_worker_stage"]
        self.assertEqual(worker["agent_id"], "agent-1")
        self.assertEqual(
            worker["write_set"],
            [
                "src/research_bridge/authority.py",
                "src/research_bridge/admission.py",
                "src/research_bridge/kernel.py",
                "src/research_bridge/control.py",
                "tests/test_stage1_authority_policy.py",
            ],
        )
        self.assertFalse(any(path.startswith("contracts/") for path in worker["write_set"]))
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions["owned-stdlib-authority-policy-verifier"],
            "selected",
        )
        self.assertEqual(
            dispositions["self-hash-and-nonempty-issuer-only"],
            "rejected-forged-authority-accepted",
        )
        self.assertEqual(
            dispositions["boolean-callback-prevalidated-result-or-default-allow"],
            "rejected-validation-bypass",
        )
        self.assertIn(
            "second-kernel-ledger-policy-store-or-domain-registry-writer",
            envelope["forbidden_scope"],
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_auth_policy_worker_lease_is_exact_and_non_expansive(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-auth-policy-boundary" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-auth-policy-boundary" / "ownership-lease.json"
        )
        expected = [
            "src/research_bridge/authority.py",
            "src/research_bridge/admission.py",
            "src/research_bridge/kernel.py",
            "src/research_bridge/control.py",
            "tests/test_stage1_authority_policy.py",
        ]

        self.assertEqual(envelope["base_sha"], "2b756ccbbb9541b98594d5247c2f02c938e17bce")
        self.assertEqual(envelope["public_authority_sha"], envelope["base_sha"])
        self.assertEqual(envelope["write_set"], expected)
        self.assertEqual(lease["write_set"], expected)
        self.assertFalse(any(path.startswith("contracts/") for path in expected))
        self.assertEqual(envelope["dependency_hashes"]["external_dependencies"], "none")
        self.assertFalse(envelope["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_auth_policy_worker_amendment_is_test_fixture_only(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-auth-policy-boundary"
            / "stage-envelope-amendment-1.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-auth-policy-boundary"
            / "ownership-lease-amendment-1.json"
        )
        added = [
            "tests/test_stage1_admission.py",
            "tests/test_stage1_assurance.py",
            "tests/test_stage1_execution_assurance.py",
            "tests/test_stage1_reference_vertical.py",
            "tests/test_stage1_control.py",
            "tests/test_stage1_control_assurance.py",
        ]

        self.assertEqual(envelope["amends_stage_id"], "s1-auth-policy-boundary")
        self.assertEqual(envelope["public_authority_sha"], "75141fbe67ff007d671822143205fd20bf839786")
        self.assertEqual(envelope["added_write_set"], added)
        self.assertEqual(lease["write_set"][-len(added) :], added)
        self.assertTrue(all(path.startswith("tests/") for path in added))
        self.assertFalse(any(path.startswith("contracts/") for path in lease["write_set"]))
        self.assertFalse(lease["delegation_allowed"])

    def test_pause_epoch_fencing_authority_reuses_the_canonical_ledger(self) -> None:
        envelope = load(
            ROOT
            / "stages"
            / "s1-pause-epoch-fencing-authority"
            / "stage-envelope.json"
        )
        lease = load(
            ROOT
            / "stages"
            / "s1-pause-epoch-fencing-authority"
            / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-pause-epoch-fencing.json")
        worker = envelope["authorized_worker_stage"]

        self.assertEqual(envelope["base_sha"], "b263d387510cc74cb159144f1725957989938731")
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        self.assertEqual(
            worker["write_set"],
            [
                "src/research_bridge/ledger.py",
                "tests/test_stage1_pause_epoch_fencing.py",
            ],
        )
        self.assertNotIn("src/research_bridge/kernel.py", worker["write_set"])
        self.assertFalse(any(path.startswith("contracts/") for path in worker["write_set"]))
        self.assertIn(
            "new-event-type-table-trigger-index-second-ledger-or-destructive-database-change",
            envelope["forbidden_scope"],
        )
        self.assertFalse(lease["delegation_allowed"])

    def test_pause_epoch_fencing_worker_lease_is_exact(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-pause-epoch-fencing" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-pause-epoch-fencing" / "ownership-lease.json"
        )
        expected = [
            "src/research_bridge/ledger.py",
            "tests/test_stage1_pause_epoch_fencing.py",
        ]

        self.assertEqual(envelope["base_sha"], "715a87255b9d81ea30f303b07d0bda9a86eaafae")
        self.assertEqual(envelope["public_authority_sha"], envelope["base_sha"])
        self.assertEqual(envelope["write_set"], expected)
        self.assertEqual(lease["write_set"], expected)
        self.assertFalse(envelope["push_authority"])
        self.assertFalse(lease["delegation_allowed"])

    def test_permit_nonce_authority_is_one_ledger_hash_only_and_atomic(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-permit-nonce-authority" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-permit-nonce-authority" / "ownership-lease.json"
        )
        reuse = load(REUSE_RECEIPTS / "s1-permit-nonce-ledger.json")
        worker = envelope["authorized_worker_stage"]

        self.assertEqual(
            envelope["base_sha"],
            "edb23da71826a201cb47109dedf9739697ab67d6",
        )
        self.assertEqual(envelope["write_set"], lease["write_set"])
        self.assertEqual(reuse["integrity"]["payload_sha256"], payload_sha256(reuse))
        self.assertEqual(worker["agent_id"], "agent-1")
        self.assertEqual(len(worker["write_set"]), 11)
        self.assertFalse(any(path.startswith("contracts/") for path in worker["write_set"]))
        dispositions = {
            item["candidate"]: item["disposition"]
            for item in reuse["payload"]["candidates"]
        }
        self.assertEqual(
            dispositions[
                "sha256-nonce-digest-in-canonical-claim-plus-partial-unique-index"
            ],
            "selected",
        )
        self.assertEqual(
            dispositions["second-ledger-or-permit-use-table"],
            "rejected-dual-source-of-truth",
        )
        self.assertEqual(
            dispositions["silent-legacy-claim-backfill"],
            "rejected-source-nonce-unrecoverable",
        )
        self.assertIn(
            "new-table-column-ledger-event-type-second-ledger-or-checkpoint-store",
            envelope["forbidden_scope"],
        )
        self.assertIn(
            "raw-permit-nonce-persistence-log-or-receipt",
            envelope["forbidden_scope"],
        )
        self.assertTrue(envelope["rollback"])
        self.assertFalse(lease["delegation_allowed"])

    def test_permit_nonce_worker_lease_is_exact_and_contract_preserving(self) -> None:
        envelope = load(
            ROOT / "stages" / "s1-permit-nonce-ledger" / "stage-envelope.json"
        )
        lease = load(
            ROOT / "stages" / "s1-permit-nonce-ledger" / "ownership-lease.json"
        )
        expected = [
            "src/research_bridge/admission.py",
            "src/research_bridge/kernel.py",
            "src/research_bridge/ledger.py",
            "src/research_bridge/execution.py",
            "tests/test_stage1_admission.py",
            "tests/test_stage1_ledger.py",
            "tests/test_stage1_assurance.py",
            "tests/test_stage1_execution.py",
            "tests/test_stage1_execution_assurance.py",
            "tests/test_stage1_control_assurance.py",
            "tests/test_stage1_pause_epoch_fencing.py",
        ]

        self.assertEqual(
            envelope["base_sha"],
            "ce6eb2265a0a51422c296e6bdea2888c1ccdfdee",
        )
        self.assertEqual(envelope["public_authority_sha"], envelope["base_sha"])
        self.assertEqual(envelope["public_authority_ci"], "29574243984")
        self.assertEqual(envelope["write_set"], expected)
        self.assertEqual(lease["write_set"], expected)
        self.assertFalse(any(path.startswith("contracts/") for path in expected))
        self.assertEqual(envelope["dependency_hashes"]["external_dependencies"], "none")
        self.assertIn(
            "new-table-column-event-type-second-ledger-or-checkpoint-store",
            envelope["forbidden_scope"],
        )
        self.assertFalse(envelope["push_authority"])
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
