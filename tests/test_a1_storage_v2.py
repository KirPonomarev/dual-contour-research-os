import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import research_bridge.ledger as ledger_module
from research_bridge.ledger import A1BundleRecord, JobLedger, LedgerError


AT = "2026-01-02T03:04:05Z"
PROJECTION_NAMES = ("admissions", "candidates", "capabilities", "material_events")


def a1_document(
    kind: str,
    suffix: str,
    *,
    classification: str = "D0",
    value: str = "synthetic-public-fixture",
) -> dict[str, object]:
    payload = {"fixture": value, "shadow_status": "SHADOW_UNAPPLIED"}
    digest = hashlib.sha256(
        ledger_module._canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return {
        "schema_id": kind,
        "schema_version": "1.0.0",
        "object_id": f"{kind.lower()}:{suffix}",
        "issued_at": AT,
        "issuer": {"id": "synthetic-test-writer", "authority_class": "test-only"},
        "contour": "governance" if kind == "CapabilityProofReceipt" else "bridge",
        "classification": classification,
        "payload": payload,
        "integrity": {
            "profile_id": "core-json-sha256-v1",
            "payload_sha256": digest,
            "parent_refs": ["fixture:public-synthetic"],
        },
    }


def projection_states(marker: str) -> dict[str, dict[str, object]]:
    return {
        name: {"count": 1, "marker": marker, "shadow_only": True}
        for name in PROJECTION_NAMES
    }


def create_exact_v1(database: Path, *, with_event: bool) -> None:
    with closing(sqlite3.connect(database)) as connection, connection:
        for _object_type, _name, statement in ledger_module._SCHEMA_V1_OBJECTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version = 1")
        if with_event:
            payload = {
                "actor": "uid:1000",
                "authority_ref": "authority:synthetic-offline",
                "event_at": AT,
                "idempotency_key": "legacy-pause-a",
                "reason": "synthetic migration fixture",
            }
            material = JobLedger._hash_material(
                sequence=1,
                event_type="pause",
                job_id="bridge-global-control",
                attempt_id="legacy-pause-a",
                fencing_epoch=0,
                event_at=AT,
                payload=payload,
                previous_sha256="0" * 64,
            )
            connection.execute(
                "INSERT INTO bridge_job_ledger VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    1,
                    "pause",
                    "bridge-global-control",
                    "legacy-pause-a",
                    0,
                    None,
                    AT,
                    ledger_module._canonical_json(payload),
                    "0" * 64,
                    hashlib.sha256(material).hexdigest(),
                ),
            )


def schema_identity(database: Path) -> tuple[int, tuple[tuple[object, ...], ...]]:
    with closing(sqlite3.connect(database)) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        objects = tuple(
            connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        )
    return version, objects


class A1StorageV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_fresh_and_nonempty_migrated_databases_have_exact_same_v2_schema(self) -> None:
        fresh_path = self.root / "fresh.sqlite3"
        migrated_path = self.root / "migrated.sqlite3"
        fresh = JobLedger(fresh_path)
        create_exact_v1(migrated_path, with_event=True)
        migrated = JobLedger(migrated_path)
        try:
            self.assertEqual(schema_identity(fresh_path), schema_identity(migrated_path))
            self.assertEqual(
                fresh.storage_coverage_manifest()["schema_version"], 2
            )
            self.assertEqual(migrated.event_count(), 1)
            self.assertTrue(migrated.verify_chain())
            self.assertTrue(migrated.verify_a1_coverage())
        finally:
            fresh.close()
            migrated.close()

        reopened = JobLedger(migrated_path)
        try:
            self.assertEqual(reopened.event_count(), 1)
            self.assertEqual(
                reopened.storage_coverage_manifest()["schema_version"], 2
            )
            self.assertTrue(reopened.verify_chain())
        finally:
            reopened.close()

    def test_fault_during_migration_rolls_back_schema_and_event(self) -> None:
        database = self.root / "migration-fault.sqlite3"
        create_exact_v1(database, with_event=True)
        before = schema_identity(database)

        class FaultingLedger(JobLedger):
            def _create_schema_objects(self, objects):  # type: ignore[no-untyped-def]
                for _object_type, name, statement in objects:
                    self._connection.execute(statement)
                    if name == "bridge_a1_objects":
                        raise sqlite3.OperationalError("synthetic migration fault")

        with self.assertRaisesRegex(LedgerError, "synthetic migration fault"):
            FaultingLedger(database)
        self.assertEqual(schema_identity(database), before)
        with closing(sqlite3.connect(database)) as connection:
            row = connection.execute(
                "SELECT event_type, event_sha256 FROM bridge_job_ledger"
            ).fetchone()
        self.assertEqual(row, ("pause", hashlib.sha256(JobLedger._hash_material(
            sequence=1,
            event_type="pause",
            job_id="bridge-global-control",
            attempt_id="legacy-pause-a",
            fencing_epoch=0,
            event_at=AT,
            payload={
                "actor": "uid:1000",
                "authority_ref": "authority:synthetic-offline",
                "event_at": AT,
                "idempotency_key": "legacy-pause-a",
                "reason": "synthetic migration fixture",
            },
            previous_sha256="0" * 64,
        )).hexdigest()))

        recovered = JobLedger(database)
        try:
            self.assertEqual(recovered.event_count(), 1)
            self.assertTrue(recovered.verify_chain())
        finally:
            recovered.close()

    def test_bundle_is_atomic_replay_safe_and_projection_complete(self) -> None:
        database = self.root / "bundle.sqlite3"
        ledger = JobLedger(database)
        documents = [
            a1_document("MaterialEvent", "one"),
            a1_document("CandidateSpecDraft", "one"),
            a1_document("AdmissionReceipt", "one"),
            a1_document("CapabilityProofReceipt", "one"),
        ]
        projections = projection_states("one")
        try:
            first = ledger.append_a1_bundle(
                objects=documents,
                projections=projections,
                idempotency_key="bundle-one",
                event_at=AT,
            )
            replay = ledger.append_a1_bundle(
                objects=documents,
                projections=projections,
                idempotency_key="bundle-one",
                event_at=AT,
            )
            self.assertIsInstance(first, A1BundleRecord)
            self.assertEqual(replay.event.event_sha256, first.event.event_sha256)
            self.assertEqual(ledger.event_count(), 1)
            self.assertEqual(ledger.event_count("a1_bundle"), 1)
            self.assertEqual(set(ledger.projection_coverage()), set(PROJECTION_NAMES))
            self.assertTrue(ledger.verify_a1_coverage())
            self.assertEqual(
                ledger.read_a1_object("materialevent:one")["payload"]["fixture"],
                "synthetic-public-fixture",
            )

            conflicting = a1_document(
                "MaterialEvent", "one", value="different-synthetic-value"
            )
            with self.assertRaisesRegex(LedgerError, "idempotency key was reused"):
                ledger.append_a1_bundle(
                    objects=[conflicting],
                    projections=projections,
                    idempotency_key="bundle-one",
                    event_at=AT,
                )
            self.assertEqual(ledger.event_count(), 1)
        finally:
            ledger.close()

    def test_failed_bundle_insert_leaves_no_event_object_or_projection_advance(self) -> None:
        database = self.root / "bundle-rollback.sqlite3"
        ledger = JobLedger(database)
        first = a1_document("MaterialEvent", "duplicate")
        try:
            committed = ledger.append_a1_bundle(
                objects=[first],
                projections=projection_states("first"),
                idempotency_key="bundle-first",
                event_at=AT,
            )
            before_projection = ledger.projection_coverage()
            with self.assertRaisesRegex(LedgerError, "UNIQUE constraint failed"):
                ledger.append_a1_bundle(
                    objects=[first],
                    projections=projection_states("must-rollback"),
                    idempotency_key="bundle-second",
                    event_at=AT,
                )
            self.assertEqual(ledger.event_count(), 1)
            self.assertEqual(ledger.event_count("a1_bundle"), 1)
            self.assertEqual(ledger.projection_coverage(), before_projection)
            self.assertEqual(
                ledger.storage_coverage_manifest()["a1_bundle_sequence_last"],
                committed.event.sequence,
            )
            self.assertTrue(ledger.verify_chain())
            self.assertTrue(ledger.verify_a1_coverage())
        finally:
            ledger.close()

    def test_a1_bundle_shares_the_existing_global_sequence(self) -> None:
        database = self.root / "global-order.sqlite3"
        ledger = JobLedger(database)
        try:
            claim = ledger.claim(
                job_id="job-global-order",
                attempt_id="attempt-global-order",
                permit_id="permit-global-order",
                permit_nonce_sha256=hashlib.sha256(b"nonce-global-order").hexdigest(),
                runner_identity="offline-runner",
                fencing_epoch=1,
                fencing_token="fence-global-order",
                admitted_at=AT,
                admission_digest=hashlib.sha256(b"admission-global-order").hexdigest(),
                accounting_policy_ref=f"budget-policy:sha256:{'a' * 64}",
                budget_scope_ref=f"budget-scope:sha256:{'b' * 64}",
                scope_limit_cost_units=10,
                trial_ref="trial:synthetic-global-order",
                provider="offline-runner",
                job_idempotency_key="job-global-order",
                reservation_cost_units=1,
                reservation_expires_at="2026-01-02T04:04:05Z",
                contour="bridge",
                classification="D0_PUBLIC",
            )
            bundle = ledger.append_a1_bundle(
                objects=[a1_document("MaterialEvent", "global-order")],
                projections=projection_states("global-order"),
                idempotency_key="bundle-global-order",
                event_at=AT,
            )
            checkpoint = ledger.checkpoint(
                job_id="job-global-order",
                attempt_id="attempt-global-order",
                fencing_epoch=1,
                fencing_token="fence-global-order",
                sequence=0,
                state_sha256=hashlib.sha256(b"state-global-order").hexdigest(),
                payload_ref="cas:synthetic-global-order",
                payload_stored_in_domain_vault=False,
                event_at=AT,
            )
            self.assertEqual(
                (claim.sequence, bundle.event.sequence, checkpoint.sequence), (1, 2, 3)
            )
            manifest = ledger.storage_coverage_manifest()
            self.assertEqual(manifest["global_sequence_last"], 3)
            self.assertEqual(manifest["a1_bundle_sequence_last"], 2)
            self.assertEqual(
                set(manifest["registered_projections"]), set(PROJECTION_NAMES)
            )
            self.assertTrue(manifest["invariants"]["no_second_event_ledger"])
            self.assertTrue(ledger.verify_chain())
            self.assertTrue(ledger.verify_a1_coverage())
        finally:
            ledger.close()

    def test_d2_d3_and_unknown_schema_are_rejected_before_transaction(self) -> None:
        database = self.root / "classification.sqlite3"
        ledger = JobLedger(database)
        try:
            for classification in ("D2", "D3", "D1_INTERNAL_SANITIZED"):
                with self.subTest(classification=classification), self.assertRaises(
                    LedgerError
                ):
                    ledger.append_a1_bundle(
                        objects=[
                            a1_document(
                                "MaterialEvent", classification, classification=classification
                            )
                        ],
                        projections=projection_states(classification),
                        idempotency_key=f"bundle-{classification}",
                        event_at=AT,
                    )
            unsupported = a1_document("MaterialEvent", "unsupported")
            unsupported["schema_id"] = "HypothesisCard"
            with self.assertRaises(LedgerError):
                ledger.append_a1_bundle(
                    objects=[unsupported],
                    projections=projection_states("unsupported"),
                    idempotency_key="bundle-unsupported",
                    event_at=AT,
                )
            self.assertEqual(ledger.event_count(), 0)
            self.assertTrue(ledger.verify_a1_coverage())
        finally:
            ledger.close()


if __name__ == "__main__":
    unittest.main()
