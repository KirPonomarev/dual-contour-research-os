import concurrent.futures
import hashlib
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.ledger import JobLedger, LedgerError, LedgerEvent


AT = "2026-01-02T03:04:05Z"
ADMISSION_SHA = hashlib.sha256(b"synthetic-admission").hexdigest()
STATE_SHA = hashlib.sha256(b"synthetic-state").hexdigest()
RESULT_SHA = hashlib.sha256(b"synthetic-result").hexdigest()
PERMIT_NONCE_SHA = hashlib.sha256(b"synthetic-permit-nonce-a").hexdigest()


def claim(
    ledger: JobLedger,
    *,
    attempt_id: str = "attempt-a",
    token: str = "fence-a",
    permit_nonce_sha256: str = PERMIT_NONCE_SHA,
) -> LedgerEvent:
    return ledger.claim(
        job_id="job-a",
        attempt_id=attempt_id,
        permit_id="permit-a",
        permit_nonce_sha256=permit_nonce_sha256,
        runner_identity="offline-runner-a",
        fencing_epoch=7,
        fencing_token=token,
        admitted_at=AT,
        admission_digest=ADMISSION_SHA,
    )


def checkpoint(
    ledger: JobLedger,
    *,
    sequence: int = 0,
    attempt_id: str = "attempt-a",
    epoch: int = 7,
    token: str = "fence-a",
    payload_ref: str = "cas:synthetic-state-a",
    in_vault: bool = False,
) -> LedgerEvent:
    return ledger.checkpoint(
        job_id="job-a",
        attempt_id=attempt_id,
        fencing_epoch=epoch,
        fencing_token=token,
        sequence=sequence,
        state_sha256=STATE_SHA,
        payload_ref=payload_ref,
        payload_stored_in_domain_vault=in_vault,
        event_at=AT,
    )


class JobLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "synthetic-ledger.sqlite3"
        self.ledger = JobLedger(self.database)

    def tearDown(self) -> None:
        self.ledger.close()
        self.temporary_directory.cleanup()

    def test_claim_checkpoint_completion_are_durable_and_globally_chained(self) -> None:
        claimed = claim(self.ledger)
        first = checkpoint(self.ledger)

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        with self.assertRaises(LedgerError):
            checkpoint(self.ledger, sequence=1, token="stale-after-reopen")
        self.assertEqual(self.ledger.event_count(), 2)
        second = checkpoint(self.ledger, sequence=1, payload_ref="vault:synthetic-state-b", in_vault=True)
        completed = self.ledger.complete(
            job_id="job-a",
            attempt_id="attempt-a",
            fencing_epoch=7,
            fencing_token="fence-a",
            result_sha256=RESULT_SHA,
            event_at=AT,
        )

        self.assertIsInstance(claimed, LedgerEvent)
        self.assertEqual([claimed.sequence, first.sequence, second.sequence, completed.sequence], [1, 2, 3, 4])
        self.assertEqual(first.payload["payload_ref"], "cas:synthetic-state-a")
        self.assertEqual(self.ledger.event_count(), 4)
        self.assertEqual(self.ledger.event_count("checkpoint"), 2)
        self.assertTrue(self.ledger.verify_chain())
        payloads = [
            row[0]
            for row in self.ledger._connection.execute(
                "SELECT payload_json FROM bridge_job_ledger ORDER BY sequence"
            ).fetchall()
        ]
        self.assertTrue(all("fencing_token_sha256" in payload for payload in payloads))
        self.assertTrue(all("fence-a" not in payload for payload in payloads))

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        self.assertEqual(self.ledger.event_count(), 4)
        self.assertTrue(self.ledger.verify_chain())

    def test_sqlite_is_wal_full_and_table_denies_update_or_delete(self) -> None:
        claim(self.ledger)
        mode = self.ledger._connection.execute("PRAGMA journal_mode").fetchone()[0]
        synchronous = self.ledger._connection.execute("PRAGMA synchronous").fetchone()[0]
        tables = [
            row[0]
            for row in self.ledger._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
        ]
        self.assertEqual(mode.lower(), "wal")
        self.assertEqual(synchronous, 2)
        self.assertEqual(tables, ["bridge_job_ledger"])
        indexes = {
            row[0]
            for row in self.ledger._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        self.assertIn("bridge_claim_one_permit_nonce", indexes)

        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "UPDATE bridge_job_ledger SET job_id = 'changed' WHERE sequence = 1"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute("DELETE FROM bridge_job_ledger WHERE sequence = 1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                """
                INSERT OR REPLACE INTO bridge_job_ledger (
                    sequence, event_type, job_id, attempt_id, fencing_epoch,
                    checkpoint_sequence, event_at, payload_json,
                    previous_sha256, event_sha256
                ) SELECT sequence, event_type, 'changed', attempt_id, fencing_epoch,
                    checkpoint_sequence, event_at, payload_json,
                    previous_sha256, event_sha256
                FROM bridge_job_ledger WHERE sequence = 1
                """
            )
        self.assertEqual(self.ledger.event_count(), 1)
        self.assertTrue(self.ledger.verify_chain())

    def test_concurrent_claim_has_exactly_one_winner(self) -> None:
        self.ledger.close()

        def contender(index: int) -> str:
            contender_ledger = JobLedger(self.database)
            try:
                contender_ledger.claim(
                    job_id="job-a",
                    attempt_id=f"attempt-{index}",
                    permit_id=f"permit-{index}",
                    permit_nonce_sha256=hashlib.sha256(
                        f"same-job-permit-nonce-{index}".encode("utf-8")
                    ).hexdigest(),
                    runner_identity=f"offline-runner-{index}",
                    fencing_epoch=index,
                    fencing_token=f"fence-{index}",
                    admitted_at=AT,
                    admission_digest=ADMISSION_SHA,
                )
                return "winner"
            except LedgerError:
                return "rejected"
            finally:
                contender_ledger.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(executor.map(contender, range(8)))

        self.ledger = JobLedger(self.database)
        self.assertEqual(outcomes.count("winner"), 1)
        self.assertEqual(outcomes.count("rejected"), 7)
        self.assertEqual(self.ledger.event_count(), 1)
        self.assertTrue(self.ledger.verify_chain())

    def test_sequential_duplicate_nonce_across_jobs_is_zero_write(self) -> None:
        claim(self.ledger)
        before = self.ledger.event_count()
        with self.assertRaises(LedgerError):
            self.ledger.claim(
                job_id="job-b",
                attempt_id="attempt-b",
                permit_id="permit-b",
                permit_nonce_sha256=PERMIT_NONCE_SHA,
                runner_identity="offline-runner-b",
                fencing_epoch=8,
                fencing_token="fence-b",
                admitted_at=AT,
                admission_digest=hashlib.sha256(b"admission-b").hexdigest(),
            )
        self.assertEqual(self.ledger.event_count(), before)

        distinct_digest = hashlib.sha256(b"synthetic-permit-nonce-b").hexdigest()
        accepted = self.ledger.claim(
            job_id="job-b",
            attempt_id="attempt-b",
            permit_id="permit-b",
            permit_nonce_sha256=distinct_digest,
            runner_identity="offline-runner-b",
            fencing_epoch=8,
            fencing_token="fence-b",
            admitted_at=AT,
            admission_digest=hashlib.sha256(b"admission-b").hexdigest(),
        )
        self.assertEqual(accepted.sequence, 2)
        self.assertEqual(self.ledger.event_count("claim"), 2)
        self.assertTrue(self.ledger.verify_chain())
        serialized = "\n".join(
            row[0]
            for row in self.ledger._connection.execute(
                "SELECT payload_json FROM bridge_job_ledger ORDER BY sequence"
            ).fetchall()
        )
        self.assertNotIn("synthetic-permit-nonce", serialized)
        self.assertIn(PERMIT_NONCE_SHA, serialized)
        self.assertIn(distinct_digest, serialized)

    def test_eight_way_nonce_race_has_one_winner_and_survives_reopen(self) -> None:
        self.ledger.close()
        barrier = threading.Barrier(8)

        def contender(index: int) -> str:
            contender_ledger = JobLedger(self.database, timeout=10)
            try:
                barrier.wait(timeout=10)
                contender_ledger.claim(
                    job_id=f"job-nonce-race-{index}",
                    attempt_id=f"attempt-nonce-race-{index}",
                    permit_id=f"permit-nonce-race-{index}",
                    permit_nonce_sha256=PERMIT_NONCE_SHA,
                    runner_identity=f"offline-runner-{index}",
                    fencing_epoch=index,
                    fencing_token=f"fence-nonce-race-{index}",
                    admitted_at=AT,
                    admission_digest=hashlib.sha256(
                        f"admission-nonce-race-{index}".encode("utf-8")
                    ).hexdigest(),
                )
                return "winner"
            except LedgerError:
                return "rejected"
            finally:
                contender_ledger.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(executor.map(contender, range(8)))

        self.ledger = JobLedger(self.database)
        self.assertEqual(outcomes.count("winner"), 1)
        self.assertEqual(outcomes.count("rejected"), 7)
        self.assertEqual(self.ledger.event_count("claim"), 1)
        self.assertTrue(self.ledger.verify_chain())

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        before = self.ledger.event_count()
        with self.assertRaises(LedgerError):
            self.ledger.claim(
                job_id="job-nonce-after-reopen",
                attempt_id="attempt-nonce-after-reopen",
                permit_id="permit-nonce-after-reopen",
                permit_nonce_sha256=PERMIT_NONCE_SHA,
                runner_identity="offline-runner-after-reopen",
                fencing_epoch=9,
                fencing_token="fence-nonce-after-reopen",
                admitted_at=AT,
                admission_digest=hashlib.sha256(b"admission-after-reopen").hexdigest(),
            )
        self.assertEqual(self.ledger.event_count(), before)
        self.assertTrue(self.ledger.verify_chain())

    def test_malformed_nonce_digest_is_rejected_without_a_write(self) -> None:
        before = self.ledger.event_count()
        with self.assertRaises(LedgerError):
            claim(self.ledger, permit_nonce_sha256="not-a-digest")
        self.assertEqual(self.ledger.event_count(), before)

    def test_legacy_missing_or_malformed_nonce_digest_blocks_new_claim(self) -> None:
        missing = object()
        for label, replacement in (("missing", missing), ("malformed", "bad")):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "legacy-ledger.sqlite3"
                legacy = JobLedger(database)
                claim(legacy)
                legacy.close()

                with closing(sqlite3.connect(database)) as connection, connection:
                    connection.row_factory = sqlite3.Row
                    connection.execute("DROP TRIGGER bridge_job_ledger_no_update")
                    row = connection.execute(
                        "SELECT * FROM bridge_job_ledger WHERE sequence = 1"
                    ).fetchone()
                    payload = json.loads(row["payload_json"])
                    if replacement is missing:
                        del payload["permit_nonce_sha256"]
                    else:
                        payload["permit_nonce_sha256"] = replacement
                    material = JobLedger._hash_material(
                        sequence=row["sequence"],
                        event_type=row["event_type"],
                        job_id=row["job_id"],
                        attempt_id=row["attempt_id"],
                        fencing_epoch=row["fencing_epoch"],
                        event_at=row["event_at"],
                        payload=payload,
                        previous_sha256=row["previous_sha256"],
                    )
                    connection.execute(
                        "UPDATE bridge_job_ledger SET payload_json = ?, event_sha256 = ? WHERE sequence = 1",
                        (
                            json.dumps(
                                payload,
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=True,
                            ),
                            hashlib.sha256(material).hexdigest(),
                        ),
                    )

                reopened = JobLedger(database)
                try:
                    self.assertTrue(reopened.verify_chain())
                    before = reopened.event_count()
                    with self.assertRaises(LedgerError):
                        reopened.claim(
                            job_id=f"job-after-{label}-legacy",
                            attempt_id=f"attempt-after-{label}-legacy",
                            permit_id=f"permit-after-{label}-legacy",
                            permit_nonce_sha256=hashlib.sha256(
                                f"new-nonce-{label}".encode("utf-8")
                            ).hexdigest(),
                            runner_identity="offline-runner-legacy-probe",
                            fencing_epoch=2,
                            fencing_token="fence-legacy-probe",
                            admitted_at=AT,
                            admission_digest=hashlib.sha256(
                                f"admission-{label}".encode("utf-8")
                            ).hexdigest(),
                        )
                    self.assertEqual(reopened.event_count(), before)
                    self.assertTrue(reopened.verify_chain())
                finally:
                    reopened.close()

    def test_stale_fencing_authority_causes_zero_writes(self) -> None:
        claim(self.ledger)
        for changes in (
            {"token": "stale-fence"},
            {"epoch": 6},
            {"attempt_id": "stale-attempt"},
        ):
            before = self.ledger.event_count()
            with self.assertRaises(LedgerError):
                checkpoint(self.ledger, **changes)
            self.assertEqual(self.ledger.event_count(), before)

        before = self.ledger.event_count()
        with self.assertRaises(LedgerError):
            self.ledger.complete(
                job_id="job-a",
                attempt_id="attempt-a",
                fencing_epoch=7,
                fencing_token="stale-fence",
                result_sha256=RESULT_SHA,
                event_at=AT,
            )
        self.assertEqual(self.ledger.event_count(), before)
        self.assertTrue(self.ledger.verify_chain())

    def test_checkpoint_sequence_and_reference_validation_are_fail_closed(self) -> None:
        claim(self.ledger)
        for changes in (
            {"sequence": 1},
            {"payload_ref": "inline:payload"},
            {"payload_ref": "cas:synthetic", "in_vault": True},
            {"payload_ref": "vault:synthetic", "in_vault": False},
        ):
            before = self.ledger.event_count()
            with self.assertRaises(LedgerError):
                checkpoint(self.ledger, **changes)
            self.assertEqual(self.ledger.event_count(), before)

        checkpoint(self.ledger, sequence=0)
        with self.assertRaises(LedgerError):
            checkpoint(self.ledger, sequence=0)
        with self.assertRaises(LedgerError):
            checkpoint(self.ledger, sequence=2)
        self.assertEqual(self.ledger.event_count(), 2)
        self.assertTrue(self.ledger.verify_chain())

    def test_payload_bytes_bad_digests_and_naive_timestamps_are_rejected(self) -> None:
        before = self.ledger.event_count()
        with self.assertRaises(LedgerError):
            self.ledger.claim(
                job_id="job-a",
                attempt_id="attempt-a",
                permit_id="permit-a",
                permit_nonce_sha256=PERMIT_NONCE_SHA,
                runner_identity="offline-runner-a",
                fencing_epoch=7,
                fencing_token=b"not-text",
                admitted_at=AT,
                admission_digest=ADMISSION_SHA,
            )
        with self.assertRaises(LedgerError):
            self.ledger.claim(
                job_id="job-a",
                attempt_id="attempt-a",
                permit_id="permit-a",
                permit_nonce_sha256=PERMIT_NONCE_SHA,
                runner_identity="offline-runner-a",
                fencing_epoch=7,
                fencing_token="fence-a",
                admitted_at="2026-01-02T03:04:05",
                admission_digest=ADMISSION_SHA,
            )
        with self.assertRaises(LedgerError):
            self.ledger.claim(
                job_id="job-a",
                attempt_id="attempt-a",
                permit_id="permit-a",
                permit_nonce_sha256=PERMIT_NONCE_SHA,
                runner_identity="offline-runner-a",
                fencing_epoch=7,
                fencing_token="fence-a",
                admitted_at=AT,
                admission_digest="not-a-digest",
            )
        self.assertEqual(self.ledger.event_count(), before)

    def test_completion_is_terminal_and_inspection_fails_after_close(self) -> None:
        claim(self.ledger)
        self.ledger.complete(
            job_id="job-a",
            attempt_id="attempt-a",
            fencing_epoch=7,
            fencing_token="fence-a",
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        with self.assertRaises(LedgerError):
            checkpoint(self.ledger)
        with self.assertRaises(LedgerError):
            self.ledger.complete(
                job_id="job-a",
                attempt_id="attempt-a",
                fencing_epoch=7,
                fencing_token="fence-a",
                result_sha256=RESULT_SHA,
                event_at=AT,
            )
        self.assertEqual(self.ledger.event_count(), 2)
        self.ledger.close()
        with self.assertRaises(LedgerError):
            self.ledger.event_count()
        self.ledger.close()

    def test_global_pause_survives_reopen_and_blocks_claim_without_a_write(self) -> None:
        paused = self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic safety hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-request-a",
            event_at=AT,
        )
        self.assertEqual(paused.event_type, "pause")
        self.assertTrue(self.ledger.is_globally_paused())
        self.assertEqual(self.ledger.pause_snapshot()["reason"], "synthetic safety hold")

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        self.assertTrue(self.ledger.is_globally_paused())
        before = self.ledger.event_count()
        with self.assertRaisesRegex(LedgerError, "global pause"):
            claim(self.ledger)
        self.assertEqual(self.ledger.event_count(), before)
        self.assertEqual(self.ledger.event_count("pause"), 1)
        self.assertTrue(self.ledger.verify_chain())

    def test_resume_requires_approval_and_unblocks_claim(self) -> None:
        self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic safety hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-request-a",
            event_at=AT,
        )
        before = self.ledger.event_count()
        for approval_ref in ("", " approval:synthetic ", b"payload"):
            with self.assertRaises(LedgerError):
                self.ledger.resume_global(
                    actor="uid:1000",
                    approval_ref=approval_ref,
                    idempotency_key="resume-request-a",
                    event_at=AT,
                )
            self.assertEqual(self.ledger.event_count(), before)

        resumed = self.ledger.resume_global(
            actor="uid:1000",
            approval_ref="approval:synthetic-offline",
            idempotency_key="resume-request-a",
            event_at=AT,
        )
        self.assertEqual(resumed.event_type, "resume")
        self.assertFalse(self.ledger.is_globally_paused())
        self.assertEqual(self.ledger.pause_snapshot()["approval_ref"], "approval:synthetic-offline")
        claimed = claim(self.ledger)
        self.assertEqual(claimed.event_type, "claim")
        self.assertTrue(self.ledger.verify_chain())

    def test_control_idempotency_is_durable_and_conflicting_reuse_is_rejected(self) -> None:
        first = self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic safety hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-request-a",
            event_at=AT,
        )
        duplicate = self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic safety hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-request-a",
            event_at=AT,
        )
        self.assertEqual(duplicate.event_sha256, first.event_sha256)
        self.assertEqual(self.ledger.event_count(), 1)

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        duplicate_after_reopen = self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic safety hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-request-a",
            event_at=AT,
        )
        self.assertEqual(duplicate_after_reopen.event_sha256, first.event_sha256)
        with self.assertRaisesRegex(LedgerError, "different control request"):
            self.ledger.resume_global(
                actor="uid:1000",
                approval_ref="approval:synthetic-offline",
                idempotency_key="pause-request-a",
                event_at=AT,
            )
        self.assertEqual(self.ledger.event_count(), 1)
        self.assertTrue(self.ledger.verify_chain())

    def test_control_transitions_fail_closed_and_add_zero_events(self) -> None:
        self.assertEqual(self.ledger.pause_snapshot(), {"paused": False})
        invalid_calls = (
            lambda: self.ledger.resume_global(
                actor="uid:1000",
                approval_ref="approval:synthetic-offline",
                idempotency_key="resume-request-a",
                event_at=AT,
            ),
            lambda: self.ledger.pause_global(
                actor="uid:1000",
                reason="",
                authority_ref="authority:synthetic-offline",
                idempotency_key="pause-request-a",
                event_at=AT,
            ),
        )
        for call in invalid_calls:
            before = self.ledger.event_count()
            with self.assertRaises(LedgerError):
                call()
            self.assertEqual(self.ledger.event_count(), before)

        self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic safety hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-request-a",
            event_at=AT,
        )
        before = self.ledger.event_count()
        with self.assertRaisesRegex(LedgerError, "already active"):
            self.ledger.pause_global(
                actor="uid:1001",
                reason="second hold",
                authority_ref="authority:synthetic-offline",
                idempotency_key="pause-request-b",
                event_at=AT,
            )
        self.assertEqual(self.ledger.event_count(), before)

        self.ledger.resume_global(
            actor="uid:1000",
            approval_ref="approval:synthetic-offline",
            idempotency_key="resume-request-a",
            event_at=AT,
        )
        before = self.ledger.event_count()
        with self.assertRaisesRegex(LedgerError, "not active"):
            self.ledger.resume_global(
                actor="uid:1000",
                approval_ref="approval:synthetic-offline",
                idempotency_key="resume-request-b",
                event_at=AT,
            )
        self.assertEqual(self.ledger.event_count(), before)
        self.assertTrue(self.ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
