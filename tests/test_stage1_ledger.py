import concurrent.futures
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.ledger import JobLedger, LedgerError, LedgerEvent


AT = "2026-01-02T03:04:05Z"
ADMISSION_SHA = hashlib.sha256(b"synthetic-admission").hexdigest()
STATE_SHA = hashlib.sha256(b"synthetic-state").hexdigest()
RESULT_SHA = hashlib.sha256(b"synthetic-result").hexdigest()


def claim(ledger: JobLedger, *, attempt_id: str = "attempt-a", token: str = "fence-a") -> LedgerEvent:
    return ledger.claim(
        job_id="job-a",
        attempt_id=attempt_id,
        permit_id="permit-a",
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
        self.assertEqual(mode.lower(), "wal")
        self.assertEqual(synchronous, 2)

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


if __name__ == "__main__":
    unittest.main()
