import concurrent.futures
import hashlib
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.ledger import JobLedger, LedgerError


AT = "2026-01-02T03:04:05Z"
ADMISSION_SHA = hashlib.sha256(b"synthetic-admission").hexdigest()
STATE_SHA = hashlib.sha256(b"synthetic-state").hexdigest()
RESULT_SHA = hashlib.sha256(b"synthetic-result").hexdigest()


def claim(
    ledger: JobLedger,
    *,
    job_id: str,
    attempt_id: str,
    token: str,
) -> None:
    ledger.claim(
        job_id=job_id,
        attempt_id=attempt_id,
        permit_id=f"permit-{job_id}",
        runner_identity="offline-runner-a",
        fencing_epoch=7,
        fencing_token=token,
        admitted_at=AT,
        admission_digest=ADMISSION_SHA,
    )


def checkpoint(
    ledger: JobLedger,
    *,
    job_id: str,
    attempt_id: str,
    token: str,
) -> None:
    ledger.checkpoint(
        job_id=job_id,
        attempt_id=attempt_id,
        fencing_epoch=7,
        fencing_token=token,
        sequence=0,
        state_sha256=STATE_SHA,
        payload_ref=f"cas:synthetic-{job_id}",
        payload_stored_in_domain_vault=False,
        event_at=AT,
    )


def complete(
    ledger: JobLedger,
    *,
    job_id: str,
    attempt_id: str,
    token: str,
) -> None:
    ledger.complete(
        job_id=job_id,
        attempt_id=attempt_id,
        fencing_epoch=7,
        fencing_token=token,
        result_sha256=RESULT_SHA,
        event_at=AT,
    )


class PauseEpochFencingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "synthetic-ledger.sqlite3"
        self.ledger = JobLedger(self.database)

    def tearDown(self) -> None:
        self.ledger.close()
        self.temporary_directory.cleanup()

    def chain_snapshot(self) -> list[tuple[int, str]]:
        return [
            (row["sequence"], row["event_sha256"])
            for row in self.ledger._connection.execute(
                "SELECT sequence, event_sha256 FROM bridge_job_ledger ORDER BY sequence"
            ).fetchall()
        ]

    def pause(self) -> None:
        self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic safety hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-request-a",
            event_at=AT,
        )

    def resume(self) -> None:
        self.ledger.resume_global(
            actor="uid:1000",
            approval_ref="approval:synthetic-offline",
            idempotency_key="resume-request-a",
            event_at=AT,
        )

    def assert_denied_without_write(self, transition: Callable[[], None]) -> None:
        before = self.chain_snapshot()
        with self.assertRaisesRegex(LedgerError, "before the latest global pause"):
            transition()
        self.assertEqual(self.chain_snapshot(), before)
        self.assertTrue(self.ledger.verify_chain())

    def test_pre_pause_attempt_is_fenced_during_pause_and_after_resume_reopen(self) -> None:
        claim(self.ledger, job_id="job-old", attempt_id="attempt-old", token="fence-old")
        self.pause()

        self.assert_denied_without_write(
            lambda: checkpoint(
                self.ledger,
                job_id="job-old",
                attempt_id="attempt-old",
                token="fence-old",
            )
        )
        self.assert_denied_without_write(
            lambda: complete(
                self.ledger,
                job_id="job-old",
                attempt_id="attempt-old",
                token="fence-old",
            )
        )
        self.resume()
        self.ledger.close()
        self.ledger = JobLedger(self.database)

        self.assert_denied_without_write(
            lambda: checkpoint(
                self.ledger,
                job_id="job-old",
                attempt_id="attempt-old",
                token="fence-old",
            )
        )
        self.assert_denied_without_write(
            lambda: complete(
                self.ledger,
                job_id="job-old",
                attempt_id="attempt-old",
                token="fence-old",
            )
        )
        self.assertEqual(self.ledger.event_count(), 3)

    def test_new_attempt_claimed_after_resume_can_checkpoint_and_complete(self) -> None:
        claim(self.ledger, job_id="job-old", attempt_id="attempt-old", token="fence-old")
        self.pause()
        self.resume()

        claim(self.ledger, job_id="job-new", attempt_id="attempt-new", token="fence-new")
        checkpoint(
            self.ledger,
            job_id="job-new",
            attempt_id="attempt-new",
            token="fence-new",
        )
        complete(
            self.ledger,
            job_id="job-new",
            attempt_id="attempt-new",
            token="fence-new",
        )

        self.assertEqual(self.ledger.event_count(), 6)
        self.assertTrue(self.ledger.verify_chain())

    def test_concurrent_pause_and_checkpoint_have_atomic_committed_order(self) -> None:
        claim(self.ledger, job_id="job-old", attempt_id="attempt-old", token="fence-old")
        self.ledger.close()
        barrier = threading.Barrier(2)

        def pause_contender() -> str:
            with JobLedger(self.database) as ledger:
                barrier.wait(timeout=5)
                ledger.pause_global(
                    actor="uid:1000",
                    reason="synthetic concurrent hold",
                    authority_ref="authority:synthetic-offline",
                    idempotency_key="pause-request-concurrent",
                    event_at=AT,
                )
                return "pause-committed"

        def checkpoint_contender() -> str:
            with JobLedger(self.database) as ledger:
                barrier.wait(timeout=5)
                try:
                    checkpoint(
                        ledger,
                        job_id="job-old",
                        attempt_id="attempt-old",
                        token="fence-old",
                    )
                except LedgerError:
                    return "checkpoint-rejected"
                return "checkpoint-committed"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            pause_future = executor.submit(pause_contender)
            checkpoint_future = executor.submit(checkpoint_contender)
            outcomes = {pause_future.result(timeout=10), checkpoint_future.result(timeout=10)}

        self.ledger = JobLedger(self.database)
        self.assertIn(
            outcomes,
            (
                {"pause-committed", "checkpoint-committed"},
                {"pause-committed", "checkpoint-rejected"},
            ),
        )
        rows = self.ledger._connection.execute(
            "SELECT sequence, event_type, attempt_id FROM bridge_job_ledger ORDER BY sequence"
        ).fetchall()
        pause_sequence = next(row["sequence"] for row in rows if row["event_type"] == "pause")
        old_attempt_events_after_pause = [
            row
            for row in rows
            if row["attempt_id"] == "attempt-old"
            and row["event_type"] in {"checkpoint", "complete"}
            and row["sequence"] > pause_sequence
        ]
        self.assertEqual(old_attempt_events_after_pause, [])
        self.assertTrue(self.ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
