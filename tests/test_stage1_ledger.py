import concurrent.futures
import hashlib
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import research_bridge.ledger as ledger_module
from research_bridge.ledger import JobLedger, LedgerError, LedgerEvent


AT = "2026-01-02T03:04:05Z"
ADMISSION_SHA = hashlib.sha256(b"synthetic-admission").hexdigest()
STATE_SHA = hashlib.sha256(b"synthetic-state").hexdigest()
RESULT_SHA = hashlib.sha256(b"synthetic-result").hexdigest()
PERMIT_NONCE_SHA = hashlib.sha256(b"synthetic-permit-nonce-a").hexdigest()
ACCOUNTING_POLICY_REF = f"budget-policy:sha256:{'a' * 64}"
BUDGET_SCOPE_REF = f"budget-scope:sha256:{'b' * 64}"


def budget_keywords(
    job_id: str,
    *,
    provider: str = "offline-runner-a",
    idempotency_key: str | None = None,
    reservation_cost_units: int = 1,
    scope_limit_cost_units: int = 100,
) -> dict[str, object]:
    return {
        "accounting_policy_ref": ACCOUNTING_POLICY_REF,
        "budget_scope_ref": BUDGET_SCOPE_REF,
        "scope_limit_cost_units": scope_limit_cost_units,
        "trial_ref": "trial:synthetic-ledger",
        "provider": provider,
        "job_idempotency_key": idempotency_key or f"idempotency:{job_id}",
        "reservation_cost_units": reservation_cost_units,
        "reservation_expires_at": "2026-01-02T04:04:05Z",
        "contour": "bridge",
        "classification": "D0_PUBLIC",
    }


def claim_keywords(
    job_id: str,
    *,
    attempt_id: str | None = None,
    permit_id: str | None = None,
    permit_nonce_sha256: str | None = None,
    runner_identity: str = "offline-runner-a",
    fencing_epoch: int = 7,
    fencing_token: str | None = None,
    admitted_at: str = AT,
    admission_digest: str = ADMISSION_SHA,
    job_idempotency_key: str | None = None,
    **budget_overrides: object,
) -> dict[str, object]:
    resolved_attempt = attempt_id or f"attempt:{job_id}"
    values = {
        "job_id": job_id,
        "attempt_id": resolved_attempt,
        "permit_id": permit_id or f"permit:{job_id}",
        "permit_nonce_sha256": permit_nonce_sha256
        or hashlib.sha256(f"nonce:{job_id}".encode("utf-8")).hexdigest(),
        "runner_identity": runner_identity,
        "fencing_epoch": fencing_epoch,
        "fencing_token": fencing_token or f"fence:{job_id}",
        "admitted_at": admitted_at,
        "admission_digest": admission_digest,
    }
    values.update(
        budget_keywords(
            job_id,
            provider=runner_identity,
            idempotency_key=job_idempotency_key,
        )
    )
    values.update(budget_overrides)
    return values


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
        **budget_keywords("job-a"),
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


def rewrite_chain_payloads(
    database: Path,
    mutate: Callable[[int, dict[str, object]], dict[str, object]],
) -> None:
    no_update_trigger_sql = next(
        statement
        for object_type, name, statement in ledger_module._LEGACY_SCHEMA_OBJECTS
        if object_type == "trigger" and name == "bridge_job_ledger_no_update"
    )
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.row_factory = sqlite3.Row
        connection.execute("DROP TRIGGER bridge_job_ledger_no_update")
        rows = connection.execute(
            "SELECT * FROM bridge_job_ledger ORDER BY sequence"
        ).fetchall()
        previous_sha256 = "0" * 64
        for row in rows:
            payload = json.loads(row["payload_json"])
            payload = mutate(row["sequence"], payload)
            material = JobLedger._hash_material(
                sequence=row["sequence"],
                event_type=row["event_type"],
                job_id=row["job_id"],
                attempt_id=row["attempt_id"],
                fencing_epoch=row["fencing_epoch"],
                event_at=row["event_at"],
                payload=payload,
                previous_sha256=previous_sha256,
            )
            event_sha256 = hashlib.sha256(material).hexdigest()
            connection.execute(
                "UPDATE bridge_job_ledger SET payload_json = ?, previous_sha256 = ?, "
                "event_sha256 = ? WHERE sequence = ?",
                (
                    ledger_module._canonical_json(payload),
                    previous_sha256,
                    event_sha256,
                    row["sequence"],
                ),
            )
            previous_sha256 = event_sha256
        connection.execute(no_update_trigger_sql)


def expire_first_reservation_at_admission(
    sequence: int, payload: dict[str, object]
) -> dict[str, object]:
    if sequence != 1:
        return payload
    reservation = payload["budget_reservation"]
    assert isinstance(reservation, dict)
    reservation_payload = reservation["payload"]
    assert isinstance(reservation_payload, dict)
    reservation_payload["expires_at"] = payload["admitted_at"]
    payload_sha256 = hashlib.sha256(
        ledger_module._canonical_json(reservation_payload).encode("utf-8")
    ).hexdigest()
    reservation["object_id"] = f"budget-reservation:sha256:{payload_sha256}"
    integrity = reservation["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = payload_sha256
    return payload


def invert_claim_completion_causality(database: Path) -> None:
    no_update_trigger_sql = next(
        statement
        for object_type, name, statement in ledger_module._LEGACY_SCHEMA_OBJECTS
        if object_type == "trigger" and name == "bridge_job_ledger_no_update"
    )
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.row_factory = sqlite3.Row
        rows = {
            row["event_type"]: row
            for row in connection.execute(
                "SELECT * FROM bridge_job_ledger ORDER BY sequence"
            )
        }
        claim_row = rows["claim"]
        complete_row = rows["complete"]
        claim_payload = json.loads(claim_row["payload_json"])
        complete_payload = json.loads(complete_row["payload_json"])

        reservation = claim_payload["budget_reservation"]
        reservation_payload = reservation["payload"]
        reservation_payload["ledger_version_before"] = 1
        reservation_sha256 = hashlib.sha256(
            ledger_module._canonical_json(reservation_payload).encode("utf-8")
        ).hexdigest()
        reservation_ref = f"budget-reservation:sha256:{reservation_sha256}"
        reservation["object_id"] = reservation_ref
        reservation["integrity"]["payload_sha256"] = reservation_sha256

        attestation = complete_payload["provider_accounting_attestation"]
        attestation["reservation_ref"] = reservation_ref
        provider_ref = "embedded:sha256:" + hashlib.sha256(
            ledger_module._canonical_json(attestation).encode("utf-8")
        ).hexdigest()
        settlement = complete_payload["settlement_receipt"]
        settlement_payload = settlement["payload"]
        settlement_payload["reservation_ref"] = reservation_ref
        settlement_payload["provider_receipt_ref"] = provider_ref
        settlement_payload["ledger_version_after"] = 1
        settlement_sha256 = hashlib.sha256(
            ledger_module._canonical_json(settlement_payload).encode("utf-8")
        ).hexdigest()
        settlement["object_id"] = f"settlement-receipt-{settlement_sha256}"
        settlement["integrity"]["payload_sha256"] = settlement_sha256
        settlement["integrity"]["parent_refs"] = [
            reservation_ref,
            claim_payload["accounting_policy_ref"],
            provider_ref,
            f"result:sha256:{complete_payload['result_sha256']}",
        ]

        connection.execute("DROP TRIGGER bridge_job_ledger_no_update")
        connection.execute(
            "UPDATE bridge_job_ledger SET sequence = sequence + 100"
        )
        previous_sha256 = "0" * 64
        for new_sequence, row, payload in (
            (1, complete_row, complete_payload),
            (2, claim_row, claim_payload),
        ):
            material = JobLedger._hash_material(
                sequence=new_sequence,
                event_type=row["event_type"],
                job_id=row["job_id"],
                attempt_id=row["attempt_id"],
                fencing_epoch=row["fencing_epoch"],
                event_at=row["event_at"],
                payload=payload,
                previous_sha256=previous_sha256,
            )
            event_sha256 = hashlib.sha256(material).hexdigest()
            connection.execute(
                "UPDATE bridge_job_ledger SET sequence = ?, payload_json = ?, "
                "previous_sha256 = ?, event_sha256 = ? WHERE sequence = ?",
                (
                    new_sequence,
                    ledger_module._canonical_json(payload),
                    previous_sha256,
                    event_sha256,
                    row["sequence"] + 100,
                ),
            )
            previous_sha256 = event_sha256
        connection.execute(no_update_trigger_sql)


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

    def test_completed_event_is_unique_validated_reopen_safe_and_read_only(self) -> None:
        claim(self.ledger)
        completed = self.ledger.complete(
            job_id="job-a",
            attempt_id="attempt-a",
            fencing_epoch=7,
            fencing_token="fence-a",
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        before = (
            self.ledger.event_count(),
            self.ledger.event_count("claim"),
            self.ledger.event_count("complete"),
        )

        self.assertEqual(self.ledger.completed_event("job-a"), completed)
        self.assertEqual(
            (
                self.ledger.event_count(),
                self.ledger.event_count("claim"),
                self.ledger.event_count("complete"),
            ),
            before,
        )

        self.ledger.close()
        self.ledger = JobLedger(self.database)
        self.assertEqual(self.ledger.completed_event("job-a"), completed)
        self.assertEqual(self.ledger.event_count(), before[0])

    def test_completed_event_fails_closed_when_job_is_not_complete(self) -> None:
        claim(self.ledger)
        for job_id in ("job-a", "job-missing", "", " padded "):
            with self.subTest(job_id=job_id), self.assertRaises(LedgerError):
                self.ledger.completed_event(job_id)
        self.assertEqual(self.ledger.event_count(), 1)

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
        self.assertEqual(
            tables,
            ["bridge_a1_objects", "bridge_a1_projection_state", "bridge_job_ledger"],
        )
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
                    **budget_keywords("job-a", provider=f"offline-runner-{index}"),
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
                **budget_keywords("job-b", provider="offline-runner-b"),
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
            **budget_keywords("job-b", provider="offline-runner-b"),
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
                    **budget_keywords(
                        f"job-nonce-race-{index}",
                        provider=f"offline-runner-{index}",
                    ),
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
                **budget_keywords(
                    "job-nonce-after-reopen",
                    provider="offline-runner-after-reopen",
                ),
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

                with self.assertRaisesRegex(
                    LedgerError, "schema fingerprint is not exact version 2"
                ):
                    JobLedger(database)

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
        replay = checkpoint(self.ledger, sequence=0)
        self.assertEqual(replay.sequence, 2)
        self.assertEqual(replay.event_at, AT)
        self.ledger.close()
        self.ledger = JobLedger(self.database)
        reopened_replay = checkpoint(self.ledger, sequence=0)
        self.assertEqual(reopened_replay.event_sha256, replay.event_sha256)
        with self.assertRaises(LedgerError):
            checkpoint(
                self.ledger,
                sequence=0,
                payload_ref="cas:conflicting-synthetic-state",
            )
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
                **budget_keywords("job-a"),
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
                **budget_keywords("job-a"),
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
                **budget_keywords("job-a"),
            )
        self.assertEqual(self.ledger.event_count(), before)

    def test_completion_is_terminal_and_inspection_fails_after_close(self) -> None:
        claim(self.ledger)
        completed = self.ledger.complete(
            job_id="job-a",
            attempt_id="attempt-a",
            fencing_epoch=7,
            fencing_token="fence-a",
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        with self.assertRaises(LedgerError):
            checkpoint(self.ledger)
        replay = self.ledger.complete(
            job_id="job-a",
            attempt_id="attempt-a",
            fencing_epoch=7,
            fencing_token="fence-a",
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        self.assertEqual(replay.event_sha256, completed.event_sha256)
        self.ledger.close()
        self.ledger = JobLedger(self.database)
        reopened_replay = self.ledger.complete(
            job_id="job-a",
            attempt_id="attempt-a",
            fencing_epoch=7,
            fencing_token="fence-a",
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        self.assertEqual(reopened_replay.event_sha256, completed.event_sha256)
        with self.assertRaises(LedgerError):
            self.ledger.complete(
                job_id="job-a",
                attempt_id="attempt-a",
                fencing_epoch=7,
                fencing_token="fence-a",
                result_sha256=hashlib.sha256(b"conflict").hexdigest(),
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

    def test_exact_v2_schema_and_empty_legacy_upgrade(self) -> None:
        expected_names = {
            name for _object_type, name, _sql in ledger_module._SCHEMA_V2_OBJECTS
        }
        version = self.ledger._connection.execute("PRAGMA user_version").fetchone()[0]
        names = {
            row[0]
            for row in self.ledger._connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        self.assertEqual(version, 2)
        self.assertEqual(names, expected_names)

        database = Path(self.temporary_directory.name) / "empty-legacy.sqlite3"
        with closing(sqlite3.connect(database)) as connection, connection:
            for _object_type, _name, statement in ledger_module._LEGACY_SCHEMA_OBJECTS:
                connection.execute(statement)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)

        upgraded = JobLedger(database)
        try:
            self.assertEqual(
                upgraded._connection.execute("PRAGMA user_version").fetchone()[0], 2
            )
            upgraded_names = {
                row[0]
                for row in upgraded._connection.execute(
                    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(upgraded_names, expected_names)
            self.assertEqual(upgraded.event_count(), 0)
        finally:
            upgraded.close()
        JobLedger(database).close()

    def test_schema_extra_missing_and_lookalike_are_rejected_without_repair(self) -> None:
        def identity(database: Path) -> tuple[int, tuple[tuple[object, ...], ...]]:
            with closing(sqlite3.connect(database)) as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                objects = tuple(
                    connection.execute(
                        "SELECT type, name, tbl_name, sql FROM sqlite_master "
                        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                    )
                )
            return version, objects

        mutations = {
            "extra": "CREATE TABLE unauthorized_extra(value TEXT)",
            "missing": "DROP INDEX bridge_claim_one_budget_reservation",
            "lookalike": (
                "DROP INDEX bridge_claim_one_budget_reservation;"
                "CREATE UNIQUE INDEX bridge_claim_one_budget_reservation "
                "ON bridge_job_ledger (json_extract(payload_json, "
                "'$.budget_reservation.object_id')) WHERE event_type='claim'"
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                database = Path(self.temporary_directory.name) / f"schema-{label}.sqlite3"
                JobLedger(database).close()
                with closing(sqlite3.connect(database)) as connection, connection:
                    for statement in mutation.split(";"):
                        connection.execute(statement)
                before = identity(database)
                with self.assertRaisesRegex(
                    LedgerError, "schema fingerprint is not exact version 2"
                ):
                    JobLedger(database)
                self.assertEqual(identity(database), before)

    def test_nonempty_unversioned_legacy_ledger_is_quarantined_unchanged(self) -> None:
        database = Path(self.temporary_directory.name) / "nonempty-legacy.sqlite3"
        with closing(sqlite3.connect(database)) as connection, connection:
            for _object_type, _name, statement in ledger_module._LEGACY_SCHEMA_OBJECTS:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO bridge_job_ledger VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    1,
                    "pause",
                    "bridge-global-control",
                    "legacy-pause",
                    0,
                    None,
                    AT,
                    "{}",
                    "0" * 64,
                    "1" * 64,
                ),
            )
        before = database.read_bytes()
        with self.assertRaisesRegex(
            LedgerError, "nonempty unversioned ledger requires quarantine"
        ):
            JobLedger(database)
        self.assertEqual(database.read_bytes(), before)
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
            names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                )
            }
        self.assertTrue(
            names.isdisjoint(
                name for _kind, name, _sql in ledger_module._BUDGET_INDEX_OBJECTS
            )
        )

    def test_global_budget_replay_requires_every_caller_binding(self) -> None:
        original = claim_keywords(
            "job-replay",
            job_idempotency_key="idempotency:global-replay",
            scope_limit_cost_units=100,
        )
        first = self.ledger.claim(**original)
        replay = self.ledger.claim(**original)
        self.assertEqual(replay.event_sha256, first.event_sha256)
        self.assertEqual(self.ledger.event_count(), 1)

        mutations = {
            "job_id": "job-replay-conflict",
            "attempt_id": "attempt:replay-conflict",
            "permit_id": "permit:replay-conflict",
            "permit_nonce_sha256": hashlib.sha256(b"nonce-conflict").hexdigest(),
            "runner_identity": "offline-runner-conflict",
            "fencing_epoch": 8,
            "fencing_token": "fence:replay-conflict",
            "admitted_at": "2026-01-02T03:05:05Z",
            "admission_digest": hashlib.sha256(b"admission-conflict").hexdigest(),
            "provider": "offline-provider-conflict",
            "accounting_policy_ref": f"budget-policy:sha256:{'c' * 64}",
            "budget_scope_ref": f"budget-scope:sha256:{'d' * 64}",
            "trial_ref": "trial:replay-conflict",
            "reservation_cost_units": 2,
            "scope_limit_cost_units": 101,
            "reservation_expires_at": "2026-01-02T05:04:05Z",
            "contour": "market",
            "classification": "D1_INTERNAL_SANITIZED",
        }
        self.assertEqual(len(original), 19)
        self.assertEqual(
            set(mutations), set(original) - {"job_idempotency_key"}
        )
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = dict(original)
                changed[field] = value
                with self.assertRaisesRegex(LedgerError, "idempotency key conflicts"):
                    self.ledger.claim(**changed)
                self.assertEqual(self.ledger.event_count(), 1)
        self.assertTrue(self.ledger.verify_chain())

    def test_invalid_persisted_expiry_blocks_replay_and_new_claim_zero_write(self) -> None:
        original = claim_keywords("job-expiry-projection")
        self.ledger.claim(**original)
        self.ledger.close()
        rewrite_chain_payloads(
            self.database,
            expire_first_reservation_at_admission,
        )
        self.ledger = JobLedger(self.database)
        self.assertTrue(self.ledger.verify_chain())
        before = self.ledger.event_count()
        for label, arguments in (
            ("exact-replay", original),
            ("new-claim", claim_keywords("job-after-expiry-projection")),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                LedgerError, "expires at or before admission"
            ):
                self.ledger.claim(**arguments)
            self.assertEqual(self.ledger.event_count(), before)
            self.assertTrue(self.ledger.verify_chain())

    def test_global_over_cap_projection_blocks_replay_and_unrelated_claim(self) -> None:
        scope_a = f"budget-scope:sha256:{'a' * 64}"
        scope_b = f"budget-scope:sha256:{'b' * 64}"
        first = claim_keywords(
            "job-projection-cap-a",
            budget_scope_ref=scope_a,
            reservation_cost_units=2,
            scope_limit_cost_units=3,
        )
        second = claim_keywords(
            "job-projection-cap-b",
            budget_scope_ref=scope_b,
            reservation_cost_units=2,
            scope_limit_cost_units=3,
        )
        self.ledger.claim(**first)
        self.ledger.claim(**second)
        self.ledger.close()

        def collapse_second_scope(
            sequence: int, payload: dict[str, object]
        ) -> dict[str, object]:
            if sequence != 2:
                return payload
            payload["budget_scope_ref"] = scope_a
            reservation = payload["budget_reservation"]
            assert isinstance(reservation, dict)
            integrity = reservation["integrity"]
            assert isinstance(integrity, dict)
            parent_refs = integrity["parent_refs"]
            assert isinstance(parent_refs, list)
            parent_refs[-1] = scope_a
            return payload

        rewrite_chain_payloads(self.database, collapse_second_scope)
        self.ledger = JobLedger(self.database)
        self.assertTrue(self.ledger.verify_chain())
        before = self.ledger.event_count()
        unrelated = claim_keywords(
            "job-unrelated-after-over-cap",
            budget_scope_ref=f"budget-scope:sha256:{'c' * 64}",
        )
        for label, arguments in (
            ("exact-replay", first),
            ("unrelated-new-claim", unrelated),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                LedgerError, "persisted budget scope exceeds its hard cap"
            ):
                self.ledger.claim(**arguments)
            self.assertEqual(self.ledger.event_count(), before)
            self.assertTrue(self.ledger.verify_chain())

    def test_causally_inverted_completion_blocks_replay_and_new_claim(self) -> None:
        original = claim_keywords("job-inverted-completion")
        self.ledger.claim(**original)
        self.ledger.complete(
            job_id=original["job_id"],
            attempt_id=original["attempt_id"],
            fencing_epoch=original["fencing_epoch"],
            fencing_token=original["fencing_token"],
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        self.ledger.close()
        invert_claim_completion_causality(self.database)
        self.ledger = JobLedger(self.database)
        self.assertTrue(self.ledger.verify_chain())
        before = self.ledger.event_count()
        for label, arguments in (
            ("exact-replay", original),
            ("unrelated-new-claim", claim_keywords("job-after-inverted-completion")),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                LedgerError, "completion does not follow its claim"
            ):
                self.ledger.claim(**arguments)
            self.assertEqual(self.ledger.event_count(), before)
            self.assertTrue(self.ledger.verify_chain())

    def test_completion_timestamp_cannot_precede_claim(self) -> None:
        arguments = claim_keywords("job-inverted-completion-time")
        self.ledger.claim(**arguments)
        before = self.ledger.event_count()
        with self.assertRaisesRegex(
            LedgerError, "completion does not follow its claim"
        ):
            self.ledger.complete(
                job_id=arguments["job_id"],
                attempt_id=arguments["attempt_id"],
                fencing_epoch=arguments["fencing_epoch"],
                fencing_token=arguments["fencing_token"],
                result_sha256=RESULT_SHA,
                event_at="2026-01-02T03:04:04Z",
            )
        self.assertEqual(self.ledger.event_count(), before)
        self.assertTrue(self.ledger.verify_chain())

    def test_projection_precedes_replay_and_pause_blocks_only_new_claim(self) -> None:
        malformed = claim_keywords("job-paused-malformed-projection")
        self.ledger.claim(**malformed)
        self.ledger.pause_global(
            actor="uid:1000",
            reason="synthetic projection ordering hold",
            authority_ref="authority:synthetic-offline",
            idempotency_key="pause-projection-ordering",
            event_at=AT,
        )
        self.ledger.close()
        rewrite_chain_payloads(
            self.database,
            expire_first_reservation_at_admission,
        )
        self.ledger = JobLedger(self.database)
        self.assertTrue(self.ledger.is_globally_paused())
        before = self.ledger.event_count()
        with self.assertRaisesRegex(LedgerError, "expires at or before admission"):
            self.ledger.claim(**malformed)
        self.assertEqual(self.ledger.event_count(), before)

        valid_database = Path(self.temporary_directory.name) / "valid-paused.sqlite3"
        valid = JobLedger(valid_database)
        valid_claim = claim_keywords("job-paused-valid-replay")
        try:
            original = valid.claim(**valid_claim)
            valid.pause_global(
                actor="uid:1000",
                reason="synthetic valid replay hold",
                authority_ref="authority:synthetic-offline",
                idempotency_key="pause-valid-replay",
                event_at=AT,
            )
            valid_before = valid.event_count()
            replay = valid.claim(**valid_claim)
            self.assertEqual(replay.sequence, original.sequence)
            self.assertEqual(replay.event_sha256, original.event_sha256)
            self.assertEqual(valid.event_count(), valid_before)
            with self.assertRaisesRegex(LedgerError, "global pause blocks job claims"):
                valid.claim(**claim_keywords("job-paused-new-claim"))
            self.assertEqual(valid.event_count(), valid_before)
            self.assertTrue(valid.verify_chain())
        finally:
            valid.close()

    def test_fixed_charge_capacity_is_cumulative_and_atomic(self) -> None:
        first = claim_keywords(
            "job-cap-a",
            reservation_cost_units=2,
            scope_limit_cost_units=3,
        )
        first_event = self.ledger.claim(**first)
        self.ledger.complete(
            job_id=first["job_id"],
            attempt_id=first["attempt_id"],
            fencing_epoch=first["fencing_epoch"],
            fencing_token=first["fencing_token"],
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        blocked = claim_keywords(
            "job-cap-b",
            reservation_cost_units=2,
            scope_limit_cost_units=3,
        )
        with self.assertRaisesRegex(LedgerError, "hard cap exceeded"):
            self.ledger.claim(**blocked)
        self.assertEqual(self.ledger.event_count(), 2)
        admitted = self.ledger.claim(
            **claim_keywords(
                "job-cap-c",
                reservation_cost_units=1,
                scope_limit_cost_units=3,
            )
        )
        self.assertEqual(first_event.sequence, 1)
        self.assertEqual(admitted.sequence, 3)

        race_database = Path(self.temporary_directory.name) / "cap-race.sqlite3"
        JobLedger(race_database).close()
        barrier = threading.Barrier(2)

        def contender(job_id: str) -> str:
            ledger = JobLedger(race_database)
            try:
                barrier.wait(timeout=10)
                ledger.claim(
                    **claim_keywords(
                        job_id,
                        reservation_cost_units=2,
                        scope_limit_cost_units=3,
                    )
                )
                return "admitted"
            except LedgerError:
                return "denied"
            finally:
                ledger.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(contender, ("job-race-a", "job-race-b")))
        self.assertEqual(outcomes.count("admitted"), 1)
        self.assertEqual(outcomes.count("denied"), 1)
        raced = JobLedger(race_database)
        try:
            self.assertEqual(raced.event_count(), 1)
            self.assertTrue(raced.verify_chain())
        finally:
            raced.close()

    def test_budget_receipts_are_exact_atomic_and_deeply_immutable(self) -> None:
        arguments = claim_keywords(
            "job-receipts",
            reservation_cost_units=2,
            scope_limit_cost_units=2,
        )
        claimed = self.ledger.claim(**arguments)
        reservation = claimed.payload["budget_reservation"]
        self.assertEqual(reservation["payload"]["ledger_version_before"], 0)
        self.assertEqual(
            set(reservation["payload"]),
            {
                "trial_ref",
                "job_ref",
                "provider",
                "idempotency_key",
                "hard_limits",
                "ledger_version_before",
                "expires_at",
            },
        )
        completed = self.ledger.complete(
            job_id=arguments["job_id"],
            attempt_id=arguments["attempt_id"],
            fencing_epoch=arguments["fencing_epoch"],
            fencing_token=arguments["fencing_token"],
            result_sha256=RESULT_SHA,
            event_at=AT,
        )
        attestation = completed.payload["provider_accounting_attestation"]
        settlement = completed.payload["settlement_receipt"]
        self.assertEqual(
            set(attestation),
            {
                "schema_id",
                "schema_version",
                "accounting_policy_ref",
                "budget_scope_ref",
                "provider",
                "reservation_ref",
                "actual_usage",
                "actual_cost",
                "released_amount",
                "provider_unknown",
                "settled_at",
            },
        )
        self.assertEqual(attestation["actual_usage"], {"cost_units": 2})
        self.assertEqual(attestation["actual_cost"], 2)
        self.assertEqual(attestation["released_amount"], 0)
        self.assertIs(attestation["provider_unknown"], True)
        self.assertEqual(settlement["payload"]["ledger_version_after"], completed.sequence)
        attestation_sha256 = hashlib.sha256(
            ledger_module._canonical_json(attestation).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            settlement["payload"]["provider_receipt_ref"],
            f"embedded:sha256:{attestation_sha256}",
        )
        with self.assertRaises(TypeError):
            reservation["payload"]["hard_limits"]["cost_units"] = 0
        with self.assertRaises(TypeError):
            attestation["actual_usage"]["cost_units"] = 0
        with self.assertRaises(TypeError):
            settlement["integrity"]["parent_refs"][0] = "changed"
        self.ledger.close()
        self.ledger = JobLedger(self.database)
        replay = self.ledger.claim(**arguments)
        self.assertEqual(replay.event_sha256, claimed.event_sha256)
        self.assertEqual(self.ledger.event_count(), 2)
        self.assertTrue(self.ledger.verify_chain())

    def test_failed_precommit_settlement_validation_leaves_unmatched_charge(self) -> None:
        arguments = claim_keywords(
            "job-settlement-fault",
            reservation_cost_units=1,
            scope_limit_cost_units=1,
        )
        self.ledger.claim(**arguments)
        with mock.patch.object(
            JobLedger,
            "_construct_settlement_receipt",
            return_value={"schema_id": "SettlementReceipt"},
        ):
            with self.assertRaises(LedgerError):
                self.ledger.complete(
                    job_id=arguments["job_id"],
                    attempt_id=arguments["attempt_id"],
                    fencing_epoch=arguments["fencing_epoch"],
                    fencing_token=arguments["fencing_token"],
                    result_sha256=RESULT_SHA,
                    event_at=AT,
                )
        self.assertEqual(self.ledger.event_count(), 1)
        self.assertEqual(self.ledger.event_count("complete"), 0)
        with self.assertRaisesRegex(LedgerError, "hard cap exceeded"):
            self.ledger.claim(
                **claim_keywords(
                    "job-after-settlement-fault",
                    reservation_cost_units=1,
                    scope_limit_cost_units=1,
                )
            )
        self.assertEqual(self.ledger.event_count(), 1)
        self.assertTrue(self.ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
