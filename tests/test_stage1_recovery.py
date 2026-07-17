from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import research_bridge.ledger as ledger_module  # noqa: E402
from research_bridge.cas import CASError, ContentAddressedStore  # noqa: E402
from research_bridge.execution import (  # noqa: E402
    ExecutionError,
    OfflineExecutionCoordinator,
)
from research_bridge.ingestion import TrustedIngestor  # noqa: E402
from research_bridge.kernel import BridgeKernel  # noqa: E402
from research_bridge.l0 import DeterministicL0Runner  # noqa: E402
from research_bridge.ledger import JobLedger, LedgerError  # noqa: E402
from tests.test_stage1_ledger import (  # noqa: E402
    AT,
    RESULT_SHA,
    STATE_SHA,
    checkpoint,
    claim,
)
from tests.test_stage1_reference_vertical import (  # noqa: E402
    INPUT_A,
    INPUT_B,
    INPUT_REFS,
    NOW,
    _authority,
    _authority_verifier,
)


CHECKPOINT_AT = "2026-01-02T03:04:06Z"
COMPLETE_AT = "2026-01-02T03:04:07Z"


class _InputReader:
    def __init__(self) -> None:
        self.values = dict(zip(INPUT_REFS, (INPUT_A, INPUT_B), strict=True))

    def __call__(self, ref: str) -> bytes:
        return self.values[ref]


class _CountingRunner:
    def __init__(self, raw: DeterministicL0Runner) -> None:
        self.raw = raw
        self.calls = 0

    def run(self, *arguments: object) -> object:
        self.calls += 1
        return self.raw.run(*arguments)  # type: ignore[arg-type]


def _coordinator(
    *,
    ledger: JobLedger,
    checkpoint_store: ContentAddressedStore,
    artifact_store: ContentAddressedStore,
    lease: dict[str, object],
) -> tuple[OfflineExecutionCoordinator, _CountingRunner]:
    lease_payload = lease["payload"]
    assert isinstance(lease_payload, dict)
    runner = _CountingRunner(
        DeterministicL0Runner(
            _InputReader(),
            chunk_size=7,
            clock=lambda: NOW,
            runner_identity=lease_payload["runner_identity"],  # type: ignore[arg-type]
        )
    )

    def current_fence(**keywords: object) -> bool:
        return keywords == {
            "attempt_id": lease_payload["attempt_id"],
            "producer_identity": lease_payload["runner_identity"],
            "fencing_token": lease_payload["fencing_token"],
        }

    ingestor = TrustedIngestor(
        artifact_store,
        fence_verifier=current_fence,
        clock=lambda: NOW,
        issuer_id="researchd-trusted-ingestor",
    )
    return (
        OfflineExecutionCoordinator(
            BridgeKernel(ledger, authority=_authority_verifier()),
            ledger,
            runner,
            checkpoint_store,
            ingestor,
        ),
        runner,
    )


def _checkpoint_call(
    ledger: JobLedger,
    *,
    event_at: str = CHECKPOINT_AT,
    state_sha256: str = STATE_SHA,
    token: str = "fence-a",
) -> object:
    return ledger.checkpoint(
        job_id="job-a",
        attempt_id="attempt-a",
        fencing_epoch=7,
        fencing_token=token,
        sequence=0,
        state_sha256=state_sha256,
        payload_ref="cas:synthetic-state-a",
        payload_stored_in_domain_vault=False,
        event_at=event_at,
    )


def _complete_call(
    ledger: JobLedger,
    *,
    result_sha256: str = RESULT_SHA,
    event_at: str = COMPLETE_AT,
    token: str = "fence-a",
) -> object:
    return ledger.complete(
        job_id="job-a",
        attempt_id="attempt-a",
        fencing_epoch=7,
        fencing_token=token,
        result_sha256=result_sha256,
        event_at=event_at,
    )


def _rewrite_chain(
    database: Path,
    mutate: object,
) -> None:
    trigger_sql = next(
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
        for persisted in rows:
            row = dict(persisted)
            payload = json.loads(row["payload_json"])
            mutate(row, payload)  # type: ignore[operator]
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
                """
                UPDATE bridge_job_ledger
                SET checkpoint_sequence = ?, event_at = ?, payload_json = ?,
                    previous_sha256 = ?, event_sha256 = ?
                WHERE sequence = ?
                """,
                (
                    row["checkpoint_sequence"],
                    row["event_at"],
                    ledger_module._canonical_json(payload),
                    previous_sha256,
                    event_sha256,
                    row["sequence"],
                ),
            )
            previous_sha256 = event_sha256
        connection.execute(trigger_sql)


def _append_checkpoint_after_completion(database: Path) -> None:
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.row_factory = sqlite3.Row
        tail = connection.execute(
            "SELECT * FROM bridge_job_ledger ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert tail is not None
        token_sha256 = hashlib.sha256(b"fence-a").hexdigest()
        payload = {
            "attempt_id": "attempt-a",
            "event_at": COMPLETE_AT,
            "fencing_epoch": 7,
            "fencing_token_sha256": token_sha256,
            "job_id": "job-a",
            "payload_ref": "cas:synthetic-state-a",
            "payload_stored_in_domain_vault": False,
            "sequence": 0,
            "state_sha256": STATE_SHA,
        }
        sequence = int(tail["sequence"]) + 1
        material = JobLedger._hash_material(
            sequence=sequence,
            event_type="checkpoint",
            job_id="job-a",
            attempt_id="attempt-a",
            fencing_epoch=7,
            event_at=COMPLETE_AT,
            payload=payload,
            previous_sha256=tail["event_sha256"],
        )
        connection.execute(
            """
            INSERT INTO bridge_job_ledger (
                sequence, event_type, job_id, attempt_id, fencing_epoch,
                checkpoint_sequence, event_at, payload_json,
                previous_sha256, event_sha256
            ) VALUES (?, 'checkpoint', 'job-a', 'attempt-a', 7, 0, ?, ?, ?, ?)
            """,
            (
                sequence,
                COMPLETE_AT,
                ledger_module._canonical_json(payload),
                tail["event_sha256"],
                hashlib.sha256(material).hexdigest(),
            ),
        )


class FinalCheckpointReopenRecoveryTests(unittest.TestCase):
    def test_exact_checkpoint_and_completion_replay_after_reopen_is_zero_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "ledger.sqlite3"
            ledger = JobLedger(database)
            claim(ledger)
            checkpoint_event = _checkpoint_call(ledger)
            completion_event = _complete_call(ledger)
            before = ledger.event_count()
            self.assertEqual(
                _checkpoint_call(
                    ledger,
                    event_at="2026-01-02T03:04:54Z",
                ).event_sha256,
                checkpoint_event.event_sha256,
            )
            self.assertEqual(
                _complete_call(ledger).event_sha256,
                completion_event.event_sha256,
            )
            for operation in (
                lambda: _checkpoint_call(
                    ledger,
                    state_sha256=hashlib.sha256(b"same-session-conflict").hexdigest(),
                ),
                lambda: _complete_call(
                    ledger,
                    result_sha256=hashlib.sha256(b"same-session-conflict").hexdigest(),
                ),
            ):
                with self.assertRaises(LedgerError):
                    operation()
                self.assertEqual(ledger.event_count(), before)
            ledger.close()

            reopened = JobLedger(database)
            try:
                before = reopened.event_count()
                checkpoint_replay = _checkpoint_call(
                    reopened,
                    event_at="2026-01-02T03:04:55Z",
                )
                completion_replay = _complete_call(reopened)
                self.assertEqual(
                    checkpoint_replay.event_sha256,
                    checkpoint_event.event_sha256,
                )
                self.assertEqual(checkpoint_replay.event_at, CHECKPOINT_AT)
                self.assertEqual(
                    completion_replay.event_sha256,
                    completion_event.event_sha256,
                )
                self.assertEqual(reopened.event_count(), before)

                reopened.pause_global(
                    actor="uid:1000",
                    reason="synthetic recovery hold",
                    authority_ref="authority:synthetic-offline",
                    idempotency_key="pause-recovery-replay",
                    event_at="2026-01-02T03:04:08Z",
                )
                before = reopened.event_count()
                self.assertEqual(
                    _checkpoint_call(
                        reopened,
                        event_at="2026-01-02T03:04:59Z",
                    ).event_sha256,
                    checkpoint_event.event_sha256,
                )
                self.assertEqual(
                    _complete_call(reopened).event_sha256,
                    completion_event.event_sha256,
                )
                self.assertEqual(reopened.event_count(), before)

                for operation in (
                    lambda: _checkpoint_call(
                        reopened,
                        state_sha256=hashlib.sha256(b"conflict").hexdigest(),
                    ),
                    lambda: _checkpoint_call(reopened, token="stale-fence"),
                    lambda: _complete_call(
                        reopened,
                        result_sha256=hashlib.sha256(b"conflict").hexdigest(),
                    ),
                    lambda: _complete_call(
                        reopened,
                        event_at="2026-01-02T03:04:08Z",
                    ),
                ):
                    with self.assertRaises(LedgerError):
                        operation()
                    self.assertEqual(reopened.event_count(), before)
                self.assertTrue(reopened.verify_chain())
            finally:
                reopened.close()

    def test_new_checkpoint_and_completion_causality_is_zero_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = JobLedger(Path(temporary) / "ledger.sqlite3")
            try:
                claim(ledger)
                before = ledger.event_count()
                with self.assertRaisesRegex(LedgerError, "precedes its claim"):
                    _checkpoint_call(
                        ledger,
                        event_at="2026-01-02T03:04:04Z",
                    )
                self.assertEqual(ledger.event_count(), before)

                _checkpoint_call(ledger)
                before = ledger.event_count()
                with self.assertRaisesRegex(
                    LedgerError,
                    "precedes its latest checkpoint",
                ):
                    _complete_call(ledger, event_at=AT)
                self.assertEqual(ledger.event_count(), before)
                _complete_call(ledger)
                self.assertTrue(ledger.verify_chain())
            finally:
                ledger.close()

    def test_chain_valid_checkpoint_projection_corruption_and_causality_fail_closed(
        self,
    ) -> None:
        mutations = {
            "invalid-state-digest": lambda row, payload: payload.update(
                {"state_sha256": "invalid"}
            )
            if row["event_type"] == "checkpoint"
            else None,
            "checkpoint-before-claim-time": lambda row, payload: (
                row.update({"event_at": "2026-01-02T03:04:04Z"}),
                payload.update({"event_at": "2026-01-02T03:04:04Z"}),
            )
            if row["event_type"] == "checkpoint"
            else None,
            "checkpoint-sequence-gap": lambda row, payload: (
                row.update({"checkpoint_sequence": 1}),
                payload.update({"sequence": 1}),
            )
            if row["event_type"] == "checkpoint"
            else None,
            "checkpoint-after-completion-time": lambda row, payload: (
                row.update({"event_at": "2026-01-02T03:04:08Z"}),
                payload.update({"event_at": "2026-01-02T03:04:08Z"}),
            )
            if row["event_type"] == "checkpoint"
            else None,
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "ledger.sqlite3"
                ledger = JobLedger(database)
                claim(ledger)
                _checkpoint_call(ledger)
                _complete_call(ledger)
                ledger.close()
                _rewrite_chain(database, mutate)

                reopened = JobLedger(database)
                try:
                    self.assertTrue(reopened.verify_chain())
                    before = reopened.event_count()
                    with self.assertRaises(LedgerError):
                        _complete_call(reopened)
                    self.assertEqual(reopened.event_count(), before)
                finally:
                    reopened.close()

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "ledger.sqlite3"
            ledger = JobLedger(database)
            claim(ledger)
            _complete_call(ledger)
            ledger.close()
            _append_checkpoint_after_completion(database)
            reopened = JobLedger(database)
            try:
                self.assertTrue(reopened.verify_chain())
                before = reopened.event_count()
                with self.assertRaisesRegex(
                    LedgerError,
                    "does not follow every checkpoint",
                ):
                    _complete_call(reopened)
                self.assertEqual(reopened.event_count(), before)
            finally:
                reopened.close()

    def test_deterministic_same_attempt_rerun_preserves_artifact_and_capacity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "ledger.sqlite3"
            checkpoint_root = root / "checkpoint-cas"
            artifact_root = root / "artifact-cas"
            job, permit, lease = _authority("D0_PUBLIC")

            first_staging = root / "first-staging"
            first_staging.mkdir()
            ledger = JobLedger(database)
            checkpoint_store = ContentAddressedStore(
                checkpoint_root, quota_bytes=1_048_576
            )
            artifact_store = ContentAddressedStore(
                artifact_root, quota_bytes=1_048_576
            )
            coordinator, first_runner = _coordinator(
                ledger=ledger,
                checkpoint_store=checkpoint_store,
                artifact_store=artifact_store,
                lease=lease,
            )
            first = coordinator.execute(job, permit, lease, first_staging, now=NOW)
            first_result_bytes = (first_staging / "result.json").read_bytes()
            first_artifact_ref = first.artifact_records[0].artifact_ref
            first_complete_payload = json.loads(
                ledger._connection.execute(
                    "SELECT payload_json FROM bridge_job_ledger "
                    "WHERE event_type = 'complete'"
                ).fetchone()[0]
            )
            first_state = (
                ledger.event_count(),
                checkpoint_store.object_count(),
                checkpoint_store.used_bytes(),
                artifact_store.object_count(),
                artifact_store.used_bytes(),
            )
            ledger.close()

            second_staging = root / "second-staging"
            second_staging.mkdir()
            reopened = JobLedger(database)
            reopened_checkpoint_store = ContentAddressedStore(
                checkpoint_root, quota_bytes=1_048_576
            )
            reopened_artifact_store = ContentAddressedStore(
                artifact_root, quota_bytes=1_048_576
            )
            reopened_coordinator, second_runner = _coordinator(
                ledger=reopened,
                checkpoint_store=reopened_checkpoint_store,
                artifact_store=reopened_artifact_store,
                lease=lease,
            )
            try:
                second = reopened_coordinator.execute(
                    job, permit, lease, second_staging, now=NOW
                )
                second_result_bytes = (second_staging / "result.json").read_bytes()
                second_complete_payload = json.loads(
                    reopened._connection.execute(
                        "SELECT payload_json FROM bridge_job_ledger "
                        "WHERE event_type = 'complete'"
                    ).fetchone()[0]
                )
                self.assertEqual(first_runner.calls, 1)
                self.assertEqual(second_runner.calls, 1)
                self.assertEqual(first_result_bytes, second_result_bytes)
                self.assertEqual(
                    hashlib.sha256(second_result_bytes).hexdigest(),
                    first_artifact_ref.removeprefix("cas:sha256:"),
                )
                self.assertEqual(
                    second.artifact_records[0].artifact_ref,
                    first_artifact_ref,
                )
                self.assertEqual(
                    second_complete_payload["result_sha256"],
                    first_complete_payload["result_sha256"],
                )
                self.assertEqual(
                    (
                        reopened.event_count(),
                        reopened_checkpoint_store.object_count(),
                        reopened_checkpoint_store.used_bytes(),
                        reopened_artifact_store.object_count(),
                        reopened_artifact_store.used_bytes(),
                    ),
                    first_state,
                )
                self.assertEqual(reopened.event_count("claim"), 1)
                self.assertEqual(reopened.event_count("checkpoint"), 1)
                self.assertEqual(reopened.event_count("complete"), 1)
                projection = reopened._budget_projection_in_transaction()
                self.assertEqual(len(projection), 1)
                self.assertEqual(projection[0].reservation_cost_units, 2)
                self.assertIsNotNone(projection[0].settlement)

                expired_staging = root / "expired-staging"
                expired_staging.mkdir()
                expired_coordinator, expired_runner = _coordinator(
                    ledger=reopened,
                    checkpoint_store=reopened_checkpoint_store,
                    artifact_store=reopened_artifact_store,
                    lease=lease,
                )
                before_expired = reopened.event_count()
                with self.assertRaises(ExecutionError):
                    expired_coordinator.execute(
                        job,
                        permit,
                        lease,
                        expired_staging,
                        now=NOW + timedelta(minutes=11),
                    )
                self.assertEqual(expired_runner.calls, 0)
                self.assertEqual(list(expired_staging.iterdir()), [])
                self.assertEqual(reopened.event_count(), before_expired)
            finally:
                reopened.close()

    def test_corrupt_reopened_checkpoint_cas_rejects_without_ledger_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "ledger.sqlite3"
            checkpoint_root = root / "checkpoint-cas"
            artifact_root = root / "artifact-cas"
            job, permit, lease = _authority("D0_PUBLIC")
            first_staging = root / "first-staging"
            first_staging.mkdir()
            ledger = JobLedger(database)
            checkpoint_store = ContentAddressedStore(
                checkpoint_root, quota_bytes=1_048_576
            )
            artifact_store = ContentAddressedStore(
                artifact_root, quota_bytes=1_048_576
            )
            coordinator, _ = _coordinator(
                ledger=ledger,
                checkpoint_store=checkpoint_store,
                artifact_store=artifact_store,
                lease=lease,
            )
            first = coordinator.execute(job, permit, lease, first_staging, now=NOW)
            checkpoint_ref = first.checkpoint_manifest["payload"]["payload_ref"]
            checkpoint_digest = checkpoint_ref.removeprefix("cas:sha256:")
            before_events = ledger.event_count()
            before_artifacts = artifact_store.object_count()
            ledger.close()

            checkpoint_object = checkpoint_root / "objects" / checkpoint_digest
            original = checkpoint_object.read_bytes()
            os.chmod(checkpoint_object, 0o600)
            checkpoint_object.write_bytes(b"x" + original[1:])
            os.chmod(checkpoint_object, 0o444)

            reopened = JobLedger(database)
            reopened_checkpoint_store = ContentAddressedStore(
                checkpoint_root, quota_bytes=1_048_576
            )
            reopened_artifact_store = ContentAddressedStore(
                artifact_root, quota_bytes=1_048_576
            )
            second_staging = root / "second-staging"
            second_staging.mkdir()
            reopened_coordinator, runner = _coordinator(
                ledger=reopened,
                checkpoint_store=reopened_checkpoint_store,
                artifact_store=reopened_artifact_store,
                lease=lease,
            )
            try:
                with self.assertRaises(ExecutionError):
                    reopened_coordinator.execute(
                        job, permit, lease, second_staging, now=NOW
                    )
                self.assertEqual(runner.calls, 1)
                self.assertEqual(reopened.event_count(), before_events)
                self.assertEqual(
                    reopened_artifact_store.object_count(), before_artifacts
                )
                with self.assertRaises(CASError):
                    reopened_checkpoint_store.verify(checkpoint_ref)
                self.assertTrue(reopened.verify_chain())
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
