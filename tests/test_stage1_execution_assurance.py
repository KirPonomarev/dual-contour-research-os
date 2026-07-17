import ast
import copy
import hashlib
import inspect
import json
import sys
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import research_bridge.execution as execution_module  # noqa: E402
from research_bridge.admission import canonical_json_sha256 as admission_sha256  # noqa: E402
from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.execution import (  # noqa: E402
    ExecutionError,
    ExecutionRecord,
    OfflineExecutionCoordinator,
    canonical_json_sha256,
)
from research_bridge.ingestion import TrustedIngestor  # noqa: E402
from research_bridge.kernel import BridgeKernel  # noqa: E402
from research_bridge.l0 import (  # noqa: E402
    DeterministicL0Runner,
    L0Checkpoint,
    L0Error,
    L0RunResult,
)
from research_bridge.ledger import JobLedger  # noqa: E402
from tests.test_stage1_authority_policy import (  # noqa: E402
    SYNTHETIC_POLICY_SHA256,
    synthetic_authority,
)


NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
FROZEN_TEMPLATE_SHA256 = "53e75c79888c60b304c0e7e5392a53c0ef508146dfd51c5dcb195a648a54f0c6"
INPUT_A = b"public synthetic input A\n"
INPUT_B = b"public synthetic input B\n"
INPUT_REFS = (
    f"cas:sha256:{hashlib.sha256(INPUT_A).hexdigest()}",
    f"cas:sha256:{hashlib.sha256(INPUT_B).hexdigest()}",
)
IMAGE_SHA256 = hashlib.sha256(b"synthetic-offline-environment").hexdigest()
POLICY_SHA256 = SYNTHETIC_POLICY_SHA256
ACCOUNTING_POLICY_REF = f"budget-policy:sha256:{'a' * 64}"
BUDGET_SCOPE_REF = f"budget-scope:sha256:{'b' * 64}"


def _authority_verifier():
    return synthetic_authority()


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _seal(document: dict[str, object]) -> dict[str, object]:
    document["integrity"]["payload_sha256"] = admission_sha256(document["payload"])
    return document


def _authority(
    *,
    classification: str = "D0_PUBLIC",
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    job_spec = _seal(
        {
            "schema_id": "JobSpec",
            "schema_version": "1.0.0",
            "object_id": "job-synthetic-execution-001",
            "issued_at": _timestamp(NOW - timedelta(minutes=2)),
            "issuer": {
                "id": "synthetic-admission-controller",
                "authority_class": "admission-controller",
            },
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "protocol_ref": "research-bridge:l0:chunk-sha256:v1",
                "code_ref": f"sha256:{FROZEN_TEMPLATE_SHA256}",
                "input_refs": list(INPUT_REFS),
                "image_digest": f"sha256:{IMAGE_SHA256}",
                "runner_profile": "L0",
                "network_policy": "offline",
                "resource_limits": {"cost_units": 2},
                "checkpoint_strategy": "single-final-checkpoint",
                "expected_output_contract": "StagingEnvelope@1.0.0",
                "idempotency_key": "synthetic-execution-idempotency-001",
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )
    permit = _seal(
        {
            "schema_id": "Permit",
            "schema_version": "1.0.0",
            "object_id": "permit-synthetic-execution-001",
            "issued_at": _timestamp(NOW - timedelta(minutes=1)),
            "issuer": {
                "id": "synthetic-permit-authority",
                "authority_class": "permit-authority",
            },
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "subject": "runner-synthetic-execution-001",
                "job_spec_sha256": admission_sha256(job_spec),
                "policy_snapshot_sha256": POLICY_SHA256,
                "code_sha256": FROZEN_TEMPLATE_SHA256,
                "input_sha256": admission_sha256(list(INPUT_REFS)),
                "image_digest": f"sha256:{IMAGE_SHA256}",
                "quotas": {
                    "accounting_policy_ref": ACCOUNTING_POLICY_REF,
                    "budget_scope_ref": BUDGET_SCOPE_REF,
                    "claims": 1,
                    "provider": job_spec["payload"]["runner_profile"],
                    "scope_limit": {"cost_units": 3},
                    "trial_ref": "trial:synthetic-execution-001",
                },
                "network_class": "offline",
                "not_before": _timestamp(NOW - timedelta(seconds=30)),
                "expires_at": _timestamp(NOW + timedelta(minutes=10)),
                "max_uses": 1,
                "nonce": "synthetic-execution-nonce-001",
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [job_spec["object_id"]],
            },
        }
    )
    lease = _seal(
        {
            "schema_id": "AttemptLease",
            "schema_version": "1.0.0",
            "object_id": "lease-synthetic-execution-001",
            "issued_at": _timestamp(NOW - timedelta(seconds=15)),
            "issuer": {"id": "synthetic-researchd", "authority_class": "researchd"},
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "attempt_id": "attempt-synthetic-execution-001",
                "permit_ref": permit["object_id"],
                "job_ref": job_spec["object_id"],
                "runner_identity": permit["payload"]["subject"],
                "fencing_epoch": 11,
                "fencing_token": "fence-synthetic-execution-011",
                "issued_at": _timestamp(NOW - timedelta(seconds=15)),
                "expires_at": _timestamp(NOW + timedelta(minutes=5)),
                "checkpoint_parent_ref": f"cas:sha256:{'9' * 64}",
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [job_spec["object_id"], permit["object_id"]],
            },
        }
    )
    return job_spec, permit, lease


class _InputReader:
    def __init__(self, values: Mapping[str, bytes] | None = None) -> None:
        self.calls: list[str] = []
        self.values = (
            dict(values)
            if values is not None
            else dict(zip(INPUT_REFS, (INPUT_A, INPUT_B), strict=True))
        )

    def __call__(self, ref: str) -> bytes:
        self.calls.append(ref)
        return self.values[ref]


class DeterministicL0AssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.job_spec, self.permit, self.lease = _authority()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _run(
        self,
        root_name: str,
        *,
        job_spec: dict[str, object] | None = None,
        reader: _InputReader | None = None,
    ) -> tuple[L0RunResult, _InputReader, Path]:
        staging_root = Path(self.temporary_directory.name) / root_name
        staging_root.mkdir()
        actual_reader = reader or _InputReader()
        runner = DeterministicL0Runner(
            actual_reader,
            chunk_size=7,
            clock=lambda: NOW,
            runner_identity=self.lease["payload"]["runner_identity"],
        )
        result = runner.run(job_spec or self.job_spec, self.lease, staging_root)
        return result, actual_reader, staging_root

    def test_single_frozen_template_is_deterministic_and_writes_exact_outputs(self) -> None:
        first, first_reader, first_root = self._run("first")
        second, second_reader, second_root = self._run("second")

        self.assertIsInstance(first, L0RunResult)
        self.assertIsInstance(first.checkpoint, L0Checkpoint)
        self.assertEqual(first_reader.calls, list(INPUT_REFS))
        self.assertEqual(second_reader.calls, list(INPUT_REFS))
        self.assertEqual(
            sorted(path.name for path in first_root.iterdir()),
            ["checkpoint.json", "result.json"],
        )
        self.assertEqual(
            (first_root / "checkpoint.json").read_bytes(),
            (second_root / "checkpoint.json").read_bytes(),
        )
        self.assertEqual(
            (first_root / "result.json").read_bytes(),
            (second_root / "result.json").read_bytes(),
        )
        self.assertEqual(first, second)
        self.assertEqual(first.code_sha256, FROZEN_TEMPLATE_SHA256)
        self.assertEqual(first.input_sha256, self.permit["payload"]["input_sha256"])
        self.assertEqual(first.environment_digest, self.job_spec["payload"]["image_digest"])
        self.assertEqual(first.started_at, first.ended_at)
        self.assertEqual(first.checkpoint.sequence, 0)

        checkpoint_bytes = (first_root / first.checkpoint.relative_path).read_bytes()
        self.assertEqual(len(checkpoint_bytes), first.checkpoint.size_bytes)
        checkpoint_document = json.loads(checkpoint_bytes)
        self.assertEqual(
            set(checkpoint_document),
            {
                "completed_ranges",
                "input_sha256",
                "sequence",
                "state_sha256",
                "template_sha256",
            },
        )
        self.assertEqual(checkpoint_document["state_sha256"], first.checkpoint.state_sha256)
        self.assertEqual(checkpoint_document["completed_ranges"], list(first.checkpoint.completed_ranges))
        self.assertTrue(checkpoint_bytes.endswith(b"\n"))
        self.assertNotIn(b"\n", checkpoint_bytes[:-1])
        envelope = first.staging_envelope
        self.assertEqual(envelope["classification"], "D0_PUBLIC")
        entries = envelope["payload"]["relative_file_manifest"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["relative_path"], "result.json")
        result_bytes = (first_root / "result.json").read_bytes()
        self.assertEqual(entries[0]["sha256"], hashlib.sha256(result_bytes).hexdigest())
        self.assertEqual(entries[0]["size_bytes"], len(result_bytes))
        result_document = json.loads(result_bytes)
        self.assertEqual(
            set(result_document),
            {"chunks", "environment_digest", "input_sha256", "inputs", "template_sha256"},
        )
        self.assertTrue(result_bytes.endswith(b"\n"))
        self.assertNotIn(b"\n", result_bytes[:-1])
        state_material = {
            "chunks": result_document["chunks"],
            "completed_ranges": checkpoint_document["completed_ranges"],
            "input_sha256": result_document["input_sha256"],
            "inputs": result_document["inputs"],
            "template_sha256": FROZEN_TEMPLATE_SHA256,
        }
        self.assertEqual(first.checkpoint.state_sha256, canonical_json_sha256(state_material))
        self.assertEqual(
            [item["sha256"] for item in result_document["inputs"]],
            [hashlib.sha256(INPUT_A).hexdigest(), hashlib.sha256(INPUT_B).hexdigest()],
        )

        serialized_outputs = checkpoint_bytes + result_bytes
        self.assertNotIn(INPUT_A, serialized_outputs)
        self.assertNotIn(INPUT_B, serialized_outputs)
        self.assertNotIn(str(first_root).encode("utf-8"), serialized_outputs)
        self.assertNotIn(b"scientific_outcome", serialized_outputs)

    def test_d1_uses_the_same_frozen_template_and_semantic_state_binds_input_bytes(self) -> None:
        job_spec, _, lease = _authority(classification="D1_INTERNAL_SANITIZED")
        staging_root = Path(self.temporary_directory.name) / "d1"
        staging_root.mkdir()
        first = DeterministicL0Runner(
            _InputReader(),
            chunk_size=7,
            clock=lambda: NOW,
            runner_identity=lease["payload"]["runner_identity"],
        ).run(job_spec, lease, staging_root)
        self.assertEqual(first.staging_envelope["classification"], "D1_INTERNAL_SANITIZED")
        self.assertEqual(first.code_sha256, FROZEN_TEMPLATE_SHA256)

        changed_bytes = b"public synthetic changed input A\n"
        changed_ref = f"cas:sha256:{hashlib.sha256(changed_bytes).hexdigest()}"
        changed_job = copy.deepcopy(job_spec)
        changed_job["payload"]["input_refs"][0] = changed_ref
        _seal(changed_job)
        changed_root = Path(self.temporary_directory.name) / "d1-changed"
        changed_root.mkdir()
        changed_reader = _InputReader(
            {
                changed_ref: changed_bytes,
                INPUT_REFS[1]: INPUT_B,
            }
        )
        changed = DeterministicL0Runner(
            changed_reader,
            chunk_size=7,
            clock=lambda: NOW,
            runner_identity=lease["payload"]["runner_identity"],
        ).run(changed_job, lease, changed_root)
        self.assertNotEqual(changed.checkpoint.state_sha256, first.checkpoint.state_sha256)
        self.assertNotEqual(changed.input_sha256, first.input_sha256)

    def test_unknown_template_or_nonoffline_profile_writes_nothing(self) -> None:
        mutations = (
            ("code_ref", "sha256:" + "0" * 64),
            ("runner_profile", "L1"),
            ("network_policy", "connected"),
            ("checkpoint_strategy", "append-only"),
            ("expected_output_contract", "ExecutionReceipt@1.0.0"),
        )
        for index, (field, value) in enumerate(mutations):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.job_spec)
                candidate["payload"][field] = value
                _seal(candidate)
                reader = _InputReader()
                staging_root = Path(self.temporary_directory.name) / f"denied-{index}"
                staging_root.mkdir()
                runner = DeterministicL0Runner(
                    reader,
                    clock=lambda: NOW,
                    runner_identity=self.lease["payload"]["runner_identity"],
                )
                with self.assertRaises(L0Error):
                    runner.run(candidate, self.lease, staging_root)
                self.assertEqual(reader.calls, [])
                self.assertEqual(list(staging_root.iterdir()), [])

    def test_input_bytes_must_match_portable_cas_ref_before_any_output_write(self) -> None:
        mismatched_reader = _InputReader(
            {
                INPUT_REFS[0]: b"different synthetic bytes",
                INPUT_REFS[1]: INPUT_B,
            }
        )
        staging_root = Path(self.temporary_directory.name) / "input-ref-mismatch"
        staging_root.mkdir()
        runner = DeterministicL0Runner(
            mismatched_reader,
            clock=lambda: NOW,
            runner_identity=self.lease["payload"]["runner_identity"],
        )
        with self.assertRaises(L0Error):
            runner.run(self.job_spec, self.lease, staging_root)
        self.assertEqual(mismatched_reader.calls, [INPUT_REFS[0]])
        self.assertEqual(list(staging_root.iterdir()), [])

    def test_d2_and_d3_are_denied_before_input_read_or_staging_write(self) -> None:
        for index, classification in enumerate(
            ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED")
        ):
            with self.subTest(classification=classification):
                job_spec, _, lease = _authority(classification=classification)
                reader = _InputReader()
                staging_root = Path(self.temporary_directory.name) / f"denied-class-{index}"
                staging_root.mkdir()
                runner = DeterministicL0Runner(
                    reader,
                    clock=lambda: NOW,
                    runner_identity=lease["payload"]["runner_identity"],
                )
                with self.assertRaises(L0Error):
                    runner.run(job_spec, lease, staging_root)
                self.assertEqual(reader.calls, [])
                self.assertEqual(list(staging_root.iterdir()), [])


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _claim_event(
    job_spec: Mapping[str, object],
    permit: Mapping[str, object],
    lease: Mapping[str, object],
) -> SimpleNamespace:
    lease_payload = lease["payload"]
    permit_payload = permit["payload"]
    token_sha256 = hashlib.sha256(
        lease_payload["fencing_token"].encode("utf-8")
    ).hexdigest()
    payload = {
        "admission_digest": "a" * 64,
        "admitted_at": _timestamp(NOW),
        "attempt_id": lease_payload["attempt_id"],
        "fencing_epoch": lease_payload["fencing_epoch"],
        "fencing_token_sha256": token_sha256,
        "job_id": job_spec["object_id"],
        "permit_id": permit["object_id"],
        "permit_nonce_sha256": hashlib.sha256(
            permit_payload["nonce"].encode("utf-8")
        ).hexdigest(),
        "runner_identity": permit_payload["subject"],
    }
    return SimpleNamespace(
        sequence=1,
        event_type="claim",
        job_id=job_spec["object_id"],
        attempt_id=lease_payload["attempt_id"],
        fencing_epoch=lease_payload["fencing_epoch"],
        event_at=_timestamp(NOW),
        payload=payload,
        previous_sha256="0" * 64,
        event_sha256="a" * 64,
    )


class _KernelSpy:
    def __init__(self, event_log: list[str], claim_event: object, error: Exception | None = None) -> None:
        self.event_log = event_log
        self.claim_event = claim_event
        self.error = error
        self.calls: list[tuple[object, object, object, object]] = []

    def claim(
        self,
        job_spec: object,
        permit: object,
        lease: object,
        *,
        now: object,
    ) -> object:
        self.calls.append((job_spec, permit, lease, now))
        if self.error is not None:
            raise self.error
        self.event_log.append("claim")
        return self.claim_event


class _RunnerSpy:
    def __init__(
        self,
        event_log: list[str],
        result: object,
        error: Exception | None = None,
    ) -> None:
        self.event_log = event_log
        self.result = result
        self.error = error
        self.calls: list[tuple[object, object, Path]] = []

    def run(self, job_spec: object, lease: object, staging_root: str | Path) -> object:
        root = Path(staging_root)
        self.calls.append((job_spec, lease, root))
        if self.error is not None:
            raise self.error
        self.event_log.append("runner")
        return self.result


class _CheckpointStoreSpy:
    def __init__(self, event_log: list[str], error: Exception | None = None) -> None:
        self.event_log = event_log
        self.error = error
        self.calls: list[dict[str, object]] = []

    def publish(
        self,
        source_path: str | Path,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> object:
        self.calls.append(
            {
                "source_path": Path(source_path),
                "expected_sha256": expected_sha256,
                "expected_size_bytes": expected_size_bytes,
            }
        )
        if self.error is not None:
            raise self.error
        self.event_log.append("checkpoint_store")
        return SimpleNamespace(
            ref=f"cas:sha256:{expected_sha256}",
            sha256=expected_sha256,
            size_bytes=expected_size_bytes,
            created=True,
        )


class _LedgerSpy:
    def __init__(
        self,
        event_log: list[str],
        *,
        checkpoint_error: Exception | None = None,
        completion_error: Exception | None = None,
    ) -> None:
        self.event_log = event_log
        self.checkpoint_error = checkpoint_error
        self.completion_error = completion_error
        self.checkpoint_calls: list[dict[str, object]] = []
        self.complete_calls: list[dict[str, object]] = []
        self.completion_event = SimpleNamespace(
            sequence=3,
            event_type="complete",
            job_id="job-synthetic-execution-001",
            attempt_id="attempt-synthetic-execution-001",
            fencing_epoch=11,
            event_at=_timestamp(NOW),
            payload={},
            previous_sha256="b" * 64,
            event_sha256="c" * 64,
        )

    def checkpoint(self, **keywords: object) -> object:
        self.checkpoint_calls.append(dict(keywords))
        if self.checkpoint_error is not None:
            raise self.checkpoint_error
        self.event_log.append("ledger_checkpoint")
        payload = {
            "attempt_id": keywords["attempt_id"],
            "event_at": keywords["event_at"],
            "fencing_epoch": keywords["fencing_epoch"],
            "fencing_token_sha256": hashlib.sha256(
                keywords["fencing_token"].encode("utf-8")
            ).hexdigest(),
            "job_id": keywords["job_id"],
            "payload_ref": keywords["payload_ref"],
            "payload_stored_in_domain_vault": keywords[
                "payload_stored_in_domain_vault"
            ],
            "sequence": keywords["sequence"],
            "state_sha256": keywords["state_sha256"],
        }
        return SimpleNamespace(
            sequence=2,
            event_type="checkpoint",
            job_id=keywords["job_id"],
            attempt_id=keywords["attempt_id"],
            fencing_epoch=keywords["fencing_epoch"],
            event_at=keywords["event_at"],
            payload=payload,
            previous_sha256="a" * 64,
            event_sha256="b" * 64,
        )

    def complete(self, **keywords: object) -> object:
        self.complete_calls.append(dict(keywords))
        if self.completion_error is not None:
            raise self.completion_error
        self.event_log.append("completion")
        fencing_token_sha256 = hashlib.sha256(
            keywords["fencing_token"].encode("utf-8")
        ).hexdigest()
        self.completion_event.payload = {
            "attempt_id": keywords["attempt_id"],
            "event_at": keywords["event_at"],
            "fencing_epoch": keywords["fencing_epoch"],
            "fencing_token_sha256": fencing_token_sha256,
            "job_id": keywords["job_id"],
            "result_sha256": keywords["result_sha256"],
        }
        self.completion_event.event_at = keywords["event_at"]
        return self.completion_event


class _IngestorSpy:
    def __init__(self, event_log: list[str], error: Exception | None = None) -> None:
        self.event_log = event_log
        self.error = error
        self.calls: list[tuple[object, Path]] = []

    def ingest(self, staging_envelope: object, staging_root: str | Path) -> tuple[object, ...]:
        self.calls.append((staging_envelope, Path(staging_root)))
        if self.error is not None:
            raise self.error
        self.event_log.append("artifacts")
        artifact_sha256 = "d" * 64
        payload = {
            "artifact_sha256": artifact_sha256,
            "size_bytes": 1,
            "producer": staging_envelope["payload"]["producer_identity"],
            "claim_class": "synthetic-mechanical-result",
            "source_refs": [f"cas:sha256:{'e' * 64}"],
            "redaction_status": "synthetic-sanitized",
            "retention_class": "synthetic-short",
            "validator_ref": "validator:synthetic-independent",
        }
        manifest = {
            "schema_id": "ArtifactManifest",
            "schema_version": "1.0.0",
            "object_id": "artifact-manifest-synthetic-execution",
            "issued_at": _timestamp(NOW),
            "issuer": {
                "id": "synthetic-trusted-ingestor",
                "authority_class": "trusted-ingestor",
            },
            "contour": staging_envelope["contour"],
            "classification": staging_envelope["classification"],
            "payload": payload,
            "integrity": {
                "payload_sha256": canonical_json_sha256(payload),
                "parent_refs": [f"cas:sha256:{artifact_sha256}"],
            },
        }
        return (
            SimpleNamespace(
                artifact_ref=f"cas:sha256:{artifact_sha256}",
                manifest=manifest,
            ),
        )


class OfflineExecutionCoordinatorAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.job_spec, self.permit, self.lease = _authority()
        result_root = self.root / "prepared-result"
        result_root.mkdir()
        self.prepared_result = DeterministicL0Runner(
            _InputReader(),
            chunk_size=7,
            clock=lambda: NOW,
            runner_identity=self.lease["payload"]["runner_identity"],
        ).run(self.job_spec, self.lease, result_root)
        self.prepared_root = result_root

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _components(
        self,
        *,
        claim_event: object | None = None,
        store_error: Exception | None = None,
        checkpoint_error: Exception | None = None,
        ingestion_error: Exception | None = None,
        completion_error: Exception | None = None,
        result: object | None = None,
    ) -> tuple[
        OfflineExecutionCoordinator,
        list[str],
        _RunnerSpy,
        _CheckpointStoreSpy,
        _LedgerSpy,
        _IngestorSpy,
    ]:
        event_log: list[str] = []
        kernel = _KernelSpy(
            event_log,
            claim_event or _claim_event(self.job_spec, self.permit, self.lease),
        )
        runner = _RunnerSpy(event_log, result or self.prepared_result)
        store = _CheckpointStoreSpy(event_log, store_error)
        ledger = _LedgerSpy(
            event_log,
            checkpoint_error=checkpoint_error,
            completion_error=completion_error,
        )
        ingestor = _IngestorSpy(event_log, ingestion_error)
        coordinator = OfflineExecutionCoordinator(kernel, ledger, runner, store, ingestor)
        return coordinator, event_log, runner, store, ledger, ingestor

    def test_invalid_authority_causes_zero_runner_or_staging_writes(self) -> None:
        database = self.root / "authority-ledger.sqlite3"
        ledger = JobLedger(database)
        staging_root = self.root / "authority-denied-staging"
        staging_root.mkdir()

        class WritingRunner:
            def __init__(self) -> None:
                self.calls = 0

            def run(self, *_: object) -> object:
                self.calls += 1
                (staging_root / "unexpected-write").write_text("synthetic")
                return self.prepared_result

        runner = WritingRunner()
        coordinator = OfflineExecutionCoordinator(
            BridgeKernel(ledger, authority=_authority_verifier()),
            ledger,
            runner,
            _CheckpointStoreSpy([]),
            _IngestorSpy([]),
        )
        denied_permit = copy.deepcopy(self.permit)
        denied_permit["payload"]["expires_at"] = _timestamp(NOW - timedelta(seconds=1))
        _seal(denied_permit)
        try:
            with self.assertRaises(ExecutionError):
                coordinator.execute(
                    self.job_spec,
                    denied_permit,
                    self.lease,
                    staging_root,
                    now=NOW,
                )
            self.assertEqual(runner.calls, 0)
            self.assertEqual(list(staging_root.iterdir()), [])
            self.assertEqual(ledger.event_count(), 0)
        finally:
            ledger.close()

    def test_claim_result_and_fence_mismatches_make_zero_checkpoint_store_calls(self) -> None:
        mismatches: list[tuple[str, object, object]] = []
        base_claim = _claim_event(self.job_spec, self.permit, self.lease)

        for name, value in (
            ("job_id", "job-synthetic-other"),
            ("attempt_id", "attempt-synthetic-other"),
            ("fencing_epoch", 12),
        ):
            values = vars(base_claim).copy()
            values[name] = value
            mismatches.append((f"claim {name}", SimpleNamespace(**values), self.prepared_result))

        token_values = vars(base_claim).copy()
        token_values["payload"] = dict(base_claim.payload)
        token_values["payload"]["fencing_token_sha256"] = "f" * 64
        mismatches.append(("claim fence digest", SimpleNamespace(**token_values), self.prepared_result))

        nonce_values = vars(base_claim).copy()
        nonce_values["payload"] = dict(base_claim.payload)
        nonce_values["payload"]["permit_nonce_sha256"] = "e" * 64
        mismatches.append(
            ("claim Permit nonce digest", SimpleNamespace(**nonce_values), self.prepared_result)
        )

        for field, value in (
            ("code_sha256", "1" * 64),
            ("input_sha256", "2" * 64),
            ("environment_digest", "sha256:" + "3" * 64),
        ):
            mismatches.append(
                (
                    f"result {field}",
                    base_claim,
                    replace(self.prepared_result, **{field: value}),
                )
            )

        staging_envelope = _plain(self.prepared_result.staging_envelope)
        staging_envelope["payload"]["fencing_token"] = "fence-synthetic-stale"
        staging_envelope["integrity"]["payload_sha256"] = canonical_json_sha256(
            staging_envelope["payload"]
        )
        mismatches.append(
            (
                "staging fence",
                base_claim,
                replace(self.prepared_result, staging_envelope=staging_envelope),
            )
        )

        for label, claim_event, result in mismatches:
            with self.subTest(label=label):
                coordinator, _, runner, store, ledger, ingestor = self._components(
                    claim_event=claim_event,
                    result=result,
                )
                with self.assertRaises(ExecutionError):
                    coordinator.execute(
                        self.job_spec,
                        self.permit,
                        self.lease,
                        self.prepared_root,
                        now=NOW,
                    )
                self.assertEqual(store.calls, [])
                if label.startswith("claim "):
                    self.assertEqual(runner.calls, [])
                else:
                    self.assertEqual(len(runner.calls), 1)
                self.assertEqual(ledger.checkpoint_calls, [])
                self.assertEqual(ingestor.calls, [])

    def test_malformed_or_symlink_checkpoint_is_denied_before_store(self) -> None:
        malformed_checkpoint = replace(
            self.prepared_result.checkpoint,
            state_sha256="not-a-digest",
        )
        malformed_result = replace(
            self.prepared_result,
            checkpoint=malformed_checkpoint,
        )

        symlink_path = self.prepared_root / "checkpoint-link.json"
        symlink_path.symlink_to(self.prepared_root / "checkpoint.json")
        symlink_checkpoint = replace(
            self.prepared_result.checkpoint,
            relative_path="checkpoint-link.json",
        )
        symlink_result = replace(
            self.prepared_result,
            checkpoint=symlink_checkpoint,
        )

        traversal_checkpoint = replace(
            self.prepared_result.checkpoint,
            relative_path="../checkpoint.json",
        )
        traversal_result = replace(
            self.prepared_result,
            checkpoint=traversal_checkpoint,
        )

        for label, result in (
            ("malformed digest", malformed_result),
            ("symlink", symlink_result),
            ("path traversal", traversal_result),
        ):
            with self.subTest(label=label):
                coordinator, _, _, store, ledger, ingestor = self._components(
                    result=result
                )
                with self.assertRaises(ExecutionError):
                    coordinator.execute(
                        self.job_spec,
                        self.permit,
                        self.lease,
                        self.prepared_root,
                        now=NOW,
                    )
                self.assertEqual(store.calls, [])
                self.assertEqual(ledger.checkpoint_calls, [])
                self.assertEqual(ingestor.calls, [])

    def test_injected_prerequisite_failures_construct_no_execution_record(self) -> None:
        failures = (
            ("checkpoint store", {"store_error": RuntimeError("synthetic CAS failure")}),
            ("ledger checkpoint", {"checkpoint_error": RuntimeError("synthetic ledger failure")}),
            ("ingestion", {"ingestion_error": RuntimeError("synthetic ingestion failure")}),
            ("completion", {"completion_error": RuntimeError("synthetic completion failure")}),
        )
        for label, failure in failures:
            with self.subTest(label=label):
                coordinator, event_log, _, _, _, _ = self._components(**failure)
                constructions: list[object] = []

                def construct_record(*args: object, **keywords: object) -> object:
                    constructions.append((args, keywords))
                    return ExecutionRecord(*args, **keywords)

                with mock.patch.object(
                    execution_module,
                    "ExecutionRecord",
                    side_effect=construct_record,
                ), mock.patch.object(
                    execution_module,
                    "_construct_execution_receipt",
                    wraps=execution_module._construct_execution_receipt,
                ) as receipt_constructor:
                    with self.assertRaises(ExecutionError):
                        coordinator.execute(
                            self.job_spec,
                            self.permit,
                            self.lease,
                            self.prepared_root,
                            now=NOW,
                        )
                self.assertEqual(constructions, [])
                self.assertEqual(receipt_constructor.call_count, 0)
                self.assertNotIn("receipt", event_log)

    def test_d2_and_d3_are_denied_before_claim_or_runner(self) -> None:
        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            with self.subTest(classification=classification):
                job_spec, permit, lease = _authority(classification=classification)
                coordinator, _, runner, store, ledger, ingestor = self._components()
                with self.assertRaises(ExecutionError):
                    coordinator.execute(
                        job_spec,
                        permit,
                        lease,
                        self.prepared_root,
                        now=NOW,
                    )
                self.assertEqual(runner.calls, [])
                self.assertEqual(store.calls, [])
                self.assertEqual(ledger.checkpoint_calls, [])
                self.assertEqual(ingestor.calls, [])

    def test_real_composed_success_is_durable_in_receipt_last_order(self) -> None:
        event_log: list[str] = []
        database = self.root / "composed-ledger.sqlite3"
        raw_ledger = JobLedger(database)
        checkpoint_store = ContentAddressedStore(
            self.root / "checkpoint-cas",
            quota_bytes=1_048_576,
        )
        artifact_store = ContentAddressedStore(
            self.root / "artifact-cas",
            quota_bytes=1_048_576,
        )
        staging_root = self.root / "composed-staging"
        staging_root.mkdir()

        class LoggingLedger:
            def __init__(self) -> None:
                self.completion_event: object | None = None

            def claim(self, **keywords: object) -> object:
                event = raw_ledger.claim(**keywords)
                event_log.append("claim")
                return event

            def checkpoint(self, **keywords: object) -> object:
                event = raw_ledger.checkpoint(**keywords)
                event_log.append("ledger_checkpoint")
                return event

            def complete(self, **keywords: object) -> object:
                event = raw_ledger.complete(**keywords)
                self.completion_event = event
                event_log.append("completion")
                return event

        class LoggingRunner:
            def __init__(self) -> None:
                self.result: object | None = None
                self.runner = DeterministicL0Runner(
                    _InputReader(),
                    chunk_size=7,
                    clock=lambda: NOW,
                    runner_identity=self_outer.lease["payload"]["runner_identity"],
                )

            def run(self, *args: object) -> object:
                result = self.runner.run(*args)
                self.result = result
                event_log.append("runner")
                return result

        class LoggingCheckpointStore:
            def publish(self, *args: object, **keywords: object) -> object:
                publication = checkpoint_store.publish(*args, **keywords)
                event_log.append("checkpoint_store")
                return publication

        fence_calls: list[dict[str, object]] = []

        def verify_fence(**keywords: object) -> bool:
            fence_calls.append(dict(keywords))
            return keywords == {
                "attempt_id": self.lease["payload"]["attempt_id"],
                "producer_identity": self.lease["payload"]["runner_identity"],
                "fencing_token": self.lease["payload"]["fencing_token"],
            }

        raw_ingestor = TrustedIngestor(
            artifact_store,
            fence_verifier=verify_fence,
            clock=lambda: NOW,
            issuer_id="researchd-trusted-ingestor",
        )
        ingestor_inputs: list[object] = []

        class LoggingIngestor:
            def ingest(self, *args: object) -> tuple[object, ...]:
                ingestor_inputs.append(args[0])
                records = raw_ingestor.ingest(*args)
                event_log.append("artifacts")
                return records

        self_outer = self
        logging_ledger = LoggingLedger()
        logging_runner = LoggingRunner()
        coordinator = OfflineExecutionCoordinator(
            BridgeKernel(logging_ledger, authority=_authority_verifier()),
            logging_ledger,
            logging_runner,
            LoggingCheckpointStore(),
            LoggingIngestor(),
        )
        real_checkpoint_constructor = execution_module._construct_checkpoint_manifest
        real_receipt_constructor = execution_module._construct_execution_receipt
        real_record = ExecutionRecord

        def construct_checkpoint(**keywords: object) -> object:
            event_log.append("checkpoint_manifest")
            return real_checkpoint_constructor(**keywords)

        def construct_receipt(**keywords: object) -> object:
            event_log.append("execution_receipt")
            return real_receipt_constructor(**keywords)

        def construct_record(*args: object, **keywords: object) -> ExecutionRecord:
            event_log.append("execution_record")
            return real_record(*args, **keywords)

        try:
            with mock.patch.object(
                execution_module,
                "_construct_checkpoint_manifest",
                side_effect=construct_checkpoint,
            ), mock.patch.object(
                execution_module,
                "_construct_execution_receipt",
                side_effect=construct_receipt,
            ), mock.patch.object(
                execution_module,
                "ExecutionRecord",
                side_effect=construct_record,
            ):
                record = coordinator.execute(
                    self.job_spec,
                    self.permit,
                    self.lease,
                    staging_root,
                    now=NOW,
                )

            self.assertEqual(
                event_log,
                [
                    "claim",
                    "runner",
                    "checkpoint_store",
                    "ledger_checkpoint",
                    "checkpoint_manifest",
                    "artifacts",
                    "completion",
                    "execution_receipt",
                    "execution_record",
                ],
            )
            self.assertIsInstance(record, ExecutionRecord)
            self.assertEqual(raw_ledger.event_count(), 3)
            self.assertTrue(raw_ledger.verify_chain())
            self.assertEqual(checkpoint_store.object_count(), 1)
            self.assertEqual(artifact_store.object_count(), 1)
            self.assertEqual(len(fence_calls), 1)
            self.assertEqual(len(ingestor_inputs), 1)
            ingestor_envelope = ingestor_inputs[0]
            self.assertIsInstance(ingestor_envelope, dict)
            self.assertIsInstance(
                ingestor_envelope["payload"]["relative_file_manifest"],
                list,
            )
            self.assertEqual(
                ingestor_envelope["integrity"]["payload_sha256"],
                canonical_json_sha256(ingestor_envelope["payload"]),
            )
            original_envelope = logging_runner.result.staging_envelope
            self.assertIsInstance(
                original_envelope["payload"]["relative_file_manifest"],
                tuple,
            )
            self.assertIsNot(ingestor_envelope, original_envelope)
            self.assertEqual(_plain(ingestor_envelope), _plain(original_envelope))

            checkpoint_bytes = (staging_root / "checkpoint.json").read_bytes()
            checkpoint_file_sha256 = hashlib.sha256(checkpoint_bytes).hexdigest()
            checkpoint_manifest = record.checkpoint_manifest
            checkpoint_payload = checkpoint_manifest["payload"]
            self.assertEqual(
                set(checkpoint_manifest),
                {
                    "schema_id",
                    "schema_version",
                    "object_id",
                    "issued_at",
                    "issuer",
                    "contour",
                    "classification",
                    "payload",
                    "integrity",
                },
            )
            self.assertEqual(
                set(checkpoint_payload),
                {
                    "run_id",
                    "attempt_id",
                    "fencing_token",
                    "completed_ranges",
                    "state_sha256",
                    "code_sha256",
                    "environment_digest",
                    "sequence",
                    "payload_ref",
                    "payload_stored_in_domain_vault",
                },
            )
            self.assertEqual(checkpoint_payload["sequence"], 0)
            self.assertEqual(
                checkpoint_payload["payload_ref"],
                f"cas:sha256:{checkpoint_file_sha256}",
            )
            self.assertEqual(
                checkpoint_payload["state_sha256"],
                json.loads(checkpoint_bytes)["state_sha256"],
            )
            self.assertNotEqual(checkpoint_payload["state_sha256"], checkpoint_file_sha256)
            self.assertFalse(checkpoint_payload["payload_stored_in_domain_vault"])
            self.assertEqual(
                checkpoint_manifest["integrity"]["payload_sha256"],
                canonical_json_sha256(checkpoint_payload),
            )
            self.assertTrue(checkpoint_store.verify(checkpoint_payload["payload_ref"]))

            receipt = record.execution_receipt
            receipt_payload = receipt["payload"]
            self.assertEqual(
                set(receipt),
                {
                    "schema_id",
                    "schema_version",
                    "object_id",
                    "issued_at",
                    "issuer",
                    "contour",
                    "classification",
                    "payload",
                    "integrity",
                },
            )
            self.assertEqual(
                set(receipt_payload),
                {
                    "permit_ref",
                    "lease_ref",
                    "job_spec_ref",
                    "code_sha256",
                    "input_sha256",
                    "environment_digest",
                    "started_at",
                    "ended_at",
                    "exit_classification",
                    "artifact_refs",
                    "resource_usage",
                    "event_chain_head",
                },
            )
            self.assertEqual(receipt["schema_id"], "ExecutionReceipt")
            self.assertEqual(receipt["classification"], "D0_PUBLIC")
            self.assertEqual(receipt_payload["permit_ref"], self.permit["object_id"])
            self.assertEqual(receipt_payload["lease_ref"], self.lease["object_id"])
            self.assertEqual(receipt_payload["job_spec_ref"], self.job_spec["object_id"])
            self.assertEqual(receipt_payload["code_sha256"], FROZEN_TEMPLATE_SHA256)
            self.assertEqual(receipt_payload["input_sha256"], self.permit["payload"]["input_sha256"])
            self.assertEqual(receipt_payload["environment_digest"], self.job_spec["payload"]["image_digest"])
            self.assertEqual(receipt_payload["exit_classification"], "mechanical-success")
            self.assertEqual(
                tuple(receipt_payload["artifact_refs"]),
                tuple(item.artifact_ref for item in record.artifact_records),
            )
            self.assertEqual(
                receipt_payload["event_chain_head"],
                logging_ledger.completion_event.event_sha256,
            )
            self.assertEqual(
                receipt["integrity"]["payload_sha256"],
                canonical_json_sha256(receipt_payload),
            )
            self.assertTrue(
                all(ref.startswith("cas:sha256:") for ref in receipt_payload["artifact_refs"])
            )

            serialized_receipt = json.dumps(_plain(receipt), sort_keys=True)
            self.assertNotIn(self.lease["payload"]["fencing_token"], serialized_receipt)
            self.assertNotIn(str(staging_root), serialized_receipt)
            self.assertNotIn("scientific_outcome", serialized_receipt)
            with self.assertRaises(TypeError):
                receipt["unexpected"] = True
            with self.assertRaises(TypeError):
                receipt_payload["resource_usage"]["unexpected"] = 1
            with self.assertRaises(TypeError):
                checkpoint_payload["completed_ranges"][0]["input_index"] = 99
            with self.assertRaises(TypeError):
                record.artifact_records[0].manifest["unexpected"] = True
        finally:
            raw_ledger.close()


class Stage1ExecutionStaticBoundaryTests(unittest.TestCase):
    def test_exports_dataclasses_and_signatures_are_exact(self) -> None:
        import research_bridge.l0 as l0_module

        self.assertEqual(
            set(l0_module.__all__),
            {"L0Error", "L0Checkpoint", "L0RunResult", "DeterministicL0Runner"},
        )
        self.assertEqual(
            set(execution_module.__all__),
            {
                "ExecutionError",
                "ExecutionRecord",
                "OfflineExecutionCoordinator",
                "canonical_json_sha256",
            },
        )
        self.assertEqual(
            [field.name for field in fields(L0Checkpoint)],
            ["sequence", "completed_ranges", "state_sha256", "relative_path", "size_bytes"],
        )
        self.assertEqual(
            [field.name for field in fields(L0RunResult)],
            [
                "checkpoint",
                "staging_envelope",
                "started_at",
                "ended_at",
                "resource_usage",
                "code_sha256",
                "input_sha256",
                "environment_digest",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(ExecutionRecord)],
            ["checkpoint_manifest", "artifact_records", "execution_receipt"],
        )

        self.assertEqual(
            {
                name
                for name, value in DeterministicL0Runner.__dict__.items()
                if not name.startswith("_") and callable(value)
            },
            {"run"},
        )
        self.assertEqual(
            {
                name
                for name, value in OfflineExecutionCoordinator.__dict__.items()
                if not name.startswith("_") and callable(value)
            },
            {"execute"},
        )

        l0_constructor = inspect.signature(DeterministicL0Runner)
        self.assertEqual(
            list(l0_constructor.parameters),
            ["input_reader", "chunk_size", "clock", "runner_identity"],
        )
        for name in ("chunk_size", "clock", "runner_identity"):
            self.assertEqual(
                l0_constructor.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        self.assertEqual(l0_constructor.parameters["chunk_size"].default, 65_536)
        self.assertEqual(
            list(inspect.signature(DeterministicL0Runner.run).parameters),
            ["self", "job_spec", "lease", "staging_root"],
        )

        coordinator_constructor = inspect.signature(OfflineExecutionCoordinator)
        self.assertEqual(
            list(coordinator_constructor.parameters),
            ["kernel", "ledger", "runner", "checkpoint_store", "ingestor", "issuer_id"],
        )
        self.assertEqual(
            coordinator_constructor.parameters["issuer_id"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(coordinator_constructor.parameters["issuer_id"].default, "researchd")
        execute = inspect.signature(OfflineExecutionCoordinator.execute)
        self.assertEqual(
            list(execute.parameters),
            ["self", "job_spec", "permit", "lease", "staging_root", "now"],
        )
        self.assertEqual(execute.parameters["now"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual(list(inspect.signature(canonical_json_sha256).parameters), ["value"])

    def test_modules_have_no_process_network_dynamic_code_or_domain_authority(self) -> None:
        forbidden_imports = {
            "aiohttp",
            "asyncio",
            "cryptography",
            "ctypes",
            "fastapi",
            "ftplib",
            "http",
            "httpx",
            "importlib",
            "multiprocessing",
            "pydantic",
            "requests",
            "smtplib",
            "socket",
            "subprocess",
            "urllib",
            "urllib3",
        }
        forbidden_identifier_fragments = {
            "deploy",
            "domain_registry",
            "exploit",
            "live_trade",
            "order_submit",
            "registry_writer",
            "scientific_outcome",
            "target_scan",
        }
        forbidden_calls = {"__import__", "compile", "eval", "exec"}
        imported_roots: set[str] = set()
        identifiers: set[str] = set()
        calls: set[str] = set()

        for filename in ("l0.py", "execution.py"):
            tree = ast.parse((SRC / "research_bridge" / filename).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_roots.update(
                        alias.name.split(".")[0] for alias in node.names
                    )
                elif isinstance(node, ast.ImportFrom) and node.level:
                    imported_roots.add("research_bridge")
                    if filename == "execution.py":
                        self.fail("execution.py must use only injected structural boundaries")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported_roots.add(node.module.split(".")[0])
                elif isinstance(node, ast.Name):
                    identifiers.add(node.id.lower())
                elif isinstance(node, ast.Attribute):
                    identifiers.add(node.attr.lower())
                elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    identifiers.add(node.name.lower())
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    calls.add(node.func.id)

        non_stdlib = {
            root
            for root in imported_roots
            if root not in sys.stdlib_module_names and root != "research_bridge"
        }
        self.assertEqual(non_stdlib, set())
        self.assertTrue(imported_roots.isdisjoint(forbidden_imports))
        self.assertTrue(calls.isdisjoint(forbidden_calls))
        violations = {
            identifier
            for identifier in identifiers
            if any(fragment in identifier for fragment in forbidden_identifier_fragments)
        }
        self.assertEqual(violations, set())


if __name__ == "__main__":
    unittest.main()
