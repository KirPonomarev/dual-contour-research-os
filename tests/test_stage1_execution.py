from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType
from typing import Any, Mapping
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.execution import (
    ExecutionError,
    ExecutionRecord,
    OfflineExecutionCoordinator,
    canonical_json_sha256,
)


AT = "2026-01-02T03:04:05Z"
ENDED_AT = "2026-01-02T03:04:06Z"
ZERO_SHA = "0" * 64
CODE_SHA = hashlib.sha256(b"synthetic-template").hexdigest()
STATE_SHA = hashlib.sha256(b"semantic-state-not-file-bytes").hexdigest()
ARTIFACT_SHA = hashlib.sha256(b"synthetic-artifact").hexdigest()
INPUT_REFS = [
    {
        "input_ref": "fixture:synthetic-input",
        "sha256": hashlib.sha256(b"synthetic-input").hexdigest(),
        "size_bytes": len(b"synthetic-input"),
    }
]
INPUT_SHA = canonical_json_sha256(INPUT_REFS)
ENVIRONMENT = "owned-l0-environment-v1"
TOKEN = "synthetic-fence-token"
TOKEN_SHA = hashlib.sha256(TOKEN.encode("utf-8")).hexdigest()
CHECKPOINT_BYTES = (
    json.dumps(
        {
            "completed_ranges": [
                {
                    "chunk_end_index_exclusive": 1,
                    "chunk_start_index": 0,
                    "input_index": 0,
                }
            ],
            "input_sha256": INPUT_SHA,
            "sequence": 0,
            "state_sha256": STATE_SHA,
            "template_sha256": CODE_SHA,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("utf-8")
CHECKPOINT_FILE_SHA = hashlib.sha256(CHECKPOINT_BYTES).hexdigest()


@dataclass(frozen=True, slots=True)
class Event:
    sequence: int
    event_type: str
    job_id: str
    attempt_id: str
    fencing_epoch: int
    event_at: str
    payload: Mapping[str, object]
    previous_sha256: str
    event_sha256: str


@dataclass(frozen=True, slots=True)
class Checkpoint:
    sequence: int
    completed_ranges: tuple[Mapping[str, int], ...]
    state_sha256: str
    relative_path: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class RunnerResult:
    checkpoint: Checkpoint
    staging_envelope: Mapping[str, Any]
    started_at: str
    ended_at: str
    resource_usage: Mapping[str, Any]
    code_sha256: str
    input_sha256: str
    environment_digest: str


@dataclass(frozen=True, slots=True)
class Publication:
    ref: str
    sha256: str
    size_bytes: int
    created: bool


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_ref: str
    manifest: Mapping[str, Any]


def event_sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class Fixture:
    def __init__(self, root: Path, *, failure: str | None = None) -> None:
        self.root = root
        self.failure = failure
        self.calls: list[str] = []
        self.job = {
            "object_id": "job-synthetic-a",
            "contour": "bridge",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": {
                "image_digest": ENVIRONMENT,
                "input_refs": [dict(INPUT_REFS[0])],
            },
        }
        self.permit = {
            "object_id": "permit-synthetic-a",
            "contour": "bridge",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": {
                "code_sha256": CODE_SHA,
                "input_sha256": INPUT_SHA,
                "nonce": "synthetic-execution-permit-nonce",
            },
        }
        self.lease = {
            "object_id": "lease-synthetic-a",
            "contour": "bridge",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": {
                "job_ref": self.job["object_id"],
                "permit_ref": self.permit["object_id"],
                "attempt_id": "attempt-synthetic-a",
                "fencing_epoch": 3,
                "fencing_token": TOKEN,
                "runner_identity": "owned-offline-runner",
            },
        }
        self.claim_event = Event(
            sequence=1,
            event_type="claim",
            job_id=self.job["object_id"],
            attempt_id=self.lease["payload"]["attempt_id"],
            fencing_epoch=self.lease["payload"]["fencing_epoch"],
            event_at=AT,
            payload=MappingProxyType(
                {
                    "admission_digest": event_sha("admission"),
                    "admitted_at": AT,
                    "attempt_id": self.lease["payload"]["attempt_id"],
                    "fencing_epoch": self.lease["payload"]["fencing_epoch"],
                    "fencing_token_sha256": TOKEN_SHA,
                    "job_id": self.job["object_id"],
                    "permit_id": self.permit["object_id"],
                    "permit_nonce_sha256": hashlib.sha256(
                        self.permit["payload"]["nonce"].encode("utf-8")
                    ).hexdigest(),
                    "runner_identity": self.lease["payload"]["runner_identity"],
                }
            ),
            previous_sha256=ZERO_SHA,
            event_sha256=event_sha("claim"),
        )
        self.checkpoint = Checkpoint(
            sequence=0,
            completed_ranges=(
                MappingProxyType(
                    {
                        "input_index": 0,
                        "chunk_start_index": 0,
                        "chunk_end_index_exclusive": 1,
                    }
                ),
            ),
            state_sha256=STATE_SHA,
            relative_path="checkpoint.json",
            size_bytes=len(CHECKPOINT_BYTES),
        )
        self.staging_payload = MappingProxyType(
            {
                "producer_identity": self.lease["payload"]["runner_identity"],
                "run_id": self.job["object_id"],
                "attempt_id": self.lease["payload"]["attempt_id"],
                "fencing_token": TOKEN,
                "relative_file_manifest": (
                    MappingProxyType(
                        {
                            "relative_path": "artifact.json",
                            "sha256": ARTIFACT_SHA,
                            "size_bytes": len(b"synthetic-artifact"),
                            "claim_class": "mechanical-output",
                            "source_refs": ("fixture:synthetic-input",),
                            "redaction_status": "sanitized",
                            "retention_class": "synthetic-test",
                            "validator_ref": "validator:synthetic",
                        }
                    ),
                ),
                "claimed_metrics": MappingProxyType({"chunks": 1}),
                "completion_reason": "mechanical-success",
            }
        )
        self.staging_envelope = MappingProxyType({
            "schema_id": "StagingEnvelope",
            "schema_version": "1.0.0",
            "object_id": "staging-synthetic-a",
            "issued_at": ENDED_AT,
            "issuer": MappingProxyType(
                {
                    "id": self.lease["payload"]["runner_identity"],
                    "authority_class": "untrusted-runner",
                }
            ),
            "contour": "bridge",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": self.staging_payload,
            "integrity": MappingProxyType(
                {
                    "payload_sha256": canonical_json_sha256(self.staging_payload),
                    "parent_refs": ("job:synthetic",),
                }
            ),
        })
        self.resource_usage = {"chunks": 1, "nested": {"cpu_units": 2}}
        self.runner_result = RunnerResult(
            checkpoint=self.checkpoint,
            staging_envelope=self.staging_envelope,
            started_at=AT,
            ended_at=ENDED_AT,
            resource_usage=self.resource_usage,
            code_sha256=CODE_SHA,
            input_sha256=INPUT_SHA,
            environment_digest=ENVIRONMENT,
        )
        self.artifact_payload = {
            "artifact_sha256": ARTIFACT_SHA,
            "size_bytes": len(b"synthetic-artifact"),
        }
        self.artifact_manifest = {
            "schema_id": "ArtifactManifest",
            "schema_version": "1.0.0",
            "object_id": "artifact-manifest-synthetic-a",
            "issued_at": ENDED_AT,
            "issuer": {"id": "ingestor", "authority_class": "trusted-ingestor"},
            "contour": "bridge",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": self.artifact_payload,
            "integrity": {
                "payload_sha256": canonical_json_sha256(self.artifact_payload),
                "parent_refs": [f"cas:sha256:{ARTIFACT_SHA}"],
            },
        }
        self.artifacts = (
            Artifact(
                artifact_ref=f"cas:sha256:{ARTIFACT_SHA}",
                manifest=self.artifact_manifest,
            ),
        )
        self.checkpoint_arguments: dict[str, Any] | None = None
        self.completion_arguments: dict[str, Any] | None = None
        self.publication_arguments: dict[str, Any] | None = None
        self.ingestor_envelope: Mapping[str, Any] | None = None
        self.kernel = _Kernel(self)
        self.runner = _Runner(self)
        self.store = _Store(self)
        self.ledger = _Ledger(self)
        self.ingestor = _Ingestor(self)

    def coordinator(self) -> OfflineExecutionCoordinator:
        return OfflineExecutionCoordinator(
            self.kernel,
            self.ledger,
            self.runner,
            self.store,
            self.ingestor,
        )

    def execute(self) -> ExecutionRecord:
        return self.coordinator().execute(
            self.job,
            self.permit,
            self.lease,
            self.root,
            now=AT,
        )


class _Kernel:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture

    def claim(self, job_spec: object, permit: object, lease: object, *, now: object) -> Event:
        self.fixture.calls.append("kernel.claim")
        if self.fixture.failure == "kernel.claim":
            raise RuntimeError("synthetic claim failure")
        return self.fixture.claim_event


class _Runner:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture

    def run(self, job_spec: object, lease: object, staging_root: object) -> RunnerResult:
        self.fixture.calls.append("runner.run")
        if self.fixture.failure == "runner.run":
            raise RuntimeError("synthetic runner failure")
        return self.fixture.runner_result


class _Store:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture

    def publish(self, source_path: object, **arguments: Any) -> Publication:
        self.fixture.calls.append("checkpoint_store.publish")
        self.fixture.publication_arguments = {
            "source_path": source_path,
            **arguments,
        }
        if self.fixture.failure == "checkpoint_store.publish":
            raise RuntimeError("synthetic publication failure")
        return Publication(
            ref=f"cas:sha256:{CHECKPOINT_FILE_SHA}",
            sha256=CHECKPOINT_FILE_SHA,
            size_bytes=len(CHECKPOINT_BYTES),
            created=True,
        )


class _Ledger:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture

    def checkpoint(self, **arguments: Any) -> Event:
        self.fixture.calls.append("ledger.checkpoint")
        self.fixture.checkpoint_arguments = dict(arguments)
        if self.fixture.failure == "ledger.checkpoint":
            raise RuntimeError("synthetic checkpoint append failure")
        return Event(
            sequence=2,
            event_type="checkpoint",
            job_id=arguments["job_id"],
            attempt_id=arguments["attempt_id"],
            fencing_epoch=arguments["fencing_epoch"],
            event_at=arguments["event_at"],
            payload=MappingProxyType(
                {
                    "attempt_id": arguments["attempt_id"],
                    "event_at": arguments["event_at"],
                    "fencing_epoch": arguments["fencing_epoch"],
                    "fencing_token_sha256": TOKEN_SHA,
                    "job_id": arguments["job_id"],
                    "payload_ref": arguments["payload_ref"],
                    "payload_stored_in_domain_vault": arguments[
                        "payload_stored_in_domain_vault"
                    ],
                    "sequence": arguments["sequence"],
                    "state_sha256": arguments["state_sha256"],
                }
            ),
            previous_sha256=event_sha("claim"),
            event_sha256=event_sha("checkpoint"),
        )

    def complete(self, **arguments: Any) -> Event:
        self.fixture.calls.append("ledger.complete")
        self.fixture.completion_arguments = dict(arguments)
        if self.fixture.failure == "ledger.complete":
            raise RuntimeError("synthetic completion append failure")
        return Event(
            sequence=3,
            event_type="complete",
            job_id=arguments["job_id"],
            attempt_id=arguments["attempt_id"],
            fencing_epoch=arguments["fencing_epoch"],
            event_at=arguments["event_at"],
            payload=MappingProxyType(
                {
                    "attempt_id": arguments["attempt_id"],
                    "event_at": arguments["event_at"],
                    "fencing_epoch": arguments["fencing_epoch"],
                    "fencing_token_sha256": TOKEN_SHA,
                    "job_id": arguments["job_id"],
                    "result_sha256": arguments["result_sha256"],
                }
            ),
            previous_sha256=event_sha("checkpoint"),
            event_sha256=event_sha("complete"),
        )


class _Ingestor:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture

    def ingest(self, staging_envelope: object, staging_root: object) -> tuple[Artifact, ...]:
        self.fixture.calls.append("ingestor.ingest")
        if self.fixture.failure == "ingestor.ingest":
            raise RuntimeError("synthetic ingestion failure")
        self.fixture.ingestor_envelope = staging_envelope  # type: ignore[assignment]
        return self.fixture.artifacts


class OfflineExecutionCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "checkpoint.json").write_bytes(CHECKPOINT_BYTES)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_success_order_bindings_receipt_last_and_deep_immutability(self) -> None:
        fixture = Fixture(self.root)
        receipt_constructor = sys.modules[
            "research_bridge.execution"
        ]._construct_execution_receipt

        def construct_receipt(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
            fixture.calls.append("execution_receipt.construct")
            return receipt_constructor(*args, **kwargs)

        with mock.patch(
            "research_bridge.execution._construct_execution_receipt",
            side_effect=construct_receipt,
        ) as receipt_builder:
            record = fixture.execute()

        self.assertEqual(
            fixture.calls,
            [
                "kernel.claim",
                "runner.run",
                "checkpoint_store.publish",
                "ledger.checkpoint",
                "ingestor.ingest",
                "ledger.complete",
                "execution_receipt.construct",
            ],
        )
        receipt_builder.assert_called_once()
        self.assertEqual(
            [field.name for field in fields(ExecutionRecord)],
            ["checkpoint_manifest", "artifact_records", "execution_receipt"],
        )
        self.assertEqual(
            fixture.publication_arguments,
            {
                "source_path": self.root / "checkpoint.json",
                "expected_sha256": CHECKPOINT_FILE_SHA,
                "expected_size_bytes": len(CHECKPOINT_BYTES),
            },
        )
        self.assertNotEqual(CHECKPOINT_FILE_SHA, STATE_SHA)
        self.assertEqual(fixture.checkpoint_arguments["state_sha256"], STATE_SHA)
        self.assertEqual(
            fixture.checkpoint_arguments["payload_ref"],
            f"cas:sha256:{CHECKPOINT_FILE_SHA}",
        )
        self.assertFalse(
            fixture.checkpoint_arguments["payload_stored_in_domain_vault"]
        )
        self.assertIsInstance(
            fixture.ingestor_envelope["payload"]["relative_file_manifest"], list
        )
        self.assertIsInstance(
            fixture.ingestor_envelope["payload"]["relative_file_manifest"][0][
                "source_refs"
            ],
            list,
        )
        self.assertIsInstance(fixture.ingestor_envelope["integrity"]["parent_refs"], list)
        self.assertEqual(
            fixture.ingestor_envelope["integrity"]["payload_sha256"],
            canonical_json_sha256(fixture.ingestor_envelope["payload"]),
        )
        checkpoint_payload = record.checkpoint_manifest["payload"]
        self.assertEqual(checkpoint_payload["state_sha256"], STATE_SHA)
        self.assertEqual(
            checkpoint_payload["payload_ref"],
            f"cas:sha256:{CHECKPOINT_FILE_SHA}",
        )
        receipt_payload = record.execution_receipt["payload"]
        self.assertEqual(receipt_payload["permit_ref"], fixture.permit["object_id"])
        self.assertEqual(receipt_payload["lease_ref"], fixture.lease["object_id"])
        self.assertEqual(receipt_payload["job_spec_ref"], fixture.job["object_id"])
        self.assertEqual(receipt_payload["exit_classification"], "mechanical-success")
        self.assertEqual(receipt_payload["event_chain_head"], event_sha("complete"))
        self.assertEqual(
            record.execution_receipt["integrity"]["payload_sha256"],
            canonical_json_sha256(receipt_payload),
        )

        with self.assertRaises(TypeError):
            record.checkpoint_manifest["payload"] = {}  # type: ignore[index]
        with self.assertRaises(TypeError):
            checkpoint_payload["completed_ranges"][0]["input_index"] = 9
        with self.assertRaises(TypeError):
            receipt_payload["resource_usage"]["nested"]["cpu_units"] = 9
        with self.assertRaises((AttributeError, TypeError)):
            record.artifact_records[0].artifact_ref = "cas:sha256:bad"  # type: ignore[misc]

        fixture.resource_usage["nested"]["cpu_units"] = 999
        fixture.artifact_payload["size_bytes"] = 999
        self.assertEqual(receipt_payload["resource_usage"]["nested"]["cpu_units"], 2)
        self.assertEqual(record.artifact_records[0].manifest["payload"]["size_bytes"], 18)

    def test_every_dependency_failure_has_no_receipt_and_stops_later_calls(self) -> None:
        expected_calls = {
            "kernel.claim": ["kernel.claim"],
            "runner.run": ["kernel.claim", "runner.run"],
            "checkpoint_store.publish": [
                "kernel.claim",
                "runner.run",
                "checkpoint_store.publish",
            ],
            "ledger.checkpoint": [
                "kernel.claim",
                "runner.run",
                "checkpoint_store.publish",
                "ledger.checkpoint",
            ],
            "ingestor.ingest": [
                "kernel.claim",
                "runner.run",
                "checkpoint_store.publish",
                "ledger.checkpoint",
                "ingestor.ingest",
            ],
            "ledger.complete": [
                "kernel.claim",
                "runner.run",
                "checkpoint_store.publish",
                "ledger.checkpoint",
                "ingestor.ingest",
                "ledger.complete",
            ],
        }
        for failure, calls in expected_calls.items():
            with self.subTest(failure=failure):
                fixture = Fixture(self.root, failure=failure)
                with mock.patch(
                    "research_bridge.execution._construct_execution_receipt"
                ) as receipt_builder:
                    with self.assertRaises(ExecutionError):
                        fixture.execute()
                self.assertEqual(fixture.calls, calls)
                receipt_builder.assert_not_called()

    def test_malformed_claim_is_rejected_before_runner(self) -> None:
        for label in ("attempt", "permit nonce digest"):
            with self.subTest(label=label):
                fixture = Fixture(self.root)
                values = {
                    field.name: getattr(fixture.claim_event, field.name)
                    for field in fields(Event)
                }
                if label == "attempt":
                    values["attempt_id"] = "stale-attempt"
                else:
                    values["payload"] = MappingProxyType(
                        {
                            **dict(fixture.claim_event.payload),
                            "permit_nonce_sha256": "f" * 64,
                        }
                    )
                fixture.claim_event = Event(**values)
                with self.assertRaises(ExecutionError):
                    fixture.execute()
                self.assertEqual(fixture.calls, ["kernel.claim"])

    def test_authority_and_runner_binding_failures_stop_before_checkpoint_store(self) -> None:
        mutations = {
            "classification": lambda f: f.lease.update(
                {"classification": "D2_DOMAIN_CONFIDENTIAL"}
            ),
            "contour": lambda f: f.permit.update({"contour": "market"}),
            "lease_job": lambda f: f.lease["payload"].update({"job_ref": "other-job"}),
            "permit_input": lambda f: f.permit["payload"].update(
                {"input_sha256": event_sha("wrong-input")}
            ),
            "runner_code": lambda f: setattr(
                f,
                "runner_result",
                RunnerResult(
                    **{
                        **{
                            field.name: getattr(f.runner_result, field.name)
                            for field in fields(RunnerResult)
                        },
                        "code_sha256": event_sha("wrong-code"),
                    }
                ),
            ),
            "staging_fence": lambda f: setattr(
                f,
                "runner_result",
                RunnerResult(
                    **{
                        **{
                            field.name: getattr(f.runner_result, field.name)
                            for field in fields(RunnerResult)
                        },
                        "staging_envelope": {
                            **dict(f.staging_envelope),
                            "payload": {
                                **dict(f.staging_payload),
                                "fencing_token": "stale-token",
                            },
                        },
                    }
                ),
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                fixture = Fixture(self.root)
                mutate(fixture)
                with self.assertRaises(ExecutionError):
                    fixture.execute()
                self.assertNotIn("checkpoint_store.publish", fixture.calls)

    def test_symlink_or_changed_checkpoint_is_rejected_before_publication(self) -> None:
        checkpoint_path = self.root / "checkpoint.json"
        checkpoint_path.unlink()
        target = self.root / "target.json"
        target.write_bytes(CHECKPOINT_BYTES)
        checkpoint_path.symlink_to(target)
        fixture = Fixture(self.root)
        with self.assertRaises(ExecutionError):
            fixture.execute()
        self.assertEqual(fixture.calls, ["kernel.claim", "runner.run"])

        checkpoint_path.unlink()
        checkpoint_path.write_bytes(CHECKPOINT_BYTES + b"x")
        fixture = Fixture(self.root)
        with self.assertRaises(ExecutionError):
            fixture.execute()
        self.assertEqual(fixture.calls, ["kernel.claim", "runner.run"])

    def test_malformed_results_from_each_durable_boundary_stop_following_calls(self) -> None:
        fixture = Fixture(self.root)
        original_publish = fixture.store.publish

        def wrong_publish(*args: Any, **kwargs: Any) -> Publication:
            original_publish(*args, **kwargs)
            return Publication(
                ref=f"cas:sha256:{event_sha('wrong-publication')}",
                sha256=event_sha("wrong-publication"),
                size_bytes=len(CHECKPOINT_BYTES),
                created=True,
            )

        fixture.store.publish = wrong_publish  # type: ignore[method-assign]
        with self.assertRaises(ExecutionError):
            fixture.execute()
        self.assertNotIn("ledger.checkpoint", fixture.calls)

        fixture = Fixture(self.root)
        original_checkpoint = fixture.ledger.checkpoint

        def wrong_checkpoint(**kwargs: Any) -> Event:
            event = original_checkpoint(**kwargs)
            return Event(
                **{
                    **{field.name: getattr(event, field.name) for field in fields(Event)},
                    "attempt_id": "stale-attempt",
                }
            )

        fixture.ledger.checkpoint = wrong_checkpoint  # type: ignore[method-assign]
        with self.assertRaises(ExecutionError):
            fixture.execute()
        self.assertNotIn("ingestor.ingest", fixture.calls)

        fixture = Fixture(self.root)
        fixture.artifact_manifest["integrity"]["payload_sha256"] = event_sha(
            "wrong-manifest"
        )
        with self.assertRaises(ExecutionError):
            fixture.execute()
        self.assertNotIn("ledger.complete", fixture.calls)

        fixture = Fixture(self.root)
        original_complete = fixture.ledger.complete

        def wrong_complete(**kwargs: Any) -> Event:
            event = original_complete(**kwargs)
            return Event(
                **{
                    **{field.name: getattr(event, field.name) for field in fields(Event)},
                    "event_sha256": "bad",
                }
            )

        fixture.ledger.complete = wrong_complete  # type: ignore[method-assign]
        with mock.patch("research_bridge.execution._construct_execution_receipt") as builder:
            with self.assertRaises(ExecutionError):
                fixture.execute()
        builder.assert_not_called()

    def test_constructor_and_canonical_json_reject_invalid_structure(self) -> None:
        fixture = Fixture(self.root)
        with self.assertRaises(ExecutionError):
            OfflineExecutionCoordinator(
                object(),
                fixture.ledger,
                fixture.runner,
                fixture.store,
                fixture.ingestor,
            )
        with self.assertRaises(ExecutionError):
            OfflineExecutionCoordinator(
                fixture.kernel,
                fixture.ledger,
                fixture.runner,
                fixture.store,
                fixture.ingestor,
                issuer_id=" local-path/id ",
            )
        for value in [b"payload", {1: "non-text"}, {"value": float("nan")}, object()]:
            with self.subTest(value=type(value).__name__), self.assertRaises(ExecutionError):
                canonical_json_sha256(value)


if __name__ == "__main__":
    unittest.main()
