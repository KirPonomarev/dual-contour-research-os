from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import research_bridge.execution as execution_module  # noqa: E402
import research_bridge.validation as validation_module  # noqa: E402
from research_bridge.admission import canonical_json_sha256 as admission_sha256  # noqa: E402
from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.execution import (  # noqa: E402
    ExecutionError,
    ExecutionRecord,
    OfflineExecutionCoordinator,
)
from research_bridge.ingestion import TrustedIngestor  # noqa: E402
from research_bridge.kernel import BridgeKernel  # noqa: E402
from tests.test_stage1_authority_policy import (  # noqa: E402
    SYNTHETIC_POLICY_SHA256,
    synthetic_authority,
)
from research_bridge.l0 import DeterministicL0Runner  # noqa: E402
from research_bridge.ledger import JobLedger  # noqa: E402
from research_bridge.validation import (  # noqa: E402
    ValidationBoundary,
    ValidationBoundaryError,
    ValidationProjection,
)


NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
FROZEN_TEMPLATE_SHA256 = "53e75c79888c60b304c0e7e5392a53c0ef508146dfd51c5dcb195a648a54f0c6"
INPUT_A = b"public synthetic reference input A\n"
INPUT_B = b"public synthetic reference input B\n"
INPUT_REFS = (
    f"cas:sha256:{hashlib.sha256(INPUT_A).hexdigest()}",
    f"cas:sha256:{hashlib.sha256(INPUT_B).hexdigest()}",
)
IMAGE_SHA256 = hashlib.sha256(b"synthetic-offline-reference-environment").hexdigest()
POLICY_SHA256 = SYNTHETIC_POLICY_SHA256
ACCOUNTING_POLICY_REF = f"budget-policy:sha256:{'a' * 64}"
BUDGET_SCOPE_REF = f"budget-scope:sha256:{'b' * 64}"


def _authority_verifier():
    return synthetic_authority(lease_issuer=("researchd", "researchd"))
PROTOCOL_REF = "research-bridge:l0:chunk-sha256:v1"
VALIDATION_POLICY_REF = "policy:synthetic-offline-reference-v1"
VALIDATOR_ID = "synthetic-reference-validator"
VALIDATOR_SHA256 = hashlib.sha256(b"synthetic-reference-validator").hexdigest()
REGISTRY_IDENTITY = "synthetic-reference-registry"
PROPOSED_SENTINEL = "synthetic-opaque-proposal"
REASON_SENTINEL = "synthetic-opaque-reason"
OUTCOME_REF = "outcome:synthetic-reference-only"
PROJECTION_FIELDS = (
    "execution_ref",
    "validation_ref",
    "domain_link_ref",
    "protocol_ref",
    "artifact_refs",
    "registry_identity",
    "registry_revision",
    "applied_outcome_ref",
    "policy_ref",
    "contour",
    "classification",
)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _seal(document: dict[str, object]) -> dict[str, object]:
    integrity = document["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = admission_sha256(document["payload"])
    return document


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _authority(
    classification: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    suffix = "d0" if classification == "D0_PUBLIC" else "d1"
    job_spec = _seal(
        {
            "schema_id": "JobSpec",
            "schema_version": "1.0.0",
            "object_id": f"job-synthetic-reference-{suffix}",
            "issued_at": _timestamp(NOW - timedelta(minutes=2)),
            "issuer": {
                "id": "synthetic-admission-controller",
                "authority_class": "admission-controller",
            },
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "protocol_ref": PROTOCOL_REF,
                "code_ref": f"sha256:{FROZEN_TEMPLATE_SHA256}",
                "input_refs": list(INPUT_REFS),
                "image_digest": f"sha256:{IMAGE_SHA256}",
                "runner_profile": "L0",
                "network_policy": "offline",
                "resource_limits": {"cost_units": 2},
                "checkpoint_strategy": "single-final-checkpoint",
                "expected_output_contract": "StagingEnvelope@1.0.0",
                "idempotency_key": f"synthetic-reference-{suffix}",
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )
    permit = _seal(
        {
            "schema_id": "Permit",
            "schema_version": "1.0.0",
            "object_id": f"permit-synthetic-reference-{suffix}",
            "issued_at": _timestamp(NOW - timedelta(minutes=1)),
            "issuer": {
                "id": "synthetic-permit-authority",
                "authority_class": "permit-authority",
            },
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "subject": f"runner-synthetic-reference-{suffix}",
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
                    "trial_ref": f"trial:synthetic-reference-{suffix}",
                },
                "network_class": "offline",
                "not_before": _timestamp(NOW - timedelta(seconds=30)),
                "expires_at": _timestamp(NOW + timedelta(minutes=10)),
                "max_uses": 1,
                "nonce": f"synthetic-reference-nonce-{suffix}",
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
            "object_id": f"lease-synthetic-reference-{suffix}",
            "issued_at": _timestamp(NOW - timedelta(seconds=15)),
            "issuer": {"id": "researchd", "authority_class": "researchd"},
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "attempt_id": f"attempt-synthetic-reference-{suffix}",
                "permit_ref": permit["object_id"],
                "job_ref": job_spec["object_id"],
                "runner_identity": permit["payload"]["subject"],  # type: ignore[index]
                "fencing_epoch": 17,
                "fencing_token": f"synthetic-reference-fence-{suffix}",
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
        self.values = dict(values or zip(INPUT_REFS, (INPUT_A, INPUT_B), strict=True))
        self.calls: list[str] = []

    def __call__(self, ref: str) -> bytes:
        self.calls.append(ref)
        return self.values[ref]


class _LoggingLedger:
    def __init__(self, raw: JobLedger, event_log: list[str]) -> None:
        self.raw = raw
        self.event_log = event_log
        self.completion_event: object | None = None

    def claim(self, **keywords: object) -> object:
        event = self.raw.claim(**keywords)  # type: ignore[arg-type]
        self.event_log.append("claim")
        return event

    def checkpoint(self, **keywords: object) -> object:
        event = self.raw.checkpoint(**keywords)  # type: ignore[arg-type]
        self.event_log.append("ledger-checkpoint")
        return event

    def complete(self, **keywords: object) -> object:
        event = self.raw.complete(**keywords)  # type: ignore[arg-type]
        self.completion_event = event
        self.event_log.append("ledger-complete")
        return event


class _LoggingRunner:
    def __init__(self, raw: DeterministicL0Runner, event_log: list[str]) -> None:
        self.raw = raw
        self.event_log = event_log

    def run(self, *args: object) -> object:
        result = self.raw.run(*args)  # type: ignore[arg-type]
        self.event_log.append("l0-run")
        return result


class _LoggingCheckpointStore:
    def __init__(self, raw: ContentAddressedStore, event_log: list[str]) -> None:
        self.raw = raw
        self.event_log = event_log

    def publish(self, *args: object, **keywords: object) -> object:
        publication = self.raw.publish(*args, **keywords)  # type: ignore[arg-type]
        self.event_log.append("checkpoint-cas")
        return publication


class _LoggingIngestor:
    def __init__(self, raw: TrustedIngestor, event_log: list[str]) -> None:
        self.raw = raw
        self.event_log = event_log

    def ingest(self, *args: object) -> tuple[object, ...]:
        records = self.raw.ingest(*args)  # type: ignore[arg-type]
        self.event_log.append("artifact-ingestion")
        return records


@dataclass
class _Environment:
    root: Path
    database_path: Path
    checkpoint_root: Path
    artifact_root: Path
    staging_root: Path
    job_spec: dict[str, object]
    permit: dict[str, object]
    lease: dict[str, object]
    reader: _InputReader
    raw_ledger: JobLedger
    ledger: _LoggingLedger
    checkpoint_store: ContentAddressedStore
    artifact_store: ContentAddressedStore
    coordinator: OfflineExecutionCoordinator
    event_log: list[str]
    fence_calls: list[dict[str, object]]


@dataclass
class _VerticalResult:
    record: ExecutionRecord
    validation_receipt: dict[str, object]
    domain_link_receipt: dict[str, object]
    projection: ValidationProjection


def _environment(
    root: Path,
    classification: str,
    *,
    reader: _InputReader | None = None,
) -> _Environment:
    job_spec, permit, lease = _authority(classification)
    event_log: list[str] = []
    database_path = root / "bridge-job-ledger.sqlite3"
    checkpoint_root = root / "checkpoint-cas"
    artifact_root = root / "artifact-cas"
    staging_root = root / "staging"
    staging_root.mkdir()
    raw_ledger = JobLedger(database_path)
    ledger = _LoggingLedger(raw_ledger, event_log)
    checkpoint_store = ContentAddressedStore(checkpoint_root, quota_bytes=1_048_576)
    artifact_store = ContentAddressedStore(artifact_root, quota_bytes=1_048_576)
    actual_reader = reader or _InputReader()
    runner = _LoggingRunner(
        DeterministicL0Runner(
            actual_reader,
            chunk_size=7,
            clock=lambda: NOW,
            runner_identity=lease["payload"]["runner_identity"],  # type: ignore[index]
        ),
        event_log,
    )
    fence_calls: list[dict[str, object]] = []

    def verify_fence(**keywords: object) -> bool:
        fence_calls.append(dict(keywords))
        lease_payload = lease["payload"]
        assert isinstance(lease_payload, dict)
        return keywords == {
            "attempt_id": lease_payload["attempt_id"],
            "producer_identity": lease_payload["runner_identity"],
            "fencing_token": lease_payload["fencing_token"],
        }

    ingestor = _LoggingIngestor(
        TrustedIngestor(
            artifact_store,
            fence_verifier=verify_fence,
            clock=lambda: NOW,
            issuer_id="researchd-trusted-ingestor",
        ),
        event_log,
    )
    coordinator = OfflineExecutionCoordinator(
        BridgeKernel(ledger, authority=_authority_verifier()),
        ledger,
        runner,
        _LoggingCheckpointStore(checkpoint_store, event_log),
        ingestor,
    )
    return _Environment(
        root=root,
        database_path=database_path,
        checkpoint_root=checkpoint_root,
        artifact_root=artifact_root,
        staging_root=staging_root,
        job_spec=job_spec,
        permit=permit,
        lease=lease,
        reader=actual_reader,
        raw_ledger=raw_ledger,
        ledger=ledger,
        checkpoint_store=checkpoint_store,
        artifact_store=artifact_store,
        coordinator=coordinator,
        event_log=event_log,
        fence_calls=fence_calls,
    )


def _synthetic_external_receipts(
    execution_receipt: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    payload = execution_receipt["payload"]
    assert isinstance(payload, Mapping)
    execution_ref = f"execution:{execution_receipt['object_id']}"
    artifact_refs = list(payload["artifact_refs"])
    validation = _seal(
        {
            "schema_id": "ValidationReceipt",
            "schema_version": "1.0.0",
            "object_id": "validation-synthetic-reference",
            "issued_at": _timestamp(NOW + timedelta(minutes=1)),
            "issuer": {
                "id": VALIDATOR_ID,
                "authority_class": "pinned-validator",
            },
            "contour": execution_receipt["contour"],
            "classification": execution_receipt["classification"],
            "payload": {
                "protocol_ref": PROTOCOL_REF,
                "execution_ref": execution_ref,
                "artifact_refs": artifact_refs,
                "validator_id": VALIDATOR_ID,
                "validator_sha256": VALIDATOR_SHA256,
                "holdout_access_ref": "holdout:none-synthetic",
                "checks_performed": [{"synthetic_check": "opaque"}],
                "metrics": {"synthetic_metric": 0},
                "tolerances": {"synthetic_tolerance": 0},
                "proposed_outcome": PROPOSED_SENTINEL,
                "reasons": [REASON_SENTINEL],
                "reproducibility_class": "synthetic-reproducible",
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [execution_ref, *artifact_refs],
            },
        }
    )
    validation_ref = f"validation:{validation['object_id']}"
    domain_link = _seal(
        {
            "schema_id": "DomainTrialLinkReceipt",
            "schema_version": "1.0.0",
            "object_id": "domain-link-synthetic-reference",
            "issued_at": _timestamp(NOW + timedelta(minutes=2)),
            "issuer": {
                "id": REGISTRY_IDENTITY,
                "authority_class": "domain-registry-writer",
            },
            "contour": execution_receipt["contour"],
            "classification": execution_receipt["classification"],
            "payload": {
                "domain_trial_id": "trial-synthetic-reference",
                "bridge_execution_ref": execution_ref,
                "protocol_ref": PROTOCOL_REF,
                "registry_identity": REGISTRY_IDENTITY,
                "registry_revision": "revision-synthetic-reference-1",
                "applied_outcome_ref": OUTCOME_REF,
                "policy_ref": VALIDATION_POLICY_REF,
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [execution_ref, validation_ref],
            },
        }
    )
    return validation, domain_link


def _run_reference_vertical(environment: _Environment) -> _VerticalResult:
    record = environment.coordinator.execute(
        environment.job_spec,
        environment.permit,
        environment.lease,
        environment.staging_root,
        now=NOW,
    )
    validation_receipt, domain_link_receipt = _synthetic_external_receipts(
        record.execution_receipt
    )
    environment.event_log.append("synthetic-external-receipts")
    projection = ValidationBoundary(
        expected_validator_id=VALIDATOR_ID,
        expected_validator_sha256=VALIDATOR_SHA256,
        expected_registry_identity=REGISTRY_IDENTITY,
    ).verify(
        record.execution_receipt,
        validation_receipt,
        domain_link_receipt,
        expected_protocol_ref=PROTOCOL_REF,
        expected_policy_ref=VALIDATION_POLICY_REF,
    )
    environment.event_log.append("reference-projection")
    return _VerticalResult(
        record=record,
        validation_receipt=validation_receipt,
        domain_link_receipt=domain_link_receipt,
        projection=projection,
    )


def _bridge_state(
    environment: _Environment,
    record: ExecutionRecord,
) -> tuple[object, ...]:
    checkpoint_ref = record.checkpoint_manifest["payload"]["payload_ref"]
    artifact_refs = tuple(item.artifact_ref for item in record.artifact_records)
    return (
        environment.raw_ledger.event_count(),
        environment.raw_ledger.event_count("claim"),
        environment.raw_ledger.event_count("checkpoint"),
        environment.raw_ledger.event_count("complete"),
        environment.raw_ledger.verify_chain(),
        environment.checkpoint_store.object_count(),
        environment.checkpoint_store.used_bytes(),
        environment.checkpoint_store.verify(checkpoint_ref),
        environment.artifact_store.object_count(),
        environment.artifact_store.used_bytes(),
        tuple(environment.artifact_store.verify(ref) for ref in artifact_refs),
    )


class Stage1ReferenceVerticalTests(unittest.TestCase):
    def test_real_d0_and_d1_reference_vertical_is_durable_ordered_and_reference_only(
        self,
    ) -> None:
        for classification in ("D0_PUBLIC", "D1_INTERNAL_SANITIZED"):
            with self.subTest(classification=classification), tempfile.TemporaryDirectory() as temporary:
                environment = _environment(Path(temporary), classification)
                real_manifest_constructor = execution_module._construct_checkpoint_manifest
                real_receipt_constructor = execution_module._construct_execution_receipt
                receipt_preconditions: list[tuple[object, ...]] = []

                def construct_manifest(**keywords: object) -> object:
                    environment.event_log.append("checkpoint-manifest")
                    return real_manifest_constructor(**keywords)  # type: ignore[arg-type]

                def construct_receipt(**keywords: object) -> object:
                    receipt_preconditions.append(
                        (
                            environment.raw_ledger.event_count(),
                            environment.raw_ledger.verify_chain(),
                            environment.checkpoint_store.object_count(),
                            environment.artifact_store.object_count(),
                        )
                    )
                    environment.event_log.append("execution-receipt")
                    return real_receipt_constructor(**keywords)  # type: ignore[arg-type]

                try:
                    with mock.patch.object(
                        execution_module,
                        "_construct_checkpoint_manifest",
                        side_effect=construct_manifest,
                    ), mock.patch.object(
                        execution_module,
                        "_construct_execution_receipt",
                        side_effect=construct_receipt,
                    ):
                        result = _run_reference_vertical(environment)

                    self.assertEqual(
                        environment.event_log,
                        [
                            "claim",
                            "l0-run",
                            "checkpoint-cas",
                            "ledger-checkpoint",
                            "checkpoint-manifest",
                            "artifact-ingestion",
                            "ledger-complete",
                            "execution-receipt",
                            "synthetic-external-receipts",
                            "reference-projection",
                        ],
                    )
                    self.assertEqual(receipt_preconditions, [(3, True, 1, 1)])
                    self.assertIs(environment.ledger.raw, environment.raw_ledger)
                    self.assertEqual(environment.reader.calls, list(INPUT_REFS))
                    self.assertEqual(len(environment.fence_calls), 1)

                    receipt = result.record.execution_receipt
                    receipt_payload = receipt["payload"]
                    self.assertEqual(receipt["schema_id"], "ExecutionReceipt")
                    self.assertEqual(receipt["classification"], classification)
                    self.assertEqual(
                        receipt_payload["exit_classification"], "mechanical-success"
                    )
                    self.assertEqual(environment.raw_ledger.event_count(), 3)
                    self.assertTrue(environment.raw_ledger.verify_chain())
                    checkpoint_ref = result.record.checkpoint_manifest["payload"][
                        "payload_ref"
                    ]
                    self.assertTrue(environment.checkpoint_store.verify(checkpoint_ref))
                    self.assertEqual(environment.checkpoint_store.object_count(), 1)
                    artifact_refs = tuple(
                        item.artifact_ref for item in result.record.artifact_records
                    )
                    self.assertEqual(tuple(receipt_payload["artifact_refs"]), artifact_refs)
                    self.assertEqual(environment.artifact_store.object_count(), 1)
                    self.assertTrue(
                        all(environment.artifact_store.verify(ref) for ref in artifact_refs)
                    )
                    self.assertEqual(
                        receipt_payload["event_chain_head"],
                        environment.ledger.completion_event.event_sha256,  # type: ignore[union-attr]
                    )
                    completion_event = environment.ledger.completion_event
                    assert completion_event is not None
                    settlement_parent = completion_event.payload[
                        "settlement_receipt"
                    ]["object_id"]
                    self.assertRegex(
                        settlement_parent,
                        r"^settlement-receipt-[a-f0-9]{64}$",
                    )
                    self.assertEqual(
                        tuple(receipt["integrity"]["parent_refs"]),
                        (
                            result.record.checkpoint_manifest["object_id"],
                            *artifact_refs,
                            settlement_parent,
                            f"ledger:{completion_event.event_sha256}",
                        ),
                    )

                    projection = result.projection
                    self.assertEqual(
                        tuple(field.name for field in fields(ValidationProjection)),
                        PROJECTION_FIELDS,
                    )
                    self.assertEqual(
                        projection.execution_ref,
                        f"execution:{receipt['object_id']}",
                    )
                    self.assertEqual(projection.artifact_refs, artifact_refs)
                    self.assertEqual(projection.protocol_ref, PROTOCOL_REF)
                    self.assertEqual(projection.policy_ref, VALIDATION_POLICY_REF)
                    self.assertEqual(projection.classification, classification)
                    self.assertFalse(hasattr(projection, "__dict__"))
                    with self.assertRaises((AttributeError, TypeError)):
                        projection.registry_revision = "changed"  # type: ignore[misc]

                    serialized_receipt = json.dumps(_plain(receipt), sort_keys=True)
                    serialized_projection = json.dumps(
                        {
                            field: _plain(getattr(projection, field))
                            for field in PROJECTION_FIELDS
                        },
                        sort_keys=True,
                    )
                    lease_payload = environment.lease["payload"]
                    assert isinstance(lease_payload, dict)
                    for forbidden in (
                        lease_payload["fencing_token"],
                        str(environment.staging_root),
                        INPUT_A.decode("utf-8").strip(),
                        INPUT_B.decode("utf-8").strip(),
                        PROPOSED_SENTINEL,
                        REASON_SENTINEL,
                        "checks_performed",
                        "metrics",
                        "tolerances",
                        "reasons",
                        "domain_trial_id",
                    ):
                        self.assertNotIn(forbidden, serialized_receipt)
                        self.assertNotIn(forbidden, serialized_projection)
                    self.assertNotIn(OUTCOME_REF, serialized_receipt)
                    self.assertIn(OUTCOME_REF, serialized_projection)
                    self.assertNotIn(PROPOSED_SENTINEL, repr(projection))

                    environment.raw_ledger.close()
                    with JobLedger(environment.database_path) as reopened_ledger:
                        self.assertEqual(reopened_ledger.event_count(), 3)
                        self.assertTrue(reopened_ledger.verify_chain())
                    reopened_checkpoint_store = ContentAddressedStore(
                        environment.checkpoint_root,
                        quota_bytes=1_048_576,
                    )
                    reopened_artifact_store = ContentAddressedStore(
                        environment.artifact_root,
                        quota_bytes=1_048_576,
                    )
                    self.assertEqual(reopened_checkpoint_store.object_count(), 1)
                    self.assertTrue(reopened_checkpoint_store.verify(checkpoint_ref))
                    self.assertEqual(reopened_artifact_store.object_count(), 1)
                    self.assertTrue(
                        all(reopened_artifact_store.verify(ref) for ref in artifact_refs)
                    )
                finally:
                    environment.raw_ledger.close()

    def test_invalid_validation_or_domain_link_has_zero_bridge_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = _environment(
                Path(temporary), "D1_INTERNAL_SANITIZED"
            )
            try:
                result = _run_reference_vertical(environment)
                before = _bridge_state(environment, result.record)
                event_log_before = tuple(environment.event_log)

                invalid_validation = copy.deepcopy(result.validation_receipt)
                invalid_validation["payload"]["proposed_outcome"] = "tampered"  # type: ignore[index]
                invalid_link = copy.deepcopy(result.domain_link_receipt)
                invalid_link["integrity"]["parent_refs"] = []  # type: ignore[index]

                boundary = ValidationBoundary(
                    expected_validator_id=VALIDATOR_ID,
                    expected_validator_sha256=VALIDATOR_SHA256,
                    expected_registry_identity=REGISTRY_IDENTITY,
                )
                for label, validation, link in (
                    (
                        "validation-integrity",
                        invalid_validation,
                        result.domain_link_receipt,
                    ),
                    (
                        "domain-parent",
                        result.validation_receipt,
                        invalid_link,
                    ),
                ):
                    with self.subTest(label=label), mock.patch.object(
                        validation_module,
                        "ValidationProjection",
                        wraps=ValidationProjection,
                    ) as projection_constructor:
                        with self.assertRaises(ValidationBoundaryError):
                            boundary.verify(
                                result.record.execution_receipt,
                                validation,
                                link,
                                expected_protocol_ref=PROTOCOL_REF,
                                expected_policy_ref=VALIDATION_POLICY_REF,
                            )
                        self.assertEqual(projection_constructor.call_count, 0)
                        self.assertEqual(_bridge_state(environment, result.record), before)
                        self.assertEqual(tuple(environment.event_log), event_log_before)
            finally:
                environment.raw_ledger.close()

    def test_execution_prerequisite_failure_produces_no_receipt_or_projection(
        self,
    ) -> None:
        bad_reader = _InputReader(
            {
                INPUT_REFS[0]: b"different synthetic bytes",
                INPUT_REFS[1]: INPUT_B,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            environment = _environment(
                Path(temporary),
                "D0_PUBLIC",
                reader=bad_reader,
            )
            result: _VerticalResult | None = None
            try:
                with mock.patch.object(
                    execution_module,
                    "_construct_execution_receipt",
                    wraps=execution_module._construct_execution_receipt,
                ) as receipt_constructor, mock.patch.object(
                    validation_module.ValidationBoundary,
                    "verify",
                    autospec=True,
                ) as validation_call:
                    with self.assertRaises(ExecutionError):
                        result = _run_reference_vertical(environment)

                self.assertIsNone(result)
                self.assertEqual(receipt_constructor.call_count, 0)
                self.assertEqual(validation_call.call_count, 0)
                self.assertEqual(environment.event_log, ["claim"])
                self.assertEqual(environment.raw_ledger.event_count(), 1)
                self.assertEqual(environment.raw_ledger.event_count("claim"), 1)
                self.assertTrue(environment.raw_ledger.verify_chain())
                self.assertEqual(environment.checkpoint_store.object_count(), 0)
                self.assertEqual(environment.artifact_store.object_count(), 0)
                self.assertEqual(list(environment.staging_root.iterdir()), [])
                self.assertEqual(bad_reader.calls, [INPUT_REFS[0]])
                self.assertEqual(environment.fence_calls, [])
            finally:
                environment.raw_ledger.close()


if __name__ == "__main__":
    unittest.main()
