from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, FrozenInstanceError
from datetime import datetime, timezone
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge.l0 import (
    DeterministicL0Runner,
    L0Checkpoint,
    L0Error,
    L0RunResult,
)


TEMPLATE = "research-bridge:l0:chunk-sha256:v1"
CODE_SHA256 = hashlib.sha256(TEMPLATE.encode("ascii")).hexdigest()
IMAGE_DIGEST = f"sha256:{'7' * 64}"
INPUT_BYTES = [b"RAW-SYNTHETIC-INPUT-ONE", b"second-synthetic-input"]
INPUT_REFS = [
    f"cas:sha256:{hashlib.sha256(value).hexdigest()}" for value in INPUT_BYTES
]
COMMON_KEYS = {
    "schema_id",
    "schema_version",
    "object_id",
    "issued_at",
    "issuer",
    "contour",
    "classification",
    "payload",
    "integrity",
}
JOB_PAYLOAD_KEYS = {
    "protocol_ref",
    "code_ref",
    "input_refs",
    "image_digest",
    "runner_profile",
    "network_policy",
    "resource_limits",
    "checkpoint_strategy",
    "expected_output_contract",
    "idempotency_key",
}
LEASE_PAYLOAD_KEYS = {
    "attempt_id",
    "permit_ref",
    "job_ref",
    "runner_identity",
    "fencing_epoch",
    "fencing_token",
    "issued_at",
    "expires_at",
    "checkpoint_parent_ref",
}


def canonical_bytes(value: object, *, newline: bool = False) -> bytes:
    suffix = "\n" if newline else ""
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + suffix
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def seal(document: dict[str, object]) -> dict[str, object]:
    document["integrity"] = {
        "payload_sha256": canonical_sha256(document["payload"]),
        "parent_refs": [],
    }
    return document


def job_spec(*, classification: str = "D1_INTERNAL_SANITIZED") -> dict[str, object]:
    return seal(
        {
            "schema_id": "JobSpec",
            "schema_version": "1.0.0",
            "object_id": "job-l0-synthetic",
            "issued_at": "2026-07-16T21:00:00Z",
            "issuer": {
                "id": "admission-synthetic",
                "authority_class": "admission-controller",
            },
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "protocol_ref": "protocol:synthetic-offline-v1",
                "code_ref": f"sha256:{CODE_SHA256}",
                "input_refs": list(INPUT_REFS),
                "image_digest": IMAGE_DIGEST,
                "runner_profile": "L0",
                "network_policy": "offline",
                "resource_limits": {"synthetic_memory_bytes": 1_000_000},
                "checkpoint_strategy": "single-final-checkpoint",
                "expected_output_contract": "StagingEnvelope@1.0.0",
                "idempotency_key": "idempotency-l0-synthetic",
            },
        }
    )


def attempt_lease(
    *, classification: str = "D1_INTERNAL_SANITIZED"
) -> dict[str, object]:
    return seal(
        {
            "schema_id": "AttemptLease",
            "schema_version": "1.0.0",
            "object_id": "lease-l0-synthetic",
            "issued_at": "2026-07-16T21:30:00Z",
            "issuer": {"id": "researchd", "authority_class": "researchd"},
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "attempt_id": "attempt-l0-synthetic",
                "permit_ref": "permit-l0-synthetic",
                "job_ref": "job-l0-synthetic",
                "runner_identity": "bridge-l0-runner",
                "fencing_epoch": 5,
                "fencing_token": "synthetic-fencing-token-never-in-files",
                "issued_at": "2026-07-16T21:30:00Z",
                "expires_at": "2026-07-16T23:00:00Z",
                "checkpoint_parent_ref": f"cas:sha256:{'3' * 64}",
            },
        }
    )


def reseal(document: dict[str, object]) -> None:
    document["integrity"]["payload_sha256"] = canonical_sha256(  # type: ignore[index]
        document["payload"]
    )


def thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {key: thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [thaw(item) for item in value]
    return value


class ReaderSpy:
    def __init__(self, values: dict[str, object]) -> None:
        self.values = values
        self.calls: list[str] = []

    def __call__(self, ref: str) -> bytes:
        self.calls.append(ref)
        value = self.values[ref]
        if isinstance(value, Exception):
            raise value
        return value  # type: ignore[return-value]


class ClockSequence:
    def __init__(self, *values: object) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> object:
        value = self.values[self.calls]
        self.calls += 1
        if isinstance(value, Exception):
            raise value
        return value


class DeterministicL0RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input_values = dict(zip(INPUT_REFS, INPUT_BYTES, strict=True))

    def clock(self) -> ClockSequence:
        return ClockSequence(
            datetime(2026, 7, 16, 22, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 7, 16, 22, 0, 1, tzinfo=timezone.utc),
        )

    def runner(
        self,
        *,
        reader: ReaderSpy | None = None,
        clock: ClockSequence | None = None,
        chunk_size: int = 8,
    ) -> tuple[DeterministicL0Runner, ReaderSpy, ClockSequence]:
        actual_reader = reader or ReaderSpy(dict(self.input_values))
        actual_clock = clock or self.clock()
        return (
            DeterministicL0Runner(
                actual_reader,
                chunk_size=chunk_size,
                clock=actual_clock,
            ),
            actual_reader,
            actual_clock,
        )

    def assert_no_outputs(self, root: Path | None = None) -> None:
        actual_root = root or self.root
        self.assertFalse((actual_root / "checkpoint.json").exists())
        self.assertFalse((actual_root / "result.json").exists())

    def assert_rejected_before_input(
        self,
        job: object,
        lease: object,
        *,
        root: object | None = None,
    ) -> None:
        runner, reader, clock = self.runner()
        with self.assertRaises(L0Error):
            runner.run(job, lease, self.root if root is None else root)  # type: ignore[arg-type]
        self.assertEqual(reader.calls, [])
        self.assertEqual(clock.calls, 0)
        if root is None or isinstance(root, Path):
            self.assert_no_outputs(self.root if root is None else root)

    def test_public_interface_is_exact_and_immutable(self) -> None:
        import research_bridge.l0 as l0

        self.assertEqual(
            l0.__all__,
            ["L0Error", "L0Checkpoint", "L0RunResult", "DeterministicL0Runner"],
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
            str(inspect.signature(DeterministicL0Runner.run)),
            "(self, job_spec: 'Mapping[str, Any]', lease: 'Mapping[str, Any]', staging_root: 'str | Path') -> 'L0RunResult'",
        )

    def test_success_writes_exact_deterministic_shapes_and_returns_strict_envelope(self) -> None:
        runner, reader, clock = self.runner()
        result = runner.run(job_spec(), attempt_lease(), self.root)

        self.assertIsInstance(result, L0RunResult)
        self.assertEqual(reader.calls, INPUT_REFS)
        self.assertEqual(clock.calls, 2)
        self.assertEqual(result.started_at, "2026-07-16T22:00:00.000000Z")
        self.assertEqual(result.ended_at, "2026-07-16T22:00:01.000000Z")
        self.assertEqual(result.code_sha256, CODE_SHA256)
        self.assertEqual(result.input_sha256, canonical_sha256(INPUT_REFS))
        self.assertEqual(result.environment_digest, IMAGE_DIGEST)

        checkpoint_bytes = (self.root / "checkpoint.json").read_bytes()
        result_bytes = (self.root / "result.json").read_bytes()
        checkpoint_document = json.loads(checkpoint_bytes)
        result_document = json.loads(result_bytes)
        self.assertEqual(checkpoint_bytes, canonical_bytes(checkpoint_document, newline=True))
        self.assertEqual(result_bytes, canonical_bytes(result_document, newline=True))
        self.assertEqual(
            set(checkpoint_document),
            {"completed_ranges", "input_sha256", "sequence", "state_sha256", "template_sha256"},
        )
        self.assertEqual(
            set(result_document),
            {"chunks", "environment_digest", "input_sha256", "inputs", "template_sha256"},
        )
        self.assertEqual(
            set(checkpoint_document["completed_ranges"][0]),
            {"input_index", "chunk_start_index", "chunk_end_index_exclusive"},
        )
        self.assertEqual(
            set(result_document["chunks"][0]),
            {"chunk_index", "input_index", "offset_bytes", "sha256", "size_bytes"},
        )
        self.assertEqual(
            set(result_document["inputs"][0]),
            {"chunk_count", "input_index", "input_ref", "sha256", "size_bytes"},
        )
        self.assertEqual(checkpoint_document["input_sha256"], canonical_sha256(INPUT_REFS))
        self.assertEqual(result_document["input_sha256"], canonical_sha256(INPUT_REFS))
        self.assertEqual(result_document["environment_digest"], IMAGE_DIGEST)
        self.assertEqual(result.checkpoint.sequence, 0)
        self.assertEqual(result.checkpoint.relative_path, "checkpoint.json")
        self.assertEqual(result.checkpoint.size_bytes, len(checkpoint_bytes))
        self.assertEqual(result.checkpoint.state_sha256, checkpoint_document["state_sha256"])
        self.assertEqual(
            result.checkpoint.state_sha256,
            canonical_sha256(
                {
                    "chunks": result_document["chunks"],
                    "completed_ranges": checkpoint_document["completed_ranges"],
                    "input_sha256": canonical_sha256(INPUT_REFS),
                    "inputs": result_document["inputs"],
                    "template_sha256": CODE_SHA256,
                }
            ),
        )
        self.assertNotEqual(
            result.checkpoint.state_sha256,
            hashlib.sha256(checkpoint_bytes).hexdigest(),
        )

        envelope = result.staging_envelope
        self.assertEqual(set(envelope), COMMON_KEYS)
        self.assertEqual(envelope["schema_id"], "StagingEnvelope")
        self.assertEqual(envelope["schema_version"], "1.0.0")
        self.assertEqual(
            envelope["issuer"],
            {"id": "bridge-l0-runner", "authority_class": "untrusted-runner"},
        )
        self.assertEqual(envelope["classification"], "D1_INTERNAL_SANITIZED")
        staging_payload = envelope["payload"]
        self.assertEqual(
            set(staging_payload),
            {
                "producer_identity",
                "run_id",
                "attempt_id",
                "fencing_token",
                "relative_file_manifest",
                "claimed_metrics",
                "completion_reason",
            },
        )
        self.assertEqual(len(staging_payload["relative_file_manifest"]), 1)
        file_entry = staging_payload["relative_file_manifest"][0]
        self.assertEqual(
            set(file_entry),
            {
                "relative_path",
                "sha256",
                "size_bytes",
                "claim_class",
                "source_refs",
                "redaction_status",
                "retention_class",
                "validator_ref",
            },
        )
        self.assertEqual(file_entry["relative_path"], "result.json")
        self.assertEqual(file_entry["sha256"], hashlib.sha256(result_bytes).hexdigest())
        self.assertEqual(file_entry["size_bytes"], len(result_bytes))
        self.assertEqual(file_entry["validator_ref"], "validator:pending-independent")
        self.assertNotEqual(file_entry["relative_path"], result.checkpoint.relative_path)
        self.assertEqual(
            envelope["integrity"]["payload_sha256"],  # type: ignore[index]
            canonical_sha256(thaw(staging_payload)),
        )

        all_output = checkpoint_bytes + result_bytes
        for raw_input in self.input_values.values():
            self.assertNotIn(raw_input, all_output)
        self.assertNotIn(str(self.root).encode(), all_output)
        self.assertNotIn(b"synthetic-fencing-token-never-in-files", all_output)
        self.assertNotIn(TEMPLATE.encode(), all_output)
        self.assertNotIn(b"outcome", all_output.lower())

    def test_bytes_are_repeatable_and_cas_ref_mismatch_writes_nothing(self) -> None:
        second_root = self.root / "second"
        second_root.mkdir()
        first_result = self.runner()[0].run(job_spec(), attempt_lease(), self.root)
        second_result = self.runner()[0].run(job_spec(), attempt_lease(), second_root)
        self.assertEqual(
            (self.root / "checkpoint.json").read_bytes(),
            (second_root / "checkpoint.json").read_bytes(),
        )
        self.assertEqual(
            (self.root / "result.json").read_bytes(),
            (second_root / "result.json").read_bytes(),
        )
        self.assertEqual(first_result.input_sha256, second_result.input_sha256)

        changed_root = self.root / "changed"
        changed_root.mkdir()
        changed_values = dict(self.input_values)
        changed_values[INPUT_REFS[0]] = b"Z" * len(self.input_values[INPUT_REFS[0]])
        self.assertEqual(len(changed_values[INPUT_REFS[0]]), len(self.input_values[INPUT_REFS[0]]))
        changed_reader = ReaderSpy(changed_values)
        changed_runner = self.runner(reader=changed_reader)[0]
        with self.assertRaises(L0Error):
            changed_runner.run(job_spec(), attempt_lease(), changed_root)
        self.assertEqual(changed_reader.calls, [INPUT_REFS[0]])
        self.assert_no_outputs(changed_root)

    def test_chunk_boundaries_empty_input_and_usage_are_mechanical(self) -> None:
        document = job_spec()
        first_data = b"abcdefghij"
        empty_ref = f"cas:sha256:{hashlib.sha256(b'').hexdigest()}"
        first_ref = f"cas:sha256:{hashlib.sha256(first_data).hexdigest()}"
        document["payload"]["input_refs"] = [first_ref, empty_ref]  # type: ignore[index]
        reseal(document)
        values = {first_ref: first_data, empty_ref: b""}
        reader = ReaderSpy(values)
        result = self.runner(reader=reader, chunk_size=4)[0].run(
            document, attempt_lease(), self.root
        )
        result_document = json.loads((self.root / "result.json").read_bytes())
        self.assertEqual([item["size_bytes"] for item in result_document["chunks"]], [4, 4, 2])
        self.assertEqual(
            result_document["inputs"],
            [
                {
                    "chunk_count": 3,
                    "input_index": 0,
                    "input_ref": first_ref,
                    "sha256": hashlib.sha256(first_data).hexdigest(),
                    "size_bytes": 10,
                },
                {
                    "chunk_count": 0,
                    "input_index": 1,
                    "input_ref": empty_ref,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "size_bytes": 0,
                },
            ],
        )
        self.assertEqual(result.resource_usage["chunk_count"], 3)
        self.assertEqual(result.resource_usage["input_bytes"], 10)

    def test_d0_allowed_and_d2_d3_denied_before_input_or_writes(self) -> None:
        public_job = job_spec(classification="D0_PUBLIC")
        public_lease = attempt_lease(classification="D0_PUBLIC")
        result = self.runner()[0].run(public_job, public_lease, self.root)
        self.assertEqual(result.staging_envelope["classification"], "D0_PUBLIC")
        self.assertEqual(
            result.staging_envelope["payload"]["relative_file_manifest"][0]["redaction_status"],  # type: ignore[index]
            "public",
        )

        denied_root = self.root / "denied"
        denied_root.mkdir()
        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            with self.subTest(classification=classification):
                self.assert_rejected_before_input(
                    job_spec(classification=classification),
                    attempt_lease(classification=classification),
                    root=denied_root,
                )

    def test_invalid_protocol_code_or_profile_never_reads_or_writes(self) -> None:
        mutations = {
            "protocol_ref": "not-a-portable-protocol-ref",
            "code_ref": f"sha256:{'0' * 64}",
            "runner_profile": "L1",
            "network_policy": "connected",
            "checkpoint_strategy": "arbitrary",
            "expected_output_contract": "ArbitraryOutput@1.0.0",
        }
        for field, value in mutations.items():
            document = job_spec()
            document["payload"][field] = value  # type: ignore[index]
            reseal(document)
            with self.subTest(field=field):
                self.assert_rejected_before_input(document, attempt_lease())

        independent_root = self.root / "independent-protocol"
        independent_root.mkdir()
        independent = job_spec()
        independent["payload"]["protocol_ref"] = "protocol:another-synthetic-v2"  # type: ignore[index]
        reseal(independent)
        result = self.runner()[0].run(independent, attempt_lease(), independent_root)
        self.assertEqual(result.code_sha256, CODE_SHA256)

    def test_exact_contract_shapes_integrity_and_authority_are_required(self) -> None:
        cases: list[tuple[dict[str, object], dict[str, object]]] = []
        extra_job = job_spec()
        extra_job["extra"] = True
        cases.append((extra_job, attempt_lease()))
        extra_payload = job_spec()
        extra_payload["payload"]["extra"] = True  # type: ignore[index]
        reseal(extra_payload)
        cases.append((extra_payload, attempt_lease()))
        bad_integrity = job_spec()
        bad_integrity["integrity"]["payload_sha256"] = "0" * 64  # type: ignore[index]
        cases.append((bad_integrity, attempt_lease()))
        bad_job_authority = job_spec()
        bad_job_authority["issuer"]["authority_class"] = "untrusted"  # type: ignore[index]
        cases.append((bad_job_authority, attempt_lease()))
        extra_lease = attempt_lease()
        extra_lease["payload"]["extra"] = True  # type: ignore[index]
        reseal(extra_lease)
        cases.append((job_spec(), extra_lease))
        bad_lease_authority = attempt_lease()
        bad_lease_authority["issuer"]["authority_class"] = "untrusted"  # type: ignore[index]
        cases.append((job_spec(), bad_lease_authority))

        for index, (job, lease) in enumerate(cases):
            with self.subTest(index=index):
                self.assert_rejected_before_input(job, lease)

    def test_lease_job_runner_contour_classification_and_time_bindings_are_strict(self) -> None:
        cases = []
        for field, value in (
            ("job_ref", "job-other"),
            ("runner_identity", "runner-other"),
            ("fencing_epoch", -1),
        ):
            lease = attempt_lease()
            lease["payload"][field] = value  # type: ignore[index]
            reseal(lease)
            cases.append(lease)
        contour = attempt_lease()
        contour["contour"] = "market"
        cases.append(contour)
        classification = attempt_lease()
        classification["classification"] = "D0_PUBLIC"
        cases.append(classification)
        time_mismatch = attempt_lease()
        time_mismatch["payload"]["issued_at"] = "2026-07-16T21:31:00Z"  # type: ignore[index]
        reseal(time_mismatch)
        cases.append(time_mismatch)
        invalid_window = attempt_lease()
        invalid_window["payload"]["expires_at"] = "2026-07-16T21:00:00Z"  # type: ignore[index]
        reseal(invalid_window)
        cases.append(invalid_window)

        for index, lease in enumerate(cases):
            with self.subTest(index=index):
                self.assert_rejected_before_input(job_spec(), lease)

    def test_portable_refs_are_validated_before_reader(self) -> None:
        for invalid_ref in (
            "/synthetic-input",
            "file:///synthetic-input",
            "relative-input",
            "C:\\synthetic\\input",
            "vault:synthetic-input",
            "cas:sha256:short",
        ):
            document = job_spec()
            document["payload"]["input_refs"] = [invalid_ref]  # type: ignore[index]
            reseal(document)
            with self.subTest(invalid_ref=invalid_ref):
                self.assert_rejected_before_input(document, attempt_lease())

    def test_each_input_is_called_once_in_order_and_reader_failures_write_nothing(self) -> None:
        runner, reader, _ = self.runner()
        runner.run(job_spec(), attempt_lease(), self.root)
        self.assertEqual(reader.calls, INPUT_REFS)

        error_root = self.root / "error"
        error_root.mkdir()
        error_reader = ReaderSpy(
            {
                INPUT_REFS[0]: INPUT_BYTES[0],
                INPUT_REFS[1]: OSError("synthetic read failure"),
            }
        )
        with self.assertRaises(L0Error):
            self.runner(reader=error_reader)[0].run(job_spec(), attempt_lease(), error_root)
        self.assertEqual(error_reader.calls, INPUT_REFS)
        self.assert_no_outputs(error_root)

        wrong_root = self.root / "wrong"
        wrong_root.mkdir()
        wrong_reader = ReaderSpy({INPUT_REFS[0]: bytearray(b"not-exact-bytes"), INPUT_REFS[1]: b""})
        with self.assertRaises(L0Error):
            self.runner(reader=wrong_reader)[0].run(job_spec(), attempt_lease(), wrong_root)
        self.assertEqual(wrong_reader.calls, [INPUT_REFS[0]])
        self.assert_no_outputs(wrong_root)

    def test_staging_root_symlink_existing_outputs_and_non_directory_fail_before_reader(self) -> None:
        root_link = self.root.parent / f"{self.root.name}-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(root_link.unlink)
        self.assert_rejected_before_input(job_spec(), attempt_lease(), root=root_link)

        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "result.json").symlink_to(self.root / "missing")
        self.assert_rejected_before_input(job_spec(), attempt_lease(), root=occupied)

        regular = self.root / "not-directory"
        regular.write_text("synthetic", encoding="utf-8")
        self.assert_rejected_before_input(job_spec(), attempt_lease(), root=regular)

    def test_outputs_are_regular_private_files_and_partial_write_is_rolled_back(self) -> None:
        self.runner()[0].run(job_spec(), attempt_lease(), self.root)
        for name in ("checkpoint.json", "result.json"):
            file_stat = (self.root / name).lstat()
            self.assertTrue(stat.S_ISREG(file_stat.st_mode))
            self.assertEqual(stat.S_IMODE(file_stat.st_mode), 0o600)

        rollback_root = self.root / "rollback"
        rollback_root.mkdir()
        real_write = os.write
        call_count = 0

        def fail_second_write(descriptor: int, data: bytes) -> int:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise OSError("synthetic short staging device")
            return real_write(descriptor, data)

        with mock.patch("research_bridge.l0.os.write", side_effect=fail_second_write):
            with self.assertRaises(L0Error):
                self.runner()[0].run(job_spec(), attempt_lease(), rollback_root)
        self.assert_no_outputs(rollback_root)

    def test_clock_is_aware_monotonic_and_within_lease_before_any_write(self) -> None:
        clocks = [
            ClockSequence(
                datetime(2026, 7, 16, 22, 0, 0),
                datetime(2026, 7, 16, 22, 0, 1, tzinfo=timezone.utc),
            ),
            ClockSequence(
                datetime(2026, 7, 16, 22, 0, 1, tzinfo=timezone.utc),
                datetime(2026, 7, 16, 22, 0, 0, tzinfo=timezone.utc),
            ),
            ClockSequence(
                datetime(2026, 7, 16, 22, 59, 59, tzinfo=timezone.utc),
                datetime(2026, 7, 16, 23, 0, 0, tzinfo=timezone.utc),
            ),
        ]
        for index, clock in enumerate(clocks):
            root = self.root / f"clock-{index}"
            root.mkdir()
            with self.subTest(index=index):
                with self.assertRaises(L0Error):
                    self.runner(clock=clock)[0].run(job_spec(), attempt_lease(), root)
                self.assert_no_outputs(root)

    def test_result_and_all_nested_contract_data_are_deeply_immutable(self) -> None:
        result = self.runner()[0].run(job_spec(), attempt_lease(), self.root)
        with self.assertRaises(FrozenInstanceError):
            result.input_sha256 = "0" * 64  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            result.checkpoint.sequence = 2  # type: ignore[misc]
        with self.assertRaises(TypeError):
            result.resource_usage["input_count"] = 0  # type: ignore[index]
        with self.assertRaises(TypeError):
            result.checkpoint.completed_ranges[0]["input_index"] = 9  # type: ignore[index]
        with self.assertRaises(TypeError):
            result.staging_envelope["object_id"] = "changed"  # type: ignore[index]
        with self.assertRaises(TypeError):
            result.staging_envelope["payload"]["claimed_metrics"]["input_count"] = 0  # type: ignore[index]
        with self.assertRaises(TypeError):
            result.staging_envelope["payload"]["relative_file_manifest"][0]["source_refs"][0] = "changed"  # type: ignore[index]

    def test_constructor_rejects_capability_or_configuration_ambiguity(self) -> None:
        with self.assertRaises(L0Error):
            DeterministicL0Runner(object())  # type: ignore[arg-type]
        with self.assertRaises(L0Error):
            DeterministicL0Runner(ReaderSpy({}), chunk_size=0)
        with self.assertRaises(L0Error):
            DeterministicL0Runner(ReaderSpy({}), chunk_size=True)  # type: ignore[arg-type]
        with self.assertRaises(L0Error):
            DeterministicL0Runner(ReaderSpy({}), clock=object())  # type: ignore[arg-type]
        with self.assertRaises(L0Error):
            DeterministicL0Runner(ReaderSpy({}), runner_identity=" runner")

    def test_source_has_no_process_network_dynamic_code_or_domain_capability(self) -> None:
        source_path = Path(__file__).resolve().parents[1] / "src" / "research_bridge" / "l0.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imported.isdisjoint(
                {"subprocess", "socket", "urllib", "http", "requests", "httpx", "asyncio"}
            )
        )
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(called_names.isdisjoint({"eval", "exec", "compile", "__import__"}))
        lowered = source.lower()
        for forbidden in ("market order", "exploit", "target host", "scientific_outcome"):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
