from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.execution import (  # noqa: E402
    ExecutionError,
    OfflineExecutionCoordinator,
)
from research_bridge.ledger import JobLedger  # noqa: E402
from tests.test_stage1_ledger import AT, claim  # noqa: E402
from tests.test_stage1_reference_vertical import (  # noqa: E402
    NOW,
    _environment,
)


TERMINAL_FIELDS = {
    "schema_id",
    "schema_version",
    "job_spec_ref",
    "permit_ref",
    "lease_ref",
    "attempt_id",
    "issuer_id",
    "contour",
    "classification",
    "code_sha256",
    "input_sha256",
    "environment_digest",
    "started_at",
    "ended_at",
    "exit_classification",
    "artifact_refs",
    "resource_usage",
    "checkpoint_manifest_object_id",
    "checkpoint_manifest_sha256",
}
MAX_TERMINAL_BYTES = 65_536


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _directory_snapshot(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    )


class _NeverUsed:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def claim(self, *arguments: object, **keywords: object) -> object:
        self.calls.append("claim")
        raise AssertionError("lookup must not claim")

    def run(self, *arguments: object, **keywords: object) -> object:
        self.calls.append("run")
        raise AssertionError("lookup must not run")

    def ingest(self, *arguments: object, **keywords: object) -> tuple[object, ...]:
        self.calls.append("ingest")
        raise AssertionError("lookup must not ingest")


def _lookup_coordinator(
    ledger: JobLedger,
    store: ContentAddressedStore,
) -> tuple[OfflineExecutionCoordinator, _NeverUsed]:
    never = _NeverUsed()
    return (
        OfflineExecutionCoordinator(never, ledger, never, store, never),
        never,
    )


def _base_terminal_material() -> dict[str, object]:
    return {
        "schema_id": "OwnedExecutionTerminalMaterial",
        "schema_version": "1.0.0",
        "job_spec_ref": "job-a",
        "permit_ref": "permit-a",
        "lease_ref": "lease-a",
        "attempt_id": "attempt-a",
        "issuer_id": "researchd",
        "contour": "bridge",
        "classification": "D0_PUBLIC",
        "code_sha256": hashlib.sha256(b"synthetic-code").hexdigest(),
        "input_sha256": hashlib.sha256(b"synthetic-input").hexdigest(),
        "environment_digest": "owned-synthetic-environment-v1",
        "started_at": AT,
        "ended_at": AT,
        "exit_classification": "mechanical-success",
        "artifact_refs": [
            f"cas:sha256:{hashlib.sha256(b'synthetic-artifact').hexdigest()}"
        ],
        "resource_usage": {"cost_units": 1},
        "checkpoint_manifest_object_id": (
            "checkpoint-manifest-" + hashlib.sha256(b"manifest-object").hexdigest()
        ),
        "checkpoint_manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
    }


class TerminalExecutionReceiptLookupTests(unittest.TestCase):
    def test_normal_terminal_bytes_bind_completion_and_reopen_lookup_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = _environment(root, "D1_INTERNAL_SANITIZED")
            record = environment.coordinator.execute(
                environment.job_spec,
                environment.permit,
                environment.lease,
                environment.staging_root,
                now=NOW,
            )
            completed = environment.raw_ledger.completed_event(
                environment.job_spec["object_id"]  # type: ignore[arg-type]
            )
            result_sha256 = completed.payload["result_sha256"]
            terminal_ref = f"cas:sha256:{result_sha256}"
            terminal_bytes = environment.checkpoint_store.read_bytes(
                terminal_ref,
                maximum_size_bytes=MAX_TERMINAL_BYTES,
            )
            terminal = json.loads(terminal_bytes)

            self.assertEqual(set(terminal), TERMINAL_FIELDS)
            self.assertEqual(
                hashlib.sha256(terminal_bytes).hexdigest(),
                completed.payload["result_sha256"],
            )
            self.assertEqual(
                terminal["checkpoint_manifest_sha256"],
                hashlib.sha256(_canonical(record.checkpoint_manifest)).hexdigest(),
            )
            self.assertEqual(environment.checkpoint_store.object_count(), 2)

            expected_receipt = _canonical(record.execution_receipt)
            before = (
                environment.raw_ledger.event_count(),
                environment.raw_ledger.event_count("claim"),
                environment.raw_ledger.event_count("checkpoint"),
                environment.raw_ledger.event_count("complete"),
                environment.checkpoint_store.object_count(),
                environment.checkpoint_store.used_bytes(),
                environment.artifact_store.object_count(),
                environment.artifact_store.used_bytes(),
                _directory_snapshot(environment.staging_root),
            )
            environment.raw_ledger.close()

            reopened_ledger = JobLedger(environment.database_path)
            reopened_store = ContentAddressedStore(
                environment.checkpoint_root,
                quota_bytes=1_048_576,
            )
            coordinator, never = _lookup_coordinator(reopened_ledger, reopened_store)
            try:
                first = coordinator.lookup_execution_receipt(
                    environment.job_spec["object_id"]  # type: ignore[arg-type]
                )
                second = coordinator.lookup_execution_receipt(
                    environment.job_spec["object_id"]  # type: ignore[arg-type]
                )
                after = (
                    reopened_ledger.event_count(),
                    reopened_ledger.event_count("claim"),
                    reopened_ledger.event_count("checkpoint"),
                    reopened_ledger.event_count("complete"),
                    reopened_store.object_count(),
                    reopened_store.used_bytes(),
                    environment.artifact_store.object_count(),
                    environment.artifact_store.used_bytes(),
                    _directory_snapshot(environment.staging_root),
                )
            finally:
                reopened_ledger.close()

            self.assertEqual(_canonical(first), expected_receipt)
            self.assertEqual(_canonical(second), expected_receipt)
            self.assertEqual(before, after)
            self.assertEqual(never.calls, [])

    def test_missing_tampered_and_legacy_terminal_material_fail_closed_without_writes(self) -> None:
        for case in ("missing", "tampered", "legacy"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                database = root / "ledger.sqlite3"
                store = ContentAddressedStore(root / "checkpoint-cas", quota_bytes=200_000)
                ledger = JobLedger(database)
                claim(ledger)
                material = _canonical(_base_terminal_material())
                result_sha256 = hashlib.sha256(material).hexdigest()
                if case != "legacy":
                    source = root / "terminal.json"
                    source.write_bytes(material)
                    store.publish(
                        source,
                        expected_sha256=result_sha256,
                        expected_size_bytes=len(material),
                    )
                ledger.complete(
                    job_id="job-a",
                    attempt_id="attempt-a",
                    fencing_epoch=7,
                    fencing_token="fence-a",
                    result_sha256=result_sha256,
                    event_at=AT,
                )
                if case == "missing":
                    object_path = root / "checkpoint-cas" / "objects" / result_sha256
                    object_path.chmod(0o600)
                    object_path.unlink()
                elif case == "tampered":
                    object_path = root / "checkpoint-cas" / "objects" / result_sha256
                    object_path.chmod(0o600)
                    object_path.write_bytes(b"x" * len(material))
                    object_path.chmod(0o444)

                coordinator, never = _lookup_coordinator(ledger, store)
                before = (
                    ledger.event_count(),
                    store.object_count(),
                    store.used_bytes(),
                )
                try:
                    with self.assertRaises(ExecutionError):
                        coordinator.lookup_execution_receipt("job-a")
                    after = (
                        ledger.event_count(),
                        store.object_count(),
                        store.used_bytes(),
                    )
                finally:
                    ledger.close()
                self.assertEqual(before, after)
                self.assertEqual(never.calls, [])

    def test_strict_decoder_rejects_malformed_noncanonical_unbounded_and_misbound_bytes(self) -> None:
        base = _base_terminal_material()
        unknown = dict(base)
        unknown["unknown"] = "forbidden"
        missing = dict(base)
        missing.pop("lease_ref")
        misbound = dict(base)
        misbound["job_spec_ref"] = "job-other"
        canonical = _canonical(base)
        cases = {
            "unknown": _canonical(unknown),
            "missing": _canonical(missing),
            "misbound": _canonical(misbound),
            "noncanonical": json.dumps(base, sort_keys=False).encode("utf-8"),
            "duplicate": canonical[:-1] + b',"schema_id":"OwnedExecutionTerminalMaterial"}',
            "nonfinite": canonical.replace(b'"cost_units":1', b'"cost_units":NaN'),
            "oversized": b" " * (MAX_TERMINAL_BYTES + 1),
            "invalid-utf8": b"\xff",
        }
        for case, encoded in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                ledger = JobLedger(root / "ledger.sqlite3")
                store = ContentAddressedStore(
                    root / "checkpoint-cas",
                    quota_bytes=200_000,
                )
                claim(ledger)
                source = root / "terminal.bin"
                source.write_bytes(encoded)
                result_sha256 = hashlib.sha256(encoded).hexdigest()
                store.publish(
                    source,
                    expected_sha256=result_sha256,
                    expected_size_bytes=len(encoded),
                )
                ledger.complete(
                    job_id="job-a",
                    attempt_id="attempt-a",
                    fencing_epoch=7,
                    fencing_token="fence-a",
                    result_sha256=result_sha256,
                    event_at=AT,
                )
                coordinator, never = _lookup_coordinator(ledger, store)
                before = (
                    ledger.event_count(),
                    store.object_count(),
                    store.used_bytes(),
                )
                try:
                    with self.assertRaises(ExecutionError):
                        coordinator.lookup_execution_receipt("job-a")
                    after = (
                        ledger.event_count(),
                        store.object_count(),
                        store.used_bytes(),
                    )
                finally:
                    ledger.close()
                self.assertEqual(before, after)
                self.assertEqual(never.calls, [])

    def test_lookup_without_completion_fails_before_cas_read_and_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = JobLedger(root / "ledger.sqlite3")
            store = ContentAddressedStore(root / "checkpoint-cas", quota_bytes=1024)
            claim(ledger)
            coordinator, never = _lookup_coordinator(ledger, store)
            before = (ledger.event_count(), store.object_count(), store.used_bytes())
            try:
                with self.assertRaises(ExecutionError):
                    coordinator.lookup_execution_receipt("job-a")
                after = (ledger.event_count(), store.object_count(), store.used_bytes())
            finally:
                ledger.close()
            self.assertEqual(before, after)
            self.assertEqual(never.calls, [])


if __name__ == "__main__":
    unittest.main()
