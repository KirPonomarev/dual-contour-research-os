from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge.ingestion import (
    ArtifactRecord,
    IngestionError,
    TrustedIngestor,
    canonical_json_sha256,
)


TOP_LEVEL_KEYS = {
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
PAYLOAD_KEYS = {
    "producer_identity",
    "run_id",
    "attempt_id",
    "fencing_token",
    "relative_file_manifest",
    "claimed_metrics",
    "completion_reason",
}
ENTRY_KEYS = {
    "relative_path",
    "sha256",
    "size_bytes",
    "claim_class",
    "source_refs",
    "redaction_status",
    "retention_class",
    "validator_ref",
}
MANIFEST_KEYS = TOP_LEVEL_KEYS
MANIFEST_PAYLOAD_KEYS = {
    "artifact_sha256",
    "size_bytes",
    "producer",
    "claim_class",
    "source_refs",
    "redaction_status",
    "retention_class",
    "validator_ref",
}


@dataclass(frozen=True, slots=True)
class FakeCASObject:
    ref: str
    sha256: str
    size_bytes: int
    created: bool


class FakeStore:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.calls: list[tuple[Path, str, int]] = []
        self.fail_on_call = fail_on_call

    def publish(
        self,
        source_path: str | Path,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> FakeCASObject:
        self.calls.append(
            (Path(source_path), expected_sha256, expected_size_bytes)
        )
        if self.fail_on_call == len(self.calls):
            raise OSError("synthetic publication failure")
        return FakeCASObject(
            ref=f"cas:sha256:{expected_sha256}",
            sha256=expected_sha256,
            size_bytes=expected_size_bytes,
            created=True,
        )


class FenceSpy:
    def __init__(self, result: object = True, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> object:
        self.calls.append(dict(kwargs))
        if self.error is not None:
            raise self.error
        return self.result


class ClockSpy:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        return self.result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_entry(relative_path: str, data: bytes, *, index: int = 0) -> dict[str, object]:
    return {
        "relative_path": relative_path,
        "sha256": sha256(data),
        "size_bytes": len(data),
        "claim_class": f"synthetic-claim-{index}",
        "source_refs": [f"public:synthetic-source-{index}"],
        "redaction_status": "sanitized",
        "retention_class": "ephemeral-test",
        "validator_ref": f"validator:synthetic-{index}",
    }


def envelope(entries: list[dict[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {
        "producer_identity": "runner-synthetic-1",
        "run_id": "run-synthetic-1",
        "attempt_id": "attempt-synthetic-1",
        "fencing_token": "synthetic-fence-token-never-persist",
        "relative_file_manifest": entries,
        "claimed_metrics": {"synthetic_count": len(entries)},
        "completion_reason": "synthetic fixture complete",
    }
    return {
        "schema_id": "StagingEnvelope",
        "schema_version": "1.0.0",
        "object_id": "staging-synthetic-1",
        "issued_at": "2026-07-16T20:00:00Z",
        "issuer": {
            "id": "runner-synthetic-1",
            "authority_class": "untrusted-runner",
        },
        "contour": "bridge",
        "classification": "D1_INTERNAL_SANITIZED",
        "payload": payload,
        "integrity": {
            "payload_sha256": canonical_json_sha256(payload),
            "parent_refs": ["attempt:synthetic-1"],
        },
    }


def reseal(document: dict[str, object]) -> None:
    document["integrity"]["payload_sha256"] = canonical_json_sha256(  # type: ignore[index]
        document["payload"]
    )


def thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {key: thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [thaw(item) for item in value]
    return value


class TrustedIngestorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.first_data = b"synthetic public artifact\n"
        self.second_data = b'{"synthetic":true}\n'
        (self.root / "first.txt").write_bytes(self.first_data)
        (self.root / "nested").mkdir()
        (self.root / "nested" / "second.json").write_bytes(self.second_data)
        self.document = envelope(
            [
                file_entry("first.txt", self.first_data, index=0),
                file_entry("nested/second.json", self.second_data, index=1),
            ]
        )

    def _ingestor(
        self,
        *,
        store: FakeStore | None = None,
        fence: FenceSpy | None = None,
        clock: ClockSpy | None = None,
    ) -> tuple[TrustedIngestor, FakeStore, FenceSpy, ClockSpy]:
        actual_store = store or FakeStore()
        actual_fence = fence or FenceSpy()
        actual_clock = clock or ClockSpy(
            datetime(2026, 7, 16, 22, 1, 2, 345678, tzinfo=timezone.utc)
        )
        return (
            TrustedIngestor(
                actual_store,
                fence_verifier=actual_fence,
                clock=actual_clock,
                issuer_id="trusted-ingestor-synthetic",
            ),
            actual_store,
            actual_fence,
            actual_clock,
        )

    def assert_rejected_before_authority(self, document: object, root: object | None = None) -> None:
        ingestor, store, fence, clock = self._ingestor()
        with self.assertRaises(IngestionError):
            ingestor.ingest(document, self.root if root is None else root)  # type: ignore[arg-type]
        self.assertEqual(fence.calls, [])
        self.assertEqual(store.calls, [])
        self.assertEqual(clock.calls, 0)

    def test_success_validates_fence_once_publishes_in_declared_order_then_manifests(self) -> None:
        ingestor, store, fence, clock = self._ingestor()
        records = ingestor.ingest(self.document, self.root)

        self.assertIsInstance(records, tuple)
        self.assertEqual(len(records), 2)
        self.assertTrue(all(isinstance(record, ArtifactRecord) for record in records))
        self.assertEqual(
            fence.calls,
            [
                {
                    "attempt_id": "attempt-synthetic-1",
                    "producer_identity": "runner-synthetic-1",
                    "fencing_token": "synthetic-fence-token-never-persist",
                }
            ],
        )
        self.assertEqual([call[0] for call in store.calls], [
            self.root / "first.txt",
            self.root / "nested" / "second.json",
        ])
        self.assertEqual(clock.calls, 1)

        expected_digests = [sha256(self.first_data), sha256(self.second_data)]
        for index, record in enumerate(records):
            manifest = record.manifest
            self.assertEqual(set(manifest), MANIFEST_KEYS)
            self.assertEqual(manifest["schema_id"], "ArtifactManifest")
            self.assertEqual(manifest["schema_version"], "1.0.0")
            self.assertRegex(manifest["object_id"], r"^artifact-manifest-[a-f0-9]{64}$")
            self.assertEqual(manifest["issued_at"], "2026-07-16T22:01:02.345678Z")
            self.assertEqual(
                manifest["issuer"],
                {"id": "trusted-ingestor-synthetic", "authority_class": "trusted-ingestor"},
            )
            self.assertEqual(manifest["contour"], "bridge")
            self.assertEqual(manifest["classification"], "D1_INTERNAL_SANITIZED")
            payload = manifest["payload"]
            self.assertEqual(set(payload), MANIFEST_PAYLOAD_KEYS)
            self.assertEqual(payload["artifact_sha256"], expected_digests[index])
            self.assertEqual(payload["producer"], "runner-synthetic-1")
            self.assertEqual(
                manifest["integrity"]["payload_sha256"],  # type: ignore[index]
                canonical_json_sha256(payload),
            )
            self.assertEqual(record.artifact_ref, f"cas:sha256:{expected_digests[index]}")
            self.assertEqual(
                manifest["integrity"]["parent_refs"],  # type: ignore[index]
                ("staging:staging-synthetic-1", record.artifact_ref),
            )

        serialized = json.dumps(thaw([record.manifest for record in records]), sort_keys=True)
        self.assertNotIn("synthetic-fence-token-never-persist", serialized)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("relative_path", serialized)
        self.assertNotIn("scientific", serialized.lower())
        self.assertNotIn("outcome", serialized.lower())

    def test_d0_is_allowed_but_d2_and_d3_are_denied_before_authority(self) -> None:
        public_document = deepcopy(self.document)
        public_document["classification"] = "D0_PUBLIC"
        records = self._ingestor()[0].ingest(public_document, self.root)
        self.assertEqual(records[0].manifest["classification"], "D0_PUBLIC")

        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            denied = deepcopy(self.document)
            denied["classification"] = classification
            with self.subTest(classification=classification):
                self.assert_rejected_before_authority(denied)

    def test_exact_envelope_and_nested_shapes_are_required(self) -> None:
        mutations = []
        extra_top = deepcopy(self.document)
        extra_top["extra"] = True
        mutations.append(extra_top)
        missing_top = deepcopy(self.document)
        del missing_top["object_id"]
        mutations.append(missing_top)
        extra_payload = deepcopy(self.document)
        extra_payload["payload"]["extra"] = True  # type: ignore[index]
        reseal(extra_payload)
        mutations.append(extra_payload)
        extra_issuer = deepcopy(self.document)
        extra_issuer["issuer"]["extra"] = True  # type: ignore[index]
        mutations.append(extra_issuer)
        extra_integrity = deepcopy(self.document)
        extra_integrity["integrity"]["extra"] = True  # type: ignore[index]
        mutations.append(extra_integrity)
        extra_entry = deepcopy(self.document)
        extra_entry["payload"]["relative_file_manifest"][0]["extra"] = True  # type: ignore[index]
        reseal(extra_entry)
        mutations.append(extra_entry)

        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                self.assert_rejected_before_authority(document)

    def test_schema_integrity_issuer_contour_and_normalized_identity_are_strict(self) -> None:
        cases: list[dict[str, object]] = []
        for field, bad_value in (
            ("schema_id", "ArtifactManifest"),
            ("schema_version", "2.0.0"),
            ("issued_at", "2026-07-16 20:00:00"),
            ("object_id", " staging-synthetic-1"),
            ("contour", "external"),
        ):
            changed = deepcopy(self.document)
            changed[field] = bad_value
            cases.append(changed)
        bad_authority = deepcopy(self.document)
        bad_authority["issuer"]["authority_class"] = "trusted-ingestor"  # type: ignore[index]
        cases.append(bad_authority)
        bad_identity = deepcopy(self.document)
        bad_identity["issuer"]["id"] = "different-runner"  # type: ignore[index]
        cases.append(bad_identity)
        bad_integrity = deepcopy(self.document)
        bad_integrity["integrity"]["payload_sha256"] = "0" * 64  # type: ignore[index]
        cases.append(bad_integrity)
        bad_producer = deepcopy(self.document)
        bad_producer["payload"]["producer_identity"] = "runner-synthetic-1 "  # type: ignore[index]
        reseal(bad_producer)
        cases.append(bad_producer)

        for index, document in enumerate(cases):
            with self.subTest(index=index):
                self.assert_rejected_before_authority(document)

    def test_manifest_must_be_nonempty_unique_and_have_strict_metadata(self) -> None:
        empty = deepcopy(self.document)
        empty["payload"]["relative_file_manifest"] = []  # type: ignore[index]
        reseal(empty)
        self.assert_rejected_before_authority(empty)

        duplicate = deepcopy(self.document)
        duplicate["payload"]["relative_file_manifest"][1]["relative_path"] = "first.txt"  # type: ignore[index]
        duplicate["payload"]["relative_file_manifest"][1]["sha256"] = sha256(self.first_data)  # type: ignore[index]
        duplicate["payload"]["relative_file_manifest"][1]["size_bytes"] = len(self.first_data)  # type: ignore[index]
        reseal(duplicate)
        self.assert_rejected_before_authority(duplicate)

        for field, bad_value in (
            ("sha256", "A" * 64),
            ("size_bytes", True),
            ("claim_class", ""),
            ("source_refs", "public:not-an-array"),
            ("redaction_status", " sanitized"),
            ("retention_class", None),
            ("validator_ref", "validator:bad\nref"),
        ):
            bad = deepcopy(self.document)
            bad["payload"]["relative_file_manifest"][0][field] = bad_value  # type: ignore[index]
            reseal(bad)
            with self.subTest(field=field):
                self.assert_rejected_before_authority(bad)

    def test_absolute_parent_dot_backslash_and_non_normalized_paths_are_denied(self) -> None:
        for relative_path in (
            "/etc/passwd",
            ".",
            "..",
            "../first.txt",
            "nested/../first.txt",
            "./first.txt",
            "nested\\second.json",
            "nested//second.json",
        ):
            bad = deepcopy(self.document)
            bad["payload"]["relative_file_manifest"][0]["relative_path"] = relative_path  # type: ignore[index]
            reseal(bad)
            with self.subTest(relative_path=relative_path):
                self.assert_rejected_before_authority(bad)

    def test_symlink_root_symlink_file_and_nonregular_file_are_denied(self) -> None:
        root_link = self.root.parent / f"{self.root.name}-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(root_link.unlink)
        self.assert_rejected_before_authority(self.document, root_link)

        file_link = self.root / "linked.txt"
        file_link.symlink_to(self.root / "first.txt")
        linked = envelope([file_entry("linked.txt", self.first_data)])
        self.assert_rejected_before_authority(linked)

        directory_entry = envelope([file_entry("nested", b"")])
        self.assert_rejected_before_authority(directory_entry)

    def test_digest_and_size_mismatch_are_denied_before_fence(self) -> None:
        wrong_digest = deepcopy(self.document)
        wrong_digest["payload"]["relative_file_manifest"][0]["sha256"] = "0" * 64  # type: ignore[index]
        reseal(wrong_digest)
        self.assert_rejected_before_authority(wrong_digest)

        wrong_size = deepcopy(self.document)
        wrong_size["payload"]["relative_file_manifest"][0]["size_bytes"] = len(self.first_data) + 1  # type: ignore[index]
        reseal(wrong_size)
        self.assert_rejected_before_authority(wrong_size)

        invalid_second = deepcopy(self.document)
        invalid_second["payload"]["relative_file_manifest"][1]["size_bytes"] = 999  # type: ignore[index]
        reseal(invalid_second)
        self.assert_rejected_before_authority(invalid_second)

    def test_host_paths_and_raw_fencing_authority_cannot_enter_cas_or_manifest(self) -> None:
        for forbidden_ref in (
            "/synthetic-host-file",
            "file:///synthetic-host-file",
            "C:\\synthetic\\host-file",
        ):
            bad_ref = deepcopy(self.document)
            bad_ref["payload"]["relative_file_manifest"][0]["source_refs"] = [forbidden_ref]  # type: ignore[index]
            reseal(bad_ref)
            with self.subTest(forbidden_ref=forbidden_ref):
                self.assert_rejected_before_authority(bad_ref)

        token = self.document["payload"]["fencing_token"]  # type: ignore[index]
        bad_metadata = deepcopy(self.document)
        bad_metadata["payload"]["relative_file_manifest"][0]["validator_ref"] = f"validator:{token}"  # type: ignore[index]
        reseal(bad_metadata)
        self.assert_rejected_before_authority(bad_metadata)

        token_data = f"synthetic output leaked {token}\n".encode()
        (self.root / "leaked.txt").write_bytes(token_data)
        bad_bytes = envelope([file_entry("leaked.txt", token_data)])
        self.assert_rejected_before_authority(bad_bytes)

    def test_stale_false_none_and_raising_fence_publish_nothing(self) -> None:
        fences = [
            FenceSpy(False),
            FenceSpy(None),
            FenceSpy(error=RuntimeError("synthetic stale fence")),
        ]
        for fence in fences:
            store = FakeStore()
            clock = ClockSpy(datetime.now(timezone.utc))
            ingestor = TrustedIngestor(store, fence_verifier=fence, clock=clock)
            with self.subTest(result=fence.result, error=fence.error):
                with self.assertRaises(IngestionError):
                    ingestor.ingest(self.document, self.root)
                self.assertEqual(len(fence.calls), 1)
                self.assertEqual(store.calls, [])
                self.assertEqual(clock.calls, 0)

    def test_partial_store_failure_emits_no_records_or_manifests(self) -> None:
        store = FakeStore(fail_on_call=2)
        clock = ClockSpy(datetime.now(timezone.utc))
        ingestor = TrustedIngestor(store, fence_verifier=FenceSpy(), clock=clock)
        with self.assertRaises(IngestionError):
            ingestor.ingest(self.document, self.root)
        self.assertEqual(len(store.calls), 2)
        self.assertEqual(clock.calls, 0, "manifest clock must run only after all publications")

    def test_malformed_store_result_fails_without_constructing_manifests(self) -> None:
        class WrongStore(FakeStore):
            def publish(self, source_path: str | Path, *, expected_sha256: str, expected_size_bytes: int) -> FakeCASObject:
                super().publish(
                    source_path,
                    expected_sha256=expected_sha256,
                    expected_size_bytes=expected_size_bytes,
                )
                return FakeCASObject(
                    ref=f"cas:sha256:{'0' * 64}",
                    sha256=expected_sha256,
                    size_bytes=expected_size_bytes,
                    created=True,
                )

        store = WrongStore()
        clock = ClockSpy(datetime.now(timezone.utc))
        ingestor = TrustedIngestor(store, fence_verifier=FenceSpy(), clock=clock)
        with self.assertRaises(IngestionError):
            ingestor.ingest(self.document, self.root)
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(clock.calls, 0)

    def test_naive_clock_fails_closed_after_publication_without_records(self) -> None:
        store = FakeStore()
        clock = ClockSpy(datetime(2026, 7, 16, 22, 1, 2))
        ingestor = TrustedIngestor(store, fence_verifier=FenceSpy(), clock=clock)
        with self.assertRaises(IngestionError):
            ingestor.ingest(self.document, self.root)
        self.assertEqual(len(store.calls), 2)
        self.assertEqual(clock.calls, 1)

        class RaisingClock:
            def __call__(self) -> object:
                raise OSError("synthetic clock failure")

        raising_store = FakeStore()
        raising_ingestor = TrustedIngestor(
            raising_store,
            fence_verifier=FenceSpy(),
            clock=RaisingClock(),
        )
        with self.assertRaises(IngestionError):
            raising_ingestor.ingest(self.document, self.root)
        self.assertEqual(len(raising_store.calls), 2)

    def test_artifact_record_fields_are_frozen(self) -> None:
        record = self._ingestor()[0].ingest(self.document, self.root)[0]
        integrity_before = record.manifest["integrity"]["payload_sha256"]  # type: ignore[index]
        with self.assertRaises((AttributeError, TypeError)):
            record.artifact_ref = "cas:sha256:wrong"  # type: ignore[misc]
        with self.assertRaises((AttributeError, TypeError)):
            record.manifest = {}  # type: ignore[misc]
        with self.assertRaises((AttributeError, TypeError)):
            record.manifest["object_id"] = "changed"  # type: ignore[index]
        with self.assertRaises((AttributeError, TypeError)):
            record.manifest["payload"]["producer"] = "changed"  # type: ignore[index]
        with self.assertRaises((AttributeError, TypeError)):
            record.manifest["payload"]["source_refs"][0] = "changed"  # type: ignore[index]
        with self.assertRaises((AttributeError, TypeError)):
            record.manifest["integrity"]["parent_refs"][0] = "changed"  # type: ignore[index]
        self.assertEqual(
            record.manifest["integrity"]["payload_sha256"],  # type: ignore[index]
            integrity_before,
        )
        self.assertEqual(
            canonical_json_sha256(record.manifest["payload"]),
            integrity_before,
        )

    def test_canonical_hash_is_utf8_deterministic_and_rejects_non_json(self) -> None:
        value = {"z": [1, True, None], "a": "λ"}
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(canonical_json_sha256(value), hashlib.sha256(encoded).hexdigest())
        for invalid in ({"bad": float("nan")}, {1: "non-text-key"}, {"bad": object()}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(IngestionError):
                    canonical_json_sha256(invalid)

    def test_constructor_is_fail_closed(self) -> None:
        with self.assertRaises(IngestionError):
            TrustedIngestor(object(), fence_verifier=FenceSpy())
        with self.assertRaises(IngestionError):
            TrustedIngestor(FakeStore(), fence_verifier=object())  # type: ignore[arg-type]
        with self.assertRaises(IngestionError):
            TrustedIngestor(FakeStore(), fence_verifier=FenceSpy(), clock=object())  # type: ignore[arg-type]
        with self.assertRaises(IngestionError):
            TrustedIngestor(FakeStore(), fence_verifier=FenceSpy(), issuer_id=" trusted")


if __name__ == "__main__":
    unittest.main()
