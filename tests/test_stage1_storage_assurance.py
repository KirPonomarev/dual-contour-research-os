import ast
import concurrent.futures
import copy
import hashlib
import inspect
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import research_bridge.ingestion as ingestion_module  # noqa: E402
from research_bridge.cas import (  # noqa: E402
    CASError,
    CASObject,
    ContentAddressedStore,
)
from research_bridge.ingestion import (  # noqa: E402
    ArtifactRecord,
    IngestionError,
    TrustedIngestor,
    canonical_json_sha256,
)


NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


class ContentAddressedStoreAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name) / "synthetic-cas"
        self.source = Path(self.temporary_directory.name) / "synthetic-source.bin"
        self.data = b"public synthetic artifact bytes\n"
        self.source.write_bytes(self.data)
        self.digest = _sha256(self.data)
        self.store = ContentAddressedStore(self.root, quota_bytes=1_048_576)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _publish(self) -> CASObject:
        return self.store.publish(
            self.source,
            expected_sha256=self.digest,
            expected_size_bytes=len(self.data),
        )

    def test_concurrent_same_digest_has_exactly_one_creation(self) -> None:
        barrier = Barrier(8)

        def publish_once(_: int) -> CASObject:
            barrier.wait(timeout=10)
            return self._publish()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(publish_once, range(8)))

        self.assertEqual(sum(result.created for result in results), 1)
        self.assertTrue(all(result.ref == f"cas:sha256:{self.digest}" for result in results))
        self.assertEqual(self.store.object_count(), 1)
        self.assertEqual(self.store.used_bytes(), len(self.data))
        self.assertTrue(self.store.verify(results[0].ref))

    def test_exact_retry_has_zero_growth_and_corrupt_canonical_object_is_denied(self) -> None:
        first = self._publish()
        used_before = self.store.used_bytes()
        count_before = self.store.object_count()
        retry = self._publish()

        self.assertTrue(first.created)
        self.assertFalse(retry.created)
        self.assertEqual(retry.ref, first.ref)
        self.assertEqual(self.store.used_bytes(), used_before)
        self.assertEqual(self.store.object_count(), count_before)

        canonical_candidates = [
            path
            for path in self.root.rglob("*")
            if path.is_file() and not path.is_symlink() and path.name == self.digest
        ]
        self.assertEqual(len(canonical_candidates), 1)
        os.chmod(canonical_candidates[0], 0o644)
        canonical_candidates[0].write_bytes(b"corrupt synthetic bytes")

        with self.assertRaises(CASError):
            self._publish()
        with self.assertRaises(CASError):
            self.store.verify(first.ref)
        self.assertEqual(self.store.object_count(), 1)

    def test_symlink_and_nonregular_sources_are_denied_without_objects(self) -> None:
        symlink_source = Path(self.temporary_directory.name) / "synthetic-link.bin"
        symlink_source.symlink_to(self.source)
        directory_source = Path(self.temporary_directory.name) / "synthetic-directory"
        directory_source.mkdir()
        traversal_parent = Path(self.temporary_directory.name) / "synthetic-parent"
        traversal_parent.mkdir()
        traversal_source = traversal_parent / ".." / self.source.name

        for label, source_path, digest, size in (
            ("symlink", symlink_source, self.digest, len(self.data)),
            ("directory", directory_source, _sha256(b""), 0),
            ("path traversal", traversal_source, self.digest, len(self.data)),
        ):
            with self.subTest(label=label):
                with self.assertRaises(CASError):
                    self.store.publish(
                        source_path,
                        expected_sha256=digest,
                        expected_size_bytes=size,
                    )
                self.assertEqual(self.store.object_count(), 0)
                self.assertEqual(self.store.used_bytes(), 0)

    def test_quota_short_write_and_durability_failures_return_no_success(self) -> None:
        quota_root = Path(self.temporary_directory.name) / "quota-cas"
        quota_store = ContentAddressedStore(quota_root, quota_bytes=len(self.data) - 1)
        with self.assertRaises(CASError):
            quota_store.publish(
                self.source,
                expected_sha256=self.digest,
                expected_size_bytes=len(self.data),
            )
        self.assertEqual(quota_store.object_count(), 0)
        self.assertEqual(quota_store.used_bytes(), 0)

        for failure_name, patch_target, side_effect in (
            ("short write", "research_bridge.cas.os.write", lambda *_: 0),
            (
                "temporary fsync",
                "research_bridge.cas.os.fsync",
                OSError("synthetic temporary durability failure"),
            ),
            (
                "canonical directory fsync",
                "research_bridge.cas.os.fsync",
                [None, OSError("synthetic directory durability failure")],
            ),
        ):
            with self.subTest(failure=failure_name):
                failure_root = (
                    Path(self.temporary_directory.name)
                    / f"failure-{failure_name.replace(' ', '-')}"
                )
                failure_store = ContentAddressedStore(
                    failure_root,
                    quota_bytes=1_048_576,
                )
                with mock.patch(patch_target, side_effect=side_effect):
                    with self.assertRaises(CASError):
                        failure_store.publish(
                            self.source,
                            expected_sha256=self.digest,
                            expected_size_bytes=len(self.data),
                        )
                self.assertEqual(failure_store.object_count(), 0)
                self.assertEqual(failure_store.used_bytes(), 0)

    def test_orphan_cleanup_is_strictly_bounded(self) -> None:
        temporary_root = self.root / ".tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        for index in range(3):
            (temporary_root / f"synthetic-orphan-{index}.tmp").write_bytes(
                f"orphan-{index}".encode("ascii")
            )

        self.assertEqual(self.store.reconcile_orphans(2), 2)
        self.assertEqual(len(list(temporary_root.iterdir())), 1)
        self.assertEqual(self.store.reconcile_orphans(2), 1)
        self.assertEqual(list(temporary_root.iterdir()), [])
        with self.assertRaises(CASError):
            self.store.reconcile_orphans(0)


class _FenceVerifier:
    def __init__(self, result: object = True, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, object]] = []

    def __call__(self, **keywords: object) -> object:
        self.calls.append(dict(keywords))
        if self.error is not None:
            raise self.error
        return self.result


class _RecordingStore:
    def __init__(self, *, fail_on: int | None = None) -> None:
        self.fail_on = fail_on
        self.calls: list[dict[str, object]] = []

    def publish(
        self,
        source_path: str | Path,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> object:
        call = {
            "source_path": Path(source_path),
            "expected_sha256": expected_sha256,
            "expected_size_bytes": expected_size_bytes,
        }
        self.calls.append(call)
        if self.fail_on == len(self.calls):
            raise CASError("synthetic publication failure")
        data = Path(source_path).read_bytes()
        if _sha256(data) != expected_sha256 or len(data) != expected_size_bytes:
            raise CASError("synthetic source integrity mismatch")
        return SimpleNamespace(
            ref=f"cas:sha256:{expected_sha256}",
            sha256=expected_sha256,
            size_bytes=expected_size_bytes,
            created=True,
        )


def _file_entry(relative_path: str, data: bytes, *, index: int) -> dict[str, object]:
    return {
        "relative_path": relative_path,
        "sha256": _sha256(data),
        "size_bytes": len(data),
        "claim_class": "synthetic-public-observation",
        "source_refs": [f"cas:sha256:{index + 1:064x}"],
        "redaction_status": "synthetic-sanitized",
        "retention_class": "synthetic-short",
        "validator_ref": "validator:synthetic-offline",
    }


def _envelope(
    entries: list[dict[str, object]],
    *,
    classification: str = "D0_PUBLIC",
) -> dict[str, object]:
    payload = {
        "producer_identity": "runner-synthetic-offline",
        "run_id": "run-synthetic-storage-001",
        "attempt_id": "attempt-synthetic-storage-001",
        "fencing_token": "fence-synthetic-storage-001",
        "relative_file_manifest": entries,
        "claimed_metrics": {},
        "completion_reason": "synthetic-complete",
    }
    return {
        "schema_id": "StagingEnvelope",
        "schema_version": "1.0.0",
        "object_id": "staging-synthetic-storage-001",
        "issued_at": "2026-01-02T03:04:05Z",
        "issuer": {
            "id": payload["producer_identity"],
            "authority_class": "untrusted-runner",
        },
        "contour": "bridge",
        "classification": classification,
        "payload": payload,
        "integrity": {
            "payload_sha256": canonical_json_sha256(payload),
            "parent_refs": [],
        },
    }


class TrustedIngestionAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.staging_root = Path(self.temporary_directory.name) / "synthetic-staging"
        self.staging_root.mkdir()
        self.files = {
            "artifact-a.txt": b"public synthetic artifact A\n",
            "nested/artifact-b.txt": b"public synthetic artifact B\n",
        }
        entries = []
        for index, (relative_path, data) in enumerate(self.files.items()):
            source_path = self.staging_root / relative_path
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(data)
            entries.append(_file_entry(relative_path, data, index=index))
        self.valid_envelope = _envelope(entries)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _ingestor(
        self,
        store: object,
        verifier: _FenceVerifier,
    ) -> TrustedIngestor:
        return TrustedIngestor(
            store,
            fence_verifier=verifier,
            clock=lambda: NOW,
        )

    def test_invalid_envelopes_make_zero_fence_and_store_calls(self) -> None:
        mutations: list[tuple[str, dict[str, object]]] = []

        missing = copy.deepcopy(self.valid_envelope)
        del missing["object_id"]
        mutations.append(("missing top-level key", missing))

        extra = copy.deepcopy(self.valid_envelope)
        extra["unexpected"] = "synthetic"
        mutations.append(("extra top-level key", extra))

        corrupt_integrity = copy.deepcopy(self.valid_envelope)
        corrupt_integrity["integrity"]["payload_sha256"] = "0" * 64
        mutations.append(("payload integrity", corrupt_integrity))

        extra_file_key = copy.deepcopy(self.valid_envelope)
        extra_file_key["payload"]["relative_file_manifest"][0]["unexpected"] = True
        extra_file_key["integrity"]["payload_sha256"] = canonical_json_sha256(
            extra_file_key["payload"]
        )
        mutations.append(("extra file key", extra_file_key))

        for label, relative_path in (
            ("parent traversal", "../outside.txt"),
            ("absolute path", "/synthetic/outside.txt"),
        ):
            candidate = copy.deepcopy(self.valid_envelope)
            candidate["payload"]["relative_file_manifest"][0][
                "relative_path"
            ] = relative_path
            candidate["integrity"]["payload_sha256"] = canonical_json_sha256(
                candidate["payload"]
            )
            mutations.append((label, candidate))

        for label, candidate in mutations:
            with self.subTest(label=label):
                store = _RecordingStore()
                verifier = _FenceVerifier()
                with self.assertRaises(IngestionError):
                    self._ingestor(store, verifier).ingest(candidate, self.staging_root)
                self.assertEqual(verifier.calls, [])
                self.assertEqual(store.calls, [])

    def test_stale_or_failed_fence_causes_zero_publications(self) -> None:
        for label, verifier in (
            ("false", _FenceVerifier(False)),
            ("none", _FenceVerifier(None)),
            ("error", _FenceVerifier(error=RuntimeError("synthetic stale fence"))),
        ):
            with self.subTest(label=label):
                store = _RecordingStore()
                with self.assertRaises(IngestionError):
                    self._ingestor(store, verifier).ingest(
                        self.valid_envelope,
                        self.staging_root,
                    )
                self.assertEqual(len(verifier.calls), 1)
                self.assertEqual(
                    set(verifier.calls[0]),
                    {"attempt_id", "producer_identity", "fencing_token"},
                )
                self.assertEqual(store.calls, [])

    def test_d2_and_d3_classifications_are_denied_before_fence(self) -> None:
        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            with self.subTest(classification=classification):
                store = _RecordingStore()
                verifier = _FenceVerifier()
                candidate = _envelope(
                    copy.deepcopy(
                        self.valid_envelope["payload"]["relative_file_manifest"]
                    ),
                    classification=classification,
                )
                with self.assertRaises(IngestionError):
                    self._ingestor(store, verifier).ingest(
                        candidate,
                        self.staging_root,
                    )
                self.assertEqual(verifier.calls, [])
                self.assertEqual(store.calls, [])

    def test_d0_and_d1_success_returns_only_portable_verified_manifests(self) -> None:
        for index, classification in enumerate(
            ("D0_PUBLIC", "D1_INTERNAL_SANITIZED")
        ):
            with self.subTest(classification=classification):
                cas_root = Path(self.temporary_directory.name) / f"cas-success-{index}"
                store = ContentAddressedStore(cas_root, quota_bytes=1_048_576)
                verifier = _FenceVerifier()
                candidate = _envelope(
                    copy.deepcopy(
                        self.valid_envelope["payload"]["relative_file_manifest"]
                    ),
                    classification=classification,
                )
                records = self._ingestor(store, verifier).ingest(
                    candidate,
                    self.staging_root,
                )

                self.assertIsInstance(records, tuple)
                self.assertEqual(len(records), len(self.files))
                self.assertEqual(len(verifier.calls), 1)
                self.assertEqual(store.object_count(), len(self.files))
                for record in records:
                    self.assertIsInstance(record, ArtifactRecord)
                    self.assertTrue(record.artifact_ref.startswith("cas:sha256:"))
                    manifest = _plain(record.manifest)
                    self.assertEqual(manifest["schema_id"], "ArtifactManifest")
                    self.assertEqual(manifest["classification"], classification)
                    self.assertEqual(
                        manifest["integrity"]["payload_sha256"],
                        canonical_json_sha256(manifest["payload"]),
                    )
                    serialized = json.dumps(manifest, sort_keys=True)
                    self.assertNotIn(
                        candidate["payload"]["fencing_token"],
                        serialized,
                    )
                    self.assertNotIn(str(self.staging_root), serialized)
                    self.assertNotIn("scientific_outcome", serialized)
                    self.assertNotIn("ExecutionReceipt", serialized)

    def test_records_are_constructed_only_after_all_publications_succeed(self) -> None:
        store = _RecordingStore()
        verifier = _FenceVerifier()
        real_record = ArtifactRecord
        construction_publish_counts: list[int] = []

        def construct_record(*args: object, **keywords: object) -> ArtifactRecord:
            construction_publish_counts.append(len(store.calls))
            return real_record(*args, **keywords)

        with mock.patch.object(
            ingestion_module,
            "ArtifactRecord",
            side_effect=construct_record,
        ):
            records = self._ingestor(store, verifier).ingest(
                self.valid_envelope,
                self.staging_root,
            )

        self.assertEqual(len(records), len(self.files))
        self.assertEqual(construction_publish_counts, [len(self.files)] * len(self.files))

    def test_second_publication_failure_constructs_zero_artifact_records(self) -> None:
        store = _RecordingStore(fail_on=2)
        verifier = _FenceVerifier()
        constructed: list[object] = []

        def record_construction(*args: object, **keywords: object) -> object:
            constructed.append((args, keywords))
            return ArtifactRecord(*args, **keywords)

        with mock.patch.object(
            ingestion_module,
            "ArtifactRecord",
            side_effect=record_construction,
        ):
            with self.assertRaises(IngestionError):
                self._ingestor(store, verifier).ingest(
                    self.valid_envelope,
                    self.staging_root,
                )

        self.assertEqual(len(store.calls), 2)
        self.assertEqual(constructed, [])


class Stage1StorageStaticBoundaryTests(unittest.TestCase):
    def test_exports_dataclasses_and_signatures_match_frozen_interfaces(self) -> None:
        import research_bridge.cas as cas_module

        self.assertEqual(
            set(cas_module.__all__),
            {"CASError", "CASObject", "ContentAddressedStore"},
        )
        self.assertEqual(
            set(ingestion_module.__all__),
            {
                "IngestionError",
                "ArtifactRecord",
                "TrustedIngestor",
                "canonical_json_sha256",
            },
        )
        self.assertEqual(
            [field.name for field in fields(CASObject)],
            ["ref", "sha256", "size_bytes", "created"],
        )
        self.assertEqual(
            [field.name for field in fields(ArtifactRecord)],
            ["artifact_ref", "manifest"],
        )

        cas_methods = {
            name
            for name, value in ContentAddressedStore.__dict__.items()
            if not name.startswith("_") and callable(value)
        }
        self.assertEqual(
            cas_methods,
            {
                "publish",
                "inspect",
                "verify",
                "read_bytes",
                "used_bytes",
                "object_count",
                "reconcile_orphans",
            },
        )
        ingestion_methods = {
            name
            for name, value in TrustedIngestor.__dict__.items()
            if not name.startswith("_") and callable(value)
        }
        self.assertEqual(ingestion_methods, {"ingest"})

        cas_constructor = inspect.signature(ContentAddressedStore)
        self.assertEqual(list(cas_constructor.parameters), ["root", "quota_bytes", "chunk_size"])
        self.assertEqual(
            cas_constructor.parameters["quota_bytes"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(cas_constructor.parameters["chunk_size"].default, 65_536)
        publish = inspect.signature(ContentAddressedStore.publish)
        self.assertEqual(
            list(publish.parameters),
            ["self", "source_path", "expected_sha256", "expected_size_bytes"],
        )
        for name in ("expected_sha256", "expected_size_bytes"):
            self.assertEqual(
                publish.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        self.assertEqual(
            list(inspect.signature(ContentAddressedStore.reconcile_orphans).parameters),
            ["self", "max_entries"],
        )
        for method_name, parameters in (
            ("inspect", ["self", "ref"]),
            ("verify", ["self", "ref"]),
            ("read_bytes", ["self", "ref", "maximum_size_bytes"]),
            ("used_bytes", ["self"]),
            ("object_count", ["self"]),
        ):
            self.assertEqual(
                list(
                    inspect.signature(
                        getattr(ContentAddressedStore, method_name)
                    ).parameters
                ),
                parameters,
            )
        self.assertEqual(
            inspect.signature(ContentAddressedStore.read_bytes)
            .parameters["maximum_size_bytes"]
            .kind,
            inspect.Parameter.KEYWORD_ONLY,
        )

        ingestor_constructor = inspect.signature(TrustedIngestor)
        self.assertEqual(
            list(ingestor_constructor.parameters),
            ["store", "fence_verifier", "clock", "issuer_id"],
        )
        for name in ("fence_verifier", "clock", "issuer_id"):
            self.assertEqual(
                ingestor_constructor.parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        self.assertEqual(
            list(inspect.signature(TrustedIngestor.ingest).parameters),
            ["self", "staging_envelope", "staging_root"],
        )
        self.assertEqual(
            list(inspect.signature(canonical_json_sha256).parameters),
            ["value"],
        )

    def test_modules_are_stdlib_only_without_runtime_or_domain_authority(self) -> None:
        forbidden_imports = {
            "aiohttp",
            "cryptography",
            "fastapi",
            "flask",
            "ftplib",
            "http",
            "httpx",
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
            "execution_receipt",
            "executionreceipt",
            "exploit",
            "live_trade",
            "order_submit",
            "registry_writer",
            "scientific_outcome",
            "target_scan",
        }
        imported_roots: set[str] = set()
        identifiers: set[str] = set()

        for filename in ("cas.py", "ingestion.py"):
            tree = ast.parse((SRC / "research_bridge" / filename).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_roots.update(
                        alias.name.split(".")[0] for alias in node.names
                    )
                elif isinstance(node, ast.ImportFrom) and node.level:
                    imported_roots.add("research_bridge")
                    if filename == "ingestion.py":
                        self.assertNotEqual(node.module, "cas")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported_roots.add(node.module.split(".")[0])
                elif isinstance(node, ast.Name):
                    identifiers.add(node.id.lower())
                elif isinstance(node, ast.Attribute):
                    identifiers.add(node.attr.lower())
                elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    identifiers.add(node.name.lower())

        non_stdlib = {
            root
            for root in imported_roots
            if root not in sys.stdlib_module_names and root != "research_bridge"
        }
        self.assertEqual(non_stdlib, set())
        self.assertTrue(imported_roots.isdisjoint(forbidden_imports))
        violations = {
            identifier
            for identifier in identifiers
            if any(fragment in identifier for fragment in forbidden_identifier_fragments)
        }
        self.assertEqual(violations, set())


if __name__ == "__main__":
    unittest.main()
