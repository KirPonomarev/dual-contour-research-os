import concurrent.futures
from dataclasses import FrozenInstanceError, fields
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.cas import CASError, CASObject, ContentAddressedStore


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class ContentAddressedStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name)
        self.root = self.base / "cas"
        self.source = self.base / "synthetic-public.bin"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def store(self, *, quota_bytes: int = 1024, chunk_size: int = 3) -> ContentAddressedStore:
        return ContentAddressedStore(
            self.root,
            quota_bytes=quota_bytes,
            chunk_size=chunk_size,
        )

    def write_source(self, payload: bytes) -> tuple[str, int]:
        self.source.write_bytes(payload)
        return digest(payload), len(payload)

    def publish(self, store: ContentAddressedStore, payload: bytes) -> CASObject:
        expected_digest, expected_size = self.write_source(payload)
        return store.publish(
            self.source,
            expected_sha256=expected_digest,
            expected_size_bytes=expected_size,
        )

    def test_publish_returns_only_immutable_portable_metadata_and_exact_retry(self) -> None:
        store = self.store(quota_bytes=7)
        first = self.publish(store, b"D0-data")
        second = store.publish(
            self.source,
            expected_sha256=first.sha256,
            expected_size_bytes=first.size_bytes,
        )

        self.assertEqual([field.name for field in fields(CASObject)], ["ref", "sha256", "size_bytes", "created"])
        self.assertEqual(first.ref, f"cas:sha256:{first.sha256}")
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertNotIn(str(self.root), first.ref)
        self.assertFalse(hasattr(first, "path"))
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            first.created = False  # type: ignore[misc]
        self.assertEqual(store.inspect(first.ref), second)
        self.assertTrue(store.verify(first.ref))
        self.assertEqual(store.used_bytes(), 7)
        self.assertEqual(store.object_count(), 1)
        mode = os.lstat(self.root / "objects" / first.sha256).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o444)

    def test_bounded_read_returns_exact_verified_bytes_without_store_mutation(self) -> None:
        store = self.store()
        payload = b"synthetic bounded terminal material"
        published = self.publish(store, payload)
        before = (store.object_count(), store.used_bytes())

        self.assertEqual(
            store.read_bytes(
                published.ref,
                maximum_size_bytes=len(payload),
            ),
            payload,
        )
        self.assertEqual((store.object_count(), store.used_bytes()), before)

        for maximum in (len(payload) - 1, -1, True, 1.5):
            with self.subTest(maximum=maximum), self.assertRaises(CASError):
                store.read_bytes(  # type: ignore[arg-type]
                    published.ref,
                    maximum_size_bytes=maximum,
                )
        self.assertEqual((store.object_count(), store.used_bytes()), before)

    def test_bounded_read_rejects_missing_symlink_wrong_mode_and_tampering(self) -> None:
        store = self.store()
        payload = b"trusted terminal"
        published = self.publish(store, payload)
        canonical = self.root / "objects" / published.sha256

        with self.assertRaises(CASError):
            store.read_bytes(
                f"cas:sha256:{'0' * 64}",
                maximum_size_bytes=1024,
            )

        canonical.chmod(0o644)
        with self.assertRaises(CASError):
            store.read_bytes(published.ref, maximum_size_bytes=1024)
        canonical.write_bytes(b"tampered terminal")
        canonical.chmod(0o444)
        with self.assertRaises(CASError):
            store.read_bytes(published.ref, maximum_size_bytes=1024)

        canonical.chmod(0o600)
        canonical.unlink()
        external = self.base / "external-terminal"
        external.write_bytes(payload)
        canonical.symlink_to(external)
        with self.assertRaises(CASError):
            store.read_bytes(published.ref, maximum_size_bytes=1024)

    def test_bounded_read_rejects_canonical_path_swap_during_streaming(self) -> None:
        store = self.store(chunk_size=3)
        payload = b"stable-terminal-material"
        published = self.publish(store, payload)
        canonical = self.root / "objects" / published.sha256
        replacement = self.base / "replacement-terminal"
        replacement.write_bytes(payload)
        real_read = os.read
        swapped = False

        def swap_after_read(fd: int, size: int) -> bytes:
            nonlocal swapped
            block = real_read(fd, size)
            if block and not swapped:
                swapped = True
                canonical.chmod(0o600)
                canonical.unlink()
                canonical.symlink_to(replacement)
            return block

        with mock.patch("research_bridge.cas.os.read", side_effect=swap_after_read):
            with self.assertRaises(CASError):
                store.read_bytes(published.ref, maximum_size_bytes=1024)

    def test_concurrent_same_digest_has_exactly_one_creator(self) -> None:
        payload = b"synthetic-concurrent-object"
        expected_digest, expected_size = self.write_source(payload)
        store = self.store(quota_bytes=len(payload))

        def publication() -> CASObject:
            return store.publish(
                self.source,
                expected_sha256=expected_digest,
                expected_size_bytes=expected_size,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            objects = list(pool.map(lambda _: publication(), range(12)))

        self.assertEqual(sum(item.created for item in objects), 1)
        self.assertEqual({item.ref for item in objects}, {f"cas:sha256:{expected_digest}"})
        self.assertEqual(store.used_bytes(), expected_size)
        self.assertEqual(store.object_count(), 1)

    def test_digest_size_and_reference_validation_fail_closed_without_object(self) -> None:
        store = self.store()
        expected_digest, expected_size = self.write_source(b"payload")

        invalid_calls = [
            {"expected_sha256": "A" * 64, "expected_size_bytes": expected_size},
            {"expected_sha256": "0" * 64, "expected_size_bytes": expected_size},
            {"expected_sha256": expected_digest, "expected_size_bytes": expected_size + 1},
            {"expected_sha256": expected_digest, "expected_size_bytes": -1},
        ]
        for arguments in invalid_calls:
            with self.subTest(arguments=arguments), self.assertRaises(CASError):
                store.publish(self.source, **arguments)

        for ref in ["", expected_digest, "cas:sha256:../escape", f"cas:sha256:{expected_digest.upper()}"]:
            with self.subTest(ref=ref), self.assertRaises(CASError):
                store.inspect(ref)
        self.assertEqual(store.object_count(), 0)

    def test_symlink_and_fifo_sources_are_rejected_without_following(self) -> None:
        payload = b"source"
        expected_digest, expected_size = self.write_source(payload)
        store = self.store()
        symlink = self.base / "source-link"
        symlink.symlink_to(self.source)

        with self.assertRaises(CASError):
            store.publish(
                symlink,
                expected_sha256=expected_digest,
                expected_size_bytes=expected_size,
            )

        if hasattr(os, "mkfifo"):
            fifo = self.base / "source-fifo"
            os.mkfifo(fifo)
            with self.assertRaises(CASError):
                store.publish(
                    fifo,
                    expected_sha256=digest(b""),
                    expected_size_bytes=0,
                )
        self.assertEqual(store.object_count(), 0)

    def test_source_and_root_traversal_or_symlink_are_rejected(self) -> None:
        expected_digest, expected_size = self.write_source(b"x")
        store = self.store()
        with self.assertRaises(CASError):
            store.publish(
                self.base / "missing" / ".." / self.source.name,
                expected_sha256=expected_digest,
                expected_size_bytes=expected_size,
            )

        real_root = self.base / "real-root"
        real_root.mkdir()
        root_link = self.base / "root-link"
        root_link.symlink_to(real_root, target_is_directory=True)
        with self.assertRaises(CASError):
            ContentAddressedStore(root_link, quota_bytes=10)

    def test_insecure_preexisting_store_directories_and_lock_are_rejected(self) -> None:
        insecure_root = self.base / "insecure-root"
        insecure_root.mkdir(mode=0o700)
        insecure_root.chmod(0o777)
        with self.assertRaises(CASError):
            ContentAddressedStore(insecure_root, quota_bytes=10)

        insecure_objects_root = self.base / "insecure-objects-cas"
        insecure_objects_root.mkdir(mode=0o700)
        (insecure_objects_root / "objects").mkdir(mode=0o700)
        (insecure_objects_root / "objects").chmod(0o770)
        with self.assertRaises(CASError):
            ContentAddressedStore(insecure_objects_root, quota_bytes=10)

        insecure_temporary_root = self.base / "insecure-temporary-cas"
        insecure_temporary_root.mkdir(mode=0o700)
        (insecure_temporary_root / "objects").mkdir(mode=0o700)
        (insecure_temporary_root / ".tmp").mkdir(mode=0o700)
        (insecure_temporary_root / ".tmp").chmod(0o707)
        with self.assertRaises(CASError):
            ContentAddressedStore(insecure_temporary_root, quota_bytes=10)

        lock_store = ContentAddressedStore(self.base / "insecure-lock-cas", quota_bytes=10)
        lock_path = self.base / "insecure-lock-cas" / ".cas.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)
        with self.assertRaises(CASError):
            lock_store.object_count()

    def test_quota_counts_canonical_and_orphan_temporary_bytes(self) -> None:
        store = self.store(quota_bytes=5)
        first = self.publish(store, b"abc")
        self.source.write_bytes(b"def")
        with self.assertRaises(CASError):
            store.publish(
                self.source,
                expected_sha256=digest(b"def"),
                expected_size_bytes=3,
            )
        self.assertTrue(store.verify(first.ref))
        self.assertEqual(store.used_bytes(), 3)

        orphan = self.root / ".tmp" / "synthetic-orphan.tmp"
        orphan.write_bytes(b"zz")
        self.source.write_bytes(b"q")
        with self.assertRaises(CASError):
            store.publish(
                self.source,
                expected_sha256=digest(b"q"),
                expected_size_bytes=1,
            )
        self.assertEqual(store.reconcile_orphans(1), 1)
        created = store.publish(
            self.source,
            expected_sha256=digest(b"q"),
            expected_size_bytes=1,
        )
        self.assertTrue(created.created)
        self.assertEqual(store.used_bytes(), 4)

    def test_corrupt_existing_object_is_never_accepted_or_replaced(self) -> None:
        store = self.store()
        published = self.publish(store, b"trusted")
        canonical = self.root / "objects" / published.sha256
        canonical.chmod(0o600)
        canonical.write_bytes(b"corrupt")

        with self.assertRaises(CASError):
            store.verify(published.ref)
        with self.assertRaises(CASError):
            store.publish(
                self.source,
                expected_sha256=published.sha256,
                expected_size_bytes=published.size_bytes,
            )
        self.assertEqual(canonical.read_bytes(), b"corrupt")

    def test_fsync_failure_returns_no_success_and_cleans_partial_state(self) -> None:
        store = self.store()
        expected_digest, expected_size = self.write_source(b"durability")
        with mock.patch("research_bridge.cas.os.fsync", side_effect=OSError("synthetic fsync failure")):
            with self.assertRaises(CASError):
                store.publish(
                    self.source,
                    expected_sha256=expected_digest,
                    expected_size_bytes=expected_size,
                )
        self.assertEqual(store.object_count(), 0)
        self.assertEqual(list((self.root / ".tmp").iterdir()), [])

        adopted_root = self.base / "adopted-cas"
        adopted_store = ContentAddressedStore(adopted_root, quota_bytes=1024)
        with mock.patch(
            "research_bridge.cas.os.fsync",
            side_effect=[None, OSError("synthetic parent fsync failure")],
        ):
            with self.assertRaises(CASError):
                adopted_store.publish(
                    self.source,
                    expected_sha256=expected_digest,
                    expected_size_bytes=expected_size,
                )
        self.assertEqual(adopted_store.object_count(), 0)
        self.assertEqual(list((adopted_root / ".tmp").iterdir()), [])

    def test_short_write_is_completed_and_zero_progress_write_is_cleaned(self) -> None:
        store = self.store(chunk_size=32)
        expected_digest, expected_size = self.write_source(b"short-write-payload")
        real_write = os.write

        def short_write(fd: int, block: bytes | memoryview) -> int:
            return real_write(fd, bytes(block[: max(1, len(block) // 2)]))

        with mock.patch("research_bridge.cas.os.write", side_effect=short_write):
            published = store.publish(
                self.source,
                expected_sha256=expected_digest,
                expected_size_bytes=expected_size,
            )
        self.assertTrue(store.verify(published.ref))

        second_store = ContentAddressedStore(self.base / "other-cas", quota_bytes=1024)
        self.source.write_bytes(b"zero-progress")
        with mock.patch("research_bridge.cas.os.write", return_value=0):
            with self.assertRaises(CASError):
                second_store.publish(
                    self.source,
                    expected_sha256=digest(b"zero-progress"),
                    expected_size_bytes=len(b"zero-progress"),
                )
        self.assertEqual(second_store.object_count(), 0)
        self.assertEqual(list((self.base / "other-cas" / ".tmp").iterdir()), [])

    def test_orphan_reconciliation_is_bounded_idempotent_and_validates_bound(self) -> None:
        store = self.store()
        temporary = self.root / ".tmp"
        for name in ["a.tmp", "b.tmp", "c.tmp"]:
            (temporary / name).write_bytes(name.encode("ascii"))

        with self.assertRaises(CASError):
            store.reconcile_orphans(0)
        self.assertEqual(store.reconcile_orphans(2), 2)
        self.assertEqual(len(list(temporary.iterdir())), 1)
        self.assertEqual(store.reconcile_orphans(2), 1)
        self.assertEqual(store.reconcile_orphans(2), 0)

        external = self.base / "external-synthetic"
        external.write_bytes(b"must-remain")
        (temporary / "symlink.tmp").symlink_to(external)
        self.assertEqual(store.reconcile_orphans(1), 1)
        self.assertEqual(external.read_bytes(), b"must-remain")


if __name__ == "__main__":
    unittest.main()
