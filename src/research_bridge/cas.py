"""Bridge-owned immutable content-addressed storage.

The store deliberately exposes content references, never filesystem paths.  A
publication is copied into a private temporary file, validated while streaming,
made read-only, fsynced, and adopted with an exclusive hard link.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import uuid
from typing import Iterator

try:  # The Bridge runtime is Unix-only, but keep import failure explicit.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on unsupported hosts
    fcntl = None  # type: ignore[assignment]


__all__ = ["CASError", "CASObject", "ContentAddressedStore"]


_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_REF_PREFIX = "cas:sha256:"


class CASError(RuntimeError):
    """A fail-closed CAS validation, integrity, quota, or durability error."""


@dataclass(frozen=True, slots=True)
class CASObject:
    """Portable metadata for an immutable CAS object."""

    ref: str
    sha256: str
    size_bytes: int
    created: bool


class ContentAddressedStore:
    """A small, quota-bounded, durable content-addressed store."""

    def __init__(
        self,
        root: os.PathLike[str] | str,
        *,
        quota_bytes: int,
        chunk_size: int = 65536,
    ) -> None:
        if isinstance(quota_bytes, bool) or not isinstance(quota_bytes, int) or quota_bytes < 0:
            raise CASError("quota_bytes must be a non-negative integer")
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise CASError("chunk_size must be a positive integer")
        if isinstance(root, bytes):
            raise CASError("root must be a text path")

        try:
            root_path = Path(os.fspath(root))
        except (TypeError, ValueError) as exc:
            raise CASError("root must be a text path") from exc
        if ".." in root_path.parts:
            raise CASError("root path traversal is forbidden")
        try:
            root_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise CASError("unable to initialize CAS root") from exc

        self._root = root_path
        self._objects = root_path / "objects"
        self._temporary = root_path / ".tmp"
        self._lock_path = root_path / ".cas.lock"
        self._quota_bytes = quota_bytes
        self._chunk_size = chunk_size
        self._thread_lock = threading.RLock()

        self._require_directory(self._root, "CAS root")
        self._make_private_directory(self._objects, "object directory")
        self._make_private_directory(self._temporary, "temporary directory")

    def publish(
        self,
        source_path: os.PathLike[str] | str,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> CASObject:
        """Validate and durably publish a regular source file.

        Exact retries return the already-published object with ``created=False``.
        Integrity and durability failures never return success.
        """

        digest = self._validate_digest(expected_sha256)
        size = self._validate_size(expected_size_bytes)
        source = self._validate_source_path(source_path)
        canonical = self._object_path(digest)

        with self._exclusive_lock():
            if self._path_exists_without_following(canonical):
                existing_size = self._verify_object_path(canonical, digest)
                if existing_size != size:
                    raise CASError("existing CAS object size does not match publication")
                self._validate_source_bytes(source, digest, size, destination_fd=None)
                return self._object(digest, size, created=False)

            allocated = self._allocated_bytes()
            if size > self._quota_bytes - allocated:
                raise CASError("CAS quota exceeded")

            temporary = self._temporary / (
                f"{digest}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
            )
            temp_fd: int | None = None
            adopted = False
            try:
                temp_fd = self._open_new_regular(temporary)
                self._validate_source_bytes(source, digest, size, destination_fd=temp_fd)
                os.fchmod(temp_fd, 0o444)
                os.fsync(temp_fd)
                os.close(temp_fd)
                temp_fd = None

                try:
                    os.link(temporary, canonical, follow_symlinks=False)
                    adopted = True
                except FileExistsError:
                    existing_size = self._verify_object_path(canonical, digest)
                    if existing_size != size:
                        raise CASError("racing CAS object size does not match publication")

                if adopted:
                    self._fsync_directory(self._objects)
                os.unlink(temporary)
                self._fsync_directory(self._temporary)

                if not adopted:
                    return self._object(digest, size, created=False)
                return self._object(digest, size, created=True)
            except Exception as exc:
                if temp_fd is not None:
                    try:
                        os.close(temp_fd)
                    except OSError:
                        pass
                if adopted:
                    self._unlink_if_same_regular(canonical, digest, size)
                self._unlink_without_following(temporary)
                if isinstance(exc, CASError):
                    raise
                raise CASError("CAS publication failed before durable completion") from exc

    def inspect(self, ref: str) -> CASObject:
        """Return verified portable metadata for ``ref``."""

        digest = self._digest_from_ref(ref)
        with self._exclusive_lock():
            size = self._verify_object_path(self._object_path(digest), digest)
            return self._object(digest, size, created=False)

    def verify(self, ref: str) -> bool:
        """Fully verify an object, raising ``CASError`` on any mismatch."""

        self.inspect(ref)
        return True

    def read_bytes(self, ref: str, *, maximum_size_bytes: int) -> bytes:
        """Return fully verified object bytes without following links.

        The size ceiling is checked before allocation and while streaming so a
        corrupt or racing object cannot turn a bounded read into an unbounded
        one.
        """

        digest = self._digest_from_ref(ref)
        if (
            isinstance(maximum_size_bytes, bool)
            or not isinstance(maximum_size_bytes, int)
            or maximum_size_bytes < 0
        ):
            raise CASError("maximum_size_bytes must be a non-negative integer")
        path = self._object_path(digest)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with self._exclusive_lock():
            try:
                path_stat = os.lstat(path)
                if not stat.S_ISREG(path_stat.st_mode) or stat.S_ISLNK(
                    path_stat.st_mode
                ):
                    raise CASError("CAS object is not a regular file")
                fd = os.open(path, flags)
            except CASError:
                raise
            except OSError as exc:
                raise CASError("CAS object is unavailable") from exc
            try:
                opened_stat = os.fstat(fd)
                if not stat.S_ISREG(opened_stat.st_mode):
                    raise CASError("CAS object is not a regular file")
                if stat.S_IMODE(opened_stat.st_mode) != 0o444:
                    raise CASError("CAS object mode is not immutable")
                if (path_stat.st_dev, path_stat.st_ino) != (
                    opened_stat.st_dev,
                    opened_stat.st_ino,
                ):
                    raise CASError("CAS object changed while it was opened")
                if opened_stat.st_size > maximum_size_bytes:
                    raise CASError("CAS object exceeds maximum_size_bytes")

                hasher = hashlib.sha256()
                total = 0
                chunks: list[bytes] = []
                while True:
                    block = os.read(fd, self._chunk_size)
                    if not block:
                        break
                    total += len(block)
                    if total > maximum_size_bytes:
                        raise CASError("CAS object exceeds maximum_size_bytes")
                    hasher.update(block)
                    chunks.append(block)

                after_stat = os.fstat(fd)
                after_path = os.lstat(path)
                if (
                    opened_stat.st_dev,
                    opened_stat.st_ino,
                    opened_stat.st_size,
                    stat.S_IMODE(opened_stat.st_mode),
                    getattr(opened_stat, "st_mtime_ns", None),
                    getattr(opened_stat, "st_ctime_ns", None),
                ) != (
                    after_stat.st_dev,
                    after_stat.st_ino,
                    after_stat.st_size,
                    stat.S_IMODE(after_stat.st_mode),
                    getattr(after_stat, "st_mtime_ns", None),
                    getattr(after_stat, "st_ctime_ns", None),
                ):
                    raise CASError("CAS object changed during bounded read")
                if (
                    not stat.S_ISREG(after_path.st_mode)
                    or stat.S_ISLNK(after_path.st_mode)
                    or stat.S_IMODE(after_path.st_mode) != 0o444
                    or (after_path.st_dev, after_path.st_ino)
                    != (after_stat.st_dev, after_stat.st_ino)
                ):
                    raise CASError("CAS object path changed during bounded read")
                if total != opened_stat.st_size or hasher.hexdigest() != digest:
                    raise CASError("CAS object integrity verification failed")
                return b"".join(chunks)
            except OSError as exc:
                raise CASError("CAS object bounded read failed") from exc
            finally:
                os.close(fd)

    def used_bytes(self) -> int:
        """Return bytes occupied by canonical objects (temporary bytes excluded)."""

        with self._exclusive_lock():
            used, _ = self._canonical_usage()
            return used

    def object_count(self) -> int:
        """Return the number of canonical objects."""

        with self._exclusive_lock():
            _, count = self._canonical_usage()
            return count

    def reconcile_orphans(self, max_entries: int) -> int:
        """Remove at most ``max_entries`` abandoned temporary entries."""

        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise CASError("max_entries must be a positive integer")
        removed = 0
        examined = 0
        with self._exclusive_lock():
            self._require_directory(self._temporary, "temporary directory")
            try:
                entries = os.scandir(self._temporary)
                with entries:
                    for entry in entries:
                        if examined >= max_entries:
                            break
                        examined += 1
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                            if stat.S_ISDIR(entry_stat.st_mode):
                                raise CASError("temporary orphan is a directory")
                            os.unlink(entry.path)
                            removed += 1
                        except FileNotFoundError:
                            continue
                        except CASError:
                            raise
                        except OSError as exc:
                            raise CASError("unable to reconcile temporary object") from exc
            except CASError:
                raise
            except OSError as exc:
                raise CASError("unable to enumerate temporary objects") from exc
            if removed:
                self._fsync_directory(self._temporary)
        return removed

    @staticmethod
    def _validate_digest(value: str) -> str:
        if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
            raise CASError("expected_sha256 must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _validate_size(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CASError("expected_size_bytes must be a non-negative integer")
        return value

    @staticmethod
    def _validate_source_path(source_path: os.PathLike[str] | str) -> Path:
        if isinstance(source_path, bytes):
            raise CASError("source_path must be a text path")
        try:
            source = Path(os.fspath(source_path))
        except (TypeError, ValueError) as exc:
            raise CASError("source_path must be a text path") from exc
        if ".." in source.parts:
            raise CASError("source path traversal is forbidden")
        try:
            source_stat = os.lstat(source)
        except OSError as exc:
            raise CASError("source path is unavailable") from exc
        if not stat.S_ISREG(source_stat.st_mode) or stat.S_ISLNK(source_stat.st_mode):
            raise CASError("source must be a non-symlink regular file")
        return source

    def _validate_source_bytes(
        self,
        source: Path,
        digest: str,
        size: int,
        *,
        destination_fd: int | None,
    ) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            before_path = os.lstat(source)
            source_fd = os.open(source, flags)
        except OSError as exc:
            raise CASError("unable to open source without following links") from exc
        try:
            before_fd = os.fstat(source_fd)
            if not stat.S_ISREG(before_path.st_mode) or not stat.S_ISREG(before_fd.st_mode):
                raise CASError("source must remain a regular file")
            if (before_path.st_dev, before_path.st_ino) != (before_fd.st_dev, before_fd.st_ino):
                raise CASError("source changed while it was opened")
            if before_fd.st_size != size:
                raise CASError("source size does not match expected_size_bytes")

            hasher = hashlib.sha256()
            total = 0
            while True:
                block = os.read(source_fd, self._chunk_size)
                if not block:
                    break
                total += len(block)
                if total > size:
                    raise CASError("source exceeds expected_size_bytes")
                hasher.update(block)
                if destination_fd is not None:
                    self._write_all(destination_fd, block)

            after_fd = os.fstat(source_fd)
            stable_fields = (
                before_fd.st_dev,
                before_fd.st_ino,
                before_fd.st_size,
                getattr(before_fd, "st_mtime_ns", None),
                getattr(before_fd, "st_ctime_ns", None),
            )
            after_fields = (
                after_fd.st_dev,
                after_fd.st_ino,
                after_fd.st_size,
                getattr(after_fd, "st_mtime_ns", None),
                getattr(after_fd, "st_ctime_ns", None),
            )
            if stable_fields != after_fields:
                raise CASError("source changed during publication")
            if total != size:
                raise CASError("source size does not match expected_size_bytes")
            if hasher.hexdigest() != digest:
                raise CASError("source digest does not match expected_sha256")
        except OSError as exc:
            raise CASError("source streaming failed") from exc
        finally:
            os.close(source_fd)

    @staticmethod
    def _write_all(fd: int, block: bytes) -> None:
        view = memoryview(block)
        while view:
            try:
                written = os.write(fd, view)
            except OSError as exc:
                raise CASError("temporary object write failed") from exc
            if written <= 0:
                raise CASError("temporary object write made no progress")
            view = view[written:]

    def _verify_object_path(self, path: Path, digest: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            path_stat = os.lstat(path)
            if not stat.S_ISREG(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode):
                raise CASError("CAS object is not a regular file")
            fd = os.open(path, flags)
        except CASError:
            raise
        except OSError as exc:
            raise CASError("CAS object is unavailable") from exc
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise CASError("CAS object is not a regular file")
            if stat.S_IMODE(opened_stat.st_mode) != 0o444:
                raise CASError("CAS object mode is not immutable")
            if (path_stat.st_dev, path_stat.st_ino) != (opened_stat.st_dev, opened_stat.st_ino):
                raise CASError("CAS object changed while it was opened")
            hasher = hashlib.sha256()
            total = 0
            while True:
                block = os.read(fd, self._chunk_size)
                if not block:
                    break
                total += len(block)
                hasher.update(block)
            after_stat = os.fstat(fd)
            if (
                opened_stat.st_dev,
                opened_stat.st_ino,
                opened_stat.st_size,
                stat.S_IMODE(opened_stat.st_mode),
                getattr(opened_stat, "st_mtime_ns", None),
                getattr(opened_stat, "st_ctime_ns", None),
            ) != (
                after_stat.st_dev,
                after_stat.st_ino,
                after_stat.st_size,
                stat.S_IMODE(after_stat.st_mode),
                getattr(after_stat, "st_mtime_ns", None),
                getattr(after_stat, "st_ctime_ns", None),
            ):
                raise CASError("CAS object changed during verification")
            if total != opened_stat.st_size or hasher.hexdigest() != digest:
                raise CASError("CAS object integrity verification failed")
            return total
        except OSError as exc:
            raise CASError("CAS object verification failed") from exc
        finally:
            os.close(fd)

    def _canonical_usage(self) -> tuple[int, int]:
        self._require_directory(self._objects, "object directory")
        used = 0
        count = 0
        try:
            entries = os.scandir(self._objects)
        except OSError as exc:
            raise CASError("unable to enumerate CAS objects") from exc
        with entries:
            for entry in entries:
                try:
                    if _DIGEST_RE.fullmatch(entry.name) is None:
                        raise CASError("unexpected canonical CAS entry")
                    entry_stat = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(entry_stat.st_mode):
                        raise CASError("canonical CAS entry is not a regular file")
                    used += entry_stat.st_size
                    count += 1
                except CASError:
                    raise
                except OSError as exc:
                    raise CASError("unable to inspect canonical CAS entry") from exc
        return used, count

    def _allocated_bytes(self) -> int:
        canonical, _ = self._canonical_usage()
        temporary = 0
        self._require_directory(self._temporary, "temporary directory")
        try:
            entries = os.scandir(self._temporary)
        except OSError as exc:
            raise CASError("unable to enumerate temporary objects") from exc
        with entries:
            for entry in entries:
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(entry_stat.st_mode):
                        raise CASError("temporary CAS entry is not a regular file")
                    temporary += entry_stat.st_size
                except CASError:
                    raise
                except OSError as exc:
                    raise CASError("unable to inspect temporary CAS entry") from exc
        return canonical + temporary

    def _object_path(self, digest: str) -> Path:
        return self._objects / digest

    @staticmethod
    def _object(digest: str, size: int, *, created: bool) -> CASObject:
        return CASObject(
            ref=f"{_REF_PREFIX}{digest}",
            sha256=digest,
            size_bytes=size,
            created=created,
        )

    @staticmethod
    def _digest_from_ref(ref: str) -> str:
        if not isinstance(ref, str) or not ref.startswith(_REF_PREFIX):
            raise CASError("invalid CAS reference")
        digest = ref[len(_REF_PREFIX) :]
        if _DIGEST_RE.fullmatch(digest) is None:
            raise CASError("invalid CAS reference")
        return digest

    @staticmethod
    def _path_exists_without_following(path: Path) -> bool:
        try:
            os.lstat(path)
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise CASError("unable to inspect CAS object path") from exc

    @staticmethod
    def _require_directory(path: Path, label: str) -> None:
        try:
            path_stat = os.lstat(path)
        except OSError as exc:
            raise CASError(f"{label} is unavailable") from exc
        if not stat.S_ISDIR(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode):
            raise CASError(f"{label} must be a non-symlink directory")
        if stat.S_IMODE(path_stat.st_mode) != 0o700:
            raise CASError(f"{label} must have mode 0700")

    def _make_private_directory(self, path: Path, label: str) -> None:
        try:
            path.mkdir(mode=0o700, exist_ok=True)
        except OSError as exc:
            raise CASError(f"unable to initialize {label}") from exc
        self._require_directory(path, label)

    @staticmethod
    def _open_new_regular(path: Path) -> int:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(path, flags, 0o600)
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode):
                os.close(fd)
                raise CASError("temporary object is not a regular file")
            return fd
        except CASError:
            raise
        except OSError as exc:
            raise CASError("unable to create exclusive temporary object") from exc

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise CASError("directory durability barrier failed") from exc

    @staticmethod
    def _unlink_without_following(path: Path) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _unlink_if_same_regular(self, path: Path, digest: str, size: int) -> None:
        try:
            if self._verify_object_path(path, digest) == size:
                os.unlink(path)
        except (CASError, OSError):
            # Cleanup is best-effort; the method never reports publication success.
            pass

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        if fcntl is None:
            raise CASError("CAS requires Unix file locking support")
        self._require_directory(self._root, "CAS root")
        self._require_directory(self._objects, "object directory")
        self._require_directory(self._temporary, "temporary directory")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with self._thread_lock:
            try:
                lock_fd = os.open(self._lock_path, flags, 0o600)
                lock_stat = os.fstat(lock_fd)
                if not stat.S_ISREG(lock_stat.st_mode):
                    os.close(lock_fd)
                    raise CASError("CAS lock is not a regular file")
                lock_path_stat = os.lstat(self._lock_path)
                if not stat.S_ISREG(lock_path_stat.st_mode):
                    os.close(lock_fd)
                    raise CASError("CAS lock path is not a regular file")
                if (lock_path_stat.st_dev, lock_path_stat.st_ino) != (
                    lock_stat.st_dev,
                    lock_stat.st_ino,
                ):
                    os.close(lock_fd)
                    raise CASError("CAS lock changed while it was opened")
                if stat.S_IMODE(lock_stat.st_mode) != 0o600 or stat.S_IMODE(
                    lock_path_stat.st_mode
                ) != 0o600:
                    os.close(lock_fd)
                    raise CASError("CAS lock must have mode 0600")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except CASError:
                raise
            except OSError as exc:
                raise CASError("unable to acquire CAS publication lock") from exc
            try:
                yield
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
