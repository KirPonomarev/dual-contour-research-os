"""Trusted ingestion boundary from untrusted staging into portable CAS records.

The adapter is deliberately domain-neutral.  It accepts only sanitized D0/D1
files, verifies every byte and the winning fencing authority before publishing,
and emits ArtifactManifest-shaped mappings only after the complete publication
set succeeds.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol


__all__ = [
    "IngestionError",
    "ArtifactRecord",
    "TrustedIngestor",
    "canonical_json_sha256",
]


_COMMON_KEYS = frozenset(
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
    }
)
_ISSUER_KEYS = frozenset({"id", "authority_class"})
_INTEGRITY_KEYS = frozenset({"payload_sha256", "parent_refs"})
_STAGING_PAYLOAD_KEYS = frozenset(
    {
        "producer_identity",
        "run_id",
        "attempt_id",
        "fencing_token",
        "relative_file_manifest",
        "claimed_metrics",
        "completion_reason",
    }
)
_FILE_ENTRY_KEYS = frozenset(
    {
        "relative_path",
        "sha256",
        "size_bytes",
        "claim_class",
        "source_refs",
        "redaction_status",
        "retention_class",
        "validator_ref",
    }
)
_CONTOURS = frozenset({"bridge", "market", "security", "governance"})
_ALLOWED_CLASSIFICATIONS = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_MAX_TEXT_LENGTH = 1024


class IngestionError(RuntimeError):
    """A fail-closed staging, fencing, publication, or manifest error."""


class _CASObject(Protocol):
    ref: str
    sha256: str
    size_bytes: int
    created: bool


class _Publisher(Protocol):
    def publish(
        self,
        source_path: str | Path,
        *,
        expected_sha256: str,
        expected_size_bytes: int,
    ) -> _CASObject: ...


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """One portable artifact reference and its trusted manifest mapping."""

    artifact_ref: str
    manifest: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _ValidatedFile:
    path: Path
    relative_path: str
    sha256: str
    size_bytes: int
    claim_class: str
    source_refs: tuple[str, ...]
    redaction_status: str
    retention_class: str
    validator_ref: str


@dataclass(frozen=True, slots=True)
class _ValidatedEnvelope:
    object_id: str
    contour: str
    classification: str
    producer_identity: str
    run_id: str
    attempt_id: str
    fencing_token: str
    files: tuple[_ValidatedFile, ...]


def canonical_json_sha256(value: Any) -> str:
    """Return SHA-256 over strict deterministic UTF-8 JSON."""

    _ensure_json_value(value, "value")
    try:
        encoded = json.dumps(
            _json_ready(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IngestionError("value is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


class TrustedIngestor:
    """Validate untrusted staging and publish only with a current fence."""

    def __init__(
        self,
        store: _Publisher,
        *,
        fence_verifier: Callable[..., object],
        clock: Callable[[], datetime | str] | None = None,
        issuer_id: str = "researchd-trusted-ingestor",
    ) -> None:
        if not callable(getattr(store, "publish", None)):
            raise IngestionError("store must expose a callable publish method")
        if not callable(fence_verifier):
            raise IngestionError("fence_verifier must be callable")
        if clock is not None and not callable(clock):
            raise IngestionError("clock must be callable")
        self._store = store
        self._fence_verifier = fence_verifier
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._issuer_id = _normalized_identifier("issuer_id", issuer_id)

    def ingest(
        self,
        staging_envelope: Mapping[str, Any],
        staging_root: str | Path,
    ) -> tuple[ArtifactRecord, ...]:
        """Validate, fence, publish in order, then create trusted manifests."""

        validated = _validate_envelope(staging_envelope, staging_root)

        try:
            fence_valid = self._fence_verifier(
                attempt_id=validated.attempt_id,
                producer_identity=validated.producer_identity,
                fencing_token=validated.fencing_token,
            )
        except Exception as exc:
            raise IngestionError("fencing authority verification failed") from exc
        if fence_valid is not True:
            raise IngestionError("fencing authority is not current")

        publications: list[_CASObject] = []
        try:
            for file_record in validated.files:
                publication = self._store.publish(
                    file_record.path,
                    expected_sha256=file_record.sha256,
                    expected_size_bytes=file_record.size_bytes,
                )
                _validate_publication(publication, file_record)
                publications.append(publication)
        except Exception as exc:
            if isinstance(exc, IngestionError):
                raise
            raise IngestionError("CAS publication failed") from exc

        try:
            issued_at = _trusted_timestamp(self._clock())
        except Exception as exc:
            if isinstance(exc, IngestionError):
                raise
            raise IngestionError("trusted ingestion clock failed") from exc
        records: list[ArtifactRecord] = []
        for index, (file_record, publication) in enumerate(
            zip(validated.files, publications, strict=True)
        ):
            payload: dict[str, Any] = {
                "artifact_sha256": file_record.sha256,
                "size_bytes": file_record.size_bytes,
                "producer": validated.producer_identity,
                "claim_class": file_record.claim_class,
                "source_refs": list(file_record.source_refs),
                "redaction_status": file_record.redaction_status,
                "retention_class": file_record.retention_class,
                "validator_ref": file_record.validator_ref,
            }
            object_digest = canonical_json_sha256(
                {
                    "artifact_sha256": file_record.sha256,
                    "attempt_id": validated.attempt_id,
                    "index": index,
                    "staging_object_id": validated.object_id,
                }
            )
            manifest: dict[str, Any] = {
                "schema_id": "ArtifactManifest",
                "schema_version": "1.0.0",
                "object_id": f"artifact-manifest-{object_digest}",
                "issued_at": issued_at,
                "issuer": {
                    "id": self._issuer_id,
                    "authority_class": "trusted-ingestor",
                },
                "contour": validated.contour,
                "classification": validated.classification,
                "payload": payload,
                "integrity": {
                    "payload_sha256": canonical_json_sha256(payload),
                    "parent_refs": [
                        f"staging:{validated.object_id}",
                        publication.ref,
                    ],
                },
            }
            records.append(
                ArtifactRecord(
                    artifact_ref=publication.ref,
                    manifest=_deep_freeze(manifest),
                )
            )
        return tuple(records)


def _validate_envelope(
    envelope: Mapping[str, Any], staging_root: str | Path
) -> _ValidatedEnvelope:
    value = _exact_mapping(envelope, _COMMON_KEYS, "staging_envelope")
    if value["schema_id"] != "StagingEnvelope":
        raise IngestionError("staging_envelope.schema_id is invalid")
    if value["schema_version"] != "1.0.0":
        raise IngestionError("staging_envelope.schema_version is invalid")
    object_id = _normalized_identifier(
        "staging_envelope.object_id", value["object_id"]
    )
    _parse_timestamp("staging_envelope.issued_at", value["issued_at"])

    issuer = _exact_mapping(value["issuer"], _ISSUER_KEYS, "staging_envelope.issuer")
    issuer_id = _normalized_identifier("staging_envelope.issuer.id", issuer["id"])
    issuer_authority = _normalized_text(
        "staging_envelope.issuer.authority_class", issuer["authority_class"]
    )
    if issuer_authority != "untrusted-runner":
        raise IngestionError("staging envelope issuer is not an untrusted runner")

    contour = value["contour"]
    if not isinstance(contour, str) or contour not in _CONTOURS:
        raise IngestionError("staging_envelope.contour is invalid")
    classification = value["classification"]
    if (
        not isinstance(classification, str)
        or classification not in _ALLOWED_CLASSIFICATIONS
    ):
        raise IngestionError("only D0/D1 staging classifications are allowed")

    payload = _exact_mapping(
        value["payload"], _STAGING_PAYLOAD_KEYS, "staging_envelope.payload"
    )
    producer_identity = _normalized_identifier(
        "staging_envelope.payload.producer_identity", payload["producer_identity"]
    )
    if issuer_id != producer_identity:
        raise IngestionError("staging issuer id does not match producer identity")
    run_id = _normalized_identifier("staging_envelope.payload.run_id", payload["run_id"])
    attempt_id = _normalized_identifier(
        "staging_envelope.payload.attempt_id", payload["attempt_id"]
    )
    fencing_token = _normalized_text(
        "staging_envelope.payload.fencing_token", payload["fencing_token"]
    )
    if not isinstance(payload["claimed_metrics"], Mapping):
        raise IngestionError("staging_envelope.payload.claimed_metrics must be an object")
    _ensure_json_value(
        payload["claimed_metrics"], "staging_envelope.payload.claimed_metrics"
    )
    _normalized_text(
        "staging_envelope.payload.completion_reason", payload["completion_reason"]
    )

    integrity = _exact_mapping(
        value["integrity"], _INTEGRITY_KEYS, "staging_envelope.integrity"
    )
    payload_sha256 = _sha256(
        "staging_envelope.integrity.payload_sha256", integrity["payload_sha256"]
    )
    _string_sequence(
        "staging_envelope.integrity.parent_refs", integrity["parent_refs"]
    )
    if not hmac.compare_digest(payload_sha256, canonical_json_sha256(payload)):
        raise IngestionError("staging envelope payload integrity mismatch")

    root = _validated_root(staging_root)
    raw_files = payload["relative_file_manifest"]
    if not isinstance(raw_files, list) or not raw_files:
        raise IngestionError("relative_file_manifest must be a nonempty array")

    paths: set[str] = set()
    files: list[_ValidatedFile] = []
    for index, raw_entry in enumerate(raw_files):
        label = f"staging_envelope.payload.relative_file_manifest[{index}]"
        entry = _exact_mapping(raw_entry, _FILE_ENTRY_KEYS, label)
        relative_path = _relative_path(f"{label}.relative_path", entry["relative_path"])
        if relative_path in paths:
            raise IngestionError("relative_file_manifest contains duplicate paths")
        paths.add(relative_path)
        expected_sha256 = _sha256(f"{label}.sha256", entry["sha256"])
        expected_size = _nonnegative_integer(f"{label}.size_bytes", entry["size_bytes"])
        claim_class = _portable_metadata_text(
            f"{label}.claim_class", entry["claim_class"]
        )
        source_refs = _portable_reference_sequence(
            f"{label}.source_refs", entry["source_refs"]
        )
        redaction_status = _portable_metadata_text(
            f"{label}.redaction_status", entry["redaction_status"]
        )
        retention_class = _portable_metadata_text(
            f"{label}.retention_class", entry["retention_class"]
        )
        validator_ref = _portable_metadata_text(
            f"{label}.validator_ref", entry["validator_ref"]
        )
        path = _validated_file(
            root,
            relative_path,
            expected_sha256,
            expected_size,
            forbidden_bytes=fencing_token.encode("utf-8"),
        )
        files.append(
            _ValidatedFile(
                path=path,
                relative_path=relative_path,
                sha256=expected_sha256,
                size_bytes=expected_size,
                claim_class=claim_class,
                source_refs=source_refs,
                redaction_status=redaction_status,
                retention_class=retention_class,
                validator_ref=validator_ref,
            )
        )

    persisted_strings = [object_id, producer_identity]
    for file_record in files:
        persisted_strings.extend(
            [
                file_record.claim_class,
                *file_record.source_refs,
                file_record.redaction_status,
                file_record.retention_class,
                file_record.validator_ref,
            ]
        )
    if any(fencing_token in item for item in persisted_strings):
        raise IngestionError("fencing authority must not enter artifact metadata")

    return _ValidatedEnvelope(
        object_id=object_id,
        contour=contour,
        classification=classification,
        producer_identity=producer_identity,
        run_id=run_id,
        attempt_id=attempt_id,
        fencing_token=fencing_token,
        files=tuple(files),
    )


def _validated_root(staging_root: str | Path) -> Path:
    if isinstance(staging_root, bytes) or not isinstance(staging_root, (str, Path)):
        raise IngestionError("staging_root must be a filesystem path")
    if not str(staging_root) or "\x00" in str(staging_root):
        raise IngestionError("staging_root is invalid")
    root = Path(staging_root)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise IngestionError("staging_root is unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise IngestionError("staging_root must be a non-symlink directory")
    return root


def _validated_file(
    root: Path,
    relative_path: str,
    expected_sha256: str,
    expected_size: int,
    *,
    forbidden_bytes: bytes,
) -> Path:
    parts = PurePosixPath(relative_path).parts
    directory_flags = os.O_RDONLY
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise IngestionError("platform cannot enforce safe staging path traversal")
    if os.open not in getattr(os, "supports_dir_fd", set()):
        raise IngestionError("platform cannot enforce descriptor-relative traversal")
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    file_flags = os.O_RDONLY
    file_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    file_descriptor: int | None = None
    digest = hashlib.sha256()
    actual_size = 0
    overlap = b""
    try:
        descriptors.append(os.open(root, directory_flags))
        for part in parts[:-1]:
            descriptors.append(
                os.open(part, directory_flags, dir_fd=descriptors[-1])
            )
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
        opened_stat = os.fstat(file_descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise IngestionError("opened staging artifact is not regular")
        while True:
            chunk = os.read(file_descriptor, 1024 * 1024)
            if not chunk:
                break
            actual_size += len(chunk)
            digest.update(chunk)
            combined = overlap + chunk
            if forbidden_bytes and forbidden_bytes in combined:
                raise IngestionError("staging artifact contains raw fencing authority")
            if len(forbidden_bytes) > 1:
                overlap = combined[-(len(forbidden_bytes) - 1) :]
    except OSError as exc:
        raise IngestionError("could not read staging artifact safely") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)

    if actual_size != expected_size:
        raise IngestionError("staging artifact size does not match its declaration")
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise IngestionError("staging artifact digest does not match its declaration")
    return root.joinpath(*parts)


def _validate_publication(publication: object, file_record: _ValidatedFile) -> None:
    expected_ref = f"cas:sha256:{file_record.sha256}"
    try:
        ref = publication.ref  # type: ignore[attr-defined]
        digest = publication.sha256  # type: ignore[attr-defined]
        size = publication.size_bytes  # type: ignore[attr-defined]
        created = publication.created  # type: ignore[attr-defined]
    except (AttributeError, TypeError) as exc:
        raise IngestionError("CAS publication result is malformed") from exc
    if ref != expected_ref or digest != file_record.sha256:
        raise IngestionError("CAS publication result has the wrong identity")
    if isinstance(size, bool) or size != file_record.size_bytes:
        raise IngestionError("CAS publication result has the wrong size")
    if not isinstance(created, bool):
        raise IngestionError("CAS publication result has invalid creation state")


def _exact_mapping(
    value: object, keys: set[str] | frozenset[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise IngestionError(f"{label} must be an object")
    copied = dict(value)
    if set(copied) != set(keys):
        raise IngestionError(f"{label} keys are not exact")
    if any(not isinstance(key, str) for key in copied):
        raise IngestionError(f"{label} keys must be text")
    return copied


def _normalized_text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise IngestionError(f"{label} must be normalized nonempty text")
    if len(value) > _MAX_TEXT_LENGTH or any(ord(character) < 32 for character in value):
        raise IngestionError(f"{label} contains invalid text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise IngestionError(f"{label} is not valid UTF-8 text") from exc
    return value


def _normalized_identifier(label: str, value: object) -> str:
    normalized = _normalized_text(label, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise IngestionError(f"{label} must be a normalized identifier")
    return normalized


def _portable_metadata_text(label: str, value: object) -> str:
    normalized = _normalized_text(label, value)
    lowered = normalized.lower()
    if (
        normalized.startswith(("/", "~"))
        or "\\" in normalized
        or lowered.startswith("file:")
        or re.match(r"^[A-Za-z]:/", normalized) is not None
    ):
        raise IngestionError(f"{label} must not contain a local host path")
    return normalized


def _sha256(label: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise IngestionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _nonnegative_integer(label: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IngestionError(f"{label} must be a non-negative integer")
    return value


def _string_sequence(label: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise IngestionError(f"{label} must be an array")
    return tuple(
        _normalized_text(f"{label}[{index}]", item)
        for index, item in enumerate(value)
    )


def _portable_reference_sequence(label: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise IngestionError(f"{label} must be an array")
    return tuple(
        _portable_metadata_text(f"{label}[{index}]", item)
        for index, item in enumerate(value)
    )


def _relative_path(label: str, value: object) -> str:
    relative = _normalized_text(label, value)
    if relative in {".", ".."} or "\\" in relative or relative.startswith("/"):
        raise IngestionError(f"{label} must be a portable relative POSIX path")
    path = PurePosixPath(relative)
    if (
        not path.parts
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IngestionError(f"{label} contains a forbidden path component")
    if path.as_posix() != relative:
        raise IngestionError(f"{label} is not normalized")
    return relative


def _parse_timestamp(label: str, value: object) -> datetime:
    if not isinstance(value, str) or _RFC3339_RE.fullmatch(value) is None:
        raise IngestionError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise IngestionError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IngestionError(f"{label} must be timezone-aware")
    return parsed


def _trusted_timestamp(value: object) -> str:
    if isinstance(value, str):
        parsed = _parse_timestamp("clock result", value)
    elif isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise IngestionError("clock result must be timezone-aware")
        parsed = value
    else:
        raise IngestionError("clock result must be a datetime or RFC3339 string")
    normalized = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    return normalized.replace("+00:00", "Z")


def _ensure_json_value(value: object, label: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise IngestionError(f"{label} contains a non-finite number")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _ensure_json_value(item, f"{label}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IngestionError(f"{label} contains a non-text key")
            _ensure_json_value(item, f"{label}.{key}")
        return
    raise IngestionError(f"{label} contains a non-JSON value")


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _json_ready(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value
