"""One frozen deterministic, in-process, offline L0 workload template."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, Callable, Mapping


__all__ = ["L0Error", "L0Checkpoint", "L0RunResult", "DeterministicL0Runner"]


_TEMPLATE_MATERIAL = "research-bridge:l0:chunk-sha256:v1"
_TEMPLATE_SHA256 = hashlib.sha256(_TEMPLATE_MATERIAL.encode("ascii")).hexdigest()
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
_JOB_PAYLOAD_KEYS = frozenset(
    {
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
)
_RESOURCE_LIMIT_KEYS = frozenset({"cost_units"})
_LEASE_PAYLOAD_KEYS = frozenset(
    {
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
)
_CONTOURS = frozenset({"bridge", "market", "security", "governance"})
_ALLOWED_CLASSIFICATIONS = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_PORTABLE_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s\\]{1,511}$")
_CAS_INPUT_REF_RE = re.compile(r"^cas:sha256:([a-f0-9]{64})$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_OUTPUT_NAMES = ("checkpoint.json", "result.json")
_MAX_TEXT_LENGTH = 1024
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class L0Error(RuntimeError):
    """A fail-closed L0 authority, input, clock, or staging error."""


@dataclass(frozen=True, slots=True)
class L0Checkpoint:
    """Immutable metadata for the single final checkpoint payload."""

    sequence: int
    completed_ranges: tuple[Mapping[str, int], ...]
    state_sha256: str
    relative_path: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class L0RunResult:
    """Immutable result of the frozen in-process L0 template."""

    checkpoint: L0Checkpoint
    staging_envelope: Mapping[str, Any]
    started_at: str
    ended_at: str
    resource_usage: Mapping[str, int]
    code_sha256: str
    input_sha256: str
    environment_digest: str


@dataclass(frozen=True, slots=True)
class _ValidatedJob:
    object_id: str
    issued_at: datetime
    contour: str
    classification: str
    input_refs: tuple[str, ...]
    image_digest: str


@dataclass(frozen=True, slots=True)
class _ValidatedLease:
    object_id: str
    issued_at: datetime
    expires_at: datetime
    attempt_id: str
    permit_ref: str
    runner_identity: str
    fencing_epoch: int
    fencing_token: str


class DeterministicL0Runner:
    """Run exactly one built-in chunk hashing template without external I/O."""

    def __init__(
        self,
        input_reader: Callable[[str], bytes],
        *,
        chunk_size: int = 65_536,
        clock: Callable[[], datetime | str] | None = None,
        runner_identity: str = "bridge-l0-runner",
    ) -> None:
        if not callable(input_reader):
            raise L0Error("input_reader must be callable")
        if (
            isinstance(chunk_size, bool)
            or not isinstance(chunk_size, int)
            or chunk_size <= 0
        ):
            raise L0Error("chunk_size must be a positive integer")
        if clock is not None and not callable(clock):
            raise L0Error("clock must be callable")
        self._input_reader = input_reader
        self._chunk_size = chunk_size
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._runner_identity = _identifier("runner_identity", runner_identity)

    def run(
        self,
        job_spec: Mapping[str, Any],
        lease: Mapping[str, Any],
        staging_root: str | Path,
    ) -> L0RunResult:
        """Validate authority, hash declared inputs, and stage two exact files."""

        job = _validate_job(job_spec)
        authority = _validate_lease(lease, job, self._runner_identity)
        root = _preflight_staging_root(staging_root)
        started = _clock_now(self._clock, "started_at")
        if job.issued_at > started:
            raise L0Error("job is not yet issued")
        if started < authority.issued_at or started >= authority.expires_at:
            raise L0Error("lease is not valid at run start")

        inputs: list[dict[str, Any]] = []
        chunks: list[dict[str, Any]] = []
        completed_ranges: list[dict[str, int]] = []
        total_input_bytes = 0
        for input_index, input_ref in enumerate(job.input_refs):
            try:
                input_bytes = self._input_reader(input_ref)
            except Exception as exc:
                raise L0Error("input_reader failed") from exc
            if type(input_bytes) is not bytes:
                raise L0Error("input_reader must return exact bytes")

            input_digest = hashlib.sha256(input_bytes).hexdigest()
            match = _CAS_INPUT_REF_RE.fullmatch(input_ref)
            if match is None or not hmac.compare_digest(input_digest, match.group(1)):
                raise L0Error("input bytes do not match their CAS reference")
            total_input_bytes += len(input_bytes)
            chunk_count = 0
            for offset in range(0, len(input_bytes), self._chunk_size):
                chunk = input_bytes[offset : offset + self._chunk_size]
                chunks.append(
                    {
                        "chunk_index": chunk_count,
                        "input_index": input_index,
                        "offset_bytes": offset,
                        "sha256": hashlib.sha256(chunk).hexdigest(),
                        "size_bytes": len(chunk),
                    }
                )
                chunk_count += 1
            inputs.append(
                {
                    "chunk_count": chunk_count,
                    "input_index": input_index,
                    "input_ref": input_ref,
                    "sha256": input_digest,
                    "size_bytes": len(input_bytes),
                }
            )
            completed_ranges.append(
                {
                    "chunk_end_index_exclusive": chunk_count,
                    "chunk_start_index": 0,
                    "input_index": input_index,
                }
            )

        ended = _clock_now(self._clock, "ended_at")
        if ended < started:
            raise L0Error("clock moved backwards during run")
        if ended >= authority.expires_at:
            raise L0Error("lease expired before staging")

        input_sha256 = _canonical_sha256(list(job.input_refs))
        environment_digest = job.image_digest
        state_sha256 = _canonical_sha256(
            {
                "chunks": chunks,
                "completed_ranges": completed_ranges,
                "input_sha256": input_sha256,
                "inputs": inputs,
                "template_sha256": _TEMPLATE_SHA256,
            }
        )
        checkpoint_payload = {
            "completed_ranges": completed_ranges,
            "input_sha256": input_sha256,
            "sequence": 0,
            "state_sha256": state_sha256,
            "template_sha256": _TEMPLATE_SHA256,
        }
        result_payload = {
            "chunks": chunks,
            "environment_digest": environment_digest,
            "input_sha256": input_sha256,
            "inputs": inputs,
            "template_sha256": _TEMPLATE_SHA256,
        }
        checkpoint_bytes = _canonical_bytes(checkpoint_payload)
        result_bytes = _canonical_bytes(result_payload)
        _write_outputs(root, checkpoint_bytes, result_bytes)

        result_sha256 = hashlib.sha256(result_bytes).hexdigest()
        result_size = len(result_bytes)
        checkpoint = L0Checkpoint(
            sequence=0,
            completed_ranges=tuple(
                _deep_freeze(item) for item in completed_ranges
            ),
            state_sha256=state_sha256,
            relative_path="checkpoint.json",
            size_bytes=len(checkpoint_bytes),
        )
        claimed_metrics = {
            "chunk_count": len(chunks),
            "input_bytes": total_input_bytes,
            "input_count": len(inputs),
            "result_bytes": result_size,
        }
        staging_payload = {
            "producer_identity": authority.runner_identity,
            "run_id": job.object_id,
            "attempt_id": authority.attempt_id,
            "fencing_token": authority.fencing_token,
            "relative_file_manifest": [
                {
                    "relative_path": "result.json",
                    "sha256": result_sha256,
                    "size_bytes": result_size,
                    "claim_class": "mechanical-chunk-hash",
                    "source_refs": list(job.input_refs),
                    "redaction_status": (
                        "public" if job.classification == "D0_PUBLIC" else "sanitized"
                    ),
                    "retention_class": "ephemeral-staging",
                    "validator_ref": "validator:pending-independent",
                }
            ],
            "claimed_metrics": claimed_metrics,
            "completion_reason": "mechanical-template-complete",
        }
        staging_id = _canonical_sha256(
            {
                "attempt_id": authority.attempt_id,
                "job_id": job.object_id,
                "result_sha256": result_sha256,
            }
        )
        staging_envelope = {
            "schema_id": "StagingEnvelope",
            "schema_version": "1.0.0",
            "object_id": f"staging-l0-{staging_id}",
            "issued_at": _format_timestamp(ended),
            "issuer": {
                "id": authority.runner_identity,
                "authority_class": "untrusted-runner",
            },
            "contour": job.contour,
            "classification": job.classification,
            "payload": staging_payload,
            "integrity": {
                "payload_sha256": _canonical_sha256(staging_payload),
                "parent_refs": [
                    f"job:{job.object_id}",
                    f"lease:{authority.object_id}",
                ],
            },
        }
        resource_usage = {
            "checkpoint_bytes": len(checkpoint_bytes),
            "chunk_count": len(chunks),
            "input_bytes": total_input_bytes,
            "input_count": len(inputs),
            "result_bytes": result_size,
        }
        return L0RunResult(
            checkpoint=checkpoint,
            staging_envelope=_deep_freeze(staging_envelope),
            started_at=_format_timestamp(started),
            ended_at=_format_timestamp(ended),
            resource_usage=_deep_freeze(resource_usage),
            code_sha256=_TEMPLATE_SHA256,
            input_sha256=input_sha256,
            environment_digest=environment_digest,
        )


def _validate_job(document: Mapping[str, Any]) -> _ValidatedJob:
    value = _contract(document, "JobSpec")
    if value["issuer"]["authority_class"] != "admission-controller":
        raise L0Error("job issuer is not the admission controller")
    payload = _exact_mapping(value["payload"], _JOB_PAYLOAD_KEYS, "job_spec.payload")
    _portable_ref("job_spec.payload.protocol_ref", payload["protocol_ref"])
    if payload["code_ref"] != f"sha256:{_TEMPLATE_SHA256}":
        raise L0Error("job code_ref does not bind the frozen L0 template")
    if payload["runner_profile"] != "L0":
        raise L0Error("job runner_profile is not L0")
    if payload["network_policy"] != "offline":
        raise L0Error("job network_policy is not offline")
    if payload["checkpoint_strategy"] != "single-final-checkpoint":
        raise L0Error("job checkpoint strategy is not frozen")
    if payload["expected_output_contract"] != "StagingEnvelope@1.0.0":
        raise L0Error("job output contract is not frozen")
    image_digest = _portable_ref(
        "job_spec.payload.image_digest", payload["image_digest"]
    )
    _identifier("job_spec.payload.idempotency_key", payload["idempotency_key"])
    resource_limits = _exact_mapping(
        payload["resource_limits"],
        _RESOURCE_LIMIT_KEYS,
        "job_spec.payload.resource_limits",
    )
    _positive_safe_integer(
        "job_spec.payload.resource_limits.cost_units",
        resource_limits["cost_units"],
    )
    raw_refs = payload["input_refs"]
    if not isinstance(raw_refs, list):
        raise L0Error("job input_refs must be an array")
    input_refs = tuple(
        _cas_input_ref(f"job_spec.payload.input_refs[{index}]", ref)
        for index, ref in enumerate(raw_refs)
    )
    return _ValidatedJob(
        object_id=_identifier("job_spec.object_id", value["object_id"]),
        issued_at=_timestamp("job_spec.issued_at", value["issued_at"]),
        contour=value["contour"],
        classification=value["classification"],
        input_refs=input_refs,
        image_digest=image_digest,
    )


def _validate_lease(
    document: Mapping[str, Any], job: _ValidatedJob, runner_identity: str
) -> _ValidatedLease:
    value = _contract(document, "AttemptLease")
    if value["issuer"]["authority_class"] != "researchd":
        raise L0Error("lease issuer is not researchd")
    payload = _exact_mapping(
        value["payload"], _LEASE_PAYLOAD_KEYS, "attempt_lease.payload"
    )
    if payload["job_ref"] != job.object_id:
        raise L0Error("lease does not bind the job")
    if payload["runner_identity"] != runner_identity:
        raise L0Error("lease does not bind this L0 runner")
    if (
        value["contour"] != job.contour
        or value["classification"] != job.classification
    ):
        raise L0Error("lease contour or classification does not match the job")
    issued_at = _timestamp("attempt_lease.payload.issued_at", payload["issued_at"])
    if issued_at != _timestamp("attempt_lease.issued_at", value["issued_at"]):
        raise L0Error("lease issued_at fields do not match")
    expires_at = _timestamp("attempt_lease.payload.expires_at", payload["expires_at"])
    if issued_at >= expires_at:
        raise L0Error("lease time window is invalid")
    fencing_epoch = payload["fencing_epoch"]
    if (
        isinstance(fencing_epoch, bool)
        or not isinstance(fencing_epoch, int)
        or fencing_epoch < 0
    ):
        raise L0Error("lease fencing_epoch must be a non-negative integer")
    _portable_ref(
        "attempt_lease.payload.checkpoint_parent_ref", payload["checkpoint_parent_ref"]
    )
    return _ValidatedLease(
        object_id=_identifier("attempt_lease.object_id", value["object_id"]),
        issued_at=issued_at,
        expires_at=expires_at,
        attempt_id=_identifier(
            "attempt_lease.payload.attempt_id", payload["attempt_id"]
        ),
        permit_ref=_identifier("attempt_lease.payload.permit_ref", payload["permit_ref"]),
        runner_identity=_identifier(
            "attempt_lease.payload.runner_identity", payload["runner_identity"]
        ),
        fencing_epoch=fencing_epoch,
        fencing_token=_text(
            "attempt_lease.payload.fencing_token", payload["fencing_token"]
        ),
    )


def _contract(document: Mapping[str, Any], schema_id: str) -> dict[str, Any]:
    label = schema_id.lower()
    value = _exact_mapping(document, _COMMON_KEYS, label)
    if value["schema_id"] != schema_id or value["schema_version"] != "1.0.0":
        raise L0Error(f"{label} schema identity is invalid")
    _identifier(f"{label}.object_id", value["object_id"])
    _timestamp(f"{label}.issued_at", value["issued_at"])
    issuer = _exact_mapping(value["issuer"], _ISSUER_KEYS, f"{label}.issuer")
    _identifier(f"{label}.issuer.id", issuer["id"])
    _text(f"{label}.issuer.authority_class", issuer["authority_class"])
    if not isinstance(value["contour"], str) or value["contour"] not in _CONTOURS:
        raise L0Error(f"{label}.contour is invalid")
    if (
        not isinstance(value["classification"], str)
        or value["classification"] not in _ALLOWED_CLASSIFICATIONS
    ):
        raise L0Error(f"{label} classification must be D0 or D1")
    integrity = _exact_mapping(
        value["integrity"], _INTEGRITY_KEYS, f"{label}.integrity"
    )
    expected = _sha256(
        f"{label}.integrity.payload_sha256", integrity["payload_sha256"]
    )
    parent_refs = integrity["parent_refs"]
    if not isinstance(parent_refs, list):
        raise L0Error(f"{label}.integrity.parent_refs must be an array")
    for index, ref in enumerate(parent_refs):
        _text(f"{label}.integrity.parent_refs[{index}]", ref)
    if not isinstance(value["payload"], Mapping):
        raise L0Error(f"{label}.payload must be an object")
    if not hmac.compare_digest(expected, _canonical_sha256(value["payload"])):
        raise L0Error(f"{label} payload integrity mismatch")
    return value


def _preflight_staging_root(staging_root: str | Path) -> Path:
    if isinstance(staging_root, bytes) or not isinstance(staging_root, (str, Path)):
        raise L0Error("staging_root must be a filesystem path")
    if not str(staging_root) or "\x00" in str(staging_root):
        raise L0Error("staging_root is invalid")
    root = Path(staging_root)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise L0Error("staging_root is unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise L0Error("staging_root must be a non-symlink directory")
    for name in _OUTPUT_NAMES:
        if os.path.lexists(root / name):
            raise L0Error("staging output already exists")
    return root


def _write_outputs(root: Path, checkpoint_bytes: bytes, result_bytes: bytes) -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise L0Error("platform cannot enforce safe staging writes")
    if os.open not in getattr(os, "supports_dir_fd", set()):
        raise L0Error("platform cannot enforce descriptor-relative staging writes")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    file_flags |= getattr(os, "O_CLOEXEC", 0)
    root_descriptor: int | None = None
    descriptors: dict[str, int] = {}
    identities: dict[str, tuple[int, int]] = {}
    success = False
    close_error: OSError | None = None
    try:
        root_descriptor = os.open(root, directory_flags)
        for name in _OUTPUT_NAMES:
            descriptor = os.open(name, file_flags, 0o600, dir_fd=root_descriptor)
            descriptors[name] = descriptor
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise L0Error("staging output is not a regular file")
            identities[name] = (file_stat.st_dev, file_stat.st_ino)
        for name, data in (
            ("checkpoint.json", checkpoint_bytes),
            ("result.json", result_bytes),
        ):
            _write_all(descriptors[name], data)
            os.fsync(descriptors[name])
            if os.fstat(descriptors[name]).st_size != len(data):
                raise L0Error("staging output size mismatch")
        os.fsync(root_descriptor)
        success = True
    except (OSError, L0Error) as exc:
        if isinstance(exc, L0Error):
            raise
        raise L0Error("durable staging write failed") from exc
    finally:
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError as exc:
                success = False
                if close_error is None:
                    close_error = exc
        if root_descriptor is not None:
            if not success:
                for name, identity in identities.items():
                    _unlink_owned(root_descriptor, name, identity)
            try:
                os.close(root_descriptor)
            except OSError as exc:
                if close_error is None:
                    close_error = exc
        if close_error is not None:
            raise L0Error("durable staging close failed") from close_error


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise L0Error("staging write made no progress")
        offset += written


def _unlink_owned(root_descriptor: int, name: str, identity: tuple[int, int]) -> None:
    try:
        current = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=root_descriptor)
    except OSError:
        return


def _clock_now(clock: Callable[[], datetime | str], label: str) -> datetime:
    try:
        return _timestamp(label, clock())
    except L0Error:
        raise
    except Exception as exc:
        raise L0Error(f"{label} clock failed") from exc


def _format_timestamp(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    return normalized.replace("+00:00", "Z")


def _timestamp(label: str, value: object) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise L0Error(f"{label} must be timezone-aware")
        return value
    if not isinstance(value, str) or _RFC3339_RE.fullmatch(value) is None:
        raise L0Error(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise L0Error(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise L0Error(f"{label} must be timezone-aware")
    return parsed


def _exact_mapping(
    value: object, keys: set[str] | frozenset[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise L0Error(f"{label} must be an object")
    copied = dict(value)
    if set(copied) != set(keys) or any(not isinstance(key, str) for key in copied):
        raise L0Error(f"{label} keys are not exact")
    return copied


def _text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise L0Error(f"{label} must be normalized nonempty text")
    if len(value) > _MAX_TEXT_LENGTH or any(
        ord(character) < 32 for character in value
    ):
        raise L0Error(f"{label} contains invalid text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise L0Error(f"{label} is not valid UTF-8 text") from exc
    return value


def _identifier(label: str, value: object) -> str:
    normalized = _text(label, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise L0Error(f"{label} must be a normalized identifier")
    return normalized


def _positive_safe_integer(label: str, value: object) -> int:
    if type(value) is not int or value < 1 or value > _MAX_SAFE_INTEGER:
        raise L0Error(f"{label} must be a positive safe integer")
    return value


def _portable_ref(label: str, value: object) -> str:
    normalized = _text(label, value)
    if (
        _PORTABLE_REF_RE.fullmatch(normalized) is None
        or normalized.startswith(("/", "~"))
        or normalized.lower().startswith("file:")
    ):
        raise L0Error(f"{label} must be a portable non-file reference")
    return normalized


def _cas_input_ref(label: str, value: object) -> str:
    normalized = _portable_ref(label, value)
    if _CAS_INPUT_REF_RE.fullmatch(normalized) is None:
        raise L0Error(f"{label} must be an exact cas:sha256 reference")
    return normalized


def _sha256(label: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise L0Error(f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_bytes(value: object) -> bytes:
    _ensure_json(value, "value")
    try:
        return (
            json.dumps(
                _json_ready(value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise L0Error("value is not canonical JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)[:-1]).hexdigest()


def _ensure_json(value: object, label: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise L0Error(f"{label} contains a non-finite number")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _ensure_json(item, f"{label}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise L0Error(f"{label} contains a non-text key")
            _ensure_json(item, f"{label}.{key}")
        return
    raise L0Error(f"{label} contains a non-JSON value")


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
