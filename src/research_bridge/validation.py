"""Pure receipt-chain verification at the Bridge/domain validation boundary.

This module validates only structure, authority, integrity, timestamps, and
portable reference bindings.  Scientific fields remain opaque and are never
returned or applied.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping, Protocol


__all__ = [
    "ValidationBoundaryError",
    "ValidationProjection",
    "ValidationBoundary",
    "DeterministicL0Validator",
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
_EXECUTION_PAYLOAD_KEYS = frozenset(
    {
        "permit_ref",
        "lease_ref",
        "job_spec_ref",
        "code_sha256",
        "input_sha256",
        "environment_digest",
        "started_at",
        "ended_at",
        "exit_classification",
        "artifact_refs",
        "resource_usage",
        "event_chain_head",
    }
)
_VALIDATION_PAYLOAD_KEYS = frozenset(
    {
        "protocol_ref",
        "execution_ref",
        "artifact_refs",
        "validator_id",
        "validator_sha256",
        "holdout_access_ref",
        "checks_performed",
        "metrics",
        "tolerances",
        "proposed_outcome",
        "reasons",
        "reproducibility_class",
    }
)
_DOMAIN_LINK_PAYLOAD_KEYS = frozenset(
    {
        "domain_trial_id",
        "bridge_execution_ref",
        "protocol_ref",
        "registry_identity",
        "registry_revision",
        "applied_outcome_ref",
        "policy_ref",
    }
)
_CONTOURS = frozenset({"bridge", "market", "security", "governance"})
_ALLOWED_CLASSIFICATIONS = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_PORTABLE_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s\\]{1,511}$")
_CAS_REF_RE = re.compile(r"^cas:sha256:[a-f0-9]{64}$")
_CHECKPOINT_MANIFEST_REF_RE = re.compile(r"^checkpoint-manifest-[a-f0-9]{64}$")
_SETTLEMENT_RECEIPT_REF_RE = re.compile(r"^settlement-receipt-[a-f0-9]{64}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_MAX_TEXT_LENGTH = 1024
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_L0_TEMPLATE_SHA256 = hashlib.sha256(
    b"research-bridge:l0:chunk-sha256:v1"
).hexdigest()
_L0_RESULT_KEYS = frozenset(
    {"chunks", "environment_digest", "input_sha256", "inputs", "template_sha256"}
)
_L0_INPUT_KEYS = frozenset(
    {"chunk_count", "input_index", "input_ref", "sha256", "size_bytes"}
)
_L0_CHUNK_KEYS = frozenset(
    {"chunk_index", "input_index", "offset_bytes", "sha256", "size_bytes"}
)


class ValidationBoundaryError(RuntimeError):
    """A fail-closed receipt structure, authority, integrity, or chain error."""


@dataclass(frozen=True, slots=True)
class ValidationProjection:
    """Deeply immutable references to a verified domain handoff."""

    execution_ref: str
    validation_ref: str
    domain_link_ref: str
    protocol_ref: str
    artifact_refs: tuple[str, ...]
    registry_identity: str
    registry_revision: str
    applied_outcome_ref: str
    policy_ref: str
    contour: str
    classification: str


class _ByteStore(Protocol):
    def read_bytes(self, ref: str, *, maximum_size_bytes: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class _Receipt:
    object_id: str
    issued_at: datetime
    issuer_id: str
    issuer_authority: str
    contour: str
    classification: str
    payload: Mapping[str, Any]
    parent_refs: tuple[str, ...]


class ValidationBoundary:
    """Verify a completed execution-to-domain-link chain without side effects."""

    def __init__(
        self,
        *,
        expected_validator_id: str,
        expected_validator_sha256: str,
        expected_registry_identity: str,
    ) -> None:
        self._expected_validator_id = _identifier(
            "expected_validator_id", expected_validator_id
        )
        self._expected_validator_sha256 = _sha256(
            "expected_validator_sha256", expected_validator_sha256
        )
        self._expected_registry_identity = _identifier(
            "expected_registry_identity", expected_registry_identity
        )

    def verify(
        self,
        execution_receipt: Mapping[str, Any],
        validation_receipt: Mapping[str, Any],
        domain_link_receipt: Mapping[str, Any],
        *,
        expected_protocol_ref: str,
        expected_policy_ref: str,
    ) -> ValidationProjection:
        """Return reference-only projection after exact in-memory verification."""

        protocol_ref = _portable_ref(
            "expected_protocol_ref", expected_protocol_ref
        )
        policy_ref = _portable_ref("expected_policy_ref", expected_policy_ref)
        execution = _receipt(
            execution_receipt,
            schema_id="ExecutionReceipt",
            payload_keys=_EXECUTION_PAYLOAD_KEYS,
        )
        validation = _receipt(
            validation_receipt,
            schema_id="ValidationReceipt",
            payload_keys=_VALIDATION_PAYLOAD_KEYS,
        )
        domain_link = _receipt(
            domain_link_receipt,
            schema_id="DomainTrialLinkReceipt",
            payload_keys=_DOMAIN_LINK_PAYLOAD_KEYS,
        )

        _shared_scope(execution, validation, domain_link)
        execution_ref, artifact_refs = _verify_execution(execution)
        validation_ref = _verify_validation_receipt(
            self,
            validation,
            execution_ref=execution_ref,
            artifact_refs=artifact_refs,
            protocol_ref=protocol_ref,
        )
        (
            domain_link_ref,
            registry_revision,
            applied_outcome_ref,
        ) = _verify_domain_link_receipt(
            self,
            domain_link,
            execution_ref=execution_ref,
            validation_ref=validation_ref,
            protocol_ref=protocol_ref,
            policy_ref=policy_ref,
        )
        if not (
            execution.issued_at <= validation.issued_at <= domain_link.issued_at
        ):
            raise ValidationBoundaryError("receipt timestamps are not monotonic")

        return ValidationProjection(
            execution_ref=execution_ref,
            validation_ref=validation_ref,
            domain_link_ref=domain_link_ref,
            protocol_ref=protocol_ref,
            artifact_refs=artifact_refs,
            registry_identity=self._expected_registry_identity,
            registry_revision=registry_revision,
            applied_outcome_ref=applied_outcome_ref,
            policy_ref=policy_ref,
            contour=execution.contour,
            classification=execution.classification,
        )


class DeterministicL0Validator:
    """Independently recompute one frozen L0 result and issue no scientific truth."""

    def __init__(
        self,
        *,
        validator_id: str,
        validator_sha256: str,
        protocol_ref: str,
        artifact_store: _ByteStore,
        input_store: _ByteStore,
        chunk_size: int = 65_536,
        maximum_artifact_bytes: int = 8_388_608,
        maximum_input_bytes: int = 67_108_864,
    ) -> None:
        self._validator_id = _identifier("validator_id", validator_id)
        self._validator_sha256 = _sha256(
            "validator_sha256", validator_sha256
        )
        self._protocol_ref = _portable_ref("protocol_ref", protocol_ref)
        _readable_store(artifact_store, "artifact_store")
        _readable_store(input_store, "input_store")
        self._artifact_store = artifact_store
        self._input_store = input_store
        self._chunk_size = _positive_safe_integer("chunk_size", chunk_size)
        self._maximum_artifact_bytes = _positive_safe_integer(
            "maximum_artifact_bytes", maximum_artifact_bytes
        )
        self._maximum_input_bytes = _positive_safe_integer(
            "maximum_input_bytes", maximum_input_bytes
        )

    def validate(
        self, execution_receipt: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Return a frozen ValidationReceipt only after exact byte recomputation."""

        execution = _receipt(
            execution_receipt,
            schema_id="ExecutionReceipt",
            payload_keys=_EXECUTION_PAYLOAD_KEYS,
        )
        execution_ref, artifact_refs = _verify_execution(execution)
        if len(artifact_refs) != 1:
            raise ValidationBoundaryError(
                "frozen L0 execution must contain exactly one result artifact"
            )
        artifact_ref = artifact_refs[0]
        artifact_bytes = _store_read(
            self._artifact_store,
            artifact_ref,
            self._maximum_artifact_bytes,
            "artifact_store",
        )
        if not hmac.compare_digest(
            hashlib.sha256(artifact_bytes).hexdigest(),
            artifact_ref.removeprefix("cas:sha256:"),
        ):
            raise ValidationBoundaryError("L0 artifact bytes do not match their CAS ref")
        result = _strict_json_object(artifact_bytes, "L0 result artifact")
        if artifact_bytes != _canonical_bytes(result, trailing_newline=True):
            raise ValidationBoundaryError("L0 result artifact is not canonical JSON")
        exact_result = _exact_mapping(result, _L0_RESULT_KEYS, "L0 result artifact")

        if exact_result["template_sha256"] != _L0_TEMPLATE_SHA256:
            raise ValidationBoundaryError("L0 result template digest mismatch")
        if exact_result["environment_digest"] != execution.payload["environment_digest"]:
            raise ValidationBoundaryError("L0 result environment digest mismatch")
        input_sha256 = _sha256(
            "L0 result input_sha256", exact_result["input_sha256"]
        )
        if input_sha256 != execution.payload["input_sha256"]:
            raise ValidationBoundaryError("L0 result input binding mismatch")
        if execution.payload["code_sha256"] != _L0_TEMPLATE_SHA256:
            raise ValidationBoundaryError("execution does not bind the frozen L0 template")

        input_refs, input_bytes = self._verify_inputs(exact_result["inputs"])
        if _canonical_sha256(list(input_refs)) != input_sha256:
            raise ValidationBoundaryError("L0 ordered input reference digest mismatch")
        chunk_count = self._verify_chunks(exact_result["chunks"], input_bytes)

        metrics = {
            "artifact_bytes": len(artifact_bytes),
            "chunk_count": chunk_count,
            "input_bytes": sum(len(value) for value in input_bytes),
            "input_count": len(input_refs),
        }
        if any(metrics[name] <= 0 for name in metrics):
            raise ValidationBoundaryError(
                "L0 validation evidence is vacuous"
            )
        payload = {
            "protocol_ref": self._protocol_ref,
            "execution_ref": execution_ref,
            "artifact_refs": list(artifact_refs),
            "validator_id": self._validator_id,
            "validator_sha256": self._validator_sha256,
            "holdout_access_ref": "holdout:none",
            "checks_performed": [
                "execution-receipt-chain",
                "artifact-cas-bytes",
                "canonical-l0-result",
                "ordered-input-cas-bytes",
                "chunk-byte-recomputation",
                "non-vacuous-input-and-chunk-evidence",
                "zero-holdout-exposure",
            ],
            "metrics": metrics,
            "tolerances": {"byte_mismatches": 0, "digest_mismatches": 0},
            "proposed_outcome": "VALIDATED_MECHANICAL",
            "reasons": ["L0_BYTES_RECOMPUTED"],
            "reproducibility_class": "deterministic-offline",
        }
        receipt = {
            "schema_id": "ValidationReceipt",
            "schema_version": "1.0.0",
            "object_id": f"validation-receipt-{_canonical_sha256(payload)}",
            "issued_at": _format_timestamp(execution.issued_at),
            "issuer": {
                "id": self._validator_id,
                "authority_class": "pinned-validator",
            },
            "contour": execution.contour,
            "classification": execution.classification,
            "payload": payload,
            "integrity": {
                "payload_sha256": _canonical_sha256(payload),
                "parent_refs": [execution_ref, *artifact_refs],
            },
        }
        return _deep_freeze(receipt)

    def _verify_inputs(
        self, supplied: object
    ) -> tuple[tuple[str, ...], tuple[bytes, ...]]:
        if not isinstance(supplied, list):
            raise ValidationBoundaryError("L0 result inputs must be an array")
        refs: list[str] = []
        values: list[bytes] = []
        for index, item in enumerate(supplied):
            entry = _exact_mapping(item, _L0_INPUT_KEYS, f"L0 input[{index}]")
            if _nonnegative_safe_integer(
                f"L0 input[{index}].input_index", entry["input_index"]
            ) != index:
                raise ValidationBoundaryError("L0 input order is invalid")
            ref = _cas_refs(f"L0 input[{index}].input_ref", [entry["input_ref"]])[0]
            if ref in refs:
                raise ValidationBoundaryError("L0 input references must be unique")
            data = _store_read(
                self._input_store,
                ref,
                self._maximum_input_bytes,
                "input_store",
            )
            digest = hashlib.sha256(data).hexdigest()
            if not hmac.compare_digest(digest, ref.removeprefix("cas:sha256:")):
                raise ValidationBoundaryError("L0 input bytes do not match their CAS ref")
            if entry["sha256"] != digest:
                raise ValidationBoundaryError("L0 input claimed digest mismatch")
            if _nonnegative_safe_integer(
                f"L0 input[{index}].size_bytes", entry["size_bytes"]
            ) != len(data):
                raise ValidationBoundaryError("L0 input claimed size mismatch")
            expected_chunks = (len(data) + self._chunk_size - 1) // self._chunk_size
            if _nonnegative_safe_integer(
                f"L0 input[{index}].chunk_count", entry["chunk_count"]
            ) != expected_chunks:
                raise ValidationBoundaryError("L0 input claimed chunk count mismatch")
            refs.append(ref)
            values.append(data)
        return tuple(refs), tuple(values)

    def _verify_chunks(self, supplied: object, inputs: tuple[bytes, ...]) -> int:
        if not isinstance(supplied, list):
            raise ValidationBoundaryError("L0 result chunks must be an array")
        cursor = 0
        for input_index, input_bytes in enumerate(inputs):
            chunk_index = 0
            for offset in range(0, len(input_bytes), self._chunk_size):
                if cursor >= len(supplied):
                    raise ValidationBoundaryError("L0 result chunk coverage is incomplete")
                entry = _exact_mapping(
                    supplied[cursor], _L0_CHUNK_KEYS, f"L0 chunk[{cursor}]"
                )
                chunk = input_bytes[offset : offset + self._chunk_size]
                expected = {
                    "chunk_index": chunk_index,
                    "input_index": input_index,
                    "offset_bytes": offset,
                    "sha256": hashlib.sha256(chunk).hexdigest(),
                    "size_bytes": len(chunk),
                }
                if entry != expected:
                    raise ValidationBoundaryError("L0 chunk byte recomputation mismatch")
                cursor += 1
                chunk_index += 1
        if cursor != len(supplied):
            raise ValidationBoundaryError("L0 result contains extra chunks")
        return cursor

def _verify_validation_receipt(
    boundary: ValidationBoundary,
    validation: _Receipt,
    *,
    execution_ref: str,
    artifact_refs: tuple[str, ...],
    protocol_ref: str,
) -> str:
    if (
        validation.issuer_id != boundary._expected_validator_id
        or validation.issuer_authority != "pinned-validator"
    ):
        raise ValidationBoundaryError("validation issuer is not the pinned validator")
    payload = validation.payload
    if payload["execution_ref"] != execution_ref:
        raise ValidationBoundaryError("validation execution reference mismatch")
    if payload["protocol_ref"] != protocol_ref:
        raise ValidationBoundaryError("validation protocol reference mismatch")
    supplied_artifacts = _cas_refs(
        "validation_receipt.payload.artifact_refs", payload["artifact_refs"]
    )
    if supplied_artifacts != artifact_refs:
        raise ValidationBoundaryError("validation artifact order or binding mismatch")
    if payload["validator_id"] != boundary._expected_validator_id:
        raise ValidationBoundaryError("validation payload validator id mismatch")
    validator_sha256 = _sha256(
        "validation_receipt.payload.validator_sha256",
        payload["validator_sha256"],
    )
    if not hmac.compare_digest(
        validator_sha256, boundary._expected_validator_sha256
    ):
        raise ValidationBoundaryError("validation payload validator digest mismatch")
    _portable_ref(
        "validation_receipt.payload.holdout_access_ref",
        payload["holdout_access_ref"],
    )
    _validate_opaque_validation_fields(payload)
    expected_parents = (execution_ref, *artifact_refs)
    if validation.parent_refs != expected_parents:
        raise ValidationBoundaryError("validation parent chain mismatch")
    return f"validation:{validation.object_id}"


def _verify_domain_link_receipt(
    boundary: ValidationBoundary,
    domain_link: _Receipt,
    *,
    execution_ref: str,
    validation_ref: str,
    protocol_ref: str,
    policy_ref: str,
) -> tuple[str, str, str]:
    if (
        domain_link.issuer_id != boundary._expected_registry_identity
        or domain_link.issuer_authority != "domain-registry-writer"
    ):
        raise ValidationBoundaryError("domain link issuer is not the registry writer")
    payload = domain_link.payload
    _identifier("domain_link_receipt.payload.domain_trial_id", payload["domain_trial_id"])
    if payload["bridge_execution_ref"] != execution_ref:
        raise ValidationBoundaryError("domain link execution reference mismatch")
    if payload["protocol_ref"] != protocol_ref:
        raise ValidationBoundaryError("domain link protocol reference mismatch")
    if payload["registry_identity"] != boundary._expected_registry_identity:
        raise ValidationBoundaryError("domain link registry identity mismatch")
    registry_revision = _identifier(
        "domain_link_receipt.payload.registry_revision",
        payload["registry_revision"],
    )
    applied_outcome_ref = _portable_ref(
        "domain_link_receipt.payload.applied_outcome_ref",
        payload["applied_outcome_ref"],
    )
    if payload["policy_ref"] != policy_ref:
        raise ValidationBoundaryError("domain link policy reference mismatch")
    if domain_link.parent_refs != (execution_ref, validation_ref):
        raise ValidationBoundaryError("domain link parent chain mismatch")
    return (
        f"domain-link:{domain_link.object_id}",
        registry_revision,
        applied_outcome_ref,
    )


def _receipt(
    document: Mapping[str, Any],
    *,
    schema_id: str,
    payload_keys: frozenset[str],
) -> _Receipt:
    label = schema_id.lower()
    value = _exact_mapping(document, _COMMON_KEYS, label)
    if value["schema_id"] != schema_id or value["schema_version"] != "1.0.0":
        raise ValidationBoundaryError(f"{label} schema identity is invalid")
    object_id = _identifier(f"{label}.object_id", value["object_id"])
    issued_at = _timestamp(f"{label}.issued_at", value["issued_at"])
    issuer = _exact_mapping(value["issuer"], _ISSUER_KEYS, f"{label}.issuer")
    issuer_id = _identifier(f"{label}.issuer.id", issuer["id"])
    issuer_authority = _identifier(
        f"{label}.issuer.authority_class", issuer["authority_class"]
    )
    contour = value["contour"]
    if not isinstance(contour, str) or contour not in _CONTOURS:
        raise ValidationBoundaryError(f"{label}.contour is invalid")
    classification = value["classification"]
    if (
        not isinstance(classification, str)
        or classification not in _ALLOWED_CLASSIFICATIONS
    ):
        raise ValidationBoundaryError(f"{label} classification must be D0 or D1")
    payload = _exact_mapping(value["payload"], payload_keys, f"{label}.payload")
    _ensure_json(payload, f"{label}.payload")
    integrity = _exact_mapping(
        value["integrity"], _INTEGRITY_KEYS, f"{label}.integrity"
    )
    supplied_digest = _sha256(
        f"{label}.integrity.payload_sha256", integrity["payload_sha256"]
    )
    if not hmac.compare_digest(supplied_digest, _canonical_sha256(payload)):
        raise ValidationBoundaryError(f"{label} payload integrity mismatch")
    raw_parents = integrity["parent_refs"]
    if not isinstance(raw_parents, (list, tuple)):
        raise ValidationBoundaryError(f"{label}.integrity.parent_refs must be an array")
    parent_refs = tuple(
        _text(f"{label}.integrity.parent_refs[{index}]", ref)
        for index, ref in enumerate(raw_parents)
    )
    return _Receipt(
        object_id=object_id,
        issued_at=issued_at,
        issuer_id=issuer_id,
        issuer_authority=issuer_authority,
        contour=contour,
        classification=classification,
        payload=payload,
        parent_refs=parent_refs,
    )


def _shared_scope(execution: _Receipt, validation: _Receipt, domain_link: _Receipt) -> None:
    if len({execution.contour, validation.contour, domain_link.contour}) != 1:
        raise ValidationBoundaryError("receipt contours do not match")
    if (
        len(
            {
                execution.classification,
                validation.classification,
                domain_link.classification,
            }
        )
        != 1
    ):
        raise ValidationBoundaryError("receipt classifications do not match")


def _verify_execution(execution: _Receipt) -> tuple[str, tuple[str, ...]]:
    if execution.issuer_id != "researchd" or execution.issuer_authority != "researchd":
        raise ValidationBoundaryError("execution issuer is not researchd")
    payload = execution.payload
    _identifier("execution_receipt.payload.permit_ref", payload["permit_ref"])
    _identifier("execution_receipt.payload.lease_ref", payload["lease_ref"])
    _identifier("execution_receipt.payload.job_spec_ref", payload["job_spec_ref"])
    _sha256("execution_receipt.payload.code_sha256", payload["code_sha256"])
    _sha256("execution_receipt.payload.input_sha256", payload["input_sha256"])
    _portable_ref(
        "execution_receipt.payload.environment_digest",
        payload["environment_digest"],
    )
    started_at = _timestamp(
        "execution_receipt.payload.started_at", payload["started_at"]
    )
    ended_at = _timestamp(
        "execution_receipt.payload.ended_at", payload["ended_at"]
    )
    if started_at > ended_at or ended_at != execution.issued_at:
        raise ValidationBoundaryError("execution timestamps are invalid or unbound")
    if payload["exit_classification"] != "mechanical-success":
        raise ValidationBoundaryError("execution is not mechanically successful")
    artifact_refs = _cas_refs(
        "execution_receipt.payload.artifact_refs", payload["artifact_refs"]
    )
    if not isinstance(payload["resource_usage"], Mapping):
        raise ValidationBoundaryError("execution resource_usage must be an object")
    _ensure_json(
        payload["resource_usage"], "execution_receipt.payload.resource_usage"
    )
    event_chain_head = _sha256(
        "execution_receipt.payload.event_chain_head", payload["event_chain_head"]
    )
    expected_object_id = f"execution-receipt-{_canonical_sha256(payload)}"
    if execution.object_id != expected_object_id:
        raise ValidationBoundaryError("execution receipt object identity mismatch")
    if not execution.parent_refs or _CHECKPOINT_MANIFEST_REF_RE.fullmatch(
        execution.parent_refs[0]
    ) is None:
        raise ValidationBoundaryError("execution checkpoint parent is invalid")
    if len(execution.parent_refs) != len(artifact_refs) + 3:
        raise ValidationBoundaryError("execution parent chain mismatch")
    settlement_parent = execution.parent_refs[-2]
    if _SETTLEMENT_RECEIPT_REF_RE.fullmatch(settlement_parent) is None:
        raise ValidationBoundaryError("execution settlement parent is invalid")
    expected_parents = (
        execution.parent_refs[0],
        *artifact_refs,
        settlement_parent,
        f"ledger:{event_chain_head}",
    )
    if execution.parent_refs != expected_parents:
        raise ValidationBoundaryError("execution parent chain mismatch")
    return f"execution:{execution.object_id}", artifact_refs


def _validate_opaque_validation_fields(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload["checks_performed"], (list, tuple)):
        raise ValidationBoundaryError("validation checks_performed must be an array")
    if not isinstance(payload["metrics"], Mapping):
        raise ValidationBoundaryError("validation metrics must be an object")
    if not isinstance(payload["tolerances"], Mapping):
        raise ValidationBoundaryError("validation tolerances must be an object")
    _text("validation_receipt.payload.proposed_outcome", payload["proposed_outcome"])
    if not isinstance(payload["reasons"], (list, tuple)):
        raise ValidationBoundaryError("validation reasons must be an array")
    _text(
        "validation_receipt.payload.reproducibility_class",
        payload["reproducibility_class"],
    )


def _cas_refs(label: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValidationBoundaryError(f"{label} must be an array")
    refs: list[str] = []
    for index, ref in enumerate(value):
        if not isinstance(ref, str) or _CAS_REF_RE.fullmatch(ref) is None:
            raise ValidationBoundaryError(f"{label}[{index}] is not a CAS reference")
        refs.append(ref)
    return tuple(refs)


def _exact_mapping(
    value: object, expected_keys: frozenset[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationBoundaryError(f"{label} must be an object")
    copied = dict(value)
    if set(copied) != set(expected_keys) or any(
        not isinstance(key, str) for key in copied
    ):
        raise ValidationBoundaryError(f"{label} keys are not exact")
    return copied


def _identifier(label: str, value: object) -> str:
    normalized = _text(label, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValidationBoundaryError(f"{label} must be a normalized identifier")
    return normalized


def _portable_ref(label: str, value: object) -> str:
    normalized = _text(label, value)
    if (
        _PORTABLE_REF_RE.fullmatch(normalized) is None
        or normalized.startswith(("/", "~"))
        or normalized.lower().startswith(("file:", "host:"))
        or re.match(r"^[A-Za-z]:/", normalized) is not None
    ):
        raise ValidationBoundaryError(f"{label} must be a portable non-file reference")
    return normalized


def _text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValidationBoundaryError(f"{label} must be normalized nonempty text")
    if len(value) > _MAX_TEXT_LENGTH or any(
        ord(character) < 32 for character in value
    ):
        raise ValidationBoundaryError(f"{label} contains invalid text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationBoundaryError(f"{label} is not valid UTF-8 text") from exc
    return value


def _sha256(label: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValidationBoundaryError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(label: str, value: object) -> datetime:
    normalized = _text(label, value)
    if _RFC3339_RE.fullmatch(normalized) is None:
        raise ValidationBoundaryError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(
            normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
        )
    except ValueError as exc:
        raise ValidationBoundaryError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationBoundaryError(f"{label} must include an offset")
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _positive_safe_integer(label: str, value: object) -> int:
    normalized = _nonnegative_safe_integer(label, value)
    if normalized == 0:
        raise ValidationBoundaryError(f"{label} must be positive")
    return normalized


def _nonnegative_safe_integer(label: str, value: object) -> int:
    if type(value) is not int or value < 0 or value > _MAX_SAFE_INTEGER:
        raise ValidationBoundaryError(f"{label} must be a non-negative safe integer")
    return value


def _readable_store(value: object, label: str) -> None:
    if not callable(getattr(value, "read_bytes", None)):
        raise ValidationBoundaryError(f"{label} must provide read_bytes")


def _store_read(
    store: _ByteStore, ref: str, maximum_size_bytes: int, label: str
) -> bytes:
    try:
        value = store.read_bytes(ref, maximum_size_bytes=maximum_size_bytes)
    except Exception as exc:
        raise ValidationBoundaryError(f"{label} failed closed") from exc
    if type(value) is not bytes:
        raise ValidationBoundaryError(f"{label} must return exact bytes")
    if len(value) > maximum_size_bytes:
        raise ValidationBoundaryError(f"{label} exceeded its byte ceiling")
    return value


def _strict_json_object(value: bytes, label: str) -> dict[str, Any]:
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")

    def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    try:
        decoded = value.decode("utf-8")
        parsed = json.loads(
            decoded,
            object_pairs_hook=exact_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValidationBoundaryError(f"{label} is not strict JSON") from exc
    if not isinstance(parsed, dict):
        raise ValidationBoundaryError(f"{label} must be an object")
    _ensure_json(parsed, label)
    return parsed


def _canonical_bytes(value: object, *, trailing_newline: bool = False) -> bytes:
    _ensure_json(value, "value")
    try:
        encoded = json.dumps(
            _json_ready(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValidationBoundaryError("value is not canonical JSON") from exc
    return encoded + (b"\n" if trailing_newline else b"")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _ensure_json(value: object, label: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationBoundaryError(f"{label} contains a non-finite number")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _ensure_json(item, f"{label}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationBoundaryError(f"{label} contains a non-text key")
            _ensure_json(item, f"{label}.{key}")
        return
    raise ValidationBoundaryError(f"{label} contains a non-JSON value")


def _json_ready(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value
