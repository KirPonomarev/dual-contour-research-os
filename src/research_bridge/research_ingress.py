"""Additive mission binding for paired P04 research ingress.

The frozen DomainExportBinding, OperationalActionEnvelope, SourceTrigger and
MaterialEvent shapes remain unchanged.  This module validates a separate
mission/action pair and supplies deterministic lineage material for the
existing single-writer Bridge runtime.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from types import MappingProxyType


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_CAS_REF_RE = re.compile(r"^cas:sha256:([a-f0-9]{64})$")
_PAIRED_ID_RE = re.compile(r"^paired-research-ingress:[a-f0-9]{64}$")
_MISSION_ID_RE = re.compile(r"^research-mission:[a-f0-9]{64}$")
_ACTION_ID_RE = re.compile(r"^research-ingress-action:[a-f0-9]{64}$")
_DOCUMENT_KEYS = frozenset(
    {"schema_id", "schema_version", "object_id", "issued_at", "payload", "integrity"}
)
_MISSION_PAYLOAD_KEYS = frozenset(
    {
        "mission_sha256",
        "plan_sha256",
        "artifact_ref",
        "artifact_sha256",
        "prepared_kimi_request_ref",
        "prepared_kimi_request_sha256",
        "artifact_size_bytes",
        "artifact_schema_id",
        "data_class",
        "project_fingerprints",
        "runtime_heads",
        "domain_binding_sha256s",
        "paired_execution_id",
        "expected_trigger_domains",
        "provider_boundary",
        "expires_at",
        "stop_conditions",
        "rollback",
        "forbidden_boundaries",
        "live_authority",
        "domain_write_authority",
        "canonical_write_authority",
    }
)
_ACTION_PAYLOAD_KEYS = frozenset(
    {
        "action_id",
        "mission_sha256",
        "plan_sha256",
        "mission_envelope_sha256",
        "exact_host_fingerprint",
        "exact_service",
        "exact_uid",
        "paired_execution_id",
        "domain_binding_sha256s",
        "expected_trigger_domains",
        "provider_calls_maximum",
        "ingress_provider_calls",
        "domain_writes",
        "canonical_writes",
        "live_authority",
        "expires_at",
        "stop_conditions",
        "rollback",
        "forbidden_boundaries",
        "authority_source_hash",
    }
)
_BOUNDARY_KEYS = frozenset(
    {
        "roles",
        "bindings",
        "reasoning_efforts",
        "maximum_calls",
        "maximum_calls_per_role",
        "fallback_allowed",
    }
)
_EXPECTED_DOMAINS = ("market", "security")
ROLE_SEQUENCE = (
    ("SCOUT_FAST", "deepseek-v4-flash", "max"),
    ("RESEARCH_WORKER", "deepseek-v4-pro", "max"),
    ("CRITIC_PRIMARY", "kimi-k3-max", "max"),
    ("CRITIC_DEEP", "gpt-5.6-sol-xhigh", "xhigh"),
    ("CHIEF_SCIENTIST", "gpt-5.6-sol-xhigh", "xhigh"),
)
MAX_ARTIFACT_BYTES = 131_072
MAX_CHAIN_REQUEST_BYTES = 49_152
_FORBIDDEN_ARTIFACT_MARKERS = (
    "D2_DOMAIN_CONFIDENTIAL",
    "D3_RESTRICTED",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "sk-or-v1-",
    "AKIA",
    "PASSWORD=",
    "API_KEY=",
    "SECRET_KEY=",
)


class ResearchIngressError(RuntimeError):
    """A mission wrapper, action, lineage or bounded artifact failed closed."""


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ResearchIngressError("mission material is not canonical JSON") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _exact(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ResearchIngressError(f"{label} shape is invalid")
    return dict(value)


def _text(value: object, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum
    ):
        raise ResearchIngressError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    text = _text(value, label, maximum=64)
    if _SHA256_RE.fullmatch(text) is None:
        raise ResearchIngressError(f"{label} is not a SHA-256")
    return text


def _git_sha(value: object, label: str) -> str:
    text = _text(value, label, maximum=40)
    if _GIT_SHA_RE.fullmatch(text) is None:
        raise ResearchIngressError(f"{label} is not a Git SHA")
    return text


def _timestamp(value: object, label: str) -> datetime:
    text = _text(value, label, maximum=64)
    if not text.endswith("Z"):
        raise ResearchIngressError(f"{label} must use canonical UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ResearchIngressError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ResearchIngressError(f"{label} is not UTC")
    return parsed


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or not value
        or len(value) != len(set(value))
    ):
        raise ResearchIngressError(f"{label} must be a non-empty unique list")
    return tuple(_text(item, f"{label} item") for item in value)


def _sha_map(value: object, keys: frozenset[str], label: str) -> dict[str, str]:
    mapped = _exact(value, keys, label)
    return {key: _sha256(mapped[key], f"{label}.{key}") for key in sorted(keys)}


def _git_map(value: object, keys: frozenset[str], label: str) -> dict[str, str]:
    mapped = _exact(value, keys, label)
    return {key: _git_sha(mapped[key], f"{label}.{key}") for key in sorted(keys)}


def _validated_payload(
    document: Mapping[str, object],
    *,
    schema_id: str,
    object_pattern: re.Pattern[str],
    payload_keys: frozenset[str],
    now: datetime,
) -> tuple[dict[str, object], datetime, datetime]:
    envelope = _exact(document, _DOCUMENT_KEYS, schema_id)
    if envelope["schema_id"] != schema_id or envelope["schema_version"] != "1.0.0":
        raise ResearchIngressError(f"{schema_id} version is unsupported")
    object_id = _text(envelope["object_id"], f"{schema_id}.object_id")
    if object_pattern.fullmatch(object_id) is None:
        raise ResearchIngressError(f"{schema_id}.object_id is invalid")
    issued = _timestamp(envelope["issued_at"], f"{schema_id}.issued_at")
    payload = _exact(envelope["payload"], payload_keys, f"{schema_id}.payload")
    integrity = _exact(
        envelope["integrity"], frozenset({"payload_sha256"}), f"{schema_id}.integrity"
    )
    expected = canonical_sha256(payload)
    if not hmac.compare_digest(
        _sha256(integrity["payload_sha256"], f"{schema_id}.integrity.payload_sha256"),
        expected,
    ):
        raise ResearchIngressError(f"{schema_id} payload integrity mismatch")
    expires = _timestamp(payload["expires_at"], f"{schema_id}.expires_at")
    current = now.astimezone(timezone.utc)
    if issued > current or expires <= issued or current > expires:
        raise ResearchIngressError(f"{schema_id} is stale, future-dated or expired")
    return payload, issued, expires


def validate_research_mission_envelope(
    document: Mapping[str, object],
    *,
    now: datetime | None = None,
) -> Mapping[str, object]:
    current = now or datetime.now(timezone.utc)
    payload, _, _ = _validated_payload(
        document,
        schema_id="ResearchMissionEnvelope",
        object_pattern=_MISSION_ID_RE,
        payload_keys=_MISSION_PAYLOAD_KEYS,
        now=current,
    )
    mission_sha = _sha256(payload["mission_sha256"], "mission_sha256")
    if document["object_id"] != f"research-mission:{mission_sha}":
        raise ResearchIngressError("mission object_id does not bind mission_sha256")
    _sha256(payload["plan_sha256"], "plan_sha256")
    artifact_sha = _sha256(payload["artifact_sha256"], "artifact_sha256")
    artifact_ref = _text(payload["artifact_ref"], "artifact_ref")
    match = _CAS_REF_RE.fullmatch(artifact_ref)
    if match is None or match.group(1) != artifact_sha:
        raise ResearchIngressError("mission artifact ref/hash binding is invalid")
    prepared_kimi_sha = _sha256(
        payload["prepared_kimi_request_sha256"],
        "prepared_kimi_request_sha256",
    )
    prepared_kimi_ref = _text(
        payload["prepared_kimi_request_ref"], "prepared_kimi_request_ref"
    )
    if prepared_kimi_sha != artifact_sha or prepared_kimi_ref != artifact_ref:
        raise ResearchIngressError(
            "prepared Kimi request must be the exact mission artifact"
        )
    if (
        type(payload["artifact_size_bytes"]) is not int
        or not 1 <= payload["artifact_size_bytes"] <= MAX_ARTIFACT_BYTES
    ):
        raise ResearchIngressError("mission artifact size is invalid")
    _text(payload["artifact_schema_id"], "artifact_schema_id", maximum=128)
    if payload["data_class"] not in {"D0_PUBLIC", "D1_INTERNAL_SANITIZED"}:
        raise ResearchIngressError("mission data class must be D0/D1")
    _sha_map(
        payload["project_fingerprints"],
        frozenset({"bridge", "market", "security"}),
        "project_fingerprints",
    )
    _git_map(
        payload["runtime_heads"],
        frozenset({"bridge", "market", "security"}),
        "runtime_heads",
    )
    bindings = _sha_map(
        payload["domain_binding_sha256s"],
        frozenset(_EXPECTED_DOMAINS),
        "domain_binding_sha256s",
    )
    if bindings["market"] == bindings["security"]:
        raise ResearchIngressError("cross-domain binding hashes must be distinct")
    paired = _text(payload["paired_execution_id"], "paired_execution_id")
    if _PAIRED_ID_RE.fullmatch(paired) is None:
        raise ResearchIngressError("paired execution identity is invalid")
    if payload["expected_trigger_domains"] != list(_EXPECTED_DOMAINS):
        raise ResearchIngressError("expected trigger domain order is invalid")
    boundary = _exact(payload["provider_boundary"], _BOUNDARY_KEYS, "provider_boundary")
    if (
        boundary["roles"] != [item[0] for item in ROLE_SEQUENCE]
        or boundary["bindings"] != [item[1] for item in ROLE_SEQUENCE]
        or boundary["reasoning_efforts"] != [item[2] for item in ROLE_SEQUENCE]
        or boundary["maximum_calls"] != len(ROLE_SEQUENCE)
        or boundary["maximum_calls_per_role"] != 1
        or boundary["fallback_allowed"] is not False
    ):
        raise ResearchIngressError("provider boundary differs from the bounded role chain")
    _string_list(payload["stop_conditions"], "stop_conditions")
    _text(payload["rollback"], "rollback", maximum=2048)
    _string_list(payload["forbidden_boundaries"], "forbidden_boundaries")
    if any(
        payload[name] is not False
        for name in ("live_authority", "domain_write_authority", "canonical_write_authority")
    ):
        raise ResearchIngressError("mission envelope grants forbidden authority")
    return MappingProxyType(payload)


def validate_research_ingress_action_envelope(
    document: Mapping[str, object],
    mission_document: Mapping[str, object],
    *,
    expected_host_fingerprint: str,
    expected_uid: int = 10002,
    now: datetime | None = None,
) -> Mapping[str, object]:
    current = now or datetime.now(timezone.utc)
    mission = validate_research_mission_envelope(mission_document, now=current)
    payload, _, _ = _validated_payload(
        document,
        schema_id="ResearchIngressActionEnvelope",
        object_pattern=_ACTION_ID_RE,
        payload_keys=_ACTION_PAYLOAD_KEYS,
        now=current,
    )
    action_id = _text(payload["action_id"], "action_id")
    if document["object_id"] != action_id or _ACTION_ID_RE.fullmatch(action_id) is None:
        raise ResearchIngressError("action object_id binding is invalid")
    if payload["mission_sha256"] != mission["mission_sha256"]:
        raise ResearchIngressError("action mission binding is invalid")
    if payload["plan_sha256"] != mission["plan_sha256"]:
        raise ResearchIngressError("action plan binding is invalid")
    if payload["mission_envelope_sha256"] != canonical_sha256(mission_document):
        raise ResearchIngressError("action mission-envelope hash is invalid")
    if payload["exact_host_fingerprint"] != _sha256(
        expected_host_fingerprint, "expected_host_fingerprint"
    ):
        raise ResearchIngressError("action host fingerprint is invalid")
    if payload["exact_service"] != "research-os-a1-ingress.service":
        raise ResearchIngressError("action service identity is invalid")
    if type(expected_uid) is not int or payload["exact_uid"] != expected_uid:
        raise ResearchIngressError("action UID identity is invalid")
    if payload["paired_execution_id"] != mission["paired_execution_id"]:
        raise ResearchIngressError("action paired execution identity is invalid")
    if payload["domain_binding_sha256s"] != mission["domain_binding_sha256s"]:
        raise ResearchIngressError("action domain bindings are hash-mixed")
    if payload["expected_trigger_domains"] != list(_EXPECTED_DOMAINS):
        raise ResearchIngressError("action trigger domain order is invalid")
    expected_zero = {
        "provider_calls_maximum": len(ROLE_SEQUENCE),
        "ingress_provider_calls": 0,
        "domain_writes": 0,
        "canonical_writes": 0,
        "live_authority": False,
    }
    if any(payload[name] != value for name, value in expected_zero.items()):
        raise ResearchIngressError("action authority/budget boundary is invalid")
    _string_list(payload["stop_conditions"], "action stop_conditions")
    _text(payload["rollback"], "action rollback", maximum=2048)
    _string_list(payload["forbidden_boundaries"], "action forbidden_boundaries")
    _sha256(payload["authority_source_hash"], "authority_source_hash")
    return MappingProxyType(payload)


def validate_mission_artifact(
    raw: bytes,
    mission_payload: Mapping[str, object],
) -> str:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ARTIFACT_BYTES:
        raise ResearchIngressError("mission artifact byte length is invalid")
    if len(raw) != mission_payload["artifact_size_bytes"]:
        raise ResearchIngressError("mission artifact size binding is invalid")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != mission_payload["artifact_sha256"]:
        raise ResearchIngressError("mission artifact hash binding is invalid")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ResearchIngressError("mission artifact must be UTF-8 text") from exc
    if not text.strip() or "\x00" in text:
        raise ResearchIngressError("mission artifact text is invalid")
    upper = text.upper()
    if any(marker.upper() in upper for marker in _FORBIDDEN_ARTIFACT_MARKERS):
        raise ResearchIngressError("mission artifact contains a forbidden data/secret marker")
    return digest


def mission_evidence_ref(mission_sha256: str) -> str:
    return "registered:research-mission/" + _sha256(mission_sha256, "mission_sha256")


def role_assignment_ref(mission_sha256: str, index: int, role: str) -> str:
    if type(index) is not int or not 0 <= index < len(ROLE_SEQUENCE):
        raise ResearchIngressError("role index is invalid")
    if role != ROLE_SEQUENCE[index][0]:
        raise ResearchIngressError("role/index binding is invalid")
    material = {
        "mission_sha256": _sha256(mission_sha256, "mission_sha256"),
        "role_index": index,
        "role": role,
        "agenda": "bounded-evolution-loop-v1",
    }
    return "research-role-assignment:" + canonical_sha256(material)


def build_role_request(
    artifact: bytes,
    *,
    mission_sha256: str,
    prepared_kimi_request_sha256: str,
    index: int,
    prior_results: Sequence[tuple[str, str, bytes | None]],
) -> str:
    validate_index = type(index) is int and 0 <= index < len(ROLE_SEQUENCE)
    if not validate_index:
        raise ResearchIngressError("role request index is invalid")
    try:
        base = artifact.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ResearchIngressError("mission artifact cannot form a role request") from exc
    role, binding, effort = ROLE_SEQUENCE[index]
    sections = [
        base,
        "\n\n## Canonical organism role execution",
        f"mission_sha256: {mission_sha256}",
        "prepared_kimi_request_sha256: "
        + _sha256(
            prepared_kimi_request_sha256,
            "prepared_kimi_request_sha256",
        ),
        f"role_index: {index}",
        f"role: {role}",
        f"exact_binding: {binding}",
        f"reasoning_effort: {effort}",
        "authority: C3_UNTRUSTED_PROPOSAL_ONLY",
        "Return evidence-bound findings; model agreement is not physical evidence.",
    ]
    if prior_results:
        sections.append("\n## Prior bounded role results")
        for prior_role, response_ref, response_bytes in prior_results:
            sections.append(f"\n### {prior_role} — {response_ref}")
            if response_bytes is None:
                sections.append("Terminal metadata only; response content unavailable.")
            else:
                try:
                    rendered = response_bytes.decode("utf-8", errors="strict")
                except UnicodeError as exc:
                    raise ResearchIngressError("prior result is not UTF-8") from exc
                if len(response_bytes) > 8_192:
                    rendered = response_bytes[:8_192].decode(
                        "utf-8", errors="ignore"
                    ) + "\n[bounded excerpt; exact full result remains at the bound CAS ref]"
                sections.append(rendered)
    if role == "SCOUT_FAST":
        sections.append("Extract the highest-information claims and missing evidence; do not adjudicate.")
    elif role == "RESEARCH_WORKER":
        sections.append("Build a primary-evidence research map and bounded experiment list.")
    elif role == "CRITIC_PRIMARY":
        sections.append("Run the required independent Kimi adversarial falsification and preserve minority objections.")
    elif role == "CRITIC_DEEP":
        sections.append("Adjudicate claims against primary and physical evidence; label missing evidence explicitly.")
    else:
        sections.append("Synthesize Cycles 2-4, retain negative results and issue claim-level dispositions with limitations.")
    request = "\n".join(sections)
    raw = request.encode("utf-8")
    if not raw or len(raw) > MAX_CHAIN_REQUEST_BYTES:
        raise ResearchIngressError("role request exceeds the bounded request size")
    return request


def schema_paths(root: Path) -> tuple[Path, Path]:
    base = root / "contracts" / "research" / "v1"
    return (
        base / "ResearchMissionEnvelope.schema.json",
        base / "ResearchIngressActionEnvelope.schema.json",
    )


__all__ = [
    "MAX_ARTIFACT_BYTES",
    "MAX_CHAIN_REQUEST_BYTES",
    "ROLE_SEQUENCE",
    "ResearchIngressError",
    "build_role_request",
    "canonical_bytes",
    "canonical_sha256",
    "mission_evidence_ref",
    "role_assignment_ref",
    "schema_paths",
    "validate_mission_artifact",
    "validate_research_ingress_action_envelope",
    "validate_research_mission_envelope",
]
