"""Pinned public synthetic Market writer used only for the S03 shadow fixture.

This domain-owned module performs no I/O and never writes a Market registry.
It only freezes one exact Bridge FreezeProjection into immutable D0 objects
whose knowledge remains SHADOW_UNAPPLIED.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from research_bridge.admission import canonical_json_sha256
from research_bridge.discovery import FreezeProjection


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_PROJECTION_KEYS = frozenset(
    {
        "algorithm_version", "candidate_ref", "candidate_sha256",
        "source_event_ref", "domain_contour", "classification", "shadow_taint",
        "policy_sha256", "context_sha256", "required_writers",
        "hypothesis_payload", "protocol_inputs", "projection_id",
    }
)
_HYPOTHESIS_KEYS = frozenset(
    {
        "hypothesis_id", "thesis", "null_hypothesis", "mechanism",
        "falsification_rule", "scope_boundary", "source_refs",
    }
)
_PROTOCOL_INPUT_KEYS = frozenset(
    {
        "primary_outcome", "input_manifest_sha256", "code_sha256",
        "environment_digest", "seed_set", "stopping_rule", "validator_sha256",
        "trial_family_id", "holdout_policy_ref",
    }
)


class SyntheticDomainError(RuntimeError):
    """The pinned synthetic domain boundary failed closed."""


@dataclass(frozen=True, slots=True)
class PinnedSyntheticDomainAuthority:
    """Non-secret identity pins supplied by the fixture domain owner."""

    contour: str
    classification: str
    hypothesis_writer_id: str
    protocol_writer_id: str
    expected_core_catalog_sha256: str

    def __post_init__(self) -> None:
        if self.contour != "market" or self.classification != "D0_PUBLIC":
            raise SyntheticDomainError("synthetic authority is fixed to public Market scope")
        for name, value in (
            ("hypothesis_writer_id", self.hypothesis_writer_id),
            ("protocol_writer_id", self.protocol_writer_id),
        ):
            _text(name, value, maximum=256)
        _sha256("expected_core_catalog_sha256", self.expected_core_catalog_sha256)


@dataclass(frozen=True, slots=True)
class SyntheticFreezeBundle:
    """Deeply immutable shadow-only domain objects and exact binding."""

    hypothesis_card: Mapping[str, object]
    protocol_snapshot: Mapping[str, object]
    projection_ref: str
    projection_sha256: str
    candidate_ref: str
    candidate_sha256: str
    shadow_taint: str

    def __post_init__(self) -> None:
        if self.shadow_taint != "SHADOW_UNAPPLIED":
            raise SyntheticDomainError("synthetic freeze bundle must remain shadow tainted")
        for name, value in (("projection_ref", self.projection_ref), ("candidate_ref", self.candidate_ref)):
            _text(name, value, maximum=512)
        _sha256("projection_sha256", self.projection_sha256)
        _sha256("candidate_sha256", self.candidate_sha256)
        object.__setattr__(self, "hypothesis_card", _freeze(_json_copy(self.hypothesis_card)))
        object.__setattr__(self, "protocol_snapshot", _freeze(_json_copy(self.protocol_snapshot)))

    def to_mapping(self) -> dict[str, object]:
        return {
            "hypothesis_card": _json_copy(self.hypothesis_card),
            "protocol_snapshot": _json_copy(self.protocol_snapshot),
            "projection_ref": self.projection_ref,
            "projection_sha256": self.projection_sha256,
            "candidate_ref": self.candidate_ref,
            "candidate_sha256": self.candidate_sha256,
            "shadow_taint": self.shadow_taint,
        }


class SyntheticMarketDomainWriter:
    """Freeze projections under two separately pinned writer identities."""

    def __init__(
        self,
        contract_root: str | Path,
        *,
        authority: PinnedSyntheticDomainAuthority,
    ) -> None:
        if not isinstance(authority, PinnedSyntheticDomainAuthority):
            raise SyntheticDomainError("pinned synthetic domain authority is required")
        catalog_path = Path(contract_root) / "catalog.json"
        try:
            catalog_bytes = catalog_path.read_bytes()
            catalog = json.loads(catalog_bytes)
        except (OSError, json.JSONDecodeError) as exc:
            raise SyntheticDomainError("Core contract catalog is unavailable") from exc
        digest = hashlib.sha256(catalog_bytes).hexdigest()
        if not hmac.compare_digest(digest, authority.expected_core_catalog_sha256):
            raise SyntheticDomainError("Core contract catalog pin mismatch")
        contracts = catalog.get("contracts")
        if not isinstance(contracts, dict):
            raise SyntheticDomainError("Core contract catalog shape is invalid")
        expected = {
            "HypothesisCard": ("domain", "domain-adapter", "proposal"),
            "ProtocolSnapshot": ("domain", "domain-registry-writer", "scientific-protocol"),
        }
        for name, pins in expected.items():
            entry = contracts.get(name)
            actual = (
                entry.get("owner"), entry.get("writer"), entry.get("authority")
            ) if isinstance(entry, dict) else None
            if actual != pins:
                raise SyntheticDomainError(f"Core {name} authority pin mismatch")
        self._authority = authority

    def freeze(self, projection: FreezeProjection, *, issued_at: str) -> SyntheticFreezeBundle:
        if not isinstance(projection, FreezeProjection):
            raise SyntheticDomainError("writer accepts only typed FreezeProjection values")
        timestamp = _timestamp("issued_at", issued_at)
        value = _exact(projection.to_mapping(), _PROJECTION_KEYS, "projection")
        if value["algorithm_version"] != "freeze-projection-v1":
            raise SyntheticDomainError("projection algorithm is not pinned")
        if (
            value["domain_contour"] != self._authority.contour
            or value["classification"] != self._authority.classification
            or value["shadow_taint"] != "SHADOW_UNAPPLIED"
        ):
            raise SyntheticDomainError("projection escaped synthetic public shadow scope")
        _text("projection_id", value["projection_id"], maximum=512)
        _text("candidate_ref", value["candidate_ref"], maximum=512)
        _text("source_event_ref", value["source_event_ref"], maximum=512)
        for name in ("candidate_sha256", "policy_sha256", "context_sha256"):
            _sha256(name, value[name])
        writers = _exact(
            value["required_writers"],
            frozenset({"HypothesisCard", "ProtocolSnapshot"}),
            "required_writers",
        )
        if writers != {
            "HypothesisCard": self._authority.hypothesis_writer_id,
            "ProtocolSnapshot": self._authority.protocol_writer_id,
        }:
            raise SyntheticDomainError("projection writer identities do not match authority pins")

        hypothesis_payload = _validate_hypothesis_payload(value["hypothesis_payload"])
        hypothesis_identity = canonical_json_sha256(
            {
                "projection_sha256": projection.sha256,
                "payload": hypothesis_payload,
                "writer": self._authority.hypothesis_writer_id,
            }
        )
        hypothesis = _domain_object(
            schema_id="HypothesisCard",
            object_id=f"hypothesis:{hypothesis_identity}",
            issued_at=timestamp,
            issuer_id=self._authority.hypothesis_writer_id,
            authority_class="domain-adapter",
            contour=self._authority.contour,
            classification=self._authority.classification,
            payload=hypothesis_payload,
            parent_refs=[f"candidate:{value['candidate_ref']}", f"projection:{value['projection_id']}"],
        )

        protocol_inputs = _validate_protocol_inputs(value["protocol_inputs"])
        protocol_payload = {"hypothesis_sha256": canonical_json_sha256(hypothesis), **protocol_inputs}
        protocol_identity = canonical_json_sha256(
            {
                "hypothesis_ref": hypothesis["object_id"],
                "payload": protocol_payload,
                "writer": self._authority.protocol_writer_id,
            }
        )
        protocol = _domain_object(
            schema_id="ProtocolSnapshot",
            object_id=f"protocol:{protocol_identity}",
            issued_at=timestamp,
            issuer_id=self._authority.protocol_writer_id,
            authority_class="domain-registry-writer",
            contour=self._authority.contour,
            classification=self._authority.classification,
            payload=protocol_payload,
            parent_refs=[
                f"candidate:{value['candidate_ref']}",
                f"projection:{value['projection_id']}",
                f"hypothesis:{hypothesis['object_id']}",
            ],
        )
        return SyntheticFreezeBundle(
            hypothesis_card=hypothesis,
            protocol_snapshot=protocol,
            projection_ref=value["projection_id"],
            projection_sha256=projection.sha256,
            candidate_ref=value["candidate_ref"],
            candidate_sha256=value["candidate_sha256"],
            shadow_taint="SHADOW_UNAPPLIED",
        )


def _domain_object(
    *, schema_id: str, object_id: str, issued_at: str, issuer_id: str,
    authority_class: str, contour: str, classification: str,
    payload: Mapping[str, object], parent_refs: list[str],
) -> dict[str, object]:
    copied_payload = _json_copy(payload)
    return {
        "schema_id": schema_id,
        "schema_version": "1.0.0",
        "object_id": object_id,
        "issued_at": issued_at,
        "issuer": {"id": issuer_id, "authority_class": authority_class},
        "contour": contour,
        "classification": classification,
        "payload": copied_payload,
        "integrity": {
            "payload_sha256": canonical_json_sha256(copied_payload),
            "parent_refs": parent_refs,
        },
    }


def _validate_hypothesis_payload(value: object) -> dict[str, object]:
    payload = _exact(value, _HYPOTHESIS_KEYS, "hypothesis_payload")
    for name in (
        "hypothesis_id", "thesis", "null_hypothesis", "mechanism",
        "falsification_rule", "scope_boundary",
    ):
        _text(f"hypothesis_payload.{name}", payload[name], maximum=4_096)
    refs = payload["source_refs"]
    if not isinstance(refs, list) or not refs or len(refs) > 64:
        raise SyntheticDomainError("hypothesis source refs must be bounded and non-empty")
    for ref in refs:
        _text("hypothesis source ref", ref, maximum=512)
    if len(refs) != len(set(refs)):
        raise SyntheticDomainError("hypothesis source refs must be unique")
    return payload


def _validate_protocol_inputs(value: object) -> dict[str, object]:
    payload = _exact(value, _PROTOCOL_INPUT_KEYS, "protocol_inputs")
    for name in (
        "primary_outcome", "environment_digest", "stopping_rule",
        "trial_family_id", "holdout_policy_ref",
    ):
        _text(f"protocol_inputs.{name}", payload[name], maximum=4_096)
    for name in ("input_manifest_sha256", "code_sha256", "validator_sha256"):
        _sha256(f"protocol_inputs.{name}", payload[name])
    seeds = payload["seed_set"]
    if (
        not isinstance(seeds, list) or not seeds or len(seeds) > 64
        or any(type(seed) is not int or seed < 0 for seed in seeds)
        or len(set(seeds)) != len(seeds)
    ):
        raise SyntheticDomainError("protocol seed set is invalid")
    if payload["holdout_policy_ref"] != "synthetic-no-true-holdout-v1":
        raise SyntheticDomainError("synthetic protocol cannot request a true holdout")
    return payload


def _exact(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise SyntheticDomainError(f"{label} shape mismatch")
    return _json_copy(value)  # type: ignore[return-value]


def _text(name: str, value: object, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SyntheticDomainError(f"{name} must be bounded non-empty text")
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise SyntheticDomainError(f"{name} must be normalized text")
    return value


def _sha256(name: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise SyntheticDomainError(f"{name} must be lowercase SHA-256")
    return value


def _timestamp(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SyntheticDomainError(f"{name} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SyntheticDomainError(f"{name} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SyntheticDomainError(f"{name} must be UTC")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_copy(item) for item in value]
    if value is None or type(value) in {str, bool, int, float}:
        return value
    raise SyntheticDomainError("value is not JSON-shaped")


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


__all__ = [
    "SyntheticDomainError", "PinnedSyntheticDomainAuthority",
    "SyntheticFreezeBundle", "SyntheticMarketDomainWriter",
]
