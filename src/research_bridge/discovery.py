"""Bounded E1A discovery fixture for IPC 1.2 collector and Scout principals.

The module is deliberately local and non-durable.  It reuses the existing
AF_UNIX control plane and frozen A1 admission kernel without adding a model
provider, scheduler, ledger, queue, or scientific writer.  All model-shaped
bytes remain untrusted and are projected into CandidateSpecDraft only after
strict parsing and trusted-field replacement.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import re
from threading import RLock
import time
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

from .admission import A1AdmissionKernel, A1AdmissionSnapshot, canonical_json_sha256


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_SOURCE_TRIGGER_KEYS = frozenset(
    {
        "trigger_id",
        "collector_id",
        "source_ref",
        "source_content_sha256",
        "observed_at",
        "summary",
        "evidence_refs",
        "transport_idempotency_key",
    }
)
_PROPOSAL_ENVELOPE_KEYS = frozenset(
    {
        "material_event_ref",
        "claim_token",
        "model_output",
        "critique_output",
        "model_call_ref",
        "critique_call_ref",
    }
)
_MODEL_BODY_KEYS = frozenset(
    {
        "candidate_id",
        "draft_revision",
        "experiment_type",
        "estimand",
        "null_hypothesis",
        "falsifier",
        "stop_condition",
        "scope",
        "expected_output",
        "evidence_refs",
        "evidence_independence_groups",
        "executor_family",
        "resource_request",
        "data_classes",
        "network_required",
        "holdout_access_requested",
        "canonical_write_requested",
        "private_api_requested",
        "live_execution_requested",
    }
)
_CRITIQUE_KEYS = frozenset({"accepted", "falsifier_present", "critique"})
_RESOURCE_KEYS = frozenset(
    {
        "wall_seconds",
        "cpu_seconds",
        "memory_mib",
        "output_bytes",
        "tokens",
        "cost_units",
    }
)
_CANDIDATE_KEYS = frozenset(
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
_CANDIDATE_TRUSTED_PAYLOAD_KEYS = frozenset(
    {
        "event_ref",
        "root_event_ref",
        "vcs_identity",
        "policy_sha256",
        "context_sha256",
        "shadow_taint",
        "model_call_refs",
        "critique_refs",
    }
)
_CANDIDATE_PAYLOAD_KEYS = _MODEL_BODY_KEYS | _CANDIDATE_TRUSTED_PAYLOAD_KEYS
_VCS_IDENTITY_KEYS = frozenset(
    {
        "repository_id",
        "head_sha",
        "base_sha",
        "worktree_clean",
        "contract_catalog_sha256",
        "a1_catalog_sha256",
        "release_manifest_sha256",
    }
)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class DiscoveryError(RuntimeError):
    """A principal, parser, claim, or projection failed closed."""


@dataclass(frozen=True, slots=True)
class ParserLimits:
    """Local bounds for one untrusted model-shaped JSON output."""

    maximum_bytes: int = 65_536
    maximum_depth: int = 16
    maximum_references: int = 64
    maximum_text_chars: int = 4_096
    maximum_parse_seconds: float = 0.25

    def __post_init__(self) -> None:
        for name, value in (
            ("maximum_bytes", self.maximum_bytes),
            ("maximum_depth", self.maximum_depth),
            ("maximum_references", self.maximum_references),
            ("maximum_text_chars", self.maximum_text_chars),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise DiscoveryError(f"{name} must be a positive integer")
        if (
            isinstance(self.maximum_parse_seconds, bool)
            or not isinstance(self.maximum_parse_seconds, (int, float))
            or not math.isfinite(float(self.maximum_parse_seconds))
            or not 0 < float(self.maximum_parse_seconds) <= 5
        ):
            raise DiscoveryError(
                "maximum_parse_seconds must be positive and at most five"
            )


@dataclass(frozen=True, slots=True)
class DiscoveryFixtureConfig:
    """Trusted frozen inputs that model or collector requests cannot override."""

    policy_sha256: str
    context_sha256: str
    classification: str
    ledger_revision: int
    root_energy: Mapping[str, object]
    remaining_energy: Mapping[str, object]
    allowed_source_prefixes: tuple[str, ...]
    collector_bindings: Mapping[str, str]
    repository_id: str
    head_sha: str
    base_sha: str
    release_manifest_sha256: str
    claim_ttl_seconds: int = 300
    maximum_reason_feedback: int = 1

    def __post_init__(self) -> None:
        for name, value in (
            ("policy_sha256", self.policy_sha256),
            ("context_sha256", self.context_sha256),
            ("release_manifest_sha256", self.release_manifest_sha256),
        ):
            _sha256(name, value)
        for name, value in (("head_sha", self.head_sha), ("base_sha", self.base_sha)):
            if not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None:
                raise DiscoveryError(f"{name} must be a 40-hex Git commit")
        if self.classification not in {"D0", "D1"}:
            raise DiscoveryError("classification must be D0 or D1")
        _nonnegative_integer("ledger_revision", self.ledger_revision)
        _text("repository_id", self.repository_id, maximum=256)
        prefixes = _string_sequence(
            "allowed_source_prefixes",
            self.allowed_source_prefixes,
            allow_empty=False,
            maximum=2_048,
        )
        if not isinstance(self.collector_bindings, Mapping) or not self.collector_bindings:
            raise DiscoveryError("collector_bindings must be a non-empty mapping")
        bindings: dict[str, str] = {}
        for actor, collector_id in self.collector_bindings.items():
            bindings[
                _text("collector actor", actor, maximum=256)
            ] = _text("collector_id", collector_id, maximum=256)
        _resource_budget("root_energy", self.root_energy)
        _resource_budget("remaining_energy", self.remaining_energy)
        if (
            isinstance(self.claim_ttl_seconds, bool)
            or not isinstance(self.claim_ttl_seconds, int)
            or not 1 <= self.claim_ttl_seconds <= 3_600
        ):
            raise DiscoveryError("claim_ttl_seconds must be between 1 and 3600")
        if (
            isinstance(self.maximum_reason_feedback, bool)
            or not isinstance(self.maximum_reason_feedback, int)
            or not 0 <= self.maximum_reason_feedback <= 4
        ):
            raise DiscoveryError("maximum_reason_feedback must be between 0 and 4")
        object.__setattr__(self, "allowed_source_prefixes", tuple(prefixes))
        object.__setattr__(self, "collector_bindings", MappingProxyType(bindings))
        object.__setattr__(
            self,
            "root_energy",
            _deep_freeze(_json_copy(self.root_energy)),
        )
        object.__setattr__(
            self,
            "remaining_energy",
            _deep_freeze(_json_copy(self.remaining_energy)),
        )


@dataclass(frozen=True, slots=True)
class FreezeProjectionConfig:
    """Trusted D0 fixture inputs that no candidate or model may override."""

    domain_contour: str
    hypothesis_writer_id: str
    protocol_writer_id: str
    input_manifest_sha256: str
    code_sha256: str
    environment_digest: str
    seed_set: tuple[int, ...]
    validator_sha256: str
    trial_family_prefix: str
    holdout_policy_ref: str

    def __post_init__(self) -> None:
        if self.domain_contour != "market":
            raise DiscoveryError("S03 synthetic fixture contour must be market")
        for name, value in (
            ("hypothesis_writer_id", self.hypothesis_writer_id),
            ("protocol_writer_id", self.protocol_writer_id),
            ("environment_digest", self.environment_digest),
            ("trial_family_prefix", self.trial_family_prefix),
            ("holdout_policy_ref", self.holdout_policy_ref),
        ):
            _text(name, value, maximum=512)
        for name, value in (
            ("input_manifest_sha256", self.input_manifest_sha256),
            ("code_sha256", self.code_sha256),
            ("validator_sha256", self.validator_sha256),
        ):
            _sha256(name, value)
        if self.holdout_policy_ref != "synthetic-no-true-holdout-v1":
            raise DiscoveryError("synthetic fixture must deny true holdout access")
        if (
            not isinstance(self.seed_set, tuple)
            or not self.seed_set
            or len(self.seed_set) > 64
            or any(type(seed) is not int or seed < 0 for seed in self.seed_set)
            or len(set(self.seed_set)) != len(self.seed_set)
        ):
            raise DiscoveryError("seed_set must contain unique non-negative integers")


@dataclass(frozen=True, slots=True)
class FreezeProjection:
    """Non-authoritative immutable request for a pinned domain fixture writer."""

    payload: Mapping[str, object]
    sha256: str

    def __post_init__(self) -> None:
        copied = _json_copy(self.payload)
        if not isinstance(copied, dict):
            raise DiscoveryError("freeze projection payload must be an object")
        digest = canonical_json_sha256(copied)
        if not hmac.compare_digest(digest, _sha256("projection sha256", self.sha256)):
            raise DiscoveryError("freeze projection digest mismatch")
        object.__setattr__(self, "payload", _deep_freeze(copied))

    def to_mapping(self) -> dict[str, object]:
        return _json_copy(self.payload)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class _Claim:
    actor: str
    token: str
    generation: int
    expires_at: datetime
    acknowledged: bool = False


class StrictProposalParser:
    """Parse bounded JSON without accepting duplicate keys or loose shapes."""

    def __init__(
        self,
        limits: ParserLimits | None = None,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(monotonic):
            raise DiscoveryError("parser monotonic clock must be callable")
        self._limits = limits or ParserLimits()
        self._monotonic = monotonic

    def parse_model_body(self, raw: str | bytes) -> dict[str, object]:
        value = self._parse_json_object(raw, "model_output")
        if set(value) != _MODEL_BODY_KEYS:
            raise DiscoveryError("model output shape mismatch")
        for field in (
            "candidate_id",
            "experiment_type",
            "estimand",
            "null_hypothesis",
            "falsifier",
            "stop_condition",
            "scope",
            "expected_output",
            "executor_family",
        ):
            _text(
                f"model_output.{field}",
                value[field],
                maximum=self._limits.maximum_text_chars,
            )
        _positive_integer("model_output.draft_revision", value["draft_revision"])
        evidence_refs = _string_sequence(
            "model_output.evidence_refs",
            value["evidence_refs"],
            allow_empty=False,
            maximum=512,
        )
        groups = value["evidence_independence_groups"]
        if not isinstance(groups, list) or not groups:
            raise DiscoveryError(
                "model_output.evidence_independence_groups must be non-empty"
            )
        parsed_groups = [
            _string_sequence(
                f"model_output.evidence_independence_groups[{index}]",
                group,
                allow_empty=False,
                maximum=512,
            )
            for index, group in enumerate(groups)
        ]
        grouped = [reference for group in parsed_groups for reference in group]
        if (
            len(grouped) != len(set(grouped))
            or set(grouped) != set(evidence_refs)
        ):
            raise DiscoveryError("evidence groups must partition evidence refs")
        if len(grouped) > self._limits.maximum_references:
            raise DiscoveryError("model output reference count exceeds the bound")
        data_classes = _string_sequence(
            "model_output.data_classes",
            value["data_classes"],
            allow_empty=False,
            maximum=256,
        )
        resource_request = _resource_budget(
            "model_output.resource_request", value["resource_request"]
        )
        for field in (
            "network_required",
            "holdout_access_requested",
            "canonical_write_requested",
            "private_api_requested",
            "live_execution_requested",
        ):
            if type(value[field]) is not bool:
                raise DiscoveryError(f"model_output.{field} must be a boolean")
        value["evidence_refs"] = evidence_refs
        value["evidence_independence_groups"] = parsed_groups
        value["data_classes"] = data_classes
        value["resource_request"] = resource_request
        return value

    def parse_critique(self, raw: str | bytes) -> dict[str, object]:
        value = self._parse_json_object(raw, "critique_output")
        if set(value) != _CRITIQUE_KEYS:
            raise DiscoveryError("critique output shape mismatch")
        if type(value["accepted"]) is not bool or type(value["falsifier_present"]) is not bool:
            raise DiscoveryError("critique booleans must be strict")
        _text(
            "critique_output.critique",
            value["critique"],
            maximum=min(self._limits.maximum_text_chars, 2_048),
        )
        return value

    def _parse_json_object(self, raw: str | bytes, label: str) -> dict[str, object]:
        if isinstance(raw, str):
            try:
                encoded = raw.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise DiscoveryError(f"{label} is not UTF-8 text") from exc
        elif isinstance(raw, bytes):
            encoded = raw
        else:
            raise DiscoveryError(f"{label} must be text or bytes")
        if not encoded or len(encoded) > self._limits.maximum_bytes:
            raise DiscoveryError(f"{label} exceeds its byte bound")
        started = self._monotonic()
        try:
            value = json.loads(
                encoded.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, DiscoveryError) as exc:
            raise DiscoveryError(f"{label} is not strict JSON") from exc
        elapsed = self._monotonic() - started
        if (
            not math.isfinite(elapsed)
            or elapsed < 0
            or elapsed > self._limits.maximum_parse_seconds
        ):
            raise DiscoveryError(f"{label} exceeded its parser time bound")
        if not isinstance(value, dict):
            raise DiscoveryError(f"{label} must be a JSON object")
        if _json_depth(value) > self._limits.maximum_depth:
            raise DiscoveryError(f"{label} exceeds its nesting bound")
        _ensure_json(value, label)
        return value


class DiscoveryFixtureService:
    """In-memory fixture boundary used only before durable E1B integration."""

    def __init__(
        self,
        admission_kernel: A1AdmissionKernel,
        config: DiscoveryFixtureConfig,
        *,
        parser: StrictProposalParser | None = None,
    ) -> None:
        if not isinstance(admission_kernel, A1AdmissionKernel):
            raise DiscoveryError("admission_kernel must be A1AdmissionKernel")
        if not isinstance(config, DiscoveryFixtureConfig):
            raise DiscoveryError("config must be DiscoveryFixtureConfig")
        self._kernel = admission_kernel
        self._config = config
        self._parser = parser or StrictProposalParser()
        self._lock = RLock()
        self._source_replays: dict[str, tuple[str, Mapping[str, object]]] = {}
        self._events: dict[str, Mapping[str, object]] = {}
        self._event_exact_keys: set[str] = set()
        self._claims: dict[str, _Claim] = {}
        self._proposal_replays: dict[str, tuple[str, Mapping[str, object]]] = {}
        self._proposals: dict[str, tuple[str, Mapping[str, object]]] = {}
        self._feedback_used: dict[str, int] = {}

    def submit_source_trigger(
        self,
        *,
        source_trigger: Mapping[str, object],
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        actor_text = _text("actor", actor, maximum=256)
        key = _text("idempotency_key", idempotency_key, maximum=256)
        trusted_collector = self._config.collector_bindings.get(actor_text)
        if trusted_collector is None:
            raise DiscoveryError("collector principal is not registered")
        trigger = _exact_mapping(source_trigger, _SOURCE_TRIGGER_KEYS, "source_trigger")
        if trigger["collector_id"] != trusted_collector:
            raise DiscoveryError("collector principal does not match collector_id")
        digest = canonical_json_sha256(trigger)
        with self._lock:
            replay = self._source_replays.get(key)
            if replay is not None:
                if not hmac.compare_digest(replay[0], digest):
                    raise DiscoveryError("source idempotency key was reused")
                return replay[1]
            result = self._kernel.materialize_source_trigger(
                trigger,
                issued_at=now,
                policy_sha256=self._config.policy_sha256,
                context_sha256=self._config.context_sha256,
                classification=self._config.classification,
                ledger_revision=self._config.ledger_revision,
                root_energy=self._config.root_energy,
                remaining_energy=self._config.remaining_energy,
                allowed_collectors=tuple(self._config.collector_bindings.values()),
                allowed_source_prefixes=self._config.allowed_source_prefixes,
                seen_exact_sha256=tuple(self._event_exact_keys),
            )
            response: dict[str, object] = {
                "decision": result.decision,
                "reason_code": result.reason_code,
                "model_calls_consumed": result.model_calls_consumed,
                "material_event": (
                    _json_copy(result.material_event)
                    if result.material_event is not None
                    else None
                ),
            }
            frozen = _deep_freeze(response)
            if result.material_event is not None:
                event = _deep_freeze(_json_copy(result.material_event))
                self._events[event["object_id"]] = event
                self._event_exact_keys.add(result.exact_key_sha256)
            self._source_replays[key] = (digest, frozen)
            return frozen

    def claim_proposal(
        self,
        *,
        material_event_ref: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        event_ref = _text("material_event_ref", material_event_ref, maximum=512)
        actor_text = _text("actor", actor, maximum=256)
        _text("idempotency_key", idempotency_key, maximum=256)
        current = _timestamp("now", now)
        with self._lock:
            if event_ref not in self._events:
                raise DiscoveryError("material event is not registered")
            existing = self._claims.get(event_ref)
            if (
                existing is not None
                and existing.expires_at > current
                and not existing.acknowledged
            ):
                if existing.actor != actor_text:
                    raise DiscoveryError("material event already has an active owner")
                return self._claim_response(event_ref, existing)
            generation = 1 if existing is None else existing.generation + 1
            expires_at = current + timedelta(
                seconds=self._config.claim_ttl_seconds
            )
            token = canonical_json_sha256(
                {
                    "actor": actor_text,
                    "event_ref": event_ref,
                    "expires_at": _format_timestamp(expires_at),
                    "generation": generation,
                }
            )
            claim = _Claim(
                actor=actor_text,
                token=token,
                generation=generation,
                expires_at=expires_at,
            )
            self._claims[event_ref] = claim
            return self._claim_response(event_ref, claim)

    def submit_proposal(
        self,
        *,
        proposal_envelope: Mapping[str, object],
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        actor_text = _text("actor", actor, maximum=256)
        key = _text("idempotency_key", idempotency_key, maximum=256)
        current = _timestamp("now", now)
        envelope = _exact_mapping(
            proposal_envelope,
            _PROPOSAL_ENVELOPE_KEYS,
            "proposal_envelope",
        )
        event_ref = _text(
            "proposal_envelope.material_event_ref",
            envelope["material_event_ref"],
            maximum=512,
        )
        claim_token = _sha256(
            "proposal_envelope.claim_token", envelope["claim_token"]
        )
        model_call_ref = _text(
            "proposal_envelope.model_call_ref",
            envelope["model_call_ref"],
            maximum=512,
        )
        critique_call_ref = _text(
            "proposal_envelope.critique_call_ref",
            envelope["critique_call_ref"],
            maximum=512,
        )
        digest = canonical_json_sha256(envelope)
        with self._lock:
            replay = self._proposal_replays.get(key)
            if replay is not None:
                if not hmac.compare_digest(replay[0], digest):
                    raise DiscoveryError("proposal idempotency key was reused")
                return replay[1]
            event = self._events.get(event_ref)
            if event is None:
                raise DiscoveryError("material event is not registered")
            claim = self._active_claim(
                event_ref,
                actor=actor_text,
                token=claim_token,
                now=current,
            )
            existing = self._proposals.get(event_ref)
            if existing is not None:
                if hmac.compare_digest(existing[0], digest):
                    self._proposal_replays[key] = existing
                    return existing[1]
                raise DiscoveryError("material event already has a different proposal")

            model_body = self._parser.parse_model_body(envelope["model_output"])
            critique = self._parser.parse_critique(envelope["critique_output"])
            if critique["accepted"] is not True or critique["falsifier_present"] is not True:
                used = self._feedback_used.get(event_ref, 0)
                if used >= self._config.maximum_reason_feedback:
                    response = _deep_freeze(
                        {
                            "decision": "PARKED",
                            "reason_code": "BUDGET_EXHAUSTED",
                            "candidate_spec_draft": None,
                            "feedback_remaining": 0,
                        }
                    )
                else:
                    used += 1
                    self._feedback_used[event_ref] = used
                    response = _deep_freeze(
                        {
                            "decision": "REJECTED",
                            "reason_code": "MISSING_REQUIRED_FIELD",
                            "candidate_spec_draft": None,
                            "feedback_remaining": max(
                                0, self._config.maximum_reason_feedback - used
                            ),
                        }
                    )
                self._proposal_replays[key] = (digest, response)
                return response

            candidate = self._project_candidate(
                event,
                model_body,
                issued_at=_format_timestamp(current),
                model_call_ref=model_call_ref,
                critique_call_ref=critique_call_ref,
            )
            response = _deep_freeze(
                {
                    "decision": "CANDIDATE_CREATED",
                    "candidate_spec_draft": candidate,
                    "feedback_remaining": self._config.maximum_reason_feedback,
                }
            )
            record = (digest, response)
            self._proposals[event_ref] = record
            self._proposal_replays[key] = record
            self._claims[event_ref] = replace(claim, acknowledged=False)
            return response

    def ack_proposal(
        self,
        *,
        material_event_ref: str,
        claim_token: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        event_ref = _text("material_event_ref", material_event_ref, maximum=512)
        actor_text = _text("actor", actor, maximum=256)
        token = _sha256("claim_token", claim_token)
        _text("idempotency_key", idempotency_key, maximum=256)
        current = _timestamp("now", now)
        with self._lock:
            claim = self._active_claim(
                event_ref,
                actor=actor_text,
                token=token,
                now=current,
                allow_acknowledged=True,
            )
            if event_ref not in self._proposals:
                raise DiscoveryError("proposal cannot be acknowledged before submission")
            if not claim.acknowledged:
                claim = replace(claim, acknowledged=True)
                self._claims[event_ref] = claim
            return _deep_freeze(
                {
                    "material_event_ref": event_ref,
                    "claim_token": claim.token,
                    "acknowledged": True,
                }
            )

    def _active_claim(
        self,
        event_ref: str,
        *,
        actor: str,
        token: str,
        now: datetime,
        allow_acknowledged: bool = False,
    ) -> _Claim:
        claim = self._claims.get(event_ref)
        if claim is None:
            raise DiscoveryError("proposal claim is missing")
        if claim.expires_at <= now:
            raise DiscoveryError("proposal claim expired")
        if claim.actor != actor or not hmac.compare_digest(claim.token, token):
            raise DiscoveryError("proposal claim is stale or transferred")
        if claim.acknowledged and not allow_acknowledged:
            raise DiscoveryError("proposal claim is already acknowledged")
        return claim

    @staticmethod
    def _claim_response(event_ref: str, claim: _Claim) -> Mapping[str, object]:
        return _deep_freeze(
            {
                "material_event_ref": event_ref,
                "claim_token": claim.token,
                "generation": claim.generation,
                "expires_at": _format_timestamp(claim.expires_at),
                "acknowledged": claim.acknowledged,
            }
        )

    def _project_candidate(
        self,
        event: Mapping[str, object],
        body: Mapping[str, object],
        *,
        issued_at: str,
        model_call_ref: str,
        critique_call_ref: str,
    ) -> Mapping[str, object]:
        event_payload = event["payload"]
        identity = canonical_json_sha256(
            {
                "candidate_id": body["candidate_id"],
                "draft_revision": body["draft_revision"],
                "event_ref": event["object_id"],
                "model_call_ref": model_call_ref,
                "critique_call_ref": critique_call_ref,
            }
        )
        payload = {
            **_json_copy(body),
            "event_ref": event["object_id"],
            "root_event_ref": event_payload["root_event_ref"],
            "vcs_identity": {
                "repository_id": self._config.repository_id,
                "head_sha": self._config.head_sha,
                "base_sha": self._config.base_sha,
                "worktree_clean": True,
                "contract_catalog_sha256": self._kernel.core_catalog_sha256,
                "a1_catalog_sha256": self._kernel.catalog_sha256,
                "release_manifest_sha256": self._config.release_manifest_sha256,
            },
            "policy_sha256": event_payload["policy_sha256"],
            "context_sha256": event_payload["context_sha256"],
            "shadow_taint": event_payload["shadow_taint"],
            "model_call_refs": [model_call_ref],
            "critique_refs": [critique_call_ref],
        }
        candidate = {
            "schema_id": "CandidateSpecDraft",
            "schema_version": "1.0.0",
            "object_id": f"candidate:{identity}",
            "issued_at": issued_at,
            "issuer": "proposal-ingestor",
            "contour": "bridge",
            "classification": event["classification"],
            "payload": payload,
            "integrity": {
                "profile_id": "core-json-sha256-v1",
                "payload_sha256": canonical_json_sha256(payload),
                "parent_refs": [
                    f"event:{event['object_id']}",
                    model_call_ref,
                    critique_call_ref,
                ],
            },
        }
        return _deep_freeze(candidate)


class FreezeProjector:
    """Project one validated-looking candidate without issuing domain objects.

    The output is only an immutable request.  It has no Core schema identity,
    issuer, scientific authority, execution authority, writer callback, or I/O
    surface.  A separately pinned domain fixture must validate and freeze it.
    """

    def __init__(self, config: FreezeProjectionConfig) -> None:
        if not isinstance(config, FreezeProjectionConfig):
            raise DiscoveryError("freeze projection config is required")
        self._config = config

    def project(self, candidate: Mapping[str, object]) -> FreezeProjection:
        document, body = self._validate_candidate(candidate)
        candidate_sha256 = canonical_json_sha256(document)
        hypothesis_payload = {
            "hypothesis_id": body["candidate_id"],
            "thesis": body["estimand"],
            "null_hypothesis": body["null_hypothesis"],
            "mechanism": body["experiment_type"],
            "falsification_rule": body["falsifier"],
            "scope_boundary": body["scope"],
            "source_refs": _json_copy(body["evidence_refs"]),
        }
        protocol_inputs = {
            "primary_outcome": body["expected_output"],
            "input_manifest_sha256": self._config.input_manifest_sha256,
            "code_sha256": self._config.code_sha256,
            "environment_digest": self._config.environment_digest,
            "seed_set": list(self._config.seed_set),
            "stopping_rule": body["stop_condition"],
            "validator_sha256": self._config.validator_sha256,
            "trial_family_id": (
                f"{self._config.trial_family_prefix}:{body['candidate_id']}"
            ),
            "holdout_policy_ref": self._config.holdout_policy_ref,
        }
        core: dict[str, object] = {
            "algorithm_version": "freeze-projection-v1",
            "candidate_ref": document["object_id"],
            "candidate_sha256": candidate_sha256,
            "source_event_ref": body["event_ref"],
            "domain_contour": self._config.domain_contour,
            "classification": "D0_PUBLIC",
            "shadow_taint": "SHADOW_UNAPPLIED",
            "policy_sha256": body["policy_sha256"],
            "context_sha256": body["context_sha256"],
            "required_writers": {
                "HypothesisCard": self._config.hypothesis_writer_id,
                "ProtocolSnapshot": self._config.protocol_writer_id,
            },
            "hypothesis_payload": hypothesis_payload,
            "protocol_inputs": protocol_inputs,
        }
        projection_identity = canonical_json_sha256(core)
        core["projection_id"] = f"freeze-projection:{projection_identity}"
        return FreezeProjection(
            payload=core,
            sha256=canonical_json_sha256(core),
        )

    @staticmethod
    def bind_admission_snapshot(
        projection: FreezeProjection,
        snapshot: A1AdmissionSnapshot,
    ) -> Mapping[str, object]:
        """Prove that admission and domain freeze bind the exact same candidate."""

        if not isinstance(projection, FreezeProjection):
            raise DiscoveryError("freeze projection is required")
        if not isinstance(snapshot, A1AdmissionSnapshot):
            raise DiscoveryError("A1 admission snapshot is required")
        projected = projection.to_mapping()
        frozen = snapshot.to_mapping()
        if (
            frozen.get("candidate_ref") != projected["candidate_ref"]
            or frozen.get("candidate_sha256") != projected["candidate_sha256"]
        ):
            raise DiscoveryError("freeze projection and admission snapshot diverge")
        return _deep_freeze(
            {
                "candidate_ref": projected["candidate_ref"],
                "candidate_sha256": projected["candidate_sha256"],
                "freeze_projection_ref": projected["projection_id"],
                "freeze_projection_sha256": projection.sha256,
                "admission_snapshot_sha256": snapshot.sha256,
                "shadow_taint": "SHADOW_UNAPPLIED",
            }
        )

    @staticmethod
    def _validate_candidate(
        candidate: Mapping[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        document = _exact_mapping(candidate, _CANDIDATE_KEYS, "candidate")
        if (
            document["schema_id"] != "CandidateSpecDraft"
            or document["schema_version"] != "1.0.0"
            or document["issuer"] != "proposal-ingestor"
            or document["contour"] != "bridge"
        ):
            raise DiscoveryError("candidate identity or writer boundary is invalid")
        if document["classification"] != "D0":
            raise DiscoveryError("S03 synthetic fixture accepts D0 candidates only")
        _text("candidate.object_id", document["object_id"], maximum=256)
        _timestamp("candidate.issued_at", document["issued_at"])
        body = _exact_mapping(
            document["payload"], _CANDIDATE_PAYLOAD_KEYS, "candidate.payload"
        )
        for field in (
            "candidate_id",
            "event_ref",
            "root_event_ref",
            "experiment_type",
            "estimand",
            "null_hypothesis",
            "falsifier",
            "stop_condition",
            "scope",
            "expected_output",
        ):
            _text(f"candidate.payload.{field}", body[field], maximum=4_096)
        _positive_integer("candidate.payload.draft_revision", body["draft_revision"])
        evidence_refs = _string_sequence(
            "candidate.payload.evidence_refs",
            body["evidence_refs"],
            allow_empty=False,
            maximum=512,
        )
        groups = body["evidence_independence_groups"]
        if not isinstance(groups, list) or not groups:
            raise DiscoveryError("candidate evidence groups must be non-empty")
        grouped = [
            reference
            for index, group in enumerate(groups)
            for reference in _string_sequence(
                f"candidate.payload.evidence_independence_groups[{index}]",
                group,
                allow_empty=False,
                maximum=512,
            )
        ]
        if len(grouped) != len(set(grouped)) or set(grouped) != set(evidence_refs):
            raise DiscoveryError("candidate evidence groups must partition refs")
        if document["object_id"] in evidence_refs or body["candidate_id"] in evidence_refs:
            raise DiscoveryError("candidate cannot use self evidence")
        _resource_budget("candidate.payload.resource_request", body["resource_request"])
        _string_sequence(
            "candidate.payload.data_classes", body["data_classes"], allow_empty=False, maximum=256
        )
        for field in (
            "network_required",
            "holdout_access_requested",
            "canonical_write_requested",
            "private_api_requested",
            "live_execution_requested",
        ):
            if type(body[field]) is not bool:
                raise DiscoveryError(f"candidate.payload.{field} must be boolean")
        vcs = _exact_mapping(body["vcs_identity"], _VCS_IDENTITY_KEYS, "candidate.vcs_identity")
        _text("candidate.vcs_identity.repository_id", vcs["repository_id"], maximum=256)
        for field in ("head_sha", "base_sha"):
            if not isinstance(vcs[field], str) or _GIT_SHA_RE.fullmatch(vcs[field]) is None:
                raise DiscoveryError(f"candidate.vcs_identity.{field} is invalid")
        if type(vcs["worktree_clean"]) is not bool:
            raise DiscoveryError("candidate.vcs_identity.worktree_clean must be boolean")
        for field in (
            "contract_catalog_sha256",
            "a1_catalog_sha256",
            "release_manifest_sha256",
        ):
            _sha256(f"candidate.vcs_identity.{field}", vcs[field])
        for field in ("policy_sha256", "context_sha256"):
            _sha256(f"candidate.payload.{field}", body[field])
        if body["shadow_taint"] not in {"NONE", "SHADOW_UNAPPLIED"}:
            raise DiscoveryError("candidate shadow taint is invalid")
        for field in ("model_call_refs", "critique_refs"):
            _string_sequence(
                f"candidate.payload.{field}", body[field], allow_empty=True, maximum=512
            )
        integrity = _exact_mapping(
            document["integrity"],
            frozenset({"profile_id", "payload_sha256", "parent_refs"}),
            "candidate.integrity",
        )
        if integrity["profile_id"] != "core-json-sha256-v1":
            raise DiscoveryError("candidate integrity profile is invalid")
        expected = canonical_json_sha256(body)
        if not hmac.compare_digest(
            expected, _sha256("candidate.integrity.payload_sha256", integrity["payload_sha256"])
        ):
            raise DiscoveryError("candidate payload integrity mismatch")
        _string_sequence(
            "candidate.integrity.parent_refs",
            integrity["parent_refs"],
            allow_empty=False,
            maximum=512,
        )
        return document, body


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise DiscoveryError(f"non-finite JSON constant is forbidden: {value}")


def _json_depth(value: object) -> int:
    if isinstance(value, Mapping):
        if not value:
            return 1
        return 1 + max(_json_depth(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        if not value:
            return 1
        return 1 + max(_json_depth(item) for item in value)
    return 0


def _ensure_json(value: object, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DiscoveryError(f"{path} contains a non-finite number")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DiscoveryError(f"{path} contains a non-text key")
            _ensure_json(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _ensure_json(item, f"{path}[{index}]")
        return
    raise DiscoveryError(f"{path} contains a non-JSON value")


def _json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_copy(item) for item in value]
    return value


def _deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _exact_mapping(
    value: object, expected_keys: frozenset[str], path: str
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise DiscoveryError(f"{path} must be an object")
    copied = _json_copy(value)
    if set(copied) != expected_keys:
        raise DiscoveryError(f"{path} shape mismatch")
    _ensure_json(copied, path)
    return copied


def _text(name: str, value: object, *, maximum: int) -> str:
    if (
        isinstance(value, bytes)
        or not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise DiscoveryError(f"{name} must be normalized bounded text")
    return value


def _string_sequence(
    name: str,
    value: object,
    *,
    allow_empty: bool,
    maximum: int,
) -> list[str]:
    if not isinstance(value, (list, tuple)) or (not allow_empty and not value):
        raise DiscoveryError(f"{name} must be a bounded string array")
    result = [
        _text(f"{name}[{index}]", item, maximum=maximum)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise DiscoveryError(f"{name} must contain unique values")
    return result


def _sha256(name: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise DiscoveryError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _nonnegative_integer(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise DiscoveryError(f"{name} must be a non-negative safe integer")
    return value


def _positive_integer(name: str, value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
        raise DiscoveryError(f"{name} must be a positive safe integer")
    return value


def _resource_budget(name: str, value: object) -> dict[str, object]:
    budget = _exact_mapping(value, _RESOURCE_KEYS, name)
    for field in ("wall_seconds", "cpu_seconds", "memory_mib", "output_bytes"):
        _positive_integer(f"{name}.{field}", budget[field])
    if budget["memory_mib"] < 64:
        raise DiscoveryError(f"{name}.memory_mib must be at least 64")
    _nonnegative_integer(f"{name}.tokens", budget["tokens"])
    cost = budget["cost_units"]
    if (
        isinstance(cost, bool)
        or not isinstance(cost, (int, float))
        or not math.isfinite(float(cost))
        or cost < 0
    ):
        raise DiscoveryError(f"{name}.cost_units must be finite and non-negative")
    return budget


def _timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DiscoveryError(f"{name} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DiscoveryError(f"{name} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise DiscoveryError(f"{name} must be UTC")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "DiscoveryError",
    "ParserLimits",
    "DiscoveryFixtureConfig",
    "StrictProposalParser",
    "DiscoveryFixtureService",
    "FreezeProjectionConfig",
    "FreezeProjection",
    "FreezeProjector",
]
