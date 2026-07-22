"""Single-writer process owner for the offline Bridge runtime.

``ResearchDaemon`` composes only the already-owned Stage 1 boundaries.  It
does not create a second ledger, a scheduler, a remote listener, or authority
for domain outcomes.  One nonblocking file lock is acquired before the sole
read-write ``JobLedger`` is opened, and the AF_UNIX socket is bound last.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import threading
from types import MappingProxyType
from typing import Any, TextIO

try:
    import fcntl
except ImportError:  # pragma: no cover - the runtime is explicitly Unix-only
    fcntl = None  # type: ignore[assignment]

from .admission import A1AdmissionKernel, canonical_json_sha256
from .authority import CorridorExecutorProfile, PinnedOfflineAuthority, TrustedIssuer
from .cas import CASError, ContentAddressedStore
from .control import ControlRouter
from .discovery import (
    DurableAdmissionConfig,
    DurableDiscoveryConfig,
    DurableDiscoveryService,
)
from .execution import (
    ExecutionError,
    OfflineExecutionCoordinator,
    ValidatedOfflineExecutionCoordinator,
)
from .ingestion import TrustedIngestor
from .ipc import (
    IPCError,
    PeerCredentials,
    UnixControlServer,
    resolve_peer_credentials,
)
from .kernel import BridgeKernel
from .l0 import DeterministicL0Runner
from .ledger import JobLedger, LedgerError
from .model_broker import (
    ModelBrokerError,
    ModelBudgetPolicy,
    ModelCallBroker,
    ModelCallSpec,
    ModelProviderRouting,
    ModelRoleRegistry,
)
from .research_ingress import (
    MAX_ARTIFACT_BYTES,
    MAX_CHAIN_REQUEST_BYTES,
    ROLE_SEQUENCE,
    ResearchIngressError,
    build_role_request,
    canonical_sha256 as research_canonical_sha256,
    mission_evidence_ref,
    role_assignment_ref,
    validate_mission_artifact,
    validate_research_ingress_action_envelope,
    validate_research_mission_envelope,
)
from .validation import DeterministicL0Validator


_ROOT_MODE = 0o700
_RUNTIME_ROOT_MODES = frozenset({_ROOT_MODE, 0o710})
_LOCK_MODE = 0o600
_DEFAULT_QUOTA_BYTES = 16 * 1024 * 1024
_DEFAULT_MAXIMUM_INPUT_BYTES = 4 * 1024 * 1024
_CONFIG_MODE = 0o600
_MAX_CONFIG_BYTES = 262_144
_MAX_CONFIG_QUOTA_BYTES = 1 << 40
_SERVICE_SCHEMA_ID = "ResearchdServiceConfig"
_LEGACY_SERVICE_SCHEMA_VERSION = "1.0.0"
_A1_SERVICE_SCHEMA_VERSION = "1.1.0"
_LEGACY_CONFIG_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "runtime_root",
        "runner_identity",
        "allowed_uids",
        "input_quota_bytes",
        "checkpoint_quota_bytes",
        "artifact_quota_bytes",
        "maximum_input_bytes",
        "deadline_seconds",
        "trusted_issuers",
        "policy_snapshots",
        "approval_receipts",
    }
)
_A1_DISABLED_CONFIG_KEYS = _LEGACY_CONFIG_KEYS | frozenset({"a1_enabled"})
_A1_ENABLED_CONFIG_KEYS = _A1_DISABLED_CONFIG_KEYS | frozenset(
    {"principal_roles", "frozen_bindings", "a1_limits"}
)
_FROZEN_BINDING_KEYS = frozenset(
    {
        "core_catalog_sha256",
        "a1_catalog_sha256",
        "release_manifest_sha256",
        "policy_sha256",
        "ipc_compatibility_profile_sha256",
        "executor_capability_refs",
        "evaluator_capability_refs",
    }
)
_ADMISSION_RUNTIME_KEY = "admission_runtime"
_ADMISSION_RUNTIME_KEYS = frozenset(
    {"model_route_proof_ref", "corridor_executor_profile"}
)
_MODEL_RUNTIME_KEY = "model_runtime"
_CONTEXT_BINDING_KEY = "context_binding"
_CONTEXT_BINDING_KEYS = frozenset(
    {
        "context_schema_version",
        "admission_authority_sha256",
        "operational_model_runtime_sha256",
        "migration_receipt",
    }
)
_CONTEXT_MIGRATION_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "from_context_sha256s",
        "to_context_sha256",
        "admission_authority_sha256",
        "operational_model_runtime_sha256",
        "ledger_rows_mutated",
        "integrity_sha256",
    }
)
_MODEL_RUNTIME_KEYS = frozenset(
    {
        "role_registry_sha256",
        "routing_profile_sha256",
        "role_evaluation_sha256",
        "worker_ipc_extension_sha256",
        "binding_revision",
        "budget_policy_ref",
        "budget_scope_ref",
        "max_active_calls",
        "max_reserved_tokens",
        "max_reserved_cost_units",
        "available_bindings",
        "role_binding_overrides",
    }
)
_MODEL_BINDING_OVERRIDE_ROLES = frozenset(
    {
        "SCOUT_FAST",
        "RESEARCH_WORKER",
        "CRITIC_PRIMARY",
        "CRITIC_DEEP",
        "CHIEF_SCIENTIST",
    }
)
_MISSION_MANIFEST_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "mission_sha256",
        "mission_envelope",
        "action_envelope",
        "material_event_refs",
        "artifact_ref",
        "queued_at",
        "decision_lineage",
        "provider_calls_maximum",
        "ingress_provider_calls",
        "domain_writes",
        "canonical_writes",
        "live_authority",
    }
)
_MISSION_STEP_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "mission_sha256",
        "role_index",
        "role",
        "model_binding",
        "reasoning_effort",
        "call_id",
        "request_ref",
        "request_sha256",
        "role_assignment_ref",
        "reserved_at",
        "fallback_used",
    }
)
_MAX_MISSION_RESULT_BYTES = 262_144
_MISSION_TOTAL_TOKEN_RESERVATION = 20_000
_MISSION_ACCOUNTING_PROFILE_SHA256 = (
    "1588317c907a6d91c5cfced2b3032e05af54991cc593faaf14e55ef5630f17e6"
)
_MISSION_ACCOUNTING_PROFILE_PATH = (
    Path(__file__).resolve().parents[2]
    / "provenance"
    / "model-accounting-mode-v1.json"
)
_MISSION_VACUOUS_PROFILE_SHA256 = (
    "3cb8ae607f1aa4b6988d69075d639b2a7ace3d00bf02a63b6c6c5e9eabe2d7ab"
)
_MISSION_VACUOUS_PROFILE_PATH = (
    Path(__file__).resolve().parents[2]
    / "provenance"
    / "model-vacuous-output-reconciliation-v1.json"
)
_MISSION_NULL_CONTENT_VACUOUS_PROFILE_SHA256 = (
    "b4534d7138b9039c879f83ac289e09e95a253874c30973e301ec20260003f385"
)
_MISSION_NULL_CONTENT_VACUOUS_PROFILE_PATH = (
    Path(__file__).resolve().parents[2]
    / "provenance"
    / "model-null-content-vacuous-reconciliation-v1.json"
)
_MISSION_CHIEF_NULL_CONTENT_VACUOUS_PROFILE_SHA256 = (
    "2aa7431a2157dfc2c523f96bc69ccf81bd8ee45d1a46a972124e4a753a71e79a"
)
_MISSION_CHIEF_NULL_CONTENT_VACUOUS_PROFILE_PATH = (
    Path(__file__).resolve().parents[2]
    / "provenance"
    / "model-chief-null-content-vacuous-reconciliation-v1.json"
)
_CORRIDOR_EXECUTOR_PROFILE_KEYS = frozenset(
    {
        "capability_ref",
        "protocol_ref",
        "code_sha256",
        "image_digest",
        "runner_identity",
        "maximum_lifetime_seconds",
    }
)
_PRINCIPAL_ROLES = frozenset(
    {"operator", "collector", "scout", "connected_worker"}
)
_A1_REQUIRED_ROLES = frozenset({"operator", "collector", "scout"})
_MODEL_REQUIRED_ROLES = _A1_REQUIRED_ROLES | {"connected_worker"}
_CORE_CATALOG_SHA256 = "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50"
_A1_CATALOG_SHA256 = "eab6401e6fc1460433a7b45b052c0218f3d26a90e6489a234bf2d51d2269dbe1"
_IPC_COMPATIBILITY_PROFILE_SHA256 = (
    "c9cdd8c51616ac843a6729166b6f21c9a44de24fac7559b86f842c7e1930ba04"
)
_MODEL_ROLE_REGISTRY_SHA256 = (
    "4faf6765f48a952e4d35540d92797330517938b34b8d2f12cde791e761a32eac"
)
_MODEL_ROUTING_PROFILE_SHA256 = (
    "37db8596a8245a6b1ea2bc5bce1495a4e7dadb314876e51397ad11dd194b3dc6"
)
_MODEL_ROUTING_PROFILE_SHA256_V2 = (
    "0539b1c2b3fd2e5b5f6e21769afe99d36a197f9399db100e5f0c5885e5da3c67"
)
_MODEL_ROUTING_PROFILE_SHA256_V3 = (
    "16b143ea3b095c6eaa34c5663c0e8f2424c7a16fc77f5f4ffd52f6298b773c43"
)
_MODEL_ROUTING_PROFILE_SHA256S = frozenset(
    {
        _MODEL_ROUTING_PROFILE_SHA256,
        _MODEL_ROUTING_PROFILE_SHA256_V2,
        _MODEL_ROUTING_PROFILE_SHA256_V3,
    }
)
_MODEL_ROLE_EVALUATION_SHA256 = (
    "111a7ac1dc954466b19d5e408debeeefcf65c76b5b025a743a2433be910c1e75"
)
_MODEL_WORKER_IPC_EXTENSION_SHA256_V1 = (
    "03d91f027bb6975c55d84acaef188546bcd24af9944a72f4ff9314296399d07a"
)
_MODEL_WORKER_IPC_EXTENSION_SHA256_V2 = (
    "467b2e5dd8583939d13e216a9f29e3578b0cc720a27081ca4f8723ad5726bac3"
)
_MODEL_WORKER_IPC_EXTENSION_SHA256S = frozenset(
    {
        _MODEL_WORKER_IPC_EXTENSION_SHA256_V1,
        _MODEL_WORKER_IPC_EXTENSION_SHA256_V2,
    }
)
_MODEL_WORKER_IPC_EXTENSION_PATHS = {
    _MODEL_WORKER_IPC_EXTENSION_SHA256_V1: "model-worker-ipc-extension-v1.json",
    _MODEL_WORKER_IPC_EXTENSION_SHA256_V2: "model-worker-ipc-extension-v2.json",
}
_MAX_CONFIG_UIDS = 16
_MAX_CONFIG_UID = 2_147_483_647
_MAX_CAPABILITY_REFS = 32
_A1_LIMIT_KEYS = frozenset({"cycle_limits", "daily_limits"})
_A1_CYCLE_LIMITS = {
    "max_admitted_experiments": 4,
    "max_model_calls": 12,
    "max_wall_seconds": 7200,
    "max_cpu_seconds": 14400,
    "max_memory_mib": 8192,
    "max_output_bytes": 1_073_741_824,
    "max_tokens": 200_000,
    "max_cost_units": 100,
}
_A1_DAILY_LIMITS = {
    "max_admitted_experiments": 16,
    "max_model_calls": 64,
    "max_wall_seconds": 28_800,
    "max_tokens": 800_000,
    "max_cost_units": 400,
}
_TRUSTED_SCHEMAS = frozenset(
    {
        "JobSpec",
        "Permit",
        "AttemptLease",
        "PolicySnapshot",
        "ApprovalReceipt",
    }
)
_TRUSTED_ISSUER_KEYS = frozenset({"issuer_id", "authority_class"})
_AUTHORITY_COMMON_KEYS = frozenset(
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
_AUTHORITY_ISSUER_KEYS = frozenset({"id", "authority_class"})
_AUTHORITY_INTEGRITY_KEYS = frozenset({"payload_sha256", "parent_refs"})
_POLICY_PAYLOAD_KEYS = frozenset(
    {
        "source_repo",
        "commit_sha",
        "aggregate_sha256",
        "covered_action_classes",
        "allow_rules",
        "deny_rules",
        "valid_from",
        "valid_until",
    }
)
_APPROVAL_PAYLOAD_KEYS = frozenset(
    {
        "action_class",
        "job_spec_sha256",
        "protocol_sha256",
        "policy_sha256",
        "quotas",
        "stop_conditions",
        "expires_at",
        "nonce",
        "revoked",
    }
)
_PUBLIC_AUTHORITY_CLASSES = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_HEX_DIGITS = frozenset("0123456789abcdef")
_CONFIG_ERROR_LINE = "researchd configuration rejected\n"
_RUNTIME_ERROR_LINE = "researchd runtime failed\n"
_L0_VALIDATOR_ID = "independent-byte-level-l0"
_L0_VALIDATOR_SOURCE_SHA256 = (
    "ea4a91d3710c6be129ebba9e27eb3bca288722af190d4feab58c0914ed259006"
)
_MAX_VALIDATOR_SOURCE_BYTES = 1_048_576
_MAX_L0_VALIDATION_ARTIFACT_BYTES = 8_388_608
_MAX_L0_VALIDATION_INPUT_BYTES = 67_108_864


class ResearchdError(RuntimeError):
    """The owned offline runtime could not start or complete one operation."""


class _ServiceConfigError(ValueError):
    """A service configuration was rejected before daemon startup."""


class _ServiceConfig:
    def __init__(
        self,
        *,
        runtime_root: str,
        authority: PinnedOfflineAuthority,
        allowed_uids: tuple[int, ...],
        principal_roles: Mapping[int, str],
        a1_enabled: bool,
        frozen_bindings: Mapping[str, object] | None,
        a1_limits: Mapping[str, object] | None,
        runner_identity: str,
        input_quota_bytes: int,
        checkpoint_quota_bytes: int,
        artifact_quota_bytes: int,
        maximum_input_bytes: int,
        deadline_seconds: float,
    ) -> None:
        self.runtime_root = runtime_root
        self.authority = authority
        self.allowed_uids = allowed_uids
        self.principal_roles = MappingProxyType(dict(principal_roles))
        self.a1_enabled = a1_enabled
        self.frozen_bindings = frozen_bindings
        self.a1_limits = a1_limits
        self.runner_identity = runner_identity
        self.input_quota_bytes = input_quota_bytes
        self.checkpoint_quota_bytes = checkpoint_quota_bytes
        self.artifact_quota_bytes = artifact_quota_bytes
        self.maximum_input_bytes = maximum_input_bytes
        self.deadline_seconds = deadline_seconds


class _CheckpointFenceLedger:
    """Remember only the current request fence after canonical checkpointing."""

    def __init__(self, ledger: JobLedger) -> None:
        self._ledger = ledger
        self._lock = threading.RLock()
        self._claimed: tuple[str, str, str] | None = None
        self._verified: tuple[str, str, str] | None = None

    def claim(self, **keywords: object) -> object:
        event = self._ledger.claim(**keywords)  # type: ignore[arg-type]
        claimed = (
            _text("attempt_id", keywords.get("attempt_id"), maximum=256),
            _text("runner_identity", keywords.get("runner_identity"), maximum=256),
            _text("fencing_token", keywords.get("fencing_token"), maximum=1024),
        )
        with self._lock:
            self._claimed = claimed
            self._verified = None
        return event

    def checkpoint(self, **keywords: object) -> object:
        event = self._ledger.checkpoint(**keywords)  # type: ignore[arg-type]
        attempt_id = _text(
            "attempt_id", keywords.get("attempt_id"), maximum=256
        )
        fencing_token = _text(
            "fencing_token", keywords.get("fencing_token"), maximum=1024
        )
        with self._lock:
            if (
                self._claimed is None
                or self._claimed[0] != attempt_id
                or self._claimed[2] != fencing_token
            ):
                raise ResearchdError("checkpoint fence does not match the current claim")
            self._verified = self._claimed
        return event

    def complete(self, **keywords: object) -> object:
        event = self._ledger.complete(**keywords)  # type: ignore[arg-type]
        self.clear()
        return event

    def completed_event(self, job_id: str) -> object:
        return self._ledger.completed_event(job_id)

    def verify_current(
        self,
        *,
        attempt_id: object,
        producer_identity: object,
        fencing_token: object,
    ) -> bool:
        candidate = (attempt_id, producer_identity, fencing_token)
        with self._lock:
            return self._verified is not None and candidate == self._verified

    def clear(self) -> None:
        with self._lock:
            self._claimed = None
            self._verified = None


def _mission_observed_accounting_evidence_ref(binding: str) -> str:
    """Validate the frozen mission-only non-numeric accounting profile."""

    normalized_binding = _text("model_binding", binding, maximum=256)
    try:
        raw = _MISSION_ACCOUNTING_PROFILE_PATH.read_bytes()
    except OSError as exc:
        raise ResearchdError("mission accounting profile is unavailable") from exc
    if (
        not raw
        or len(raw) > 65_536
        or hashlib.sha256(raw).hexdigest()
        != _MISSION_ACCOUNTING_PROFILE_SHA256
    ):
        raise ResearchdError("mission accounting profile identity drifted")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise ResearchdError("mission accounting profile has duplicate keys")
            value[key] = item
        return value

    try:
        profile = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchdError("mission accounting profile is not strict JSON") from exc
    if not isinstance(profile, dict) or set(profile) != {
        "profile_id",
        "schema_version",
        "status",
        "accounting_mode",
        "scope",
        "required_evidence",
        "fail_closed",
        "forbidden_claims",
    }:
        raise ResearchdError("mission accounting profile shape drifted")
    scope = profile["scope"]
    if not isinstance(scope, dict) or set(scope) != {
        "mission_only",
        "eligible_bindings",
        "monetary_enforcement",
        "synthetic_reservation_release",
    }:
        raise ResearchdError("mission accounting scope shape drifted")
    if (
        profile["profile_id"] != "research-mission-accounting-mode-v1"
        or profile["schema_version"] != "1.0.0"
        or profile["status"] != "frozen"
        or profile["accounting_mode"] != "OBSERVED_NO_NUMERIC_COST"
        or scope["mission_only"] is not True
        or scope["monetary_enforcement"] != "DISABLED_OBSERVATIONAL"
        or scope["synthetic_reservation_release"]
        != "EXPLICIT_RECEIPT_BOUND_RECONCILIATION_ONLY"
        or not isinstance(scope["eligible_bindings"], list)
        or normalized_binding not in scope["eligible_bindings"]
        or profile["required_evidence"]
        != [
            "terminal_state_succeeded_or_failed_known",
            "exact_actual_tokens",
            "provider_response_receipt_identity",
            "mission_role_step_binding",
            "immutable_accounting_profile_identity",
        ]
        or profile["fail_closed"]
        != [
            "unknown_or_ambiguous_transmission",
            "missing_actual_tokens",
            "missing_provider_receipt",
            "provider_receipt_identity_mismatch",
            "numeric_cost_mode_with_null_cost",
            "accounting_profile_or_binding_mismatch",
        ]
        or profile["forbidden_claims"]
        != [
            "zero_cost",
            "no_payment_due",
            "numeric_provider_cost",
            "scientific_or_live_authority",
        ]
    ):
        raise ResearchdError("mission accounting profile policy drifted")
    return "accounting-policy:sha256:" + _MISSION_ACCOUNTING_PROFILE_SHA256


def _mission_vacuous_reconciliation_profile() -> Mapping[str, object]:
    """Load the one exact sanitized provider-response adjudication profile."""

    try:
        raw = _MISSION_VACUOUS_PROFILE_PATH.read_bytes()
    except OSError as exc:
        raise ResearchdError("mission vacuous-output profile is unavailable") from exc
    if (
        not raw
        or len(raw) > 65_536
        or hashlib.sha256(raw).hexdigest() != _MISSION_VACUOUS_PROFILE_SHA256
    ):
        raise ResearchdError("mission vacuous-output profile identity drifted")
    try:
        profile = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchdError("mission vacuous-output profile is not JSON") from exc
    expected = {
        "schema_id": "ModelVacuousOutputReconciliationEvidence",
        "schema_version": "1.0.0",
        "mission_sha256": "d7bc485d07e1bc94a35cbb3367c8978fa9173e9a85984d0306233faccfde4272",
        "call_id": "model-call:ab10a4ee29f64c0f6b099f92f97df72f9755abee8d270811785fa0961559df3f",
        "request_sha256": "2646a5851f90a274af2f4511cd83b53e6aaca3df0d1958e5c338df55b0336c2a",
        "model_binding": "deepseek-v4-pro",
        "raw_response_ref": "private-cas:sha256:a4c9eaae70446c60c995f1c07994b70710551accc1166c189a1160e2d82e9f69",
        "provider_body_sha256": "5c10b8434b2fb83e958115af9a6780a7ad4ffb54daf9fe0838a23dcd51357cdc",
        "provider_receipt_ref": "provider-response:sha256:5c10b8434b2fb83e958115af9a6780a7ad4ffb54daf9fe0838a23dcd51357cdc",
        "http_status": 200,
        "protocol": "OPENAI_CHAT_COMPLETIONS",
        "actual_tokens": 5551,
        "actual_cost_units": None,
        "completion_tokens": 4096,
        "prompt_tokens": 1455,
        "content_bytes": 0,
        "finish_reason": "length",
        "network_calls": 1,
        "request_bytes_sent": True,
        "failure_code": "VACUOUS_OUTPUT",
        "monetary_enforcement": "DISABLED_OBSERVATIONAL",
        "raw_or_credential_bytes_present": False,
        "grants_retry": False,
        "grants_authority": False,
    }
    if profile != expected:
        raise ResearchdError("mission vacuous-output profile policy drifted")
    return MappingProxyType(profile)


def _matches_mission_vacuous_reconciliation(
    *,
    mission_sha256: str,
    call_id: object,
    request_sha256: object,
    model_binding: str,
    failure_code: object,
) -> bool:
    """Return true only for the one frozen UNKNOWN adjudication tuple."""

    profile = _mission_vacuous_reconciliation_profile()
    return (
        mission_sha256 == profile["mission_sha256"]
        and call_id == profile["call_id"]
        and request_sha256 == profile["request_sha256"]
        and model_binding == profile["model_binding"]
        and failure_code == "AMBIGUOUS_PROVIDER_OUTCOME"
    )


def _mission_null_content_vacuous_reconciliation_profile(
) -> Mapping[str, object]:
    """Load the one exact sanitized null-content provider adjudication."""

    try:
        raw = _MISSION_NULL_CONTENT_VACUOUS_PROFILE_PATH.read_bytes()
    except OSError as exc:
        raise ResearchdError(
            "mission null-content vacuous profile is unavailable"
        ) from exc
    if (
        not raw
        or len(raw) > 65_536
        or hashlib.sha256(raw).hexdigest()
        != _MISSION_NULL_CONTENT_VACUOUS_PROFILE_SHA256
    ):
        raise ResearchdError("mission null-content vacuous profile identity drifted")
    try:
        profile = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchdError(
            "mission null-content vacuous profile is not JSON"
        ) from exc
    expected = {
        "schema_id": "ModelNullContentVacuousReconciliationEvidence",
        "schema_version": "1.0.0",
        "mission_sha256": "7d7dcbce44eaa5b1df58d07cdd49d5d094a7d69a717382b984b2183e0b6fa7ab",
        "role_index": 3,
        "role": "CRITIC_DEEP",
        "call_id": "model-call:22aa12635f149a06c0bf577cb50b45fbc15af4029b1d98ee68b4b467b56caf68",
        "request_sha256": "1804d51d59650296ac1bbacb52072edd0db1e25d81c8c892c512119cbcb76dc6",
        "provider_request_sha256": "c7ac6f7fd2edb9b7dfaa9384b841d0f060134f7bf900972b7927463be768cb41",
        "model_binding": "gpt-5.6-sol-xhigh",
        "reasoning_effort": "xhigh",
        "raw_response_ref": "private-cas:sha256:c535ee80764ececc8ed76f8fc46306af19f2a3bb1bb7f4ec4170f5ee26ccef09",
        "raw_response_bytes": 53964,
        "provider_body_sha256": "88d0cb2c01ff014b83f14264a255f80e1fd30fb1c2faa831a4d5b9fdb572c3bb",
        "provider_body_bytes": 40386,
        "provider_response_id_sha256": "c33eb67a2e5d549ba4ecf888840c11942a5a70520185685d5f29f0e0bc89136b",
        "provider_receipt_ref": "provider-response:sha256:88d0cb2c01ff014b83f14264a255f80e1fd30fb1c2faa831a4d5b9fdb572c3bb",
        "http_status": 200,
        "protocol": "OPENAI_CHAT_COMPLETIONS",
        "api_model": "openai/gpt-5.6-sol",
        "actual_tokens": 10304,
        "actual_cost_units": None,
        "observed_provider_monetary_cost": 0.16167625,
        "completion_tokens": 4096,
        "prompt_tokens": 6208,
        "reasoning_tokens": 4096,
        "content_is_null": True,
        "content_bytes": 0,
        "reasoning_is_null": True,
        "finish_reason": "length",
        "network_calls": 1,
        "request_bytes_sent": True,
        "worker_failure_code": "MALFORMED_RESPONSE",
        "core_failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
        "failure_code": "VACUOUS_OUTPUT",
        "monetary_enforcement": "DISABLED_OBSERVATIONAL",
        "zero_cost_claim": False,
        "raw_or_credential_bytes_present": False,
        "grants_retry": False,
        "grants_authority": False,
    }
    if profile != expected:
        raise ResearchdError("mission null-content vacuous profile policy drifted")
    return MappingProxyType(profile)


def _matches_mission_null_content_vacuous_reconciliation(
    *,
    mission_sha256: str,
    role_index: int,
    role: str,
    call_id: object,
    request_sha256: object,
    model_binding: str,
    reasoning_effort: str,
    failure_code: object,
) -> bool:
    """Return true only for the authorized GPT null-content UNKNOWN tuple."""

    profile = _mission_null_content_vacuous_reconciliation_profile()
    return (
        mission_sha256 == profile["mission_sha256"]
        and role_index == profile["role_index"]
        and role == profile["role"]
        and call_id == profile["call_id"]
        and request_sha256 == profile["request_sha256"]
        and model_binding == profile["model_binding"]
        and reasoning_effort == profile["reasoning_effort"]
        and failure_code == profile["core_failure_code"]
    )


def _mission_chief_null_content_vacuous_reconciliation_profile(
) -> Mapping[str, object]:
    """Load the one exact sanitized final-role provider adjudication."""

    try:
        raw = _MISSION_CHIEF_NULL_CONTENT_VACUOUS_PROFILE_PATH.read_bytes()
    except OSError as exc:
        raise ResearchdError(
            "mission Chief null-content vacuous profile is unavailable"
        ) from exc
    if (
        not raw
        or len(raw) > 65_536
        or hashlib.sha256(raw).hexdigest()
        != _MISSION_CHIEF_NULL_CONTENT_VACUOUS_PROFILE_SHA256
    ):
        raise ResearchdError(
            "mission Chief null-content vacuous profile identity drifted"
        )
    try:
        profile = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchdError(
            "mission Chief null-content vacuous profile is not JSON"
        ) from exc
    expected = {
        "schema_id": "ModelChiefNullContentVacuousReconciliationEvidence",
        "schema_version": "1.0.0",
        "mission_sha256": "7d7dcbce44eaa5b1df58d07cdd49d5d094a7d69a717382b984b2183e0b6fa7ab",
        "role_index": 4,
        "role": "CHIEF_SCIENTIST",
        "call_id": "model-call:a0ea4cd88530adc49114dbdb76d3cb72b510a875cbf62264d53a04558871863d",
        "request_sha256": "a239c40fa7eb96b47e8a542127d0d1dca1dda346c6bbd0c5b7926e85dfcad9a9",
        "provider_request_sha256": "c8ac9c4b935d088eef24f10a26a18bcc03daeeb41b5ea7c8c2f5efe4a0e84936",
        "model_binding": "gpt-5.6-sol-xhigh",
        "reasoning_effort": "xhigh",
        "raw_response_ref": "private-cas:sha256:9a41b212b14b18e1934ab52377274f4ff0b6051191a06ca1830ffbb019086dcc",
        "raw_response_bytes": 51852,
        "provider_body_sha256": "2e7d74f4eaea22c081b5909052772d402bb714d42a1d2d8fb50df73c921718d0",
        "provider_body_bytes": 38800,
        "provider_response_id_sha256": "21489395dec444da337637c1be32b1f4ac69cd4254b0db1519e43ddd16cde6e2",
        "provider_receipt_ref": "provider-response:sha256:2e7d74f4eaea22c081b5909052772d402bb714d42a1d2d8fb50df73c921718d0",
        "http_status": 200,
        "protocol": "OPENAI_CHAT_COMPLETIONS",
        "api_model": "openai/gpt-5.6-sol",
        "actual_tokens": 10382,
        "actual_cost_units": None,
        "observed_provider_monetary_cost": 0.16216375,
        "completion_tokens": 4096,
        "prompt_tokens": 6286,
        "reasoning_tokens": 4096,
        "content_is_null": True,
        "content_bytes": 0,
        "reasoning_is_null": True,
        "finish_reason": "length",
        "network_calls": 1,
        "request_bytes_sent": True,
        "worker_failure_code": "MALFORMED_RESPONSE",
        "core_failure_code": "AMBIGUOUS_PROVIDER_OUTCOME",
        "failure_code": "VACUOUS_OUTPUT",
        "monetary_enforcement": "DISABLED_OBSERVATIONAL",
        "zero_cost_claim": False,
        "raw_or_credential_bytes_present": False,
        "grants_retry": False,
        "grants_authority": False,
    }
    if profile != expected:
        raise ResearchdError(
            "mission Chief null-content vacuous profile policy drifted"
        )
    return MappingProxyType(profile)


def _matches_mission_chief_null_content_vacuous_reconciliation(
    *,
    mission_sha256: str,
    role_index: int,
    role: str,
    call_id: object,
    request_sha256: object,
    model_binding: str,
    reasoning_effort: str,
    failure_code: object,
) -> bool:
    """Return true only for the authorized final-role UNKNOWN tuple."""

    profile = _mission_chief_null_content_vacuous_reconciliation_profile()
    return (
        mission_sha256 == profile["mission_sha256"]
        and role_index == profile["role_index"]
        and role == profile["role"]
        and call_id == profile["call_id"]
        and request_sha256 == profile["request_sha256"]
        and model_binding == profile["model_binding"]
        and reasoning_effort == profile["reasoning_effort"]
        and failure_code == profile["core_failure_code"]
    )


class ResearchDaemon:
    """Own one private runtime root, one ledger writer, and one local socket."""

    def __init__(
        self,
        runtime_root: str | Path,
        *,
        authority: PinnedOfflineAuthority,
        allowed_uids: Iterable[int],
        principal_roles: Mapping[int, str] | None = None,
        a1_enabled: bool = False,
        frozen_bindings: Mapping[str, object] | None = None,
        a1_limits: Mapping[str, object] | None = None,
        runner_identity: str,
        input_quota_bytes: int = _DEFAULT_QUOTA_BYTES,
        checkpoint_quota_bytes: int = _DEFAULT_QUOTA_BYTES,
        artifact_quota_bytes: int = _DEFAULT_QUOTA_BYTES,
        maximum_input_bytes: int = _DEFAULT_MAXIMUM_INPUT_BYTES,
        deadline_seconds: float = 5.0,
        contract_root: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
        credential_resolver: Callable[[Any], PeerCredentials] = resolve_peer_credentials,
    ) -> None:
        if isinstance(runtime_root, bytes) or not isinstance(runtime_root, (str, Path)):
            raise ResearchdError("runtime_root must be a text filesystem path")
        root = Path(runtime_root)
        if not str(root) or "\x00" in str(root) or ".." in root.parts:
            raise ResearchdError("runtime_root is invalid")
        try:
            allowed = frozenset(allowed_uids)
        except TypeError as exc:
            raise ResearchdError("allowed_uids must be an iterable") from exc
        if not allowed or any(type(uid) is not int or uid < 0 for uid in allowed):
            raise ResearchdError("allowed_uids must contain non-negative integers")
        if type(a1_enabled) is not bool:
            raise ResearchdError("a1_enabled must be boolean")
        if a1_enabled and not isinstance(frozen_bindings, Mapping):
            raise ResearchdError("A1 runtime requires frozen bindings")
        if a1_enabled and not isinstance(a1_limits, Mapping):
            raise ResearchdError("A1 runtime requires bounded limits")
        if not a1_enabled and frozen_bindings is not None:
            raise ResearchdError("disabled A1 runtime cannot carry frozen bindings")
        if not a1_enabled and a1_limits is not None:
            raise ResearchdError("disabled A1 runtime cannot carry A1 limits")
        model_runtime_enabled = bool(
            a1_enabled
            and isinstance(frozen_bindings, Mapping)
            and _MODEL_RUNTIME_KEY in frozen_bindings
        )
        roles = _runtime_principal_roles(
            allowed,
            principal_roles=principal_roles,
            a1_enabled=a1_enabled,
            model_runtime_enabled=model_runtime_enabled,
        )
        if model_runtime_enabled:
            _validate_model_runtime_limits(frozen_bindings, a1_limits)
        for name, value in (
            ("input_quota_bytes", input_quota_bytes),
            ("checkpoint_quota_bytes", checkpoint_quota_bytes),
            ("artifact_quota_bytes", artifact_quota_bytes),
            ("maximum_input_bytes", maximum_input_bytes),
        ):
            if type(value) is not int or value <= 0:
                raise ResearchdError(f"{name} must be a positive integer")
        if clock is not None and not callable(clock):
            raise ResearchdError("clock must be callable")
        if not callable(credential_resolver):
            raise ResearchdError("credential_resolver must be callable")

        self._root = root
        self._authority = authority
        self._allowed_uids = allowed
        self._principal_roles = roles
        self._a1_enabled = a1_enabled
        self._frozen_bindings = frozen_bindings
        self._a1_limits = a1_limits
        self._runner_identity = _text(
            "runner_identity", runner_identity, maximum=256
        )
        self._input_quota_bytes = input_quota_bytes
        self._checkpoint_quota_bytes = checkpoint_quota_bytes
        self._artifact_quota_bytes = artifact_quota_bytes
        self._maximum_input_bytes = maximum_input_bytes
        self._deadline_seconds = deadline_seconds
        if (
            contract_root is not None
            and (
                isinstance(contract_root, bytes)
                or not isinstance(contract_root, (str, Path))
            )
        ):
            raise ResearchdError("contract_root is invalid")
        default_contract_root = Path(__file__).resolve().parents[2] / "contracts"
        selected_contract_root = (
            default_contract_root if contract_root is None else Path(contract_root)
        )
        if (
            not str(selected_contract_root)
            or "\x00" in str(selected_contract_root)
            or ".." in selected_contract_root.parts
        ):
            raise ResearchdError("contract_root is invalid")
        self._contract_root = selected_contract_root
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._credential_resolver = credential_resolver

        self._state_lock = threading.RLock()
        self._dispatch_lock = threading.RLock()
        self._root_fd: int | None = None
        self._root_identity: tuple[int, int] | None = None
        self._lock_fd: int | None = None
        self._ledger: JobLedger | None = None
        self._fence_ledger: _CheckpointFenceLedger | None = None
        self._input_store: ContentAddressedStore | None = None
        self._checkpoint_store: ContentAddressedStore | None = None
        self._artifact_store: ContentAddressedStore | None = None
        self._coordinator: OfflineExecutionCoordinator | None = None
        self._validated_coordinator: ValidatedOfflineExecutionCoordinator | None = None
        self._validation_protocol_ref: str | None = None
        self._a1_backend: DurableDiscoveryService | None = None
        self._model_broker: ModelCallBroker | None = None
        self._model_routing: ModelProviderRouting | None = None
        self._model_available_bindings: frozenset[str] = frozenset()
        self._model_role_binding_overrides: Mapping[str, str] = {}
        self._server: UnixControlServer | None = None
        self._started = False

    @property
    def socket_path(self) -> Path:
        return self._root / "researchd.sock"

    def start(self) -> None:
        """Acquire ownership, compose the runtime, and bind AF_UNIX last."""

        with self._state_lock:
            if self._started or self._root_fd is not None:
                raise ResearchdError("researchd is already started")
            try:
                self._root_fd, self._root_identity = _open_runtime_root(self._root)
                self._lock_fd = _acquire_runtime_lock(self._root)

                ledger = JobLedger(self._root / "bridge-job-ledger.sqlite3")
                self._ledger = ledger
                if ledger.verify_chain() is not True:
                    raise ResearchdError("ledger chain verification failed")

                self._input_store = ContentAddressedStore(
                    self._root / "input-cas",
                    quota_bytes=self._input_quota_bytes,
                )
                self._checkpoint_store = ContentAddressedStore(
                    self._root / "checkpoint-cas",
                    quota_bytes=self._checkpoint_quota_bytes,
                )
                self._artifact_store = ContentAddressedStore(
                    self._root / "artifact-cas",
                    quota_bytes=self._artifact_quota_bytes,
                )
                _private_directory(self._root / "staging-by-attempt-digest")
                _private_directory(self._root / "research-mission-manifests")
                _private_directory(self._root / "research-mission-steps")
                _private_directory(self._root / "research-mission-terminal")
                _private_directory(self._root / "mission-publication-tmp")

                fence_ledger = _CheckpointFenceLedger(ledger)
                self._fence_ledger = fence_ledger
                runner = DeterministicL0Runner(
                    self._read_input,
                    clock=self._clock,
                    runner_identity=self._runner_identity,
                )
                ingestor = TrustedIngestor(
                    self._artifact_store,
                    fence_verifier=fence_ledger.verify_current,
                    clock=self._clock,
                    issuer_id="researchd-trusted-ingestor",
                )
                coordinator = OfflineExecutionCoordinator(
                    BridgeKernel(fence_ledger, authority=self._authority),
                    fence_ledger,
                    runner,
                    self._checkpoint_store,
                    ingestor,
                    issuer_id="researchd",
                )
                self._coordinator = coordinator
                corridor_profile = _corridor_executor_profile(
                    a1_enabled=self._a1_enabled,
                    frozen_bindings=self._frozen_bindings,
                )
                if corridor_profile is not None:
                    _verify_l0_validator_source()
                    validator = DeterministicL0Validator(
                        validator_id=_L0_VALIDATOR_ID,
                        validator_sha256=_L0_VALIDATOR_SOURCE_SHA256,
                        protocol_ref=corridor_profile.protocol_ref,
                        artifact_store=self._artifact_store,
                        input_store=self._input_store,
                        maximum_artifact_bytes=min(
                            self._artifact_quota_bytes,
                            _MAX_L0_VALIDATION_ARTIFACT_BYTES,
                        ),
                        maximum_input_bytes=min(
                            self._maximum_input_bytes,
                            _MAX_L0_VALIDATION_INPUT_BYTES,
                        ),
                    )
                    self._validated_coordinator = ValidatedOfflineExecutionCoordinator(
                        coordinator,
                        validator,
                        expected_validator_id=_L0_VALIDATOR_ID,
                        expected_validator_sha256=_L0_VALIDATOR_SOURCE_SHA256,
                        expected_protocol_ref=corridor_profile.protocol_ref,
                    )
                    self._validation_protocol_ref = corridor_profile.protocol_ref
                a1_backend: DurableDiscoveryService | None = None
                if self._a1_enabled:
                    discovery_config = _discovery_config_from_authority(
                        self._authority,
                        frozen_bindings=self._frozen_bindings,
                        a1_limits=self._a1_limits,
                        principal_roles=self._principal_roles,
                        now=self._clock(),
                    )
                    kernel = A1AdmissionKernel(
                        self._contract_root,
                        expected_a1_catalog_sha256=_A1_CATALOG_SHA256,
                        expected_core_catalog_sha256=_CORE_CATALOG_SHA256,
                    )
                    a1_backend = DurableDiscoveryService(
                        kernel,
                        ledger,
                        discovery_config,
                        authority=self._authority,
                    )
                    self._a1_backend = a1_backend
                self._recover_validated_feedback_tail()
                self._start_model_runtime(ledger)
                router = ControlRouter(
                    self,
                    a1_backend=a1_backend,
                    model_backend=(self if self._model_broker is not None else None),
                    authority=self._authority,
                    clock=self._clock,
                )
                server = UnixControlServer(
                    self.socket_path,
                    router,
                    allowed_uids=self._allowed_uids,
                    principal_roles=self._principal_roles,
                    deadline_seconds=self._deadline_seconds,
                    credential_resolver=self._credential_resolver,
                )
                self._server = server
                _verify_runtime_root(
                    self._root,
                    self._root_fd,
                    self._root_identity,
                )
                server.start()
                self._started = True
            except Exception as exc:
                self._close_components()
                if isinstance(exc, ResearchdError):
                    raise
                raise ResearchdError("researchd startup failed closed") from exc

    def serve_once(self) -> object:
        """Serially accept and complete one authenticated local request."""

        server = self._require_server()
        with self._dispatch_lock:
            return server.serve_once()

    def serve_forever(self) -> None:
        """Run the serial dispatcher until ``close`` stops the server."""

        self._require_server().serve_forever()

    def close(self) -> None:
        """Close the owned socket and ledger before releasing runtime ownership."""

        with self._state_lock:
            self._close_components()

    def pause_snapshot(self) -> Mapping[str, object]:
        with self._dispatch_lock:
            return self._require_ledger().pause_snapshot()

    def pause_global(self, **keywords: object) -> object:
        with self._dispatch_lock:
            self._require_fence_ledger().clear()
            return self._require_ledger().pause_global(**keywords)  # type: ignore[arg-type]

    def resume_global(self, **keywords: object) -> object:
        with self._dispatch_lock:
            self._require_fence_ledger().clear()
            return self._require_ledger().resume_global(**keywords)  # type: ignore[arg-type]

    def submit(
        self,
        *,
        job_spec: Mapping[str, object],
        permit: Mapping[str, object],
        lease: Mapping[str, object],
        idempotency_key: str,
        now: object,
    ) -> Mapping[str, object]:
        """Execute one fresh bounded attempt; ambiguous retries must use lookup."""

        with self._dispatch_lock:
            coordinator = self._require_coordinator()
            job_payload = _mapping_member(job_spec, "payload", "job_spec")
            job_idempotency = _text(
                "job_spec.payload.idempotency_key",
                job_payload.get("idempotency_key"),
                maximum=256,
            )
            request_idempotency = _text(
                "idempotency_key", idempotency_key, maximum=256
            )
            if request_idempotency != job_idempotency:
                raise ResearchdError("submit idempotency binding is invalid")
            job_spec_ref = _text(
                "job_spec.object_id", job_spec.get("object_id"), maximum=256
            )
            if self._a1_enabled:
                a1_backend = self._a1_backend
                if a1_backend is None:
                    raise ResearchdError("A1 submit requires the durable admission backend")
                try:
                    issued_bundle = a1_backend.resolve_issued_authority_bundle(
                        job_spec_ref=job_spec_ref
                    )
                except Exception as exc:
                    raise ResearchdError(
                        "A1 submit requires one exact durable issued authority bundle"
                    ) from exc
                submitted_bundle = {
                    "job_spec": job_spec,
                    "permit": permit,
                    "lease": lease,
                }
                if _canonical_json_bytes(issued_bundle) != _canonical_json_bytes(
                    submitted_bundle
                ):
                    raise ResearchdError(
                        "A1 submit differs from the durable issued authority bundle"
                    )
            lease_payload = _mapping_member(lease, "payload", "lease")
            attempt_id = _text(
                "lease.payload.attempt_id",
                lease_payload.get("attempt_id"),
                maximum=256,
            )
            validation_protocol_ref = self._validation_protocol_ref
            if validation_protocol_ref is not None:
                submitted_protocol_ref = _text(
                    "job_spec.payload.protocol_ref",
                    job_payload.get("protocol_ref"),
                    maximum=512,
                )
                if submitted_protocol_ref != validation_protocol_ref:
                    raise ResearchdError(
                        "submit protocol differs from frozen validation protocol"
                    )
            staging_root = self._fresh_staging_directory(attempt_id)
            try:
                validated_coordinator = self._validated_coordinator
                if validated_coordinator is None:
                    record = coordinator.execute(
                        job_spec,
                        permit,
                        lease,
                        staging_root,
                        now=now,
                    )
                    immediate = coordinator.lookup_execution_receipt(job_spec_ref)
                    if _canonical_json_bytes(
                        record.execution_receipt
                    ) != _canonical_json_bytes(immediate):
                        raise ResearchdError(
                            "submit receipt differs from canonical terminal lookup"
                        )
                    return {"execution_receipt": _json_copy(immediate)}

                record = validated_coordinator.execute_and_validate(
                    job_spec,
                    permit,
                    lease,
                    staging_root,
                    now=now,
                )
                immediate = validated_coordinator.validate_completed(job_spec_ref)
                if (
                    _canonical_json_bytes(record.execution_receipt)
                    != _canonical_json_bytes(immediate.execution_receipt)
                    or _canonical_json_bytes(record.validation_receipt)
                    != _canonical_json_bytes(immediate.validation_receipt)
                ):
                    raise ResearchdError(
                        "submit receipts differ from canonical terminal validation"
                    )
                feedback = None
                if self._a1_backend is not None:
                    feedback = self._a1_backend.close_validated_execution(
                        job_spec_ref=job_spec_ref,
                        execution_receipt=immediate.execution_receipt,
                        validation_receipt=immediate.validation_receipt,
                        now=self._clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    )
                return {
                    "execution_receipt": _json_copy(immediate.execution_receipt),
                    "validation_receipt": _json_copy(immediate.validation_receipt),
                    "feedback": _json_copy(feedback),
                }
            except ResearchdError:
                raise
            except Exception as exc:
                raise ResearchdError("offline submission failed closed") from exc
            finally:
                self._require_fence_ledger().clear()

    def lookup(self, *, job_spec_ref: str) -> Mapping[str, object]:
        """Return the canonical completed receipt through the zero-write lookup."""

        with self._dispatch_lock:
            reference = _text("job_spec_ref", job_spec_ref, maximum=256)
            try:
                validated_coordinator = self._validated_coordinator
                if validated_coordinator is None:
                    receipt = self._require_coordinator().lookup_execution_receipt(
                        reference
                    )
                    return {"execution_receipt": _json_copy(receipt)}
                record = validated_coordinator.validate_completed(reference)
            except Exception as exc:
                raise ResearchdError("terminal receipt lookup failed closed") from exc
            return {
                "execution_receipt": _json_copy(record.execution_receipt),
                "validation_receipt": _json_copy(record.validation_receipt),
                "feedback": (
                    None
                    if self._a1_backend is None
                    else _json_copy(
                        self._a1_backend.lookup_validated_feedback(
                            execution_ref=(
                                "execution:" + str(record.execution_receipt["object_id"])
                            )
                        )
                    )
                ),
            }

    def _recover_validated_feedback_tail(self) -> None:
        """Close only completed validated A1 jobs before the IPC socket is bound."""

        backend = self._a1_backend
        coordinator = self._validated_coordinator
        ledger = self._ledger
        if backend is None or coordinator is None or ledger is None:
            return
        for job_spec_ref in backend.issued_job_refs():
            try:
                ledger.completed_event(job_spec_ref)
            except LedgerError:
                continue
            try:
                record = coordinator.validate_completed(job_spec_ref)
                backend.close_validated_execution(
                    job_spec_ref=job_spec_ref,
                    execution_receipt=record.execution_receipt,
                    validation_receipt=record.validation_receipt,
                    now=self._clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                )
            except ExecutionError:
                # A completed execution can be independently invalid (for
                # example, vacuous evidence).  It remains durable and
                # feedback-free; startup must neither reexecute it nor turn
                # mechanical invalidity into an epistemic outcome.  Ledger,
                # source-pin, ownership and composition failures occur outside
                # this narrow validation boundary and remain fatal.
                continue

    def queue_research_mission(
        self,
        *,
        mission_envelope: Mapping[str, object],
        action_envelope: Mapping[str, object],
        material_event_refs: object,
        artifact_body: str,
        expected_host_fingerprint: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        """Queue one preauthorized mission after both P04 MaterialEvents exist.

        Queueing performs no model reservation and no provider call.  The
        existing Scout/dispatcher tick is the only path that may advance the
        stored mission into the model broker.
        """

        if not isinstance(actor, str) or not actor.startswith("collector:uid:"):
            raise ResearchdError("research mission queue requires the collector principal")
        _text("idempotency_key", idempotency_key, maximum=256)
        current = _research_timestamp(now)
        try:
            mission = validate_research_mission_envelope(
                mission_envelope,
                now=current,
            )
            action = validate_research_ingress_action_envelope(
                action_envelope,
                mission_envelope,
                expected_host_fingerprint=expected_host_fingerprint,
                expected_uid=int(actor.rsplit(":", 1)[1]),
                now=current,
            )
            if not isinstance(material_event_refs, (list, tuple)):
                raise ResearchIngressError("material_event_refs must be a pair")
            refs = tuple(
                _text("material_event_ref", item, maximum=256)
                for item in material_event_refs
            )
            if len(refs) != 2 or len(set(refs)) != 2:
                raise ResearchIngressError("material_event_refs must be a unique pair")
            raw = artifact_body.encode("utf-8", errors="strict")
            validate_mission_artifact(raw, mission)
            self._validate_mission_material_events(mission, refs)
            artifact_ref = self._store_input_bytes(
                raw,
                expected_sha256=str(mission["artifact_sha256"]),
                maximum=MAX_ARTIFACT_BYTES,
            )
            if artifact_ref != mission["artifact_ref"]:
                raise ResearchIngressError("runtime CAS ref differs from mission artifact ref")
            mission_sha = str(mission["mission_sha256"])
            decision_lineage = {
                "agenda": {
                    "status": "PROPOSED",
                    "decision_ref": "agenda:" + mission_sha,
                    "evidence_refs": list(refs),
                },
                "portfolio": {
                    "status": "SELECTED",
                    "decision_ref": "portfolio:" + mission_sha,
                    "maximum_calls": len(ROLE_SEQUENCE),
                },
                "scout": {
                    "status": "PENDING_AUTONOMOUS_TICK",
                    "decision_ref": "scout-decision:" + mission_sha,
                },
            }
            manifest = {
                "schema_id": "ResearchMissionRuntimeManifest",
                "schema_version": "1.0.0",
                "mission_sha256": mission_sha,
                "mission_envelope": _json_copy(mission_envelope),
                "action_envelope": _json_copy(action_envelope),
                "material_event_refs": list(refs),
                "artifact_ref": artifact_ref,
                "queued_at": now,
                "decision_lineage": decision_lineage,
                "provider_calls_maximum": action["provider_calls_maximum"],
                "ingress_provider_calls": action["ingress_provider_calls"],
                "domain_writes": action["domain_writes"],
                "canonical_writes": action["canonical_writes"],
                "live_authority": action["live_authority"],
            }
            _private_directory(
                self._root / "research-mission-steps" / mission_sha
            )
            path = self._mission_manifest_path(mission_sha)
            if path.exists():
                existing = _read_private_json(
                    path, _MISSION_MANIFEST_KEYS, "mission manifest"
                )
                manifest["queued_at"] = existing["queued_at"]
            created = _write_immutable_private_json(path, manifest)
            stored = _read_private_json(path, _MISSION_MANIFEST_KEYS, "mission manifest")
            stable_fields = set(_MISSION_MANIFEST_KEYS) - {"queued_at"}
            if any(stored[name] != manifest[name] for name in stable_fields):
                raise ResearchdError("research mission replay differs from immutable manifest")
            return MappingProxyType(
                {
                    "status": "QUEUED" if created else "ALREADY_QUEUED",
                    "mission_sha256": mission_sha,
                    "mission_manifest_sha256": research_canonical_sha256(stored),
                    "artifact_ref": artifact_ref,
                    "material_event_refs": refs,
                    "decision_lineage": MappingProxyType(decision_lineage),
                    "source_trigger_count": 2,
                    "expected_trigger_domains": ("market", "security"),
                    "provider_calls_consumed": 0,
                    "domain_writes": 0,
                    "canonical_writes": 0,
                    "live_authority": False,
                }
            )
        except (ResearchIngressError, UnicodeError, ValueError) as exc:
            raise ResearchdError("research mission queue failed closed") from exc

    def advance_research_missions(
        self,
        *,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        """Advance at most one role through the existing WIP=1 model broker."""

        if not isinstance(actor, str) or not actor.startswith("scout:uid:"):
            raise ResearchdError("research mission advance requires the Scout principal")
        _text("idempotency_key", idempotency_key, maximum=256)
        current = _research_timestamp(now)
        retired_expired_mission = (
            self._reconcile_expired_exact_vacuous_reservation(
                current=current,
                now=now,
            )
        )
        for path in self._mission_manifest_paths():
            if path.stem == retired_expired_mission:
                continue
            manifest = _read_private_json(
                path, _MISSION_MANIFEST_KEYS, "mission manifest"
            )
            mission_document = _mapping_member(
                manifest, "mission_envelope", "mission manifest"
            )
            mission = validate_research_mission_envelope(
                mission_document,
                now=current,
            )
            mission_sha = str(mission["mission_sha256"])
            if self._mission_terminal_path(mission_sha).exists():
                continue
            refs_raw = manifest["material_event_refs"]
            if not isinstance(refs_raw, list):
                raise ResearchdError("mission material event refs are invalid")
            self._validate_mission_material_events(mission, tuple(refs_raw))
            artifact = self._read_input(str(manifest["artifact_ref"]))
            validate_mission_artifact(artifact, mission)
            prior_results: list[tuple[str, str, bytes | None]] = []
            for index, (role, expected_binding, effort) in enumerate(ROLE_SEQUENCE):
                step_path = self._mission_step_path(mission_sha, index)
                if step_path.exists():
                    step = _read_private_json(
                        step_path, _MISSION_STEP_KEYS, "mission role step"
                    )
                    if (
                        step["mission_sha256"] != mission_sha
                        or step["role_index"] != index
                        or step["role"] != role
                        or step["model_binding"] != expected_binding
                        or step["reasoning_effort"] != effort
                        or step["fallback_used"] is not False
                    ):
                        raise ResearchdError("mission role step binding drifted")
                    snapshot = self._require_model_runtime()[0].snapshot(
                        str(step["call_id"])
                    )
                    state = snapshot["state"]
                    if state in {"RESERVED", "SENT", "PROPOSED"}:
                        return MappingProxyType(
                            {
                                "status": "WAIT_CURRENT_CALL",
                                "mission_sha256": mission_sha,
                                "role": role,
                                "call_id": step["call_id"],
                                "state": state,
                                "provider_calls_reserved": index + 1,
                            }
                        )
                    if state == "UNKNOWN":
                        profile = _mission_vacuous_reconciliation_profile()
                        exact_vacuous = _matches_mission_vacuous_reconciliation(
                            mission_sha256=mission_sha,
                            call_id=step["call_id"],
                            request_sha256=snapshot["request_sha256"],
                            model_binding=expected_binding,
                            failure_code=snapshot["failure_code"],
                        )
                        if not exact_vacuous:
                            exact_null_content = (
                                self._reconcile_exact_null_content_vacuous_reservation(
                                    mission_sha256=mission_sha,
                                    role_index=index,
                                    role=role,
                                    model_binding=expected_binding,
                                    reasoning_effort=effort,
                                    step=step,
                                    snapshot=snapshot,
                                    now=now,
                                )
                            )
                            if exact_null_content is not None:
                                snapshot = exact_null_content
                                state = snapshot["state"]
                                exact_vacuous = True
                        if not exact_vacuous:
                            exact_chief_null_content = (
                                self._reconcile_exact_chief_null_content_vacuous_reservation(
                                    mission_sha256=mission_sha,
                                    role_index=index,
                                    role=role,
                                    model_binding=expected_binding,
                                    reasoning_effort=effort,
                                    step=step,
                                    snapshot=snapshot,
                                    now=now,
                                )
                            )
                            if exact_chief_null_content is not None:
                                snapshot = exact_chief_null_content
                                state = snapshot["state"]
                                exact_vacuous = True
                        if not exact_vacuous:
                            return MappingProxyType(
                                {
                                    "status": "WAIT_PROVIDER",
                                    "mission_sha256": mission_sha,
                                    "role": role,
                                    "call_id": step["call_id"],
                                    "state": state,
                                    "reason": "AMBIGUOUS_PROVIDER_OUTCOME",
                                }
                            )
                        if state == "UNKNOWN":
                            broker, _ = self._require_model_runtime()
                            broker.reconcile_vacuous_unknown(
                                str(step["call_id"]),
                                actual_tokens=int(profile["actual_tokens"]),
                                provider_receipt_ref=str(
                                    profile["provider_receipt_ref"]
                                ),
                                accounting_evidence_ref=(
                                    "accounting-policy:sha256:"
                                    + _MISSION_VACUOUS_PROFILE_SHA256
                                ),
                                event_at=now,
                                idempotency_key=(
                                    f"mission:{mission_sha}:{index}:"
                                    "vacuous-output-reconcile"
                                ),
                            )
                            snapshot = broker.snapshot(str(step["call_id"]))
                            state = snapshot["state"]
                    if state in {"SUCCEEDED", "FAILED_KNOWN"}:
                        if (
                            snapshot["actual_tokens"] is None
                            or snapshot["provider_receipt_ref"] is None
                        ):
                            return MappingProxyType(
                                {
                                    "status": "WAIT_PROVIDER",
                                    "mission_sha256": mission_sha,
                                    "role": role,
                                    "call_id": step["call_id"],
                                    "state": state,
                                    "reason": "PROVIDER_ACCOUNTING_IDENTITY_NOT_PROVEN",
                                }
                            )
                        broker, _ = self._require_model_runtime()
                        if snapshot["actual_cost_units"] is None:
                            accounting_evidence_ref = (
                                _mission_observed_accounting_evidence_ref(
                                    expected_binding
                                )
                            )
                            broker.reconcile_observed_no_numeric_cost(
                                str(step["call_id"]),
                                actual_tokens=int(snapshot["actual_tokens"]),
                                provider_receipt_ref=str(
                                    snapshot["provider_receipt_ref"]
                                ),
                                accounting_evidence_ref=accounting_evidence_ref,
                                event_at=now,
                                idempotency_key=(
                                    f"mission:{mission_sha}:{index}:"
                                    "observed-no-numeric-cost-reconcile"
                                ),
                            )
                        else:
                            broker.reconcile(
                                str(step["call_id"]),
                                actual_tokens=int(snapshot["actual_tokens"]),
                                actual_cost_units=int(
                                    snapshot["actual_cost_units"]
                                ),
                                provider_receipt_ref=str(
                                    snapshot["provider_receipt_ref"]
                                ),
                                event_at=now,
                                idempotency_key=(
                                    f"mission:{mission_sha}:{index}:auto-reconcile"
                                ),
                            )
                        snapshot = broker.snapshot(str(step["call_id"]))
                        state = snapshot["state"]
                    if state != "RECONCILED" or snapshot["budget_released"] is not True:
                        raise ResearchdError("mission call lacks a reconciled terminal state")
                    response_ref = snapshot["response_ref"]
                    response_bytes: bytes | None = None
                    if response_ref is not None:
                        response_bytes = self._read_input(str(response_ref))
                    prior_evidence = str(response_ref or state)
                    if response_ref is None and snapshot["failure_code"] is not None:
                        prior_evidence = (
                            "failed-role:"
                            + str(snapshot["previous_state"])
                            + ":"
                            + str(snapshot["failure_code"])
                            + ":"
                            + str(snapshot["provider_receipt_ref"])
                        )
                    prior_results.append((role, prior_evidence, response_bytes))
                    continue

                request_body = build_role_request(
                    artifact,
                    mission_sha256=mission_sha,
                    prepared_kimi_request_sha256=str(
                        mission["prepared_kimi_request_sha256"]
                    ),
                    index=index,
                    prior_results=prior_results,
                )
                result = self.reserve_model_call(
                    role=role,
                    role_assignment_ref=role_assignment_ref(mission_sha, index, role),
                    classification=(
                        "D0" if mission["data_class"] == "D0_PUBLIC" else "D1"
                    ),
                    request_body=request_body,
                    max_tokens=_MISSION_TOTAL_TOKEN_RESERVATION,
                    max_cost_units=1,
                    expires_at=str(mission["expires_at"]),
                    actor=actor,
                    idempotency_key=f"mission:{mission_sha}:{index}:{role}",
                    now=now,
                )
                if result["status"] != "RESERVED":
                    return MappingProxyType(
                        {
                            "status": result["status"],
                            "mission_sha256": mission_sha,
                            "role": role,
                            "model_binding": None,
                            "used_fallback": False,
                            "reason": "EXACT_ROLE_UNAVAILABLE",
                        }
                    )
                if result["model_binding"] != expected_binding or result["used_fallback"] is not False:
                    raise ResearchdError("mission route attempted fallback or substitution")
                step = {
                    "schema_id": "ResearchMissionRoleReservationReceipt",
                    "schema_version": "1.0.0",
                    "mission_sha256": mission_sha,
                    "role_index": index,
                    "role": role,
                    "model_binding": expected_binding,
                    "reasoning_effort": effort,
                    "call_id": result["call_id"],
                    "request_ref": result["request_ref"],
                    "request_sha256": result["request_sha256"],
                    "role_assignment_ref": role_assignment_ref(mission_sha, index, role),
                    "reserved_at": now,
                    "fallback_used": False,
                }
                _write_immutable_private_json(step_path, step)
                return MappingProxyType(
                    {
                        "status": "RESERVED",
                        "mission_sha256": mission_sha,
                        "role": role,
                        "role_index": index,
                        "model_binding": expected_binding,
                        "reasoning_effort": effort,
                        "call_id": result["call_id"],
                        "request_ref": result["request_ref"],
                        "used_fallback": False,
                        "provider_calls_reserved": index + 1,
                    }
                )

            terminal = {
                "schema_id": "ResearchMissionModelChainReceipt",
                "schema_version": "1.0.0",
                "mission_sha256": mission_sha,
                "status": "MODEL_CHAIN_COMPLETE",
                "completed_at": now,
                "role_count": len(ROLE_SEQUENCE),
                "call_ids": [
                    _read_private_json(
                        self._mission_step_path(mission_sha, index),
                        _MISSION_STEP_KEYS,
                        "mission role step",
                    )["call_id"]
                    for index in range(len(ROLE_SEQUENCE))
                ],
                "provider_calls_maximum": len(ROLE_SEQUENCE),
                "fallback_used": False,
                "domain_writes": 0,
                "canonical_writes": 0,
                "live_authority": False,
            }
            _write_immutable_private_json(
                self._mission_terminal_path(mission_sha), terminal
            )
            return MappingProxyType(_json_copy(terminal))
        return MappingProxyType(
            {
                "status": "NO_MISSION_WORK",
                "provider_calls_reserved": 0,
                "domain_writes": 0,
                "canonical_writes": 0,
                "live_authority": False,
            }
        )

    def _reconcile_exact_null_content_vacuous_reservation(
        self,
        *,
        mission_sha256: str,
        role_index: int,
        role: str,
        model_binding: str,
        reasoning_effort: str,
        step: Mapping[str, object],
        snapshot: Mapping[str, object],
        now: str,
    ) -> Mapping[str, object] | None:
        """Release only the authorized active-mission GPT vacuous call."""

        profile = _mission_null_content_vacuous_reconciliation_profile()
        if not _matches_mission_null_content_vacuous_reconciliation(
            mission_sha256=mission_sha256,
            role_index=role_index,
            role=role,
            call_id=step["call_id"],
            request_sha256=snapshot["request_sha256"],
            model_binding=model_binding,
            reasoning_effort=reasoning_effort,
            failure_code=snapshot["failure_code"],
        ):
            return None
        expected_step = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "fallback_used": False,
        }
        if any(step[name] != value for name, value in expected_step.items()):
            return None

        broker, _ = self._require_model_runtime()
        evidence_ref = (
            "accounting-policy:sha256:"
            + _MISSION_NULL_CONTENT_VACUOUS_PROFILE_SHA256
        )
        broker.reconcile_vacuous_unknown(
            str(profile["call_id"]),
            actual_tokens=int(profile["actual_tokens"]),
            provider_receipt_ref=str(profile["provider_receipt_ref"]),
            accounting_evidence_ref=evidence_ref,
            event_at=now,
            idempotency_key=(
                f"mission:{mission_sha256}:{role_index}:"
                "null-content-vacuous-output-reconcile:v1"
            ),
        )
        reconciled = broker.snapshot(str(profile["call_id"]))
        expected_terminal = {
            "state": "RECONCILED",
            "previous_state": "UNKNOWN",
            "failure_code": "VACUOUS_OUTPUT",
            "actual_tokens": profile["actual_tokens"],
            "actual_cost_units": None,
            "provider_receipt_ref": profile["provider_receipt_ref"],
            "response_ref": None,
            "accounting_mode": "OBSERVED_NO_NUMERIC_COST",
            "accounting_evidence_ref": evidence_ref,
            "budget_released": True,
        }
        if any(
            reconciled[name] != value
            for name, value in expected_terminal.items()
        ):
            raise ResearchdError(
                "exact null-content vacuous reconciliation terminal drifted"
            )
        return reconciled

    def _reconcile_exact_chief_null_content_vacuous_reservation(
        self,
        *,
        mission_sha256: str,
        role_index: int,
        role: str,
        model_binding: str,
        reasoning_effort: str,
        step: Mapping[str, object],
        snapshot: Mapping[str, object],
        now: str,
    ) -> Mapping[str, object] | None:
        """Release only the authorized final-role vacuous call."""

        profile = _mission_chief_null_content_vacuous_reconciliation_profile()
        if not _matches_mission_chief_null_content_vacuous_reconciliation(
            mission_sha256=mission_sha256,
            role_index=role_index,
            role=role,
            call_id=step["call_id"],
            request_sha256=snapshot["request_sha256"],
            model_binding=model_binding,
            reasoning_effort=reasoning_effort,
            failure_code=snapshot["failure_code"],
        ):
            return None
        expected_step = {
            "mission_sha256": profile["mission_sha256"],
            "role_index": profile["role_index"],
            "role": profile["role"],
            "model_binding": profile["model_binding"],
            "reasoning_effort": profile["reasoning_effort"],
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "fallback_used": False,
        }
        if any(step[name] != value for name, value in expected_step.items()):
            return None

        broker, _ = self._require_model_runtime()
        evidence_ref = (
            "accounting-policy:sha256:"
            + _MISSION_CHIEF_NULL_CONTENT_VACUOUS_PROFILE_SHA256
        )
        broker.reconcile_vacuous_unknown(
            str(profile["call_id"]),
            actual_tokens=int(profile["actual_tokens"]),
            provider_receipt_ref=str(profile["provider_receipt_ref"]),
            accounting_evidence_ref=evidence_ref,
            event_at=now,
            idempotency_key=(
                f"mission:{mission_sha256}:{role_index}:"
                "chief-null-content-vacuous-output-reconcile:v1"
            ),
        )
        reconciled = broker.snapshot(str(profile["call_id"]))
        expected_terminal = {
            "state": "RECONCILED",
            "previous_state": "UNKNOWN",
            "failure_code": "VACUOUS_OUTPUT",
            "actual_tokens": profile["actual_tokens"],
            "actual_cost_units": None,
            "provider_receipt_ref": profile["provider_receipt_ref"],
            "response_ref": None,
            "accounting_mode": "OBSERVED_NO_NUMERIC_COST",
            "accounting_evidence_ref": evidence_ref,
            "budget_released": True,
        }
        if any(
            reconciled[name] != value
            for name, value in expected_terminal.items()
        ):
            raise ResearchdError(
                "exact Chief null-content vacuous reconciliation terminal drifted"
            )
        return reconciled

    def _reconcile_expired_exact_vacuous_reservation(
        self,
        *,
        current: datetime,
        now: str,
    ) -> str | None:
        """Release only the frozen vacuous call after its mission expired.

        This is resource cleanup, not renewed mission authority.  An exact
        cleanup match is skipped by the caller so the expired mission cannot
        reserve another role.  Every other expired mission still reaches the
        normal fail-closed envelope validator.
        """

        profile = _mission_vacuous_reconciliation_profile()
        mission_sha = str(profile["mission_sha256"])
        manifest_path = self._mission_manifest_path(mission_sha)
        if not manifest_path.exists():
            return None
        manifest = _read_private_json(
            manifest_path,
            _MISSION_MANIFEST_KEYS,
            "mission manifest",
        )
        if manifest["mission_sha256"] != mission_sha:
            raise ResearchdError("exact expired mission manifest identity drifted")
        mission_document = _mapping_member(
            manifest,
            "mission_envelope",
            "mission manifest",
        )
        if set(mission_document) != {
            "schema_id",
            "schema_version",
            "object_id",
            "issued_at",
            "payload",
            "integrity",
        }:
            raise ResearchdError("exact expired mission envelope shape drifted")
        payload = _mapping_member(
            mission_document,
            "payload",
            "exact expired mission envelope",
        )
        integrity = _mapping_member(
            mission_document,
            "integrity",
            "exact expired mission envelope",
        )
        if (
            mission_document["schema_id"] != "ResearchMissionEnvelope"
            or mission_document["schema_version"] != "1.0.0"
            or mission_document["object_id"] != f"research-mission:{mission_sha}"
            or payload.get("mission_sha256") != mission_sha
            or set(integrity) != {"payload_sha256"}
            or not hmac.compare_digest(
                str(integrity.get("payload_sha256")),
                research_canonical_sha256(payload),
            )
        ):
            raise ResearchdError("exact expired mission envelope identity drifted")
        expires_at = payload.get("expires_at")
        if not isinstance(expires_at, str):
            raise ResearchdError("exact expired mission expiry is invalid")
        if current <= _research_timestamp(expires_at):
            return None

        role_index = 1
        expected_role, expected_binding, expected_effort = ROLE_SEQUENCE[role_index]
        if expected_binding != profile["model_binding"]:
            raise ResearchdError("exact vacuous profile role binding drifted")
        step_path = self._mission_step_path(mission_sha, role_index)
        if not step_path.exists():
            return None
        step = _read_private_json(
            step_path,
            _MISSION_STEP_KEYS,
            "mission role step",
        )
        expected_step = {
            "mission_sha256": mission_sha,
            "role_index": role_index,
            "role": expected_role,
            "model_binding": expected_binding,
            "reasoning_effort": expected_effort,
            "call_id": profile["call_id"],
            "request_sha256": profile["request_sha256"],
            "fallback_used": False,
        }
        if any(step[name] != value for name, value in expected_step.items()):
            return None

        broker, _ = self._require_model_runtime()
        snapshot = broker.snapshot(str(profile["call_id"]))
        if snapshot["state"] == "UNKNOWN":
            if not _matches_mission_vacuous_reconciliation(
                mission_sha256=mission_sha,
                call_id=step["call_id"],
                request_sha256=snapshot["request_sha256"],
                model_binding=expected_binding,
                failure_code=snapshot["failure_code"],
            ):
                return None
            broker.reconcile_vacuous_unknown(
                str(profile["call_id"]),
                actual_tokens=int(profile["actual_tokens"]),
                provider_receipt_ref=str(profile["provider_receipt_ref"]),
                accounting_evidence_ref=(
                    "accounting-policy:sha256:"
                    + _MISSION_VACUOUS_PROFILE_SHA256
                ),
                event_at=now,
                idempotency_key=(
                    f"mission:{mission_sha}:expired-vacuous-output-reconcile:v1"
                ),
            )
            snapshot = broker.snapshot(str(profile["call_id"]))

        expected_terminal = {
            "state": "RECONCILED",
            "previous_state": "UNKNOWN",
            "failure_code": "VACUOUS_OUTPUT",
            "actual_tokens": profile["actual_tokens"],
            "actual_cost_units": None,
            "provider_receipt_ref": profile["provider_receipt_ref"],
            "response_ref": None,
            "accounting_mode": "OBSERVED_NO_NUMERIC_COST",
            "accounting_evidence_ref": (
                "accounting-policy:sha256:" + _MISSION_VACUOUS_PROFILE_SHA256
            ),
            "budget_released": True,
        }
        if any(snapshot[name] != value for name, value in expected_terminal.items()):
            return None
        return mission_sha

    def research_mission_status(
        self,
        *,
        mission_sha256: str,
        actor: str,
    ) -> Mapping[str, object]:
        """Return ref-only mission lineage without changing durable state."""

        if not isinstance(actor, str) or not actor.startswith("scout:uid:"):
            raise ResearchdError("research mission status requires the Scout principal")
        if not _is_sha256(mission_sha256):
            raise ResearchdError("research mission SHA is invalid")
        manifest = _read_private_json(
            self._mission_manifest_path(mission_sha256),
            _MISSION_MANIFEST_KEYS,
            "mission manifest",
        )
        calls = []
        for index, (role, binding, effort) in enumerate(ROLE_SEQUENCE):
            path = self._mission_step_path(mission_sha256, index)
            if not path.exists():
                calls.append(
                    {
                        "role_index": index,
                        "role": role,
                        "model_binding": binding,
                        "reasoning_effort": effort,
                        "state": "NOT_RESERVED",
                    }
                )
                continue
            step = _read_private_json(path, _MISSION_STEP_KEYS, "mission role step")
            snapshot = self._require_model_runtime()[0].snapshot(str(step["call_id"]))
            calls.append(
                {
                    "role_index": index,
                    "role": role,
                    "model_binding": binding,
                    "reasoning_effort": effort,
                    "call_id": step["call_id"],
                    "request_sha256": step["request_sha256"],
                    "state": snapshot["state"],
                    "response_ref": snapshot["response_ref"],
                    "actual_tokens": snapshot["actual_tokens"],
                    "actual_cost_units": snapshot["actual_cost_units"],
                    "provider_receipt_ref": snapshot["provider_receipt_ref"],
                    "failure_code": snapshot["failure_code"],
                    "terminal_origin_state": (
                        snapshot["previous_state"]
                        if snapshot["state"] == "RECONCILED"
                        else snapshot["state"]
                    ),
                    "accounting_mode": snapshot["accounting_mode"],
                    "accounting_evidence_ref": snapshot[
                        "accounting_evidence_ref"
                    ],
                    "budget_released": snapshot["budget_released"],
                }
            )
        terminal_path = self._mission_terminal_path(mission_sha256)
        return MappingProxyType(
            {
                "status": "MODEL_CHAIN_COMPLETE" if terminal_path.exists() else "IN_PROGRESS",
                "mission_sha256": mission_sha256,
                "mission_manifest_sha256": research_canonical_sha256(manifest),
                "material_event_refs": tuple(manifest["material_event_refs"]),
                "artifact_ref": manifest["artifact_ref"],
                "calls": tuple(MappingProxyType(item) for item in calls),
                "provider_calls_reserved": sum(
                    1 for item in calls if item["state"] != "NOT_RESERVED"
                ),
                "provider_calls_maximum": len(ROLE_SEQUENCE),
                "fallback_used": False,
                "domain_writes": 0,
                "canonical_writes": 0,
                "live_authority": False,
            }
        )

    def _store_input_bytes(
        self,
        raw: bytes,
        *,
        expected_sha256: str,
        maximum: int = MAX_CHAIN_REQUEST_BYTES,
    ) -> str:
        store = self._input_store
        if store is None:
            raise ResearchdError("input CAS is unavailable")
        if (
            not isinstance(raw, bytes)
            or type(maximum) is not int
            or maximum < 1
            or not raw
            or len(raw) > maximum
        ):
            raise ResearchdError("input publication bytes are invalid")
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ResearchdError("input publication hash is invalid")
        temporary: Path | None = None
        descriptor: int | None = None
        try:
            descriptor, name = tempfile.mkstemp(
                prefix=".mission-", dir=self._root / "mission-publication-tmp"
            )
            temporary = Path(name)
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(raw):
                written += os.write(descriptor, raw[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            store_blob = getattr(store, "publish")
            stored = store_blob(
                temporary,
                expected_sha256=expected_sha256,
                expected_size_bytes=len(raw),
            )
            return stored.ref
        except (OSError, CASError) as exc:
            raise ResearchdError("input CAS publication failed closed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def _validate_mission_material_events(
        self,
        mission: Mapping[str, object],
        refs: Sequence[object],
    ) -> None:
        if len(refs) != 2:
            raise ResearchIngressError("mission requires exactly two MaterialEvents")
        ledger = self._require_ledger()
        expected_mission_ref = mission_evidence_ref(str(mission["mission_sha256"]))
        bindings = mission["domain_binding_sha256s"]
        if not isinstance(bindings, Mapping):
            raise ResearchIngressError("mission binding map is invalid")
        observed_domains: list[str] = []
        for raw_ref in refs:
            ref = _text("material_event_ref", raw_ref, maximum=256)
            event = ledger.read_a1_object(ref)
            if event.get("schema_id") != "MaterialEvent":
                raise ResearchIngressError("mission ref is not a MaterialEvent")
            payload = _mapping_member(event, "payload", "MaterialEvent")
            evidence = payload.get("evidence_refs")
            materiality = _mapping_member(
                payload, "materiality_inputs", "MaterialEvent.payload"
            )
            source_ref = materiality.get("source_ref")
            if not isinstance(evidence, (list, tuple)) or expected_mission_ref not in evidence:
                raise ResearchIngressError("MaterialEvent omits mission evidence")
            matches = [
                domain
                for domain in ("market", "security")
                if isinstance(source_ref, str)
                and source_ref.startswith(f"registered:domain-export/{domain}/")
            ]
            if len(matches) != 1:
                raise ResearchIngressError("MaterialEvent domain provenance is invalid")
            domain = matches[0]
            binding_ref = "registered:domain-export-binding/" + str(bindings[domain])
            if binding_ref not in evidence:
                raise ResearchIngressError("MaterialEvent omits exact domain binding evidence")
            observed_domains.append(domain)
        if tuple(observed_domains) != ("market", "security"):
            raise ResearchIngressError("MaterialEvents are swapped or cross-domain")

    def _mission_manifest_path(self, mission_sha256: str) -> Path:
        if not _is_sha256(mission_sha256):
            raise ResearchdError("mission SHA is invalid")
        return self._root / "research-mission-manifests" / f"{mission_sha256}.json"

    def _mission_manifest_paths(self) -> tuple[Path, ...]:
        root = self._root / "research-mission-manifests"
        _validate_private_directory(root, "research mission manifest directory")
        paths = tuple(sorted(root.glob("*.json")))
        for path in paths:
            if not _is_sha256(path.stem):
                raise ResearchdError("mission manifest filename is invalid")
        return paths

    def _mission_step_path(self, mission_sha256: str, index: int) -> Path:
        if not _is_sha256(mission_sha256) or type(index) is not int or not 0 <= index < len(ROLE_SEQUENCE):
            raise ResearchdError("mission step identity is invalid")
        directory = self._root / "research-mission-steps" / mission_sha256
        _validate_private_directory(directory, "research mission step directory")
        return directory / f"{index}.json"

    def _mission_terminal_path(self, mission_sha256: str) -> Path:
        if not _is_sha256(mission_sha256):
            raise ResearchdError("mission terminal identity is invalid")
        return self._root / "research-mission-terminal" / f"{mission_sha256}.json"

    def _mission_context_for_call(
        self, call_id: str
    ) -> tuple[str, Mapping[str, object]] | None:
        normalized = _text("call_id", call_id, maximum=128)
        for manifest_path in self._mission_manifest_paths():
            mission_sha = manifest_path.stem
            for index in range(len(ROLE_SEQUENCE)):
                step_path = self._mission_step_path(mission_sha, index)
                if not step_path.exists():
                    continue
                step = _read_private_json(
                    step_path, _MISSION_STEP_KEYS, "mission role step"
                )
                if step["call_id"] == normalized:
                    return mission_sha, step
        return None

    def reserve_model_call(
        self,
        *,
        role: str,
        role_assignment_ref: str,
        classification: str,
        request_body: str,
        max_tokens: int,
        max_cost_units: int,
        expires_at: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        """Reserve one policy-routed call without granting model authority."""

        if not isinstance(actor, str) or not actor.startswith("scout:uid:"):
            raise ResearchdError("model reservation requires the Scout principal")
        broker, routing = self._require_model_runtime()
        try:
            decision = routing.route(
                role,
                classification,
                available_bindings=self._model_available_bindings,
            )
            if decision.status != "ROUTED":
                return MappingProxyType(
                    {
                        "status": decision.status,
                        "role": decision.role,
                        "model_binding": None,
                        "routing_profile_sha256": decision.profile_sha256,
                        "used_fallback": False,
                        "durable_transition": None,
                    }
                )
            if decision.used_fallback:
                if (
                    self._model_role_binding_overrides.get(role)
                    != decision.binding
                ):
                    raise ResearchdError(
                        "fallback route lacks an exact durable registry binding"
                    )
            request_bytes = request_body.encode("utf-8", errors="strict")
            request_sha256 = hashlib.sha256(request_bytes).hexdigest()
            request_ref = self._store_input_bytes(
                request_bytes,
                expected_sha256=request_sha256,
            )
            handle = broker.prepare(
                ModelCallSpec(
                    role=role,
                    role_assignment_ref=role_assignment_ref,
                    classification=classification,
                    request_bytes=request_bytes,
                    max_tokens=max_tokens,
                    max_cost_units=max_cost_units,
                    expires_at=expires_at,
                    idempotency_key=idempotency_key,
                ),
                event_at=now,
            )
            snapshot = broker.snapshot(handle.call_id)
            if snapshot["model_binding"] != decision.binding:
                raise ResearchdError(
                    "policy route differs from the durable registry binding"
                )
            result = dict(self._sanitized_model_state(snapshot))
            result.update(
                {
                    "status": "RESERVED",
                    "dispatch_token": _model_dispatch_token(
                        snapshot, self._model_worker_ipc_extension_sha256()
                    ),
                    "request_body": request_body,
                    "request_ref": request_ref,
                    "routing_profile_sha256": decision.profile_sha256,
                    "used_fallback": decision.used_fallback,
                    "durable_transition": "PROPOSED_THEN_RESERVED",
                }
            )
            return MappingProxyType(result)
        except (ModelBrokerError, UnicodeError) as exc:
            raise ResearchdError("model reservation failed closed") from exc

    def begin_model_call(
        self,
        *,
        call_id: str,
        dispatch_token: str,
        request_body: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        """Persist SENT before acknowledging one worker egress dispatch."""

        if not isinstance(actor, str) or not actor.startswith("connected_worker:uid:"):
            raise ResearchdError("model begin requires the connected worker principal")
        broker, routing = self._require_model_runtime()
        try:
            before = broker.snapshot(call_id)
            _verify_model_dispatch_token(
                before, dispatch_token, self._model_worker_ipc_extension_sha256()
            )
            handle = broker.begin_external(
                call_id,
                request_bytes=request_body.encode("utf-8", errors="strict"),
                event_at=now,
            )
            snapshot = broker.snapshot(handle.call_id)
            binding = routing.binding(snapshot["model_binding"])  # type: ignore[arg-type]
            result = dict(self._sanitized_model_state(snapshot))
            result.update(
                {
                    "egress_authorized": True,
                    "provider_slot": binding.provider_slot,
                    "candidate_api_identifier": binding.candidate_api_identifier,
                    "durable_transition": "RESERVED_TO_SENT_BEFORE_ACK",
                }
            )
            return MappingProxyType(result)
        except (ModelBrokerError, UnicodeError) as exc:
            raise ResearchdError("model begin failed closed") from exc

    def complete_model_call(
        self,
        *,
        call_id: str,
        dispatch_token: str,
        outcome: str,
        response_ref: str | None,
        actual_tokens: int | None,
        actual_cost_units: int | None,
        provider_receipt_ref: str | None,
        failure_code: str | None,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        """Persist sanitized worker completion metadata without raw bytes."""

        if not isinstance(actor, str) or not actor.startswith("connected_worker:uid:"):
            raise ResearchdError(
                "model completion requires the connected worker principal"
            )
        broker, _ = self._require_model_runtime()
        try:
            before = broker.snapshot(call_id)
            _verify_model_dispatch_token(
                before, dispatch_token, self._model_worker_ipc_extension_sha256()
            )
            handle = broker.complete_external(
                call_id,
                outcome=outcome,
                response_ref=response_ref,
                actual_tokens=actual_tokens,
                actual_cost_units=actual_cost_units,
                provider_receipt_ref=provider_receipt_ref,
                failure_code=failure_code,
                event_at=now,
            )
            return self._sanitized_model_state(broker.snapshot(handle.call_id))
        except ModelBrokerError as exc:
            raise ResearchdError("model completion failed closed") from exc

    def complete_research_model_call(
        self,
        *,
        call_id: str,
        dispatch_token: str,
        outcome: str,
        response_ref: str | None,
        response_body: str | None,
        actual_tokens: int | None,
        actual_cost_units: int | None,
        provider_receipt_ref: str | None,
        failure_code: str | None,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        """Commit one extracted D0/D1 mission result before terminal metadata."""

        if self._mission_context_for_call(call_id) is None:
            raise ResearchdError("research completion call is not mission-bound")
        if outcome == "SUCCEEDED":
            if not isinstance(response_body, str) or not isinstance(response_ref, str):
                raise ResearchdError("successful research completion lacks extracted output")
            raw = response_body.encode("utf-8", errors="strict")
            if not raw or len(raw) > _MAX_MISSION_RESULT_BYTES:
                raise ResearchdError("research completion output exceeds its bound")
            expected_ref = "cas:sha256:" + hashlib.sha256(raw).hexdigest()
            if not hmac.compare_digest(expected_ref, response_ref):
                raise ResearchdError("research completion output/ref binding is invalid")
            stored_ref = self._store_input_bytes(
                raw,
                expected_sha256=expected_ref.removeprefix("cas:sha256:"),
                maximum=_MAX_MISSION_RESULT_BYTES,
            )
            if stored_ref != response_ref:
                raise ResearchdError("research completion CAS ref drifted")
        elif response_body is not None:
            raise ResearchdError("non-successful research completion carries output")
        return self.complete_model_call(
            call_id=call_id,
            dispatch_token=dispatch_token,
            outcome=outcome,
            response_ref=response_ref,
            actual_tokens=actual_tokens,
            actual_cost_units=actual_cost_units,
            provider_receipt_ref=provider_receipt_ref,
            failure_code=failure_code,
            actor=actor,
            idempotency_key=idempotency_key,
            now=now,
        )

    def lookup_model_call(
        self, *, call_id: str, actor: str
    ) -> Mapping[str, object]:
        """Return one sanitized durable state without changing the ledger."""

        if not isinstance(actor, str) or not actor.startswith(
            ("scout:uid:", "connected_worker:uid:")
        ):
            raise ResearchdError("model lookup principal is invalid")
        broker, _ = self._require_model_runtime()
        try:
            return self._sanitized_model_state(broker.snapshot(call_id))
        except ModelBrokerError as exc:
            raise ResearchdError("model lookup failed closed") from exc

    def list_reserved_model_calls(
        self, *, actor: str, maximum: int = 1
    ) -> Mapping[str, object]:
        """List RESERVED model calls for dispatch discovery.

        Read-only query bounded by WIP limit.  Only RESERVED state is
        returned; SENT, terminal, and expired calls are excluded.
        """

        if not isinstance(actor, str) or not actor.startswith(
            ("connected_worker:uid:", "scout:uid:")
        ):
            raise ResearchdError(
                "list_reserved_model_calls requires connected_worker or scout principal"
            )
        if maximum != 1:
            raise ResearchdError("production reserved-call maximum must be 1")
        broker, _ = self._require_model_runtime()
        try:
            all_states = self._ledger.model_call_states()
            reserved = []
            now_iso = self._clock().astimezone(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            )
            for record in all_states:
                snap = record.snapshot
                if snap.get("state") != "RESERVED":
                    continue
                expires = snap.get("expires_at")
                if isinstance(expires, str) and expires <= now_iso:
                    continue
                request_ref = "cas:sha256:" + str(snap["request_sha256"])
                request_raw = self._read_input(request_ref)
                try:
                    request_body = request_raw.decode("utf-8", errors="strict")
                except UnicodeError as exc:
                    raise ResearchdError("reserved model request is not UTF-8") from exc
                item = dict(self._sanitized_model_state(snap))
                item.update(
                    {
                        "dispatch_token": _model_dispatch_token(
                            snap, self._model_worker_ipc_extension_sha256()
                        ),
                        "request_ref": request_ref,
                        "request_body": request_body,
                        "completion_command": "complete_model_call",
                    }
                )
                mission_context = self._mission_context_for_call(
                    str(snap["call_id"])
                )
                if mission_context is not None:
                    mission_sha, step = mission_context
                    item.update(
                        {
                            "research_mission_sha256": mission_sha,
                            "research_role_index": step["role_index"],
                            "reasoning_effort": step["reasoning_effort"],
                            "completion_command": "complete_research_model_call",
                        }
                    )
                reserved.append(MappingProxyType(item))
                if len(reserved) >= maximum:
                    break
            return MappingProxyType(
                {
                    "status": "NO_RESERVED_CALLS" if not reserved else "FOUND",
                    "reserved_calls": tuple(reserved),
                    "count": len(reserved),
                    "wip_limit": maximum,
                }
            )
        except (ModelBrokerError, LedgerError) as exc:
            raise ResearchdError(
                "list_reserved_model_calls failed closed"
            ) from exc

    def reconcile_model_call(
        self,
        *,
        call_id: str,
        actual_tokens: int,
        actual_cost_units: int,
        provider_receipt_ref: str,
        actor: str,
        idempotency_key: str,
        now: str,
    ) -> Mapping[str, object]:
        """Apply exact operator billing evidence through the single writer."""

        if not isinstance(actor, str) or not actor.startswith("uid:"):
            raise ResearchdError("model reconciliation requires the operator principal")
        broker, _ = self._require_model_runtime()
        try:
            before = broker.snapshot(call_id)
            if before["state"] == "RECONCILED":
                expected = {
                    "actual_tokens": actual_tokens,
                    "actual_cost_units": actual_cost_units,
                    "provider_receipt_ref": provider_receipt_ref,
                }
                if any(before[name] != value for name, value in expected.items()):
                    raise ModelBrokerError(
                        "reconciliation replay differs from durable state"
                    )
                return self._sanitized_model_state(before)
            handle = broker.reconcile(
                call_id,
                actual_tokens=actual_tokens,
                actual_cost_units=actual_cost_units,
                provider_receipt_ref=provider_receipt_ref,
                event_at=now,
                idempotency_key=idempotency_key,
            )
            return self._sanitized_model_state(broker.snapshot(handle.call_id))
        except ModelBrokerError as exc:
            raise ResearchdError("model reconciliation failed closed") from exc

    def validate_proposal_envelope(
        self, proposal_envelope: Mapping[str, object]
    ) -> None:
        """Require two distinct successful, role-correct durable call refs."""

        if not isinstance(proposal_envelope, Mapping):
            raise ResearchdError("proposal envelope must be an object")
        model_ref = proposal_envelope.get("model_call_ref")
        critique_ref = proposal_envelope.get("critique_call_ref")
        if not isinstance(model_ref, str) or not isinstance(critique_ref, str):
            raise ResearchdError("proposal model-call references are invalid")
        if model_ref == critique_ref:
            raise ResearchdError("proposal requires distinct model-call references")
        broker, _ = self._require_model_runtime()
        try:
            model = broker.snapshot(model_ref)
            critique = broker.snapshot(critique_ref)
        except ModelBrokerError as exc:
            raise ResearchdError(
                "proposal model-call references are not durable"
            ) from exc
        if not _successful_model_snapshot(model):
            raise ResearchdError("proposal model call is not successful")
        if not _successful_model_snapshot(critique):
            raise ResearchdError("proposal critique call is not successful")
        if model["role"] not in {"SCOUT_FAST", "RESEARCH_WORKER"}:
            raise ResearchdError("proposal model role is invalid")
        if critique["role"] not in {
            "CRITIC_PRIMARY",
            "CRITIC_DEEP",
            "CHIEF_SCIENTIST",
        }:
            raise ResearchdError("proposal critique role is invalid")
        if model["classification"] != critique["classification"]:
            raise ResearchdError("proposal model classifications differ")
        for snapshot, field in (
            (model, "model_output"),
            (critique, "critique_output"),
        ):
            output = proposal_envelope.get(field)
            if not isinstance(output, str):
                raise ResearchdError("proposal model output is invalid")
            expected_ref = "cas:sha256:" + hashlib.sha256(
                output.encode("utf-8", errors="strict")
            ).hexdigest()
            if not hmac.compare_digest(str(snapshot["response_ref"]), expected_ref):
                raise ResearchdError(
                    "proposal model output differs from durable response evidence"
                )

    def _require_model_runtime(
        self,
    ) -> tuple[ModelCallBroker, ModelProviderRouting]:
        broker = self._model_broker
        routing = self._model_routing
        if not self._started or broker is None or routing is None:
            raise ResearchdError("model runtime is unavailable")
        return broker, routing

    def _model_worker_ipc_extension_sha256(self) -> str:
        runtime = _model_runtime_binding(self._frozen_bindings)
        if runtime is None:
            raise ResearchdError("model runtime is unavailable")
        value = runtime.get("worker_ipc_extension_sha256")
        if value not in _MODEL_WORKER_IPC_EXTENSION_SHA256S:
            raise ResearchdError("model worker IPC extension binding is stale")
        return str(value)

    @staticmethod
    def _sanitized_model_state(
        snapshot: Mapping[str, object],
    ) -> Mapping[str, object]:
        fields = (
            "call_id",
            "state",
            "request_sha256",
            "registry_sha256",
            "binding_revision",
            "role",
            "model_binding",
            "classification",
            "max_tokens",
            "max_cost_units",
            "expires_at",
            "response_ref",
            "actual_tokens",
            "actual_cost_units",
            "provider_receipt_ref",
            "failure_code",
            "ambiguous_usage",
            "budget_released",
            "auto_retry",
        )
        return MappingProxyType({field: snapshot[field] for field in fields})

    def _start_model_runtime(self, ledger: JobLedger) -> None:
        runtime = _model_runtime_binding(self._frozen_bindings)
        if runtime is None:
            return
        provenance_root = self._contract_root.parent / "provenance"
        _verify_bound_file(
            provenance_root / "model-role-evaluation-v2.json",
            runtime["role_evaluation_sha256"],
            "model role evaluation",
        )
        extension_sha256 = str(runtime["worker_ipc_extension_sha256"])
        extension_path = _MODEL_WORKER_IPC_EXTENSION_PATHS.get(extension_sha256)
        if extension_path is None:
            raise ResearchdError("model worker IPC extension binding is stale")
        _verify_bound_file(
            provenance_root / extension_path,
            extension_sha256,
            "model worker IPC extension",
        )
        try:
            overrides = runtime["role_binding_overrides"]  # type: ignore[index]
            registry = ModelRoleRegistry(
                self._contract_root
                / "a1"
                / "v1"
                / "profiles"
                / "model_role_registry_v1.json",
                expected_profile_sha256=runtime["role_registry_sha256"],  # type: ignore[arg-type]
                binding_revision=runtime["binding_revision"],  # type: ignore[arg-type]
                binding_overrides=overrides,  # type: ignore[arg-type]
            )
            routing_paths = {
                _MODEL_ROUTING_PROFILE_SHA256: (
                    provenance_root / "model-provider-routing-v1.json"
                ),
                _MODEL_ROUTING_PROFILE_SHA256_V2: (
                    provenance_root / "model-provider-routing-v2.json"
                ),
                _MODEL_ROUTING_PROFILE_SHA256_V3: (
                    provenance_root / "model-provider-routing-v2.json"
                ),
            }
            routing_path = routing_paths.get(runtime["routing_profile_sha256"])
            if routing_path is None:
                raise ModelBrokerError("model routing profile is unsupported")
            routing = ModelProviderRouting(
                routing_path,
                expected_profile_sha256=runtime["routing_profile_sha256"],  # type: ignore[arg-type]
                role_registry=registry,
            )
            available = frozenset(runtime["available_bindings"])  # type: ignore[arg-type]
            for binding in available:
                if routing.binding(binding).availability != "FIXTURE_ONLY":
                    raise ModelBrokerError(
                        "available model binding is not fixture-evaluated"
                    )
            broker = ModelCallBroker(
                registry=registry,
                ledger=ledger,
                budget_policy=ModelBudgetPolicy(
                    policy_ref=runtime["budget_policy_ref"],  # type: ignore[arg-type]
                    scope_ref=runtime["budget_scope_ref"],  # type: ignore[arg-type]
                    max_active_calls=runtime["max_active_calls"],  # type: ignore[arg-type]
                    max_reserved_tokens=runtime["max_reserved_tokens"],  # type: ignore[arg-type]
                    max_reserved_cost_units=runtime["max_reserved_cost_units"],  # type: ignore[arg-type]
                ),
            )
            for record in ledger.model_call_states():
                if record.snapshot["state"] == "SENT":
                    broker.recover_sent(
                        record.snapshot["call_id"],  # type: ignore[arg-type]
                        event_at=_bounded_recovery_time(
                            self._clock(), record.snapshot
                        ),
                    )
        except (ModelBrokerError, TypeError, ValueError) as exc:
            raise ResearchdError("model runtime binding failed closed") from exc
        self._model_broker = broker
        self._model_routing = routing
        self._model_available_bindings = available
        self._model_role_binding_overrides = overrides  # type: ignore[assignment]

    def _fresh_staging_directory(self, attempt_id: str) -> Path:
        digest = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()
        path = self._root / "staging-by-attempt-digest" / digest
        try:
            path.mkdir(mode=_ROOT_MODE)
        except FileExistsError as exc:
            raise ResearchdError(
                "attempt staging already exists; use lookup after an ambiguous response"
            ) from exc
        except OSError as exc:
            raise ResearchdError("attempt staging could not be created") from exc
        _validate_private_directory(path, "attempt staging directory")
        return path

    def _read_input(self, ref: str) -> bytes:
        store = self._input_store
        if store is None:
            raise ResearchdError("input store is unavailable")
        return store.read_bytes(
            ref,
            maximum_size_bytes=self._maximum_input_bytes,
        )

    def _require_server(self) -> UnixControlServer:
        with self._state_lock:
            if not self._started or self._server is None:
                raise ResearchdError("researchd is not started")
            return self._server

    def _require_ledger(self) -> JobLedger:
        if not self._started or self._ledger is None:
            raise ResearchdError("researchd ledger is unavailable")
        return self._ledger

    def _require_fence_ledger(self) -> _CheckpointFenceLedger:
        if not self._started or self._fence_ledger is None:
            raise ResearchdError("researchd fence adapter is unavailable")
        return self._fence_ledger

    def _require_coordinator(self) -> OfflineExecutionCoordinator:
        if not self._started or self._coordinator is None:
            raise ResearchdError("researchd coordinator is unavailable")
        return self._coordinator

    def _close_components(self) -> None:
        server = self._server
        self._server = None
        self._started = False
        if server is not None:
            server.close()

        ledger = self._ledger
        self._ledger = None
        if ledger is not None:
            ledger.close()

        self._coordinator = None
        self._validated_coordinator = None
        self._validation_protocol_ref = None
        self._a1_backend = None
        self._model_broker = None
        self._model_routing = None
        self._model_available_bindings = frozenset()
        self._model_role_binding_overrides = {}
        self._fence_ledger = None
        self._input_store = None
        self._checkpoint_store = None
        self._artifact_store = None

        lock_fd = self._lock_fd
        self._lock_fd = None
        if lock_fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

        root_fd = self._root_fd
        self._root_fd = None
        self._root_identity = None
        if root_fd is not None:
            os.close(root_fd)

    def __enter__(self) -> ResearchDaemon:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _verify_bound_file(path: Path, expected_sha256: object, label: str) -> None:
    if not isinstance(expected_sha256, str) or not _is_sha256(expected_sha256):
        raise ResearchdError(f"{label} digest is invalid")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ResearchdError(f"{label} is unavailable") from exc
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ResearchdError(f"{label} digest is stale")


def _model_dispatch_token(
    snapshot: Mapping[str, object], worker_ipc_extension_sha256: str
) -> str:
    fields = (
        "call_id",
        "request_sha256",
        "registry_sha256",
        "binding_revision",
        "role",
        "model_binding",
        "classification",
        "max_tokens",
        "max_cost_units",
        "expires_at",
    )
    material = {field: snapshot[field] for field in fields}
    if worker_ipc_extension_sha256 not in _MODEL_WORKER_IPC_EXTENSION_SHA256S:
        raise ResearchdError("model worker IPC extension binding is stale")
    material["worker_ipc_extension_sha256"] = worker_ipc_extension_sha256
    return hashlib.sha256(_canonical_json_bytes(material)).hexdigest()


def _verify_model_dispatch_token(
    snapshot: Mapping[str, object], supplied: str, worker_ipc_extension_sha256: str
) -> None:
    if not isinstance(supplied, str) or not hmac.compare_digest(
        _model_dispatch_token(snapshot, worker_ipc_extension_sha256), supplied
    ):
        raise ResearchdError("model dispatch token is invalid")


def _successful_model_snapshot(snapshot: Mapping[str, object]) -> bool:
    return snapshot.get("state") == "SUCCEEDED" or (
        snapshot.get("state") == "RECONCILED"
        and snapshot.get("previous_state") == "SUCCEEDED"
    )


def _bounded_recovery_time(
    current: datetime, snapshot: Mapping[str, object]
) -> str:
    if (
        not isinstance(current, datetime)
        or current.tzinfo is None
        or current.utcoffset() != timezone.utc.utcoffset(current)
    ):
        raise ResearchdError("model recovery clock must return aware UTC")
    sent_raw = snapshot.get("sent_at")
    expires_raw = snapshot.get("expires_at")
    if not isinstance(sent_raw, str) or not isinstance(expires_raw, str):
        raise ResearchdError("model recovery timestamps are invalid")
    try:
        sent = datetime.fromisoformat(sent_raw.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResearchdError("model recovery timestamps are invalid") from exc
    bounded = max(sent, min(current, expires))
    return bounded.isoformat().replace("+00:00", "Z")


def _corridor_executor_profile(
    *,
    a1_enabled: bool,
    frozen_bindings: Mapping[str, object] | None,
) -> CorridorExecutorProfile | None:
    if not a1_enabled:
        return None
    if not isinstance(frozen_bindings, Mapping):
        raise ResearchdError("A1 validation requires frozen runtime bindings")
    runtime_binding = frozen_bindings.get(_ADMISSION_RUNTIME_KEY)
    if runtime_binding is None:
        return None
    if not isinstance(runtime_binding, Mapping):
        raise ResearchdError("A1 validation runtime binding is invalid")
    profile = runtime_binding.get("corridor_executor_profile")
    if profile is None:
        return None
    if type(profile) is not CorridorExecutorProfile:
        raise ResearchdError("A1 validation corridor profile is invalid")
    return profile


def _verify_l0_validator_source() -> None:
    module = sys.modules.get(DeterministicL0Validator.__module__)
    source_location = getattr(module, "__file__", None)
    if not isinstance(source_location, str) or not source_location.endswith(".py"):
        raise ResearchdError("pinned L0 validator source is unavailable")
    if not hasattr(os, "O_NOFOLLOW"):
        raise ResearchdError("platform cannot verify the pinned L0 validator source")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(source_location, flags)
    except OSError as exc:
        raise ResearchdError("pinned L0 validator source cannot be opened") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_VALIDATOR_SOURCE_BYTES
        ):
            raise ResearchdError("pinned L0 validator source is invalid")
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise ResearchdError("pinned L0 validator source is truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        if digest.hexdigest() != _L0_VALIDATOR_SOURCE_SHA256:
            raise ResearchdError("pinned L0 validator source digest is stale")
    finally:
        os.close(descriptor)


def _open_runtime_root(root: Path) -> tuple[int, tuple[int, int]]:
    _validate_runtime_root_directory(root)
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ResearchdError("platform cannot enforce runtime root ownership")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise ResearchdError("runtime root cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(root)
        identity = (opened.st_dev, opened.st_ino)
        if identity != (current.st_dev, current.st_ino):
            raise ResearchdError("runtime root identity changed during open")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) not in _RUNTIME_ROOT_MODES
            or opened.st_uid != os.geteuid()
        ):
            raise ResearchdError("runtime root ownership or mode is invalid")
        return descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def _verify_runtime_root(
    root: Path,
    descriptor: int,
    identity: tuple[int, int],
) -> None:
    opened = os.fstat(descriptor)
    current = os.lstat(root)
    if (
        (opened.st_dev, opened.st_ino) != identity
        or (current.st_dev, current.st_ino) != identity
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or stat.S_IMODE(current.st_mode) not in _RUNTIME_ROOT_MODES
        or current.st_uid != os.geteuid()
    ):
        raise ResearchdError("runtime root changed before socket bind")


def _acquire_runtime_lock(root: Path) -> int:
    if fcntl is None or not hasattr(os, "O_NOFOLLOW"):
        raise ResearchdError("platform cannot enforce the runtime lock")
    path = root / ".researchd.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, _LOCK_MODE)
    except OSError as exc:
        raise ResearchdError("runtime lock cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or identity != (current.st_dev, current.st_ino)
            or stat.S_IMODE(opened.st_mode) != _LOCK_MODE
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
        ):
            raise ResearchdError("runtime lock ownership or mode is invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ResearchdError("runtime root already has an active writer") from exc
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=_ROOT_MODE, exist_ok=True)
    except OSError as exc:
        raise ResearchdError("private runtime directory cannot be initialized") from exc
    _validate_private_directory(path, "private runtime directory")


def _research_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ResearchdError("research mission clock is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ResearchdError("research mission clock is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ResearchdError("research mission clock is not UTC")
    return parsed


def _write_immutable_private_json(path: Path, value: Mapping[str, object]) -> bool:
    """Create one owner-only immutable receipt or prove an exact replay."""

    _private_directory(path.parent)
    raw = _canonical_json_bytes(value) + b"\n"
    if len(raw) > 2 * 1024 * 1024:
        raise ResearchdError("immutable mission receipt exceeds its bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        existing = _read_private_bytes(path, maximum=2 * 1024 * 1024)
        if not hmac.compare_digest(existing, raw):
            raise ResearchdError("immutable mission receipt replay differs")
        return False
    except OSError as exc:
        raise ResearchdError("immutable mission receipt cannot be reserved") from exc
    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return True
    except OSError as exc:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ResearchdError("immutable mission receipt write failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_private_bytes(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or not 0 < before.st_size <= maximum
        ):
            raise ResearchdError("private mission receipt identity is invalid")
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ResearchdError("private mission receipt changed before open")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise ResearchdError("private mission receipt is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
        ):
            raise ResearchdError("private mission receipt changed while read")
        return b"".join(chunks)
    except OSError as exc:
        raise ResearchdError("private mission receipt is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_private_json(
    path: Path,
    keys: frozenset[str],
    label: str,
) -> dict[str, object]:
    raw = _read_private_bytes(path, maximum=2 * 1024 * 1024)

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise ResearchdError(f"{label} contains duplicate keys")
            result[key] = item
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ResearchdError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != keys:
        raise ResearchdError(f"{label} shape is invalid")
    return value


def _validate_runtime_root_directory(path: Path) -> None:
    """Allow only private ownership or group traversal to the 0660 socket."""

    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ResearchdError("runtime root is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) not in _RUNTIME_ROOT_MODES
        or metadata.st_uid != os.geteuid()
    ):
        raise ResearchdError("runtime root ownership or mode is invalid")


def _validate_private_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ResearchdError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != _ROOT_MODE
        or metadata.st_uid != os.geteuid()
    ):
        raise ResearchdError(f"{label} ownership or mode is invalid")


def _mapping_member(
    value: Mapping[str, object],
    name: str,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ResearchdError(f"{label} must be an object")
    member = value.get(name)
    if not isinstance(member, Mapping):
        raise ResearchdError(f"{label}.{name} must be an object")
    return member


def _text(label: str, value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ResearchdError(f"{label} must be normalized non-empty text")
    return value


def _json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_copy(item) for item in value]
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            _json_copy(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ResearchdError("receipt is not canonical JSON data") from exc


def _service_arguments(argv: Sequence[str] | None) -> _ServiceConfig:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--config":
        raise _ServiceConfigError("exactly one config path is required")
    return _service_config_from_path(arguments[1])


def _service_config_from_path(config_path: str) -> _ServiceConfig:
    if not isinstance(config_path, str) or not config_path or "\x00" in config_path:
        raise _ServiceConfigError("config path is invalid")
    raw = _read_owner_only_config(config_path)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _ServiceConfigError("config is not utf-8") from exc
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_strict_config_object,
            parse_constant=_reject_config_constant,
        )
    except (json.JSONDecodeError, _ServiceConfigError) as exc:
        raise _ServiceConfigError("config is not strict json") from exc
    _ensure_finite_json(decoded)
    if not isinstance(decoded, dict):
        raise _ServiceConfigError("config must be an object")
    return _service_config_from_mapping(decoded)


def _read_owner_only_config(config_path: str) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _ServiceConfigError("platform cannot safely open config")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(config_path, flags)
    except OSError as exc:
        raise _ServiceConfigError("config cannot be opened safely") from exc
    try:
        identity = _verify_config_descriptor(config_path, descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, _MAX_CONFIG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_CONFIG_BYTES:
                raise _ServiceConfigError("config is too large")
        if total == 0:
            raise _ServiceConfigError("config is empty")
        if _verify_config_descriptor(config_path, descriptor) != identity:
            raise _ServiceConfigError("config identity changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_config_descriptor(config_path: str, descriptor: int) -> tuple[int, int]:
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(config_path)
    except OSError as exc:
        raise _ServiceConfigError("config metadata is unavailable") from exc
    identity = (opened.st_dev, opened.st_ino)
    if (
        identity != (current.st_dev, current.st_ino)
        or not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or stat.S_IMODE(opened.st_mode) != _CONFIG_MODE
        or opened.st_uid != os.geteuid()
        or opened.st_nlink != 1
    ):
        raise _ServiceConfigError("config ownership or mode is invalid")
    return identity


def _strict_config_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _ServiceConfigError("config contains a duplicate key")
        result[key] = value
    return result


def _reject_config_constant(value: str) -> object:
    raise _ServiceConfigError("config contains a non-finite number")


def _ensure_finite_json(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise _ServiceConfigError("config contains a non-finite number")
    if isinstance(value, list):
        for item in value:
            _ensure_finite_json(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _ServiceConfigError("config object key is not text")
            _ensure_finite_json(item)


def _service_config_from_mapping(config: Mapping[str, object]) -> _ServiceConfig:
    config_keys = set(config)
    if config_keys == _LEGACY_CONFIG_KEYS:
        config_mode = "legacy"
    elif config_keys == _A1_DISABLED_CONFIG_KEYS:
        config_mode = "a1-disabled"
    elif config_keys == _A1_ENABLED_CONFIG_KEYS:
        config_mode = "a1-enabled"
    else:
        raise _ServiceConfigError("config shape is invalid")
    if config.get("schema_id") != _SERVICE_SCHEMA_ID:
        raise _ServiceConfigError("config schema id is invalid")
    expected_version = (
        _LEGACY_SERVICE_SCHEMA_VERSION
        if config_mode == "legacy"
        else _A1_SERVICE_SCHEMA_VERSION
    )
    if config.get("schema_version") != expected_version:
        raise _ServiceConfigError("config schema version is invalid")

    runtime_root = _config_text(config.get("runtime_root"), "runtime_root", maximum=4096)
    runner_identity = _config_text(
        config.get("runner_identity"), "runner_identity", maximum=256
    )
    allowed_uids = _allowed_uids(
        config.get("allowed_uids"),
        legacy=config_mode != "a1-enabled",
    )
    if config_mode == "a1-enabled":
        a1_enabled = _config_bool(config.get("a1_enabled"), "a1_enabled")
        if not a1_enabled:
            raise _ServiceConfigError("full A1 config requires a1_enabled")
        principal_roles = _principal_roles(
            config.get("principal_roles"),
            allowed_uids=allowed_uids,
            a1_enabled=a1_enabled,
        )
        frozen_bindings = _frozen_bindings(
            config.get("frozen_bindings"),
            a1_enabled=a1_enabled,
            policy_snapshots=config.get("policy_snapshots"),
        )
        admission_runtime = frozen_bindings.get(_ADMISSION_RUNTIME_KEY)
        corridor_profile = (
            admission_runtime.get("corridor_executor_profile")
            if isinstance(admission_runtime, Mapping)
            else None
        )
        if (
            corridor_profile is not None
            and (
                type(corridor_profile) is not CorridorExecutorProfile
                or corridor_profile.runner_identity != runner_identity
            )
        ):
            raise _ServiceConfigError("corridor runner identity is mixed")
        a1_limits = _a1_limits(
            config.get("a1_limits"),
            a1_enabled=a1_enabled,
        )
        model_runtime_enabled = _MODEL_RUNTIME_KEY in frozen_bindings
        expected_roles = (
            _MODEL_REQUIRED_ROLES if model_runtime_enabled else _A1_REQUIRED_ROLES
        )
        if frozenset(principal_roles.values()) != expected_roles:
            raise _ServiceConfigError(
                "principal role set does not match the frozen runtime bindings"
            )
        if model_runtime_enabled:
            try:
                _validate_model_runtime_limits(frozen_bindings, a1_limits)
            except ResearchdError as exc:
                raise _ServiceConfigError(
                    "model runtime exceeds the configured A1 boundary"
                ) from exc
    elif config_mode == "a1-disabled":
        a1_enabled = _config_bool(config.get("a1_enabled"), "a1_enabled")
        if a1_enabled:
            raise _ServiceConfigError("enabled A1 config is incomplete")
        principal_roles = MappingProxyType({uid: "operator" for uid in allowed_uids})
        frozen_bindings = None
        a1_limits = None
    else:
        a1_enabled = False
        principal_roles = MappingProxyType({uid: "operator" for uid in allowed_uids})
        frozen_bindings = None
        a1_limits = None
    input_quota_bytes = _quota_bytes(config.get("input_quota_bytes"))
    checkpoint_quota_bytes = _quota_bytes(config.get("checkpoint_quota_bytes"))
    artifact_quota_bytes = _quota_bytes(config.get("artifact_quota_bytes"))
    maximum_input_bytes = _quota_bytes(config.get("maximum_input_bytes"))
    if maximum_input_bytes > input_quota_bytes:
        raise _ServiceConfigError("maximum input exceeds input quota")
    deadline_seconds = _deadline_seconds(config.get("deadline_seconds"))
    authority = _authority_from_config(config)
    if frozen_bindings is not None:
        try:
            authority.verify_policy_binding(
                str(frozen_bindings["policy_sha256"]),
                now=datetime.now(timezone.utc),
            )
        except Exception as exc:
            raise _ServiceConfigError("A1 policy binding is invalid") from exc

    return _ServiceConfig(
        runtime_root=runtime_root,
        authority=authority,
        allowed_uids=allowed_uids,
        principal_roles=principal_roles,
        a1_enabled=a1_enabled,
        frozen_bindings=frozen_bindings,
        a1_limits=a1_limits,
        runner_identity=runner_identity,
        input_quota_bytes=input_quota_bytes,
        checkpoint_quota_bytes=checkpoint_quota_bytes,
        artifact_quota_bytes=artifact_quota_bytes,
        maximum_input_bytes=maximum_input_bytes,
        deadline_seconds=deadline_seconds,
    )


def _allowed_uids(value: object, *, legacy: bool) -> tuple[int, ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_CONFIG_UIDS:
        raise _ServiceConfigError("allowed uid set is invalid")
    if any(type(uid) is not int or not 0 <= uid <= _MAX_CONFIG_UID for uid in value):
        raise _ServiceConfigError("allowed uid set is invalid")
    if len(value) != len(set(value)):
        raise _ServiceConfigError("allowed uid set is invalid")
    if legacy and (len(value) != 1 or value[0] != os.geteuid()):
        raise _ServiceConfigError("allowed uid set is invalid")
    return tuple(sorted(value))


def _principal_roles(
    value: object,
    *,
    allowed_uids: tuple[int, ...],
    a1_enabled: bool,
) -> Mapping[int, str]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("principal_roles must be an object")
    roles: dict[int, str] = {}
    for key, role in value.items():
        if (
            not isinstance(key, str)
            or not key
            or not key.isascii()
            or not key.isdecimal()
        ):
            raise _ServiceConfigError("principal role UID is invalid")
        uid = int(key)
        if str(uid) != key or uid > _MAX_CONFIG_UID:
            raise _ServiceConfigError("principal role UID is invalid")
        if uid in roles or role not in _PRINCIPAL_ROLES:
            raise _ServiceConfigError("principal role mapping is invalid")
        roles[uid] = role
    if set(roles) != set(allowed_uids):
        raise _ServiceConfigError("principal roles must cover allowed UIDs exactly")
    assigned = frozenset(roles.values())
    if a1_enabled:
        if assigned not in {_A1_REQUIRED_ROLES, _MODEL_REQUIRED_ROLES}:
            raise _ServiceConfigError("A1 principal role set is incomplete")
    elif assigned != {"operator"}:
        raise _ServiceConfigError("disabled A1 config must be operator-only")
    return MappingProxyType(roles)


def _runtime_principal_roles(
    allowed_uids: frozenset[int],
    *,
    principal_roles: Mapping[int, str] | None,
    a1_enabled: bool,
    model_runtime_enabled: bool,
) -> Mapping[int, str]:
    if principal_roles is None:
        roles = {uid: "operator" for uid in allowed_uids}
    elif isinstance(principal_roles, Mapping):
        roles = dict(principal_roles)
    else:
        raise ResearchdError("principal_roles must map verified UIDs to roles")
    if set(roles) != set(allowed_uids):
        raise ResearchdError("principal_roles must cover exactly the allowed UIDs")
    if any(
        type(uid) is not int or role not in _PRINCIPAL_ROLES
        for uid, role in roles.items()
    ):
        raise ResearchdError("principal_roles contains an invalid principal")
    assigned = frozenset(roles.values())
    expected = _MODEL_REQUIRED_ROLES if model_runtime_enabled else _A1_REQUIRED_ROLES
    if a1_enabled and assigned != expected:
        raise ResearchdError("A1 principal role set is incomplete")
    if not a1_enabled and assigned != {"operator"}:
        raise ResearchdError("disabled A1 runtime must be operator-only")
    return MappingProxyType(roles)


def _frozen_bindings(
    value: object,
    *,
    a1_enabled: bool,
    policy_snapshots: object,
) -> Mapping[str, object] | None:
    if not a1_enabled:
        if value is not None:
            raise _ServiceConfigError("disabled A1 config cannot carry frozen bindings")
        return None
    if not isinstance(value, dict):
        raise _ServiceConfigError("A1 frozen bindings must be an object")
    binding_keys = set(value)
    if (
        not _FROZEN_BINDING_KEYS.issubset(binding_keys)
        or binding_keys - _FROZEN_BINDING_KEYS
        - {_ADMISSION_RUNTIME_KEY, _MODEL_RUNTIME_KEY, _CONTEXT_BINDING_KEY}
    ):
        raise _ServiceConfigError("frozen_bindings shape is invalid")
    for name in (
        "core_catalog_sha256",
        "a1_catalog_sha256",
        "release_manifest_sha256",
        "policy_sha256",
        "ipc_compatibility_profile_sha256",
    ):
        if not _is_sha256(value.get(name)):
            raise _ServiceConfigError("frozen binding digest is invalid")
    if value["core_catalog_sha256"] != _CORE_CATALOG_SHA256:
        raise _ServiceConfigError("Core catalog binding is stale")
    if value["a1_catalog_sha256"] != _A1_CATALOG_SHA256:
        raise _ServiceConfigError("A1 catalog binding is stale")
    if value["ipc_compatibility_profile_sha256"] != _IPC_COMPATIBILITY_PROFILE_SHA256:
        raise _ServiceConfigError("IPC compatibility profile binding is stale")
    if not isinstance(policy_snapshots, dict) or set(policy_snapshots) != {
        value["policy_sha256"]
    }:
        raise _ServiceConfigError("A1 policy resolver binding is mixed or empty")
    executor_refs = _capability_refs(
        value.get("executor_capability_refs"), "executor capability ref"
    )
    evaluator_refs = _capability_refs(
        value.get("evaluator_capability_refs"), "evaluator capability ref"
    )
    frozen: dict[str, object] = {
            "core_catalog_sha256": value["core_catalog_sha256"],
            "a1_catalog_sha256": value["a1_catalog_sha256"],
            "release_manifest_sha256": value["release_manifest_sha256"],
            "policy_sha256": value["policy_sha256"],
            "ipc_compatibility_profile_sha256": value[
                "ipc_compatibility_profile_sha256"
            ],
            "executor_capability_refs": executor_refs,
            "evaluator_capability_refs": evaluator_refs,
        }
    raw_runtime = value.get(_ADMISSION_RUNTIME_KEY)
    if raw_runtime is not None:
        if not isinstance(raw_runtime, dict):
            raise _ServiceConfigError("admission runtime binding is invalid")
        _expect_config_keys(
            raw_runtime, _ADMISSION_RUNTIME_KEYS, "admission_runtime"
        )
        model_route_proof_ref = _config_text(
            raw_runtime.get("model_route_proof_ref"),
            "model_route_proof_ref",
            maximum=512,
        )
        raw_profile = raw_runtime.get("corridor_executor_profile")
        profile: CorridorExecutorProfile | None = None
        if raw_profile is not None:
            if not isinstance(raw_profile, dict):
                raise _ServiceConfigError("corridor executor profile is invalid")
            _expect_config_keys(
                raw_profile,
                _CORRIDOR_EXECUTOR_PROFILE_KEYS,
                "corridor_executor_profile",
            )
            capability_ref = _config_text(
                raw_profile.get("capability_ref"),
                "corridor capability_ref",
                maximum=512,
            )
            if capability_ref not in executor_refs:
                raise _ServiceConfigError("corridor capability is not frozen")
            code_sha256 = raw_profile.get("code_sha256")
            if not _is_sha256(code_sha256):
                raise _ServiceConfigError("corridor code digest is invalid")
            maximum_lifetime = raw_profile.get("maximum_lifetime_seconds")
            if type(maximum_lifetime) is not int or not 1 <= maximum_lifetime <= 300:
                raise _ServiceConfigError("corridor lifetime is invalid")
            try:
                profile = CorridorExecutorProfile(
                    capability_ref=capability_ref,
                    protocol_ref=_config_text(
                        raw_profile.get("protocol_ref"),
                        "corridor protocol_ref",
                        maximum=512,
                    ),
                    code_sha256=str(code_sha256),
                    image_digest=_config_text(
                        raw_profile.get("image_digest"),
                        "corridor image_digest",
                        maximum=512,
                    ),
                    runner_identity=_config_text(
                        raw_profile.get("runner_identity"),
                        "corridor runner_identity",
                        maximum=256,
                    ),
                    maximum_lifetime_seconds=maximum_lifetime,
                )
            except Exception as exc:
                raise _ServiceConfigError("corridor executor profile is invalid") from exc
        frozen[_ADMISSION_RUNTIME_KEY] = MappingProxyType(
            {
                "model_route_proof_ref": model_route_proof_ref,
                "corridor_executor_profile": profile,
            }
        )
    raw_model_runtime = value.get(_MODEL_RUNTIME_KEY)
    if raw_model_runtime is not None:
        frozen[_MODEL_RUNTIME_KEY] = _model_runtime_from_config(raw_model_runtime)
    raw_context_binding = value.get(_CONTEXT_BINDING_KEY)
    if raw_context_binding is not None:
        frozen[_CONTEXT_BINDING_KEY] = _context_binding_from_config(
            raw_context_binding
        )
    return MappingProxyType(frozen)


def _context_binding_from_config(value: object) -> Mapping[str, object]:
    """Parse an explicit additive v1-to-v2 context migration receipt."""

    if not isinstance(value, dict):
        raise _ServiceConfigError("context binding must be an object")
    _expect_config_keys(value, _CONTEXT_BINDING_KEYS, "context_binding")
    if value.get("context_schema_version") != "a1-context-v2":
        raise _ServiceConfigError("context schema version is invalid")
    for name in (
        "admission_authority_sha256",
        "operational_model_runtime_sha256",
    ):
        if not _is_sha256(value.get(name)):
            raise _ServiceConfigError(f"{name} is invalid")
    raw_receipt = value.get("migration_receipt")
    if raw_receipt is None:
        return MappingProxyType(
            {
                "context_schema_version": "a1-context-v2",
                "admission_authority_sha256": value["admission_authority_sha256"],
                "operational_model_runtime_sha256": value[
                    "operational_model_runtime_sha256"
                ],
                "migration_receipt": None,
            }
        )
    if not isinstance(raw_receipt, dict):
        raise _ServiceConfigError("context migration receipt is invalid")
    _expect_config_keys(
        raw_receipt, _CONTEXT_MIGRATION_KEYS, "context migration receipt"
    )
    if (
        raw_receipt.get("schema_id") != "ContextBindingMigrationReceipt"
        or raw_receipt.get("schema_version") != "1.0.0"
        or raw_receipt.get("ledger_rows_mutated") != 0
    ):
        raise _ServiceConfigError("context migration receipt semantics drifted")
    raw_from = raw_receipt.get("from_context_sha256s")
    if not isinstance(raw_from, list) or not 1 <= len(raw_from) <= 8:
        raise _ServiceConfigError("context migration sources are invalid")
    migration_from = tuple(raw_from)
    if (
        len(migration_from) != len(set(migration_from))
        or any(not _is_sha256(item) for item in migration_from)
        or not _is_sha256(raw_receipt.get("to_context_sha256"))
        or raw_receipt.get("admission_authority_sha256")
        != value.get("admission_authority_sha256")
        or raw_receipt.get("operational_model_runtime_sha256")
        != value.get("operational_model_runtime_sha256")
    ):
        raise _ServiceConfigError("context migration receipt binding is invalid")
    integrity_payload = {
        key: raw_receipt[key]
        for key in _CONTEXT_MIGRATION_KEYS
        if key != "integrity_sha256"
    }
    if raw_receipt.get("integrity_sha256") != canonical_json_sha256(
        integrity_payload
    ):
        raise _ServiceConfigError("context migration receipt integrity is invalid")
    return MappingProxyType(
        {
            "context_schema_version": "a1-context-v2",
            "admission_authority_sha256": value["admission_authority_sha256"],
            "operational_model_runtime_sha256": value[
                "operational_model_runtime_sha256"
            ],
            "migration_receipt": MappingProxyType(
                {**raw_receipt, "from_context_sha256s": migration_from}
            ),
        }
    )


def _capability_refs(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_CAPABILITY_REFS:
        raise _ServiceConfigError("capability refs are invalid")
    refs = tuple(_config_text(item, label, maximum=512) for item in value)
    if len(refs) != len(set(refs)):
        raise _ServiceConfigError("capability refs are invalid")
    return refs


def _model_runtime_from_config(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("model runtime binding is invalid")
    _expect_config_keys(value, _MODEL_RUNTIME_KEYS, "model_runtime")
    expected_digests = {
        "role_registry_sha256": _MODEL_ROLE_REGISTRY_SHA256,
        "role_evaluation_sha256": _MODEL_ROLE_EVALUATION_SHA256,
    }
    for name, expected in expected_digests.items():
        if value.get(name) != expected:
            raise _ServiceConfigError(f"{name} binding is stale")
    worker_ipc_extension_sha256 = value.get("worker_ipc_extension_sha256")
    if worker_ipc_extension_sha256 not in _MODEL_WORKER_IPC_EXTENSION_SHA256S:
        raise _ServiceConfigError("worker_ipc_extension_sha256 binding is stale")
    routing_profile_sha256 = value.get("routing_profile_sha256")
    if routing_profile_sha256 not in _MODEL_ROUTING_PROFILE_SHA256S:
        raise _ServiceConfigError("routing_profile_sha256 binding is stale")
    binding_revision = _config_text(
        value.get("binding_revision"), "binding_revision", maximum=128
    )
    budget_policy_ref = _config_budget_ref(
        value.get("budget_policy_ref"), "budget_policy_ref", "budget-policy"
    )
    budget_scope_ref = _config_budget_ref(
        value.get("budget_scope_ref"), "budget_scope_ref", "budget-scope"
    )
    limits: dict[str, int] = {}
    for name in (
        "max_active_calls",
        "max_reserved_tokens",
        "max_reserved_cost_units",
    ):
        raw = value.get(name)
        if type(raw) is not int or not 1 <= raw <= 9_007_199_254_740_991:
            raise _ServiceConfigError(f"{name} is invalid")
        limits[name] = raw
    raw_available = value.get("available_bindings")
    if not isinstance(raw_available, list) or len(raw_available) > 32:
        raise _ServiceConfigError("available model bindings are invalid")
    available = tuple(
        _config_text(item, "available model binding", maximum=256)
        for item in raw_available
    )
    if len(available) != len(set(available)):
        raise _ServiceConfigError("available model bindings are invalid")
    raw_overrides = value.get("role_binding_overrides")
    if not isinstance(raw_overrides, dict):
        raise _ServiceConfigError("role_binding_overrides must be an object")
    overrides: dict[str, str] = {}
    for raw_role, raw_binding in raw_overrides.items():
        role_name = _config_text(raw_role, "binding override role", maximum=128)
        if role_name not in _MODEL_BINDING_OVERRIDE_ROLES:
            raise _ServiceConfigError(
                "binding override role is not an active model role"
            )
        overrides[role_name] = _config_text(
            raw_binding, f"binding override for {role_name}", maximum=256
        )
    return MappingProxyType(
        {
            **expected_digests,
            "worker_ipc_extension_sha256": worker_ipc_extension_sha256,
            "routing_profile_sha256": routing_profile_sha256,
            "binding_revision": binding_revision,
            "budget_policy_ref": budget_policy_ref,
            "budget_scope_ref": budget_scope_ref,
            **limits,
            "available_bindings": available,
            "role_binding_overrides": MappingProxyType(overrides),
        }
    )


def _config_budget_ref(value: object, label: str, prefix: str) -> str:
    normalized = _config_text(value, label, maximum=96)
    marker = f"{prefix}:sha256:"
    if not normalized.startswith(marker) or not _is_sha256(
        normalized.removeprefix(marker)
    ):
        raise _ServiceConfigError(f"{label} is invalid")
    return normalized


def _validate_model_runtime_limits(
    frozen_bindings: Mapping[str, object] | None,
    a1_limits: Mapping[str, object] | None,
) -> None:
    runtime = _model_runtime_binding(frozen_bindings)
    if runtime is None or not isinstance(a1_limits, Mapping):
        raise ResearchdError("model runtime requires bounded A1 limits")
    cycle = a1_limits.get("cycle_limits")
    if not isinstance(cycle, Mapping):
        raise ResearchdError("model runtime cycle limits are invalid")
    comparisons = (
        ("max_active_calls", "max_model_calls"),
        ("max_reserved_tokens", "max_tokens"),
        ("max_reserved_cost_units", "max_cost_units"),
    )
    for runtime_name, cycle_name in comparisons:
        runtime_value = runtime.get(runtime_name)
        cycle_value = cycle.get(cycle_name)
        if (
            type(runtime_value) is not int
            or type(cycle_value) is not int
            or runtime_value > cycle_value
        ):
            raise ResearchdError("model runtime exceeds the A1 cycle budget")


def _model_runtime_binding(
    frozen_bindings: Mapping[str, object] | None,
) -> Mapping[str, object] | None:
    if not isinstance(frozen_bindings, Mapping):
        return None
    runtime = frozen_bindings.get(_MODEL_RUNTIME_KEY)
    if runtime is None:
        return None
    if not isinstance(runtime, Mapping) or set(runtime) != _MODEL_RUNTIME_KEYS:
        raise ResearchdError("model runtime binding is invalid")
    expected_digests = {
        "role_registry_sha256": _MODEL_ROLE_REGISTRY_SHA256,
        "role_evaluation_sha256": _MODEL_ROLE_EVALUATION_SHA256,
    }
    if any(runtime.get(name) != expected for name, expected in expected_digests.items()):
        raise ResearchdError("model runtime digest binding is stale")
    if runtime.get("worker_ipc_extension_sha256") not in _MODEL_WORKER_IPC_EXTENSION_SHA256S:
        raise ResearchdError("model runtime digest binding is stale")
    if runtime.get("routing_profile_sha256") not in _MODEL_ROUTING_PROFILE_SHA256S:
        raise ResearchdError("model runtime routing binding is stale")
    if not isinstance(runtime.get("binding_revision"), str):
        raise ResearchdError("model runtime binding revision is invalid")
    available = runtime.get("available_bindings")
    if not isinstance(available, (list, tuple)) or len(available) > 32:
        raise ResearchdError("available model bindings are invalid")
    if any(not isinstance(item, str) or not item for item in available):
        raise ResearchdError("available model bindings are invalid")
    return runtime


def _config_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise _ServiceConfigError(f"{label} must be boolean")
    return value


def _a1_limits(
    value: object,
    *,
    a1_enabled: bool,
) -> Mapping[str, object] | None:
    if not a1_enabled:
        if value is not None:
            raise _ServiceConfigError("disabled A1 config cannot carry A1 limits")
        return None
    if not isinstance(value, dict):
        raise _ServiceConfigError("A1 limits must be an object")
    _expect_config_keys(value, _A1_LIMIT_KEYS, "a1_limits")
    cycle = _bounded_limit_map(
        value.get("cycle_limits"),
        maximums=_A1_CYCLE_LIMITS,
        label="cycle_limits",
    )
    daily = _bounded_limit_map(
        value.get("daily_limits"),
        maximums=_A1_DAILY_LIMITS,
        label="daily_limits",
    )
    if daily["max_admitted_experiments"] < cycle["max_admitted_experiments"]:
        raise _ServiceConfigError("daily admission limit is below cycle limit")
    if daily["max_model_calls"] < cycle["max_model_calls"]:
        raise _ServiceConfigError("daily model-call limit is below cycle limit")
    if daily["max_wall_seconds"] < cycle["max_wall_seconds"]:
        raise _ServiceConfigError("daily wall-time limit is below cycle limit")
    if daily["max_tokens"] < cycle["max_tokens"]:
        raise _ServiceConfigError("daily token limit is below cycle limit")
    if daily["max_cost_units"] < cycle["max_cost_units"]:
        raise _ServiceConfigError("daily cost limit is below cycle limit")
    return MappingProxyType({"cycle_limits": cycle, "daily_limits": daily})


def _derive_context_identities(
    frozen_bindings: Mapping[str, object],
    a1_limits: Mapping[str, object],
) -> Mapping[str, str]:
    """Derive reproducible v1/v2 context identities from normalized bindings."""

    policy_sha256 = frozen_bindings.get("policy_sha256")
    if not _is_sha256(policy_sha256):
        raise ResearchdError("A1 discovery policy binding is invalid")
    runtime_context: object = None
    runtime_binding = frozen_bindings.get(_ADMISSION_RUNTIME_KEY)
    if isinstance(runtime_binding, Mapping):
        profile = runtime_binding.get("corridor_executor_profile")
        profile_context: object = None
        if type(profile) is CorridorExecutorProfile:
            profile_context = {
                "capability_ref": profile.capability_ref,
                "protocol_ref": profile.protocol_ref,
                "code_sha256": profile.code_sha256,
                "image_digest": profile.image_digest,
                "runner_identity": profile.runner_identity,
                "maximum_lifetime_seconds": profile.maximum_lifetime_seconds,
                "runner_profile": profile.runner_profile,
                "input_ref_prefixes": profile.input_ref_prefixes,
            }
        runtime_context = {
            "model_route_proof_ref": runtime_binding.get("model_route_proof_ref"),
            "corridor_executor_profile": profile_context,
        }
    admission_authority_payload: dict[str, object] = {
        "a1_limits": a1_limits,
        "core_catalog_sha256": frozen_bindings.get("core_catalog_sha256"),
        "a1_catalog_sha256": frozen_bindings.get("a1_catalog_sha256"),
        "release_manifest_sha256": frozen_bindings.get("release_manifest_sha256"),
        "policy_sha256": policy_sha256,
    }
    if runtime_binding is not None:
        admission_authority_payload["admission_runtime"] = runtime_context
    model_runtime = frozen_bindings.get(_MODEL_RUNTIME_KEY)
    if model_runtime is not None and not isinstance(model_runtime, Mapping):
        raise ResearchdError("A1 model runtime binding is invalid")
    legacy_payload = dict(admission_authority_payload)
    if model_runtime is not None:
        legacy_payload["model_runtime"] = _json_copy(model_runtime)
    admission_authority_sha256 = canonical_json_sha256(admission_authority_payload)
    operational_model_runtime_sha256 = canonical_json_sha256(
        None if model_runtime is None else _json_copy(model_runtime)
    )
    context_v2_sha256 = canonical_json_sha256(
        {
            "context_schema_version": "a1-context-v2",
            "admission_authority_sha256": admission_authority_sha256,
            "operational_model_runtime_sha256": operational_model_runtime_sha256,
        }
    )
    return MappingProxyType(
        {
            "legacy_context_sha256": canonical_json_sha256(legacy_payload),
            "admission_authority_sha256": admission_authority_sha256,
            "operational_model_runtime_sha256": operational_model_runtime_sha256,
            "context_v2_sha256": context_v2_sha256,
        }
    )


def _discovery_config_from_authority(
    authority: PinnedOfflineAuthority,
    *,
    frozen_bindings: Mapping[str, object] | None,
    a1_limits: Mapping[str, object] | None,
    principal_roles: Mapping[int, str],
    now: datetime,
) -> DurableDiscoveryConfig:
    """Derive discovery trust only from already-frozen runtime inputs."""

    if not isinstance(frozen_bindings, Mapping) or not isinstance(a1_limits, Mapping):
        raise ResearchdError("A1 discovery requires frozen runtime bindings")
    policy_sha256 = frozen_bindings.get("policy_sha256")
    if not _is_sha256(policy_sha256):
        raise ResearchdError("A1 discovery policy binding is invalid")
    try:
        authority.verify_policy_binding(policy_sha256, now=now)
        # The resolver was fully copied and verified by PinnedOfflineAuthority;
        # no caller-controlled document is accepted at this boundary.
        policy = authority._resolve_policy(policy_sha256)  # type: ignore[attr-defined]
    except Exception as exc:
        raise ResearchdError("A1 discovery policy is unavailable") from exc
    payload = policy.get("payload")
    if not isinstance(payload, Mapping):
        raise ResearchdError("A1 discovery policy payload is invalid")
    covered = payload.get("covered_action_classes")
    required_actions = {"source_trigger_materialization", "scout_proposal"}
    if not isinstance(covered, (list, tuple)) or not required_actions.issubset(covered):
        raise ResearchdError("A1 discovery actions are not policy-covered")
    allow_rules = payload.get("allow_rules")
    origins: set[str] = set()
    if isinstance(allow_rules, (list, tuple)):
        for rule in allow_rules:
            if isinstance(rule, Mapping):
                value = rule.get("data_origin")
                if isinstance(value, (list, tuple)):
                    origins.update(item for item in value if isinstance(item, str))
    if not {"public", "already_registered"}.issubset(origins):
        raise ResearchdError("A1 discovery source origins are not policy-covered")

    source_repo = _text(
        "policy.payload.source_repo", payload.get("source_repo"), maximum=256
    )
    commit_sha = _text(
        "policy.payload.commit_sha", payload.get("commit_sha"), maximum=40
    )
    if len(commit_sha) != 40 or any(character not in _HEX_DIGITS for character in commit_sha):
        raise ResearchdError("A1 discovery policy commit is invalid")
    classification_value = policy.get("classification")
    classification = {
        "D0_PUBLIC": "D0",
        "D1_INTERNAL_SANITIZED": "D1",
    }.get(classification_value)
    if classification is None:
        raise ResearchdError("A1 discovery accepts only D0/D1 policy state")
    cycle = a1_limits.get("cycle_limits")
    if not isinstance(cycle, Mapping):
        raise ResearchdError("A1 discovery cycle limits are invalid")
    source_rate_limit = cycle.get("max_model_calls")
    if type(source_rate_limit) is not int or source_rate_limit < 0:
        raise ResearchdError("A1 discovery source rate limit is invalid")
    energy = {
        "wall_seconds": cycle.get("max_wall_seconds"),
        "cpu_seconds": cycle.get("max_cpu_seconds"),
        "memory_mib": cycle.get("max_memory_mib"),
        "output_bytes": cycle.get("max_output_bytes"),
        "tokens": cycle.get("max_tokens"),
        "cost_units": cycle.get("max_cost_units"),
    }
    collectors = {
        f"collector:uid:{uid}": f"collector:uid:{uid}"
        for uid, role in principal_roles.items()
        if role == "collector"
    }
    if len(collectors) != 1:
        raise ResearchdError("A1 discovery requires exactly one collector principal")
    identities = _derive_context_identities(frozen_bindings, a1_limits)
    context_binding = frozen_bindings.get(_CONTEXT_BINDING_KEY)
    context_schema_version = "a1-context-v1"
    admission_authority_sha256: str | None = None
    operational_model_runtime_sha256: str | None = None
    migration_from_context_sha256s: tuple[str, ...] = ()
    if context_binding is None:
        context_sha256 = identities["legacy_context_sha256"]
    else:
        if not isinstance(context_binding, Mapping):
            raise ResearchdError("A1 context binding is invalid")
        context_schema_version = "a1-context-v2"
        admission_authority_sha256 = identities["admission_authority_sha256"]
        operational_model_runtime_sha256 = identities[
            "operational_model_runtime_sha256"
        ]
        context_sha256 = identities["context_v2_sha256"]
        migration = context_binding.get("migration_receipt")
        if (
            context_binding.get("admission_authority_sha256")
            != admission_authority_sha256
            or context_binding.get("operational_model_runtime_sha256")
            != operational_model_runtime_sha256
        ):
            raise ResearchdError("A1 context migration binding drifted")
        if migration is not None:
            if (
                not isinstance(migration, Mapping)
                or migration.get("to_context_sha256") != context_sha256
            ):
                raise ResearchdError("A1 context migration binding drifted")
            sources = migration.get("from_context_sha256s")
            if not isinstance(sources, tuple):
                raise ResearchdError("A1 context migration sources are invalid")
            migration_from_context_sha256s = sources
    try:
        executor_refs = frozen_bindings.get("executor_capability_refs")
        evaluator_refs = frozen_bindings.get("evaluator_capability_refs")
        if not isinstance(executor_refs, tuple) or not isinstance(evaluator_refs, tuple):
            raise ResearchdError("A1 admission capability bindings are invalid")
        runtime_binding = frozen_bindings.get(_ADMISSION_RUNTIME_KEY)
        admission_config: DurableAdmissionConfig | None = None
        evidence_prefixes: tuple[str, ...] | None = None
        if runtime_binding is not None:
            if not isinstance(runtime_binding, Mapping):
                raise ResearchdError("A1 admission runtime binding is invalid")
            profile = runtime_binding.get("corridor_executor_profile")
            if profile is not None and type(profile) is not CorridorExecutorProfile:
                raise ResearchdError("A1 corridor executor profile is invalid")
            route_ref = runtime_binding.get("model_route_proof_ref")
            if not isinstance(route_ref, str):
                raise ResearchdError("A1 model route proof binding is invalid")
            admission_config = DurableAdmissionConfig(
                cycle_limits=cycle,
                daily_limits=a1_limits["daily_limits"],
                executor_capability_refs=executor_refs,
                evaluator_capability_refs=evaluator_refs,
                model_route_proof_ref=route_ref,
                corridor_executor_profile=profile,
                corridor_lifetime_seconds=(
                    profile.maximum_lifetime_seconds
                    if type(profile) is CorridorExecutorProfile
                    else 120
                ),
            )
            evidence_prefixes = ("public:", "registered:", "cas:sha256:")
        return DurableDiscoveryConfig(
            policy_sha256=policy_sha256,
            context_sha256=context_sha256,
            classification=classification,
            root_energy=energy,
            remaining_energy=energy,
            allowed_source_prefixes=("public:", "registered:"),
            allowed_evidence_prefixes=evidence_prefixes,
            collector_bindings=collectors,
            repository_id=source_repo,
            head_sha=commit_sha,
            base_sha=commit_sha,
            release_manifest_sha256=str(
                frozen_bindings.get("release_manifest_sha256")
            ),
            context_schema_version=context_schema_version,
            admission_authority_sha256=admission_authority_sha256,
            operational_model_runtime_sha256=operational_model_runtime_sha256,
            migration_from_context_sha256s=migration_from_context_sha256s,
            maximum_source_triggers_per_window=min(1_024, max(1, source_rate_limit)),
            source_rate_window_seconds=60,
            admission=admission_config,
        )
    except Exception as exc:
        raise ResearchdError("A1 discovery runtime binding is invalid") from exc


def _bounded_limit_map(
    value: object,
    *,
    maximums: Mapping[str, int],
    label: str,
) -> Mapping[str, int]:
    if not isinstance(value, dict):
        raise _ServiceConfigError(f"{label} must be an object")
    _expect_config_keys(value, frozenset(maximums), label)
    bounded: dict[str, int] = {}
    for name, maximum in maximums.items():
        item = value.get(name)
        if type(item) is not int or not 0 < item <= maximum:
            raise _ServiceConfigError(f"{label} exceeds the frozen policy")
        bounded[name] = item
    return MappingProxyType(bounded)


def _quota_bytes(value: object) -> int:
    if type(value) is not int or value <= 0 or value > _MAX_CONFIG_QUOTA_BYTES:
        raise _ServiceConfigError("quota is invalid")
    return value


def _deadline_seconds(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _ServiceConfigError("deadline is invalid")
    deadline = float(value)
    if not math.isfinite(deadline) or not 0 < deadline <= 5:
        raise _ServiceConfigError("deadline is invalid")
    return deadline


def _authority_from_config(config: Mapping[str, object]) -> PinnedOfflineAuthority:
    trusted = _trusted_issuers(config.get("trusted_issuers"))
    policies = _authority_document_map(
        config.get("policy_snapshots"),
        schema_id="PolicySnapshot",
        sha256_keys=True,
    )
    approvals = _authority_document_map(
        config.get("approval_receipts"),
        schema_id="ApprovalReceipt",
        sha256_keys=False,
    )
    try:
        return PinnedOfflineAuthority(
            trusted_issuers=trusted,
            policy_snapshots=policies,
            approval_receipts=approvals,
        )
    except Exception as exc:
        raise _ServiceConfigError("authority config is invalid") from exc


def _trusted_issuers(value: object) -> dict[str, TrustedIssuer]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("trusted issuers must be an object")
    _expect_config_keys(value, _TRUSTED_SCHEMAS, "trusted_issuers")
    trusted: dict[str, TrustedIssuer] = {}
    for schema_id in sorted(_TRUSTED_SCHEMAS):
        record = value[schema_id]
        if not isinstance(record, dict):
            raise _ServiceConfigError("trusted issuer record is invalid")
        _expect_config_keys(record, _TRUSTED_ISSUER_KEYS, "trusted_issuer")
        trusted[schema_id] = TrustedIssuer(
            _config_text(record.get("issuer_id"), "issuer_id", maximum=256),
            _config_text(
                record.get("authority_class"), "authority_class", maximum=256
            ),
        )
    return trusted


def _authority_document_map(
    value: object,
    *,
    schema_id: str,
    sha256_keys: bool,
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("authority resolver must be an object")
    result: dict[str, Mapping[str, Any]] = {}
    for key, document in value.items():
        text_key = _config_text(key, "authority resolver key", maximum=256)
        if sha256_keys and not _is_sha256(text_key):
            raise _ServiceConfigError("authority resolver key is invalid")
        result[text_key] = _authority_document(document, schema_id=schema_id)
    return result


def _authority_document(value: object, *, schema_id: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _ServiceConfigError("authority document must be an object")
    _reject_private_classification(value)
    _expect_config_keys(value, _AUTHORITY_COMMON_KEYS, "authority_document")
    if value.get("schema_id") != schema_id or value.get("schema_version") != "1.0.0":
        raise _ServiceConfigError("authority document schema is invalid")
    _config_text(value.get("object_id"), "authority object_id", maximum=256)
    _config_text(value.get("issued_at"), "authority issued_at", maximum=64)
    issuer = value.get("issuer")
    if not isinstance(issuer, dict):
        raise _ServiceConfigError("authority issuer is invalid")
    _expect_config_keys(issuer, _AUTHORITY_ISSUER_KEYS, "authority_issuer")
    _config_text(issuer.get("id"), "authority issuer id", maximum=256)
    _config_text(issuer.get("authority_class"), "authority class", maximum=256)
    _config_text(value.get("contour"), "authority contour", maximum=64)
    if value.get("classification") not in _PUBLIC_AUTHORITY_CLASSES:
        raise _ServiceConfigError("authority classification is invalid")
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise _ServiceConfigError("authority payload is invalid")
    if schema_id == "PolicySnapshot":
        _policy_payload(payload)
    elif schema_id == "ApprovalReceipt":
        _approval_payload(payload)
    integrity = value.get("integrity")
    if not isinstance(integrity, dict):
        raise _ServiceConfigError("authority integrity is invalid")
    _expect_config_keys(integrity, _AUTHORITY_INTEGRITY_KEYS, "authority_integrity")
    if not _is_sha256(integrity.get("payload_sha256")):
        raise _ServiceConfigError("authority payload digest is invalid")
    parent_refs = integrity.get("parent_refs")
    if not isinstance(parent_refs, list):
        raise _ServiceConfigError("authority parent refs are invalid")
    for parent_ref in parent_refs:
        _config_text(parent_ref, "authority parent ref", maximum=256)
    return value


def _policy_payload(value: Mapping[str, object]) -> None:
    _expect_config_keys(value, _POLICY_PAYLOAD_KEYS, "policy_payload")
    for name in ("source_repo", "commit_sha", "valid_from", "valid_until"):
        _config_text(value.get(name), name, maximum=256)
    if not _is_sha256(value.get("aggregate_sha256")):
        raise _ServiceConfigError("policy aggregate digest is invalid")
    _text_list(value.get("covered_action_classes"), "covered action class")
    for name in ("allow_rules", "deny_rules"):
        if not isinstance(value.get(name), list):
            raise _ServiceConfigError("policy rule list is invalid")


def _approval_payload(value: Mapping[str, object]) -> None:
    _expect_config_keys(value, _APPROVAL_PAYLOAD_KEYS, "approval_payload")
    _config_text(value.get("action_class"), "approval action class", maximum=256)
    for name in ("job_spec_sha256", "protocol_sha256", "policy_sha256"):
        if not _is_sha256(value.get(name)):
            raise _ServiceConfigError("approval digest is invalid")
    if not isinstance(value.get("quotas"), dict):
        raise _ServiceConfigError("approval quotas are invalid")
    if not isinstance(value.get("stop_conditions"), list):
        raise _ServiceConfigError("approval stop conditions are invalid")
    _config_text(value.get("expires_at"), "approval expiration", maximum=64)
    _config_text(value.get("nonce"), "approval nonce", maximum=256)
    if type(value.get("revoked")) is not bool:
        raise _ServiceConfigError("approval revoked flag is invalid")


def _reject_private_classification(value: object) -> None:
    if isinstance(value, dict):
        if (
            "classification" in value
            and value.get("classification") not in _PUBLIC_AUTHORITY_CLASSES
        ):
            raise _ServiceConfigError("authority classification is invalid")
        for item in value.values():
            _reject_private_classification(item)
    elif isinstance(value, list):
        for item in value:
            _reject_private_classification(item)


def _text_list(value: object, label: str) -> None:
    if not isinstance(value, list):
        raise _ServiceConfigError("text list is invalid")
    for item in value:
        _config_text(item, label, maximum=256)


def _expect_config_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    label: str,
) -> None:
    if set(value) != expected:
        raise _ServiceConfigError(f"{label} shape is invalid")


def _config_text(value: object, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise _ServiceConfigError(f"{label} must be normalized text")
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX_DIGITS for character in value)
    )


def _write_generic_error(stream: TextIO, line: str) -> None:
    stream.write(line)
    stream.flush()


def run(argv: Sequence[str] | None = None, *, stderr: TextIO | None = None) -> int:
    """Run ``ResearchDaemon`` from one owner-only service configuration."""

    error_stream = sys.stderr if stderr is None else stderr
    try:
        service = _service_arguments(argv)
        daemon = ResearchDaemon(
            service.runtime_root,
            authority=service.authority,
            allowed_uids=service.allowed_uids,
            principal_roles=service.principal_roles,
            a1_enabled=service.a1_enabled,
            frozen_bindings=service.frozen_bindings,
            a1_limits=service.a1_limits,
            runner_identity=service.runner_identity,
            input_quota_bytes=service.input_quota_bytes,
            checkpoint_quota_bytes=service.checkpoint_quota_bytes,
            artifact_quota_bytes=service.artifact_quota_bytes,
            maximum_input_bytes=service.maximum_input_bytes,
            deadline_seconds=service.deadline_seconds,
        )
    except Exception:
        _write_generic_error(error_stream, _CONFIG_ERROR_LINE)
        return 2

    stopping = False
    prior_handlers: dict[int, Any] = {}

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        nonlocal stopping
        stopping = True
        daemon.close()

    try:
        prior_handlers[signal.SIGTERM] = signal.getsignal(signal.SIGTERM)
        prior_handlers[signal.SIGINT] = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        daemon.start()
        try:
            daemon.serve_forever()
        except Exception:
            if stopping:
                return 0
            raise
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        if stopping:
            return 0
        _write_generic_error(error_stream, _RUNTIME_ERROR_LINE)
        return 3
    finally:
        for signum, handler in prior_handlers.items():
            try:
                signal.signal(signum, handler)
            except Exception:
                pass
        daemon.close()


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()


__all__ = ["ResearchdError", "ResearchDaemon", "run", "main"]
