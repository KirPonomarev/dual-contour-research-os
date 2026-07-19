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
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import threading
from types import MappingProxyType
from typing import Any, TextIO

try:
    import fcntl
except ImportError:  # pragma: no cover - the runtime is explicitly Unix-only
    fcntl = None  # type: ignore[assignment]

from .admission import A1AdmissionKernel, canonical_json_sha256
from .authority import CorridorExecutorProfile, PinnedOfflineAuthority, TrustedIssuer
from .cas import ContentAddressedStore
from .control import ControlRouter
from .discovery import (
    DurableAdmissionConfig,
    DurableDiscoveryConfig,
    DurableDiscoveryService,
)
from .execution import (
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
from .ledger import JobLedger
from .validation import DeterministicL0Validator


_ROOT_MODE = 0o700
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
_PRINCIPAL_ROLES = frozenset({"operator", "collector", "scout"})
_A1_REQUIRED_ROLES = frozenset({"operator", "collector", "scout"})
_CORE_CATALOG_SHA256 = "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50"
_A1_CATALOG_SHA256 = "eab6401e6fc1460433a7b45b052c0218f3d26a90e6489a234bf2d51d2269dbe1"
_IPC_COMPATIBILITY_PROFILE_SHA256 = (
    "c9cdd8c51616ac843a6729166b6f21c9a44de24fac7559b86f842c7e1930ba04"
)
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
    "6377a7d60c0246d38d2fefe5a3a685409a3434342e41d0d88262ece8d326fa51"
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
        roles = _runtime_principal_roles(
            allowed,
            principal_roles=principal_roles,
            a1_enabled=a1_enabled,
        )
        if a1_enabled and not isinstance(frozen_bindings, Mapping):
            raise ResearchdError("A1 runtime requires frozen bindings")
        if a1_enabled and not isinstance(a1_limits, Mapping):
            raise ResearchdError("A1 runtime requires bounded limits")
        if not a1_enabled and frozen_bindings is not None:
            raise ResearchdError("disabled A1 runtime cannot carry frozen bindings")
        if not a1_enabled and a1_limits is not None:
            raise ResearchdError("disabled A1 runtime cannot carry A1 limits")
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
                router = ControlRouter(
                    self,
                    a1_backend=a1_backend,
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
                return {
                    "execution_receipt": _json_copy(immediate.execution_receipt),
                    "validation_receipt": _json_copy(immediate.validation_receipt),
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
            }

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
    _validate_private_directory(root, "runtime root")
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
            or stat.S_IMODE(opened.st_mode) != _ROOT_MODE
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
        or stat.S_IMODE(current.st_mode) != _ROOT_MODE
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
        if assigned != _A1_REQUIRED_ROLES:
            raise _ServiceConfigError("A1 principal role set is incomplete")
    elif assigned != {"operator"}:
        raise _ServiceConfigError("disabled A1 config must be operator-only")
    return MappingProxyType(roles)


def _runtime_principal_roles(
    allowed_uids: frozenset[int],
    *,
    principal_roles: Mapping[int, str] | None,
    a1_enabled: bool,
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
    if a1_enabled and assigned != _A1_REQUIRED_ROLES:
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
    if binding_keys not in (
        set(_FROZEN_BINDING_KEYS),
        set(_FROZEN_BINDING_KEYS | {_ADMISSION_RUNTIME_KEY}),
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
    return MappingProxyType(frozen)


def _capability_refs(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_CAPABILITY_REFS:
        raise _ServiceConfigError("capability refs are invalid")
    refs = tuple(_config_text(item, label, maximum=512) for item in value)
    if len(refs) != len(set(refs)):
        raise _ServiceConfigError("capability refs are invalid")
    return refs


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
    context_payload: dict[str, object] = {
        "a1_limits": a1_limits,
        "core_catalog_sha256": frozen_bindings.get("core_catalog_sha256"),
        "a1_catalog_sha256": frozen_bindings.get("a1_catalog_sha256"),
        "release_manifest_sha256": frozen_bindings.get("release_manifest_sha256"),
        "policy_sha256": policy_sha256,
    }
    if runtime_binding is not None:
        context_payload["admission_runtime"] = runtime_context
    context_sha256 = canonical_json_sha256(context_payload)
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
