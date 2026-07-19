"""Feature-off generated-code isolation gate; no executor or subprocess lives here."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Mapping, Sequence


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_REF_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s\\]{1,511}$")
_CAS_RE = re.compile(r"^cas:sha256:([a-f0-9]{64})$")
_IMAGE_RE = re.compile(r"^sha256:([a-f0-9]{64})$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_LEVELS = ("L1", "L2")


class GeneratedExecutionError(RuntimeError):
    """A generated execution authority, isolation or provenance check failed closed."""


class GeneratedIsolationPolicy:
    """Load the exact feature-off L1/L2 isolation policy."""

    def __init__(self, profile_path: str | Path, *, expected_profile_sha256: str) -> None:
        profile = _load_profile(profile_path, expected_profile_sha256)
        if set(profile) != {
            "profile_id", "schema_version", "status", "feature_enabled_by_default",
            "allowed_classifications", "levels", "artifact_limits", "required_backend",
            "statuses", "invariants",
        }:
            raise GeneratedExecutionError("generated isolation profile keys drifted")
        expected_levels = {
            "L1": {
                "timeout_seconds": 5, "cpu_millis": 500,
                "memory_bytes": 134217728, "pids": 32,
                "workspace_bytes": 8388608, "output_bytes": 1048576,
            },
            "L2": {
                "timeout_seconds": 15, "cpu_millis": 1000,
                "memory_bytes": 268435456, "pids": 64,
                "workspace_bytes": 16777216, "output_bytes": 2097152,
            },
        }
        if (
            profile["profile_id"] != "generated-code-isolation-ladder-v1"
            or profile["schema_version"] != "1.0.0"
            or profile["status"] != "frozen-feature-off-isolation-policy"
            or profile["feature_enabled_by_default"] is not False
            or profile["allowed_classifications"] != ["D0_PUBLIC"]
            or profile["levels"] != expected_levels
            or profile["artifact_limits"] != {
                "max_code_bytes": 262144,
                "max_input_refs": 16,
                "max_output_artifacts": 16,
            }
            or profile["required_backend"] != {
                "isolation_kind": "ROOTLESS_OCI_CONTAINER",
                "network_mode": "NONE", "root_filesystem": "READ_ONLY",
                "workspace": "EPHEMERAL_TMPFS", "host_mounts": "NONE",
                "devices": "NONE", "linux_capabilities": "DROP_ALL",
                "no_new_privileges": True, "seccomp": "REQUIRED",
                "environment_allowlist": [],
            }
            or profile["statuses"] != [
                "FEATURE_DISABLED", "READY_FOR_ISOLATED_EXECUTOR",
                "MECHANICAL_EXECUTION_PASS", "REJECTED_BOUNDARY",
                "ROLLBACK_PROPOSAL_ONLY", "WAIT_AUTHORITY",
            ]
        ):
            raise GeneratedExecutionError("generated isolation profile semantics drifted")
        expected_invariants = {
            "L3_registered": False,
            "child_must_match_parent_code_input_image_and_fence": True,
            "child_cost_must_not_exceed_parent_permit": True,
            "network_calls_allowed": 0,
            "private_or_live_data_allowed": False,
            "absolute_or_host_paths_allowed": False,
            "unrestricted_code_execution": False,
            "artifact_provenance_required": True,
            "output_must_be_CAS_addressed": True,
            "rollback_is_descriptive_and_requires_authority": True,
            "automatic_deploy": False,
            "canonical_writes": 0,
            "grants_authority": False,
        }
        if profile["invariants"] != expected_invariants:
            raise GeneratedExecutionError("generated isolation invariants drifted")
        self.profile_sha256 = expected_profile_sha256
        self.levels = MappingProxyType({key: MappingProxyType(value) for key, value in expected_levels.items()})
        self.max_code_bytes = 262144
        self.max_input_refs = 16
        self.max_output_artifacts = 16
        self.feature_enabled_by_default = False


@dataclass(frozen=True, slots=True)
class GeneratedCodeArtifact:
    artifact_ref: str
    content_sha256: str
    size_bytes: int
    generated_from_ref: str
    source_refs: tuple[str, ...]
    language: str
    classification: str = "D0_PUBLIC"
    executable_payload_in_bridge: bool = False
    grants_authority: bool = False

    def __post_init__(self) -> None:
        match = _CAS_RE.fullmatch(self.artifact_ref)
        digest = _digest(self.content_sha256, "artifact content_sha256")
        if match is None or match.group(1) != digest:
            raise GeneratedExecutionError("generated artifact CAS identity mismatch")
        _positive(self.size_bytes, "artifact size_bytes")
        _reference(self.generated_from_ref, "generated_from_ref")
        _references(self.source_refs, "artifact source_refs")
        if self.language not in {"python", "javascript", "shell"}:
            raise GeneratedExecutionError("generated artifact language is not frozen")
        if (
            self.classification != "D0_PUBLIC"
            or self.executable_payload_in_bridge
            or self.grants_authority
        ):
            raise GeneratedExecutionError("generated artifact boundary widened")


@dataclass(frozen=True, slots=True)
class SandboxBackendDescriptor:
    backend_ref: str
    attestation_ref: str
    attestation_sha256: str
    image_digest: str
    supported_levels: tuple[str, ...]
    isolation_kind: str = "ROOTLESS_OCI_CONTAINER"
    network_mode: str = "NONE"
    root_filesystem: str = "READ_ONLY"
    workspace: str = "EPHEMERAL_TMPFS"
    host_mounts: str = "NONE"
    devices: str = "NONE"
    linux_capabilities: str = "DROP_ALL"
    no_new_privileges: bool = True
    seccomp: str = "REQUIRED"
    environment_allowlist: tuple[str, ...] = ()
    grants_authority: bool = False

    def __post_init__(self) -> None:
        _reference(self.backend_ref, "backend_ref")
        _reference(self.attestation_ref, "backend attestation_ref")
        _digest(self.attestation_sha256, "backend attestation_sha256")
        if _IMAGE_RE.fullmatch(self.image_digest) is None:
            raise GeneratedExecutionError("backend image digest is invalid")
        if self.supported_levels != _LEVELS:
            raise GeneratedExecutionError("backend must support exact L1/L2 ladder")
        if (
            self.isolation_kind != "ROOTLESS_OCI_CONTAINER"
            or self.network_mode != "NONE"
            or self.root_filesystem != "READ_ONLY"
            or self.workspace != "EPHEMERAL_TMPFS"
            or self.host_mounts != "NONE"
            or self.devices != "NONE"
            or self.linux_capabilities != "DROP_ALL"
            or self.no_new_privileges is not True
            or self.seccomp != "REQUIRED"
            or self.environment_allowlist != ()
            or self.grants_authority
        ):
            raise GeneratedExecutionError("backend isolation boundary widened")


class SandboxExecutorRegistry:
    """Immutable registry of attested external executors; it cannot execute code."""

    def __init__(self, backends: Sequence[SandboxBackendDescriptor]) -> None:
        if not isinstance(backends, Sequence) or isinstance(backends, (str, bytes)):
            raise GeneratedExecutionError("sandbox backends must be a sequence")
        if not backends or any(not isinstance(item, SandboxBackendDescriptor) for item in backends):
            raise GeneratedExecutionError("sandbox backend registry is empty or untyped")
        values = {item.backend_ref: item for item in backends}
        if len(values) != len(backends):
            raise GeneratedExecutionError("sandbox backend identity is duplicated")
        self._backends = MappingProxyType(values)

    def resolve(self, backend_ref: str, level: str) -> SandboxBackendDescriptor:
        ref = _reference(backend_ref, "backend_ref")
        if level not in _LEVELS:
            raise GeneratedExecutionError("L3 or unknown execution level is unreachable")
        try:
            backend = self._backends[ref]
        except KeyError as exc:
            raise GeneratedExecutionError("sandbox backend is not registered") from exc
        if level not in backend.supported_levels:
            raise GeneratedExecutionError("sandbox backend does not support level")
        return backend


@dataclass(frozen=True, slots=True)
class IsolationRollbackPlan:
    rollback_ref: str
    plan_sha256: str
    artifact_ref: str
    backend_ref: str
    actions: tuple[str, ...]
    state: str = "WAIT_AUTHORITY"
    executable_payload_present: bool = False
    rollback_applied: bool = False
    deployment_changed: bool = False
    canonical_writes: int = 0
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class SandboxLaunchPlan:
    plan_ref: str
    plan_sha256: str
    policy_sha256: str
    level: str
    artifact_ref: str
    backend_ref: str
    backend_attestation_sha256: str
    job_ref: str
    permit_ref: str
    lease_ref: str
    attempt_id: str
    fencing_epoch: int
    fencing_token_sha256: str
    image_digest: str
    input_refs: tuple[str, ...]
    resource_caps: Mapping[str, int]
    isolation: Mapping[str, object]
    rollback: IsolationRollbackPlan
    status: str = "READY_FOR_ISOLATED_EXECUTOR"
    feature_enabled: bool = True
    embedded_executor: bool = False
    network_enabled: bool = False
    host_paths_exposed: bool = False
    private_or_live_data: bool = False
    automatic_deploy: bool = False
    canonical_writes: int = 0
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class GeneratedExecutionDecision:
    status: str
    reason_code: str
    plan: SandboxLaunchPlan | None
    feature_enabled: bool
    generated_code_executed: bool = False
    side_effects: bool = False
    grants_authority: bool = False


@dataclass(frozen=True, slots=True)
class SandboxResourceUsage:
    wall_seconds: int
    cpu_millis: int
    max_memory_bytes: int
    max_pids: int
    workspace_bytes: int
    output_bytes: int

    def __post_init__(self) -> None:
        for name in (
            "wall_seconds", "cpu_millis", "max_memory_bytes", "max_pids",
            "workspace_bytes", "output_bytes",
        ):
            _nonnegative(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class SandboxOutputArtifact:
    artifact_ref: str
    content_sha256: str
    size_bytes: int
    relative_path: str
    source_plan_ref: str

    def __post_init__(self) -> None:
        match = _CAS_RE.fullmatch(self.artifact_ref)
        digest = _digest(self.content_sha256, "output content_sha256")
        if match is None or match.group(1) != digest:
            raise GeneratedExecutionError("output artifact CAS identity mismatch")
        _nonnegative(self.size_bytes, "output size_bytes")
        _relative_path(self.relative_path)
        _reference(self.source_plan_ref, "output source_plan_ref")


@dataclass(frozen=True, slots=True)
class SandboxExecutionResult:
    result_ref: str
    plan_sha256: str
    backend_ref: str
    backend_attestation_sha256: str
    attempt_id: str
    fencing_epoch: int
    fencing_token_sha256: str
    image_digest: str
    exit_classification: str
    resource_usage: SandboxResourceUsage
    output_artifacts: tuple[SandboxOutputArtifact, ...]
    network_calls: int = 0
    host_write_attempts: int = 0
    device_attempts: int = 0
    privilege_escalation_attempts: int = 0
    timed_out: bool = False

    def __post_init__(self) -> None:
        _reference(self.result_ref, "result_ref")
        _digest(self.plan_sha256, "result plan_sha256")
        _reference(self.backend_ref, "result backend_ref")
        _digest(self.backend_attestation_sha256, "result backend attestation")
        _reference(self.attempt_id, "result attempt_id")
        _positive(self.fencing_epoch, "result fencing_epoch")
        _digest(self.fencing_token_sha256, "result fencing token sha256")
        if _IMAGE_RE.fullmatch(self.image_digest) is None:
            raise GeneratedExecutionError("result image digest is invalid")
        if self.exit_classification not in {"SUCCESS", "FAILED", "RESOURCE_LIMIT"}:
            raise GeneratedExecutionError("result exit classification is invalid")
        if not isinstance(self.resource_usage, SandboxResourceUsage):
            raise GeneratedExecutionError("result resource usage is untyped")
        if not isinstance(self.output_artifacts, tuple) or any(
            not isinstance(item, SandboxOutputArtifact) for item in self.output_artifacts
        ):
            raise GeneratedExecutionError("result outputs are untyped")
        for name in (
            "network_calls", "host_write_attempts", "device_attempts",
            "privilege_escalation_attempts",
        ):
            _nonnegative(getattr(self, name), name)
        if type(self.timed_out) is not bool:
            raise GeneratedExecutionError("result timed_out must be boolean")


@dataclass(frozen=True, slots=True)
class GeneratedExecutionReceipt:
    receipt_ref: str
    plan_sha256: str
    result_ref: str
    status: str
    reason_codes: tuple[str, ...]
    output_artifact_refs: tuple[str, ...]
    rollback: IsolationRollbackPlan
    receipt_sha256: str
    mechanical_only: bool = True
    scientific_truth_claimed: bool = False
    network_calls: int = 0
    host_writes: int = 0
    deployment_changed: bool = False
    canonical_writes: int = 0
    grants_authority: bool = False


def plan_generated_execution(
    policy: GeneratedIsolationPolicy,
    registry: SandboxExecutorRegistry,
    artifact: GeneratedCodeArtifact,
    job_spec: Mapping[str, object],
    permit: Mapping[str, object],
    lease: Mapping[str, object],
    *,
    backend_ref: str,
    feature_enabled: bool = False,
) -> GeneratedExecutionDecision:
    """Build an immutable external launch plan; never run the artifact here."""

    if not isinstance(policy, GeneratedIsolationPolicy):
        raise GeneratedExecutionError("generated isolation policy is required")
    if not isinstance(registry, SandboxExecutorRegistry):
        raise GeneratedExecutionError("sandbox executor registry is required")
    if not isinstance(artifact, GeneratedCodeArtifact):
        raise GeneratedExecutionError("generated code artifact is required")
    if type(feature_enabled) is not bool:
        raise GeneratedExecutionError("feature_enabled must be boolean")
    if not feature_enabled:
        return GeneratedExecutionDecision(
            status="FEATURE_DISABLED", reason_code="FEATURE_OFF_BY_DEFAULT",
            plan=None, feature_enabled=False,
        )
    if artifact.size_bytes > policy.max_code_bytes:
        raise GeneratedExecutionError("generated code artifact exceeds frozen size")
    parent = _parent_binding(job_spec, permit, lease, artifact)
    if len(parent["input_refs"]) > policy.max_input_refs:
        raise GeneratedExecutionError("generated execution input capacity exceeded")
    level = str(parent["level"])
    backend = registry.resolve(backend_ref, level)
    if backend.image_digest != parent["image_digest"]:
        raise GeneratedExecutionError("backend image is not the parent-pinned image")
    caps = dict(policy.levels[level])
    caps["cost_units"] = int(parent["cost_units"])
    isolation = {
        "isolation_kind": "ROOTLESS_OCI_CONTAINER", "network_mode": "NONE",
        "root_filesystem": "READ_ONLY", "workspace": "EPHEMERAL_TMPFS",
        "host_mounts": "NONE", "devices": "NONE",
        "linux_capabilities": "DROP_ALL", "no_new_privileges": True,
        "seccomp": "REQUIRED", "environment_allowlist": (),
    }
    material = {
        "policy_sha256": policy.profile_sha256, "level": level,
        "artifact_ref": artifact.artifact_ref, "backend_ref": backend.backend_ref,
        "backend_attestation_sha256": backend.attestation_sha256,
        "job_ref": parent["job_ref"], "permit_ref": parent["permit_ref"],
        "lease_ref": parent["lease_ref"], "attempt_id": parent["attempt_id"],
        "fencing_epoch": parent["fencing_epoch"],
        "fencing_token_sha256": parent["fencing_token_sha256"],
        "image_digest": parent["image_digest"], "input_refs": parent["input_refs"],
        "resource_caps": caps, "isolation": isolation,
        "status": "READY_FOR_ISOLATED_EXECUTOR", "feature_enabled": True,
        "embedded_executor": False, "network_enabled": False,
        "host_paths_exposed": False, "private_or_live_data": False,
        "automatic_deploy": False, "canonical_writes": 0, "grants_authority": False,
    }
    plan_sha = _sha(material)
    plan_ref = "sandbox-plan:sha256:" + plan_sha
    rollback_material = {
        "plan_sha256": plan_sha, "artifact_ref": artifact.artifact_ref,
        "backend_ref": backend.backend_ref,
        "actions": ("disable-feature", "invalidate-artifact", "revoke-backend-attestation"),
        "state": "WAIT_AUTHORITY", "executable_payload_present": False,
        "rollback_applied": False, "deployment_changed": False,
        "canonical_writes": 0, "grants_authority": False,
    }
    rollback = IsolationRollbackPlan(
        rollback_ref="isolation-rollback:sha256:" + _sha(rollback_material),
        **rollback_material,
    )
    plan = SandboxLaunchPlan(
        plan_ref=plan_ref, plan_sha256=plan_sha,
        policy_sha256=policy.profile_sha256, level=level,
        artifact_ref=artifact.artifact_ref, backend_ref=backend.backend_ref,
        backend_attestation_sha256=backend.attestation_sha256,
        job_ref=str(parent["job_ref"]), permit_ref=str(parent["permit_ref"]),
        lease_ref=str(parent["lease_ref"]), attempt_id=str(parent["attempt_id"]),
        fencing_epoch=int(parent["fencing_epoch"]),
        fencing_token_sha256=str(parent["fencing_token_sha256"]),
        image_digest=str(parent["image_digest"]),
        input_refs=tuple(parent["input_refs"]),
        resource_caps=MappingProxyType(caps),
        isolation=MappingProxyType(isolation), rollback=rollback,
    )
    return GeneratedExecutionDecision(
        status="READY_FOR_ISOLATED_EXECUTOR", reason_code="PASS_FOR_FROZEN_ISOLATION_SCOPE",
        plan=plan, feature_enabled=True,
    )


def validate_generated_result(
    policy: GeneratedIsolationPolicy,
    plan: SandboxLaunchPlan,
    result: SandboxExecutionResult,
) -> GeneratedExecutionReceipt:
    """Validate attested result metadata and CAS outputs; never apply an outcome."""

    if not isinstance(policy, GeneratedIsolationPolicy) or not isinstance(plan, SandboxLaunchPlan):
        raise GeneratedExecutionError("typed policy and sandbox plan are required")
    if not isinstance(result, SandboxExecutionResult):
        raise GeneratedExecutionError("typed sandbox result is required")
    _validate_plan(policy, plan)
    if (
        result.plan_sha256 != plan.plan_sha256
        or result.backend_ref != plan.backend_ref
        or result.backend_attestation_sha256 != plan.backend_attestation_sha256
        or result.attempt_id != plan.attempt_id
        or result.fencing_epoch != plan.fencing_epoch
        or result.fencing_token_sha256 != plan.fencing_token_sha256
        or result.image_digest != plan.image_digest
    ):
        raise GeneratedExecutionError("sandbox result binding mismatch")
    if len(result.output_artifacts) > policy.max_output_artifacts:
        raise GeneratedExecutionError("sandbox output artifact capacity exceeded")
    if len({item.artifact_ref for item in result.output_artifacts}) != len(result.output_artifacts):
        raise GeneratedExecutionError("sandbox output artifact is duplicated")
    for item in result.output_artifacts:
        if item.source_plan_ref != plan.plan_ref:
            raise GeneratedExecutionError("sandbox output provenance mismatch")
    usage = result.resource_usage
    caps = plan.resource_caps
    exceeded = (
        usage.wall_seconds > caps["timeout_seconds"]
        or usage.cpu_millis > caps["cpu_millis"]
        or usage.max_memory_bytes > caps["memory_bytes"]
        or usage.max_pids > caps["pids"]
        or usage.workspace_bytes > caps["workspace_bytes"]
        or usage.output_bytes > caps["output_bytes"]
        or sum(item.size_bytes for item in result.output_artifacts) > caps["output_bytes"]
    )
    boundary_attempt = any((
        result.network_calls, result.host_write_attempts, result.device_attempts,
        result.privilege_escalation_attempts,
    ))
    reasons: set[str] = set()
    if exceeded or result.timed_out or result.exit_classification == "RESOURCE_LIMIT":
        reasons.add("RESOURCE_BOUNDARY_REACHED")
    if boundary_attempt:
        reasons.add("ISOLATION_BOUNDARY_ATTEMPTED")
    if result.exit_classification == "FAILED":
        reasons.add("EXECUTOR_REPORTED_FAILURE")
    status = "MECHANICAL_EXECUTION_PASS" if not reasons and result.exit_classification == "SUCCESS" else "REJECTED_BOUNDARY"
    if status == "MECHANICAL_EXECUTION_PASS":
        reasons.add("PASS_FOR_FROZEN_ISOLATION_SCOPE")
    material = {
        "plan_sha256": plan.plan_sha256, "result_ref": result.result_ref,
        "status": status, "reason_codes": tuple(sorted(reasons)),
        "output_artifact_refs": tuple(item.artifact_ref for item in result.output_artifacts),
        "rollback_ref": plan.rollback.rollback_ref, "mechanical_only": True,
        "scientific_truth_claimed": False, "network_calls": 0, "host_writes": 0,
        "deployment_changed": False, "canonical_writes": 0, "grants_authority": False,
    }
    digest = _sha(material)
    return GeneratedExecutionReceipt(
        receipt_ref="generated-execution-receipt:sha256:" + digest,
        plan_sha256=plan.plan_sha256, result_ref=result.result_ref,
        status=status, reason_codes=tuple(sorted(reasons)),
        output_artifact_refs=tuple(item.artifact_ref for item in result.output_artifacts),
        rollback=plan.rollback, receipt_sha256=digest,
    )


def _parent_binding(
    job_spec: Mapping[str, object],
    permit: Mapping[str, object],
    lease: Mapping[str, object],
    artifact: GeneratedCodeArtifact,
) -> dict[str, object]:
    job = _document(job_spec, "JobSpec", "admission-controller")
    permission = _document(permit, "Permit", "permit-authority")
    attempt = _document(lease, "AttemptLease", "researchd")
    if job["classification"] != "D0_PUBLIC" or permission["classification"] != "D0_PUBLIC" or attempt["classification"] != "D0_PUBLIC":
        raise GeneratedExecutionError("private or live classification is denied")
    jp = job["payload"]; pp = permission["payload"]; lp = attempt["payload"]
    assert isinstance(jp, Mapping) and isinstance(pp, Mapping) and isinstance(lp, Mapping)
    level = jp.get("runner_profile")
    if level not in _LEVELS:
        raise GeneratedExecutionError("L3 or unknown execution level is unreachable")
    if jp.get("network_policy") != "offline":
        raise GeneratedExecutionError("generated execution network must be offline")
    code_ref = jp.get("code_ref")
    if code_ref != "sha256:" + artifact.content_sha256:
        raise GeneratedExecutionError("parent code binding does not match artifact")
    input_refs = jp.get("input_refs")
    if not isinstance(input_refs, list) or not input_refs or any(_CAS_RE.fullmatch(str(item)) is None for item in input_refs):
        raise GeneratedExecutionError("parent input_refs are not portable CAS refs")
    if len(input_refs) != len(set(input_refs)):
        raise GeneratedExecutionError("parent input_refs are duplicated")
    image = jp.get("image_digest")
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise GeneratedExecutionError("parent image digest is invalid")
    limits = jp.get("resource_limits")
    if not isinstance(limits, Mapping) or set(limits) != {"cost_units"}:
        raise GeneratedExecutionError("parent resource limits are not frozen")
    cost = _positive(limits["cost_units"], "parent cost_units")
    if pp.get("job_spec_sha256") != _sha(job_spec):
        raise GeneratedExecutionError("permit does not bind exact JobSpec")
    if (
        pp.get("code_sha256") != artifact.content_sha256
        or pp.get("input_sha256") != _sha(input_refs)
        or pp.get("image_digest") != image
        or pp.get("network_class") != "offline"
        or pp.get("max_uses") != 1
    ):
        raise GeneratedExecutionError("permit child binding is wider than parent")
    quotas = pp.get("quotas")
    if not isinstance(quotas, Mapping) or quotas.get("provider") != level:
        raise GeneratedExecutionError("permit executor provider does not match level")
    scope = quotas.get("scope_limit")
    if not isinstance(scope, Mapping) or set(scope) != {"cost_units"}:
        raise GeneratedExecutionError("permit scope limit is invalid")
    if cost > _positive(scope["cost_units"], "permit cost scope"):
        raise GeneratedExecutionError("child cost exceeds parent permit")
    if lp.get("permit_ref") != permission["object_id"] or lp.get("job_ref") != job["object_id"]:
        raise GeneratedExecutionError("lease does not bind parent job and permit")
    if lp.get("runner_identity") != pp.get("subject"):
        raise GeneratedExecutionError("lease runner identity is transferred")
    epoch = _positive(lp.get("fencing_epoch"), "fencing_epoch")
    token = lp.get("fencing_token")
    if not isinstance(token, str) or not token:
        raise GeneratedExecutionError("fencing token is invalid")
    return {
        "level": level, "job_ref": job["object_id"],
        "permit_ref": permission["object_id"], "lease_ref": attempt["object_id"],
        "attempt_id": _reference(lp.get("attempt_id"), "attempt_id"),
        "fencing_epoch": epoch,
        "fencing_token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "image_digest": image, "input_refs": tuple(input_refs), "cost_units": cost,
    }


def _document(value: Mapping[str, object], schema_id: str, authority_class: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_id", "schema_version", "object_id", "issued_at", "issuer",
        "contour", "classification", "payload", "integrity",
    }:
        raise GeneratedExecutionError(f"{schema_id} shape mismatch")
    result = dict(value)
    if result["schema_id"] != schema_id or result["schema_version"] != "1.0.0":
        raise GeneratedExecutionError(f"{schema_id} identity mismatch")
    _reference(result["object_id"], f"{schema_id} object_id")
    issuer = result["issuer"]
    if not isinstance(issuer, Mapping) or issuer.get("authority_class") != authority_class:
        raise GeneratedExecutionError(f"{schema_id} issuer authority mismatch")
    payload = result["payload"]; integrity = result["integrity"]
    if not isinstance(payload, Mapping) or not isinstance(integrity, Mapping):
        raise GeneratedExecutionError(f"{schema_id} payload or integrity is invalid")
    if integrity.get("payload_sha256") != _sha(payload):
        raise GeneratedExecutionError(f"{schema_id} integrity mismatch")
    return result


def _validate_plan(policy: GeneratedIsolationPolicy, plan: SandboxLaunchPlan) -> None:
    if (
        plan.policy_sha256 != policy.profile_sha256
        or plan.level not in _LEVELS
        or plan.status != "READY_FOR_ISOLATED_EXECUTOR"
        or not plan.feature_enabled
        or plan.embedded_executor
        or plan.network_enabled
        or plan.host_paths_exposed
        or plan.private_or_live_data
        or plan.automatic_deploy
        or plan.canonical_writes
        or plan.grants_authority
        or plan.rollback.executable_payload_present
        or plan.rollback.rollback_applied
        or plan.rollback.deployment_changed
        or plan.rollback.canonical_writes
        or plan.rollback.grants_authority
    ):
        raise GeneratedExecutionError("sandbox launch plan boundary widened")
    if dict(plan.isolation) != {
        "isolation_kind": "ROOTLESS_OCI_CONTAINER", "network_mode": "NONE",
        "root_filesystem": "READ_ONLY", "workspace": "EPHEMERAL_TMPFS",
        "host_mounts": "NONE", "devices": "NONE",
        "linux_capabilities": "DROP_ALL", "no_new_privileges": True,
        "seccomp": "REQUIRED", "environment_allowlist": (),
    }:
        raise GeneratedExecutionError("sandbox launch isolation drifted")
    expected_caps = dict(policy.levels[plan.level])
    cost = plan.resource_caps.get("cost_units")
    _positive(cost, "plan cost_units")
    expected_caps["cost_units"] = cost
    if dict(plan.resource_caps) != expected_caps:
        raise GeneratedExecutionError("sandbox launch resource caps drifted")


def _load_profile(path: str | Path, expected_sha256: str) -> dict[str, object]:
    _digest(expected_sha256, "profile expected sha256")
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise GeneratedExecutionError("generated isolation profile unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise GeneratedExecutionError("generated isolation profile digest mismatch")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GeneratedExecutionError("generated isolation profile is invalid JSON") from exc
    if not isinstance(value, dict):
        raise GeneratedExecutionError("generated isolation profile must be an object")
    return value


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise GeneratedExecutionError("output relative path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise GeneratedExecutionError("output path escapes ephemeral workspace")
    return value


def _reference(value: object, name: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise GeneratedExecutionError(f"{name} must be a portable reference")
    if value.lower().startswith(("file:", "host:")) or value.startswith(("/", "~")):
        raise GeneratedExecutionError(f"{name} cannot reference a local path or host")
    return value


def _references(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise GeneratedExecutionError(f"{name} must be a non-empty tuple")
    result = tuple(_reference(item, name) for item in value)
    if len(result) != len(set(result)):
        raise GeneratedExecutionError(f"{name} must be unique")
    return result


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise GeneratedExecutionError(f"{name} must be sha256")
    return value


def _nonnegative(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise GeneratedExecutionError(f"{name} must be a non-negative safe integer")
    return value


def _positive(value: object, name: str) -> int:
    result = _nonnegative(value, name)
    if result == 0:
        raise GeneratedExecutionError(f"{name} must be positive")
    return result


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(_json_ready(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    ).hexdigest()


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


__all__ = [
    "GeneratedExecutionError", "GeneratedIsolationPolicy", "GeneratedCodeArtifact",
    "SandboxBackendDescriptor", "SandboxExecutorRegistry", "IsolationRollbackPlan",
    "SandboxLaunchPlan", "GeneratedExecutionDecision", "SandboxResourceUsage",
    "SandboxOutputArtifact", "SandboxExecutionResult", "GeneratedExecutionReceipt",
    "plan_generated_execution", "validate_generated_result",
]
