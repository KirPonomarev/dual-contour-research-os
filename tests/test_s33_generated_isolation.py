from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.generated_execution import (  # noqa: E402
    GeneratedCodeArtifact,
    GeneratedExecutionError,
    GeneratedIsolationPolicy,
    SandboxBackendDescriptor,
    SandboxExecutionResult,
    SandboxExecutorRegistry,
    SandboxOutputArtifact,
    SandboxResourceUsage,
    plan_generated_execution,
    validate_generated_result,
)


PROFILE = ROOT / "provenance" / "generated-code-isolation-ladder-v1.json"
PROFILE_SHA = "a02fb9bb7e328f355cae083193f4ae63bfb299bf2e4c633ae496ccf31ca0ef89"
CODE_SHA = hashlib.sha256(b"synthetic generated code reference only").hexdigest()
INPUT_SHA = hashlib.sha256(b"synthetic public input").hexdigest()
IMAGE_SHA = hashlib.sha256(b"rootless synthetic OCI image").hexdigest()


def canonical(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


def seal(document: dict[str, object]) -> dict[str, object]:
    document["integrity"]["payload_sha256"] = canonical(document["payload"])  # type: ignore[index]
    return document


def authority(level: str = "L1", classification: str = "D0_PUBLIC"):
    job = seal({
        "schema_id": "JobSpec", "schema_version": "1.0.0", "object_id": "job:s33",
        "issued_at": "2026-07-19T00:00:00Z",
        "issuer": {"id": "admission", "authority_class": "admission-controller"},
        "contour": "bridge", "classification": classification,
        "payload": {
            "protocol_ref": "protocol:s33", "code_ref": "sha256:" + CODE_SHA,
            "input_refs": ["cas:sha256:" + INPUT_SHA],
            "image_digest": "sha256:" + IMAGE_SHA, "runner_profile": level,
            "network_policy": "offline", "resource_limits": {"cost_units": 2},
            "checkpoint_strategy": "append-only",
            "expected_output_contract": "GeneratedExecutionReceipt",
            "idempotency_key": "s33-synthetic",
        },
        "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
    })
    permit = seal({
        "schema_id": "Permit", "schema_version": "1.0.0", "object_id": "permit:s33",
        "issued_at": "2026-07-19T00:00:01Z",
        "issuer": {"id": "permit", "authority_class": "permit-authority"},
        "contour": "bridge", "classification": classification,
        "payload": {
            "subject": "runner:s33", "job_spec_sha256": canonical(job),
            "policy_snapshot_sha256": PROFILE_SHA, "code_sha256": CODE_SHA,
            "input_sha256": canonical(job["payload"]["input_refs"]),
            "image_digest": "sha256:" + IMAGE_SHA,
            "quotas": {"provider": level, "scope_limit": {"cost_units": 3}},
            "network_class": "offline", "not_before": "2026-07-19T00:00:00Z",
            "expires_at": "2026-07-19T00:10:00Z", "max_uses": 1,
            "nonce": "s33-nonce",
        },
        "integrity": {"payload_sha256": "0" * 64, "parent_refs": ["job:s33"]},
    })
    lease = seal({
        "schema_id": "AttemptLease", "schema_version": "1.0.0", "object_id": "lease:s33",
        "issued_at": "2026-07-19T00:00:02Z",
        "issuer": {"id": "researchd", "authority_class": "researchd"},
        "contour": "bridge", "classification": classification,
        "payload": {
            "attempt_id": "attempt:s33", "permit_ref": "permit:s33",
            "job_ref": "job:s33", "runner_identity": "runner:s33",
            "fencing_epoch": 7, "fencing_token": "s33-fence",
            "issued_at": "2026-07-19T00:00:02Z",
            "expires_at": "2026-07-19T00:05:00Z",
            "checkpoint_parent_ref": "cas:sha256:" + "9" * 64,
        },
        "integrity": {"payload_sha256": "0" * 64, "parent_refs": ["job:s33", "permit:s33"]},
    })
    return job, permit, lease


class GeneratedIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = GeneratedIsolationPolicy(PROFILE, expected_profile_sha256=PROFILE_SHA)
        self.artifact = GeneratedCodeArtifact(
            artifact_ref="cas:sha256:" + CODE_SHA, content_sha256=CODE_SHA,
            size_bytes=1024, generated_from_ref="proposal:s33",
            source_refs=("evidence:public",), language="python",
        )
        self.backend = SandboxBackendDescriptor(
            backend_ref="backend:rootless-s33", attestation_ref="attestation:s33",
            attestation_sha256="a" * 64, image_digest="sha256:" + IMAGE_SHA,
            supported_levels=("L1", "L2"),
        )
        self.registry = SandboxExecutorRegistry((self.backend,))

    def decision(self, level: str = "L1", *, enabled: bool = True):
        return plan_generated_execution(
            self.policy, self.registry, self.artifact, *authority(level),
            backend_ref=self.backend.backend_ref, feature_enabled=enabled,
        )

    def result(self, plan, **changes):
        output_sha = hashlib.sha256(b"synthetic output reference only").hexdigest()
        values = {
            "result_ref": "result:s33", "plan_sha256": plan.plan_sha256,
            "backend_ref": plan.backend_ref,
            "backend_attestation_sha256": plan.backend_attestation_sha256,
            "attempt_id": plan.attempt_id, "fencing_epoch": plan.fencing_epoch,
            "fencing_token_sha256": plan.fencing_token_sha256,
            "image_digest": plan.image_digest, "exit_classification": "SUCCESS",
            "resource_usage": SandboxResourceUsage(1, 100, 1024, 2, 1024, 128),
            "output_artifacts": (SandboxOutputArtifact(
                "cas:sha256:" + output_sha, output_sha, 128, "outputs/result.json",
                plan.plan_ref,
            ),),
        }
        values.update(changes)
        return SandboxExecutionResult(**values)

    def test_feature_is_off_by_default_and_executes_nothing(self) -> None:
        decision = self.decision(enabled=False)
        self.assertEqual(decision.status, "FEATURE_DISABLED")
        self.assertIsNone(decision.plan)
        self.assertFalse(decision.generated_code_executed)
        self.assertFalse(decision.side_effects)
        self.assertFalse(decision.grants_authority)

    def test_l1_and_l2_are_bounded_and_l3_is_unreachable(self) -> None:
        for level, timeout in (("L1", 5), ("L2", 15)):
            plan = self.decision(level).plan
            self.assertEqual(plan.level, level)
            self.assertEqual(plan.resource_caps["timeout_seconds"], timeout)
            self.assertEqual(plan.resource_caps["cost_units"], 2)
            self.assertEqual(plan.isolation["network_mode"], "NONE")
            self.assertEqual(plan.isolation["host_mounts"], "NONE")
            self.assertFalse(plan.embedded_executor)
            self.assertFalse(plan.grants_authority)
        with self.assertRaisesRegex(GeneratedExecutionError, "L3"):
            self.decision("L3")

    def test_parent_code_input_image_network_classification_and_cost_are_inherited(self) -> None:
        mutations = []
        job, permit, lease = authority()
        bad = deepcopy(job); bad["payload"]["network_policy"] = "connected"; seal(bad)
        mutations.append((bad, permit, lease))
        job, permit, lease = authority(classification="D2_DOMAIN_CONFIDENTIAL")
        mutations.append((job, permit, lease))
        job, permit, lease = authority(); permit["payload"]["code_sha256"] = "0" * 64; seal(permit)
        mutations.append((job, permit, lease))
        job, permit, lease = authority(); permit["payload"]["quotas"]["scope_limit"]["cost_units"] = 1; seal(permit)
        mutations.append((job, permit, lease))
        for values in mutations:
            with self.subTest(), self.assertRaises(GeneratedExecutionError):
                plan_generated_execution(
                    self.policy, self.registry, self.artifact, *values,
                    backend_ref=self.backend.backend_ref, feature_enabled=True,
                )

    def test_weak_unregistered_or_wrong_image_backend_is_denied(self) -> None:
        with self.assertRaises(GeneratedExecutionError):
            replace(self.backend, network_mode="BRIDGE")
        with self.assertRaises(GeneratedExecutionError):
            plan_generated_execution(
                self.policy, self.registry, self.artifact, *authority(),
                backend_ref="backend:missing", feature_enabled=True,
            )
        wrong = replace(self.backend, image_digest="sha256:" + "0" * 64)
        with self.assertRaises(GeneratedExecutionError):
            plan_generated_execution(
                self.policy, SandboxExecutorRegistry((wrong,)), self.artifact,
                *authority(), backend_ref=wrong.backend_ref, feature_enabled=True,
            )

    def test_CAS_provenance_path_and_plan_tamper_fail_closed(self) -> None:
        with self.assertRaises(GeneratedExecutionError):
            replace(self.artifact, artifact_ref="cas:sha256:" + "0" * 64)
        plan = self.decision().plan
        with self.assertRaises(GeneratedExecutionError):
            SandboxOutputArtifact("cas:sha256:" + "0" * 64, "1" * 64, 1, "../escape", plan.plan_ref)
        with self.assertRaisesRegex(GeneratedExecutionError, "plan integrity"):
            validate_generated_result(self.policy, replace(plan, job_ref="job:forged"), self.result(plan))

    def test_valid_result_is_mechanical_only_with_descriptive_rollback(self) -> None:
        plan = self.decision().plan
        receipt = validate_generated_result(self.policy, plan, self.result(plan))
        self.assertEqual(receipt.status, "MECHANICAL_EXECUTION_PASS")
        self.assertTrue(receipt.mechanical_only)
        self.assertFalse(receipt.scientific_truth_claimed)
        self.assertEqual(receipt.rollback.state, "WAIT_AUTHORITY")
        self.assertFalse(receipt.rollback.executable_payload_present)
        self.assertFalse(receipt.rollback.rollback_applied)
        self.assertFalse(receipt.deployment_changed)
        self.assertEqual(receipt.canonical_writes, 0)
        self.assertFalse(receipt.grants_authority)

    def test_resource_network_host_device_privilege_and_timeout_reject(self) -> None:
        plan = self.decision().plan
        cases = (
            {"network_calls": 1}, {"host_write_attempts": 1}, {"device_attempts": 1},
            {"privilege_escalation_attempts": 1}, {"timed_out": True},
            {"resource_usage": replace(self.result(plan).resource_usage, max_memory_bytes=plan.resource_caps["memory_bytes"] + 1)},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                receipt = validate_generated_result(self.policy, plan, self.result(plan, **changes))
                self.assertEqual(receipt.status, "REJECTED_BOUNDARY")
                self.assertFalse(receipt.rollback.rollback_applied)
                self.assertFalse(receipt.grants_authority)

    def test_stale_fence_attestation_image_or_output_provenance_is_denied(self) -> None:
        plan = self.decision().plan
        cases = (
            {"fencing_epoch": plan.fencing_epoch + 1},
            {"fencing_token_sha256": "0" * 64},
            {"backend_attestation_sha256": "0" * 64},
            {"image_digest": "sha256:" + "0" * 64},
            {"output_artifacts": (replace(self.result(plan).output_artifacts[0], source_plan_ref="sandbox-plan:foreign"),)},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(GeneratedExecutionError):
                validate_generated_result(self.policy, plan, self.result(plan, **changes))

    def test_module_has_no_executor_process_network_dynamic_code_or_host_IO(self) -> None:
        path = ROOT / "src" / "research_bridge" / "generated_execution.py"
        tree = ast.parse(path.read_text())
        imported = set()
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.add(node.func.id)
        self.assertTrue(imported.isdisjoint({"subprocess", "socket", "urllib", "requests", "docker"}))
        self.assertTrue(calls.isdisjoint({"eval", "exec", "compile", "open", "system", "popen"}))
        registry = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "SandboxExecutorRegistry")
        methods = {node.name for node in registry.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(methods, {"__init__", "resolve"})


if __name__ == "__main__":
    unittest.main()
