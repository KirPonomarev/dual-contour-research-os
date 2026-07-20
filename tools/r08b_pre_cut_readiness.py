#!/usr/bin/env python3
"""Validate owner-only R08B two-role evidence without publishing private bytes."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any

from verify_final_release_freeze import (
    FinalReleaseFreezeError,
    V24_PLAN_ID,
    V24_PLAN_VERSION,
    verify_v24_status_docs,
)


ROOT = Path(__file__).resolve().parents[1]
STAGE_RECEIPT = "r08b-r6-private-two-role-precut-pass.json"
PROPOSAL_RECEIPT = "private-proposal-envelope.json"
CRITIC_MANIFEST = "critic-minimal-manifest.json"
EXPECTED_PRIVATE_STAGE_SHA256 = (
    "07ce02c895a0be88399418b1134ea943c407da513c08a24084a34763173ad14c"
)
EXPECTED_PROPOSAL_SHA256 = (
    "01db7297a081d8543862fb0aff866dbfc225c6d0c05787b4b232514bd3e86a67"
)
EXPECTED_CRITIC_MANIFEST_SHA256 = (
    "4f719e4c80add6a96f7a44a3e5561557dd70d1874f01e1b122acae334b272d2d"
)
PRIVATE_EVIDENCE_HEAD = "051fe747f3971142e04ba06c96977084d0f62b24"
PRIVATE_EVIDENCE_TREE = "b4bc5744c2415914005690167edd068964db6433"
PUBLIC_R6_RECEIPT = "docs/receipts/integration/r08b-r6-private-two-role-precut.json"
PUBLIC_R6_RECEIPT_SHA256 = (
    "cb0b39d553ee5f9b89903df28a44fb6a82e2cc27bcdfa870cd48e8d582e48188"
)
PUBLIC_R6_RECEIPT_HEAD = "671af7e7908830c45aff64f3bb0984ffa8661564"
PUBLIC_R6_RECEIPT_TREE = "13d6ff8ed7acf7a098cf62320db205c043f53aeb"
R7_AUTHORITY_HEAD = "e80f134ff36555822e4d89d5946465fc3dd43ed5"
R7_AUTHORITY_TREE = "93b8dd0bd079ba63c7f232b1ddbc581a5c9a3a43"
R7_AUTHORITY_CI_RUN = 29710065714
PACKET = "docs/receipts/release/r08b-deployment-operator-rollback-packet.json"
RUNBOOK = "docs/R08B_RELEASE_OPERATOR_RUNBOOK.md"


class ReadinessError(RuntimeError):
    """Raised when private evidence cannot support the sanitized claim."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReadinessError(message)


def _private_json(path: Path) -> tuple[dict[str, Any], str]:
    _require(path.exists() and not path.is_symlink(), f"{path.name} is missing or linked")
    mode = path.stat().st_mode
    _require(stat.S_ISREG(mode), f"{path.name} is not regular")
    _require(stat.S_IMODE(mode) == 0o600, f"{path.name} mode is not 0600")
    raw = path.read_bytes()
    _require(len(raw) <= 262_144, f"{path.name} exceeds the private receipt bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadinessError(f"{path.name} is not JSON") from exc
    _require(isinstance(value, dict), f"{path.name} is not an object")
    return value, _digest_bytes(raw)


def _public_json(path: Path) -> tuple[dict[str, Any], str]:
    _require(path.is_file() and not path.is_symlink(), f"public JSON missing:{path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadinessError(f"public JSON invalid:{path}") from exc
    _require(isinstance(value, dict), f"public JSON is not an object:{path}")
    return value, _digest_bytes(raw)


def _claims(stage: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
    payload = stage.get("payload")
    proposal_payload = proposal.get("payload")
    _require(isinstance(payload, dict), "private stage payload is missing")
    _require(isinstance(proposal_payload, dict), "proposal payload is missing")
    return {
        "candidate_sha": payload.get("candidate_sha"),
        "candidate_tree_sha": payload.get("candidate_tree_sha"),
        "candidate_ci": payload.get("candidate_exact_head_ci_run"),
        "fixture_generator": (payload.get("source") or {}).get("fixture_generator"),
        "worker_family": (payload.get("worker") or {}).get("declared_family"),
        "worker_group": (payload.get("worker") or {}).get(
            "declared_provenance_group"
        ),
        "worker_calls": (payload.get("worker") or {}).get("provider_calls"),
        "worker_reconciled": (payload.get("worker") or {}).get(
            "budget_reconciled"
        ),
        "worker_released": (payload.get("worker") or {}).get("budget_released"),
        "worker_retry": (payload.get("worker") or {}).get("automatic_retry"),
        "critic_family": (payload.get("critic") or {}).get("declared_family"),
        "critic_group": (payload.get("critic") or {}).get(
            "declared_provenance_group"
        ),
        "critic_calls": (payload.get("critic") or {}).get("provider_calls"),
        "critic_reconciled": (payload.get("critic") or {}).get(
            "budget_reconciled"
        ),
        "critic_released": (payload.get("critic") or {}).get("budget_released"),
        "critic_retry": (payload.get("critic") or {}).get("automatic_retry"),
        "critic_decision": (payload.get("critic") or {}).get("decision"),
        "critic_exact_token": (payload.get("critic") or {}).get(
            "output_exact_contract_token"
        ),
        "proposal_status": proposal_payload.get("status"),
        "proposal_calls": proposal_payload.get("total_provider_calls"),
        "proposal_maximum_calls": proposal_payload.get("maximum_provider_calls"),
        "proposal_retry": proposal_payload.get("automatic_retry"),
        "distinct_families": proposal_payload.get(
            "distinct_declared_model_families"
        ),
        "distinct_groups": proposal_payload.get(
            "distinct_declared_provenance_groups"
        ),
        "upstream_independence": proposal_payload.get(
            "upstream_provider_independence"
        ),
        "raw_public": proposal_payload.get("raw_or_credential_bytes_public"),
        "canonical_actions": proposal_payload.get("canonical_or_live_actions"),
        "grants_authority": proposal_payload.get("grants_authority"),
        "parent_pre_cut_complete": (payload.get("disposition") or {}).get(
            "parent_r08b_pre_cut_complete"
        ),
    }


def _validate_core_claims(claims: dict[str, Any]) -> None:
    _require(
        claims["candidate_sha"] is None
        and claims["candidate_tree_sha"] is None
        and claims["candidate_ci"] == "NOT_CUT",
        "candidate was selected prematurely",
    )
    _require(claims["fixture_generator"] is False, "source is a fixture")
    _require(
        isinstance(claims["worker_family"], str)
        and isinstance(claims["critic_family"], str)
        and claims["worker_family"] != claims["critic_family"],
        "declared model families are not distinct",
    )
    _require(
        isinstance(claims["worker_group"], str)
        and isinstance(claims["critic_group"], str)
        and claims["worker_group"] != claims["critic_group"],
        "declared provenance groups are not distinct",
    )
    _require(
        claims["worker_calls"] == 1
        and claims["critic_calls"] == 1
        and claims["proposal_calls"] == 2
        and claims["proposal_maximum_calls"] == 2,
        "two-role call accounting is invalid",
    )
    _require(
        claims["worker_reconciled"] is True
        and claims["worker_released"] is True
        and claims["critic_reconciled"] is True
        and claims["critic_released"] is True,
        "provider accounting is not reconciled",
    )
    _require(
        claims["worker_retry"] is False
        and claims["critic_retry"] is False
        and claims["proposal_retry"] is False,
        "automatic retry was enabled",
    )
    _require(
        claims["critic_decision"] == "PASS"
        and claims["critic_exact_token"] is True,
        "Critic did not return the exact PASS contract",
    )
    _require(
        claims["proposal_status"] == "PASS_PRE_CUT_TWO_ROLE_PROPOSAL_ENVELOPE",
        "proposal envelope did not pass",
    )
    _require(
        claims["distinct_families"] is True and claims["distinct_groups"] is True,
        "proposal diversity flags are false",
    )
    _require(
        claims["upstream_independence"] == "NOT_ESTABLISHED",
        "upstream independence was overstated",
    )
    _require(
        claims["raw_public"] is False
        and claims["canonical_actions"] == 0
        and claims["grants_authority"] is False,
        "privacy or authority boundary failed",
    )
    _require(
        claims["parent_pre_cut_complete"] is False,
        "component receipt overstates parent pre-cut completion",
    )


def _validate_receipts(
    stage: dict[str, Any],
    proposal: dict[str, Any],
    critic_manifest: dict[str, Any],
    *,
    expected_head: str,
    expected_tree: str,
    stage_sha256: str,
    proposal_sha256: str,
    critic_manifest_sha256: str,
) -> dict[str, Any]:
    _require(
        stage.get("schema_id") == "R08BPrivatePreCutStageReceipt"
        and stage.get("classification") == "PRIVATE_OWNER_ONLY",
        "private stage receipt identity is invalid",
    )
    payload = stage.get("payload")
    _require(isinstance(payload, dict), "private stage payload is missing")
    _require(
        payload.get("status") == "PASS_PRIVATE_TWO_ROLE_PROPOSAL_EVIDENCE",
        "private stage did not pass",
    )
    _require(
        payload.get("repository_head_sha") == expected_head
        and payload.get("repository_tree_sha") == expected_tree
        and payload.get("repository_remote_equal") is True
        and isinstance(payload.get("repository_exact_head_ci_run"), int),
        "repository evidence binding is invalid",
    )
    runtime = payload.get("runtime_subject")
    source = payload.get("source")
    worker = payload.get("worker")
    critic = payload.get("critic")
    envelope = payload.get("proposal_envelope")
    _require(
        all(isinstance(item, dict) for item in (runtime, source, worker, critic, envelope)),
        "private stage components are missing",
    )
    assert isinstance(runtime, dict)
    assert isinstance(source, dict)
    assert isinstance(worker, dict)
    assert isinstance(critic, dict)
    assert isinstance(envelope, dict)
    _require(
        runtime.get("current_worker_image_revision") == expected_head
        and runtime.get("release_relevant_bytes_equal") is True,
        "current runtime binding is invalid",
    )
    for name in (
        "core_image_id",
        "current_worker_image_id",
        "provider_profile_v3_sha256",
        "provider_tool_v3_sha256",
        "model_worker_v3_sha256",
        "runtime_policy_v3_sha256",
        "rendered_config_sha256",
    ):
        _require(isinstance(runtime.get(name), str), f"runtime {name} is missing")
    _require(
        source.get("source_class") == "D0_PUBLIC"
        and source.get("fixture_generator") is False
        and source.get("fresh_external_source_reads") == 0,
        "real source binding is invalid",
    )
    _require(
        envelope.get("private_receipt_sha256") == proposal_sha256
        and critic.get("sanitized_manifest_file_sha256") == critic_manifest_sha256,
        "private child receipt hashes do not reconcile",
    )
    _require(
        stage_sha256 == EXPECTED_PRIVATE_STAGE_SHA256
        and proposal_sha256 == EXPECTED_PROPOSAL_SHA256
        and critic_manifest_sha256 == EXPECTED_CRITIC_MANIFEST_SHA256,
        "private receipt immutable hash is unexpected",
    )

    _require(
        proposal.get("schema_id") == "R08BPrivatePreCutProposalEnvelopeReceipt"
        and proposal.get("classification") == "PRIVATE_OWNER_ONLY",
        "proposal receipt identity is invalid",
    )
    proposal_payload = proposal.get("payload")
    proposal_integrity = proposal.get("integrity")
    _require(
        isinstance(proposal_payload, dict) and isinstance(proposal_integrity, dict),
        "proposal receipt structure is invalid",
    )
    assert isinstance(proposal_payload, dict)
    assert isinstance(proposal_integrity, dict)
    _require(
        proposal_integrity.get("payload_sha256")
        == _digest_bytes(_canonical(proposal_payload)),
        "proposal payload integrity failed",
    )
    _require(
        proposal_payload.get("repository_head") == expected_head
        and proposal_payload.get("source_content_sha256")
        == source.get("content_sha256")
        and (proposal_payload.get("worker") or {}).get("output_sha256")
        == worker.get("output_sha256")
        and (proposal_payload.get("critic") or {}).get("output_sha256")
        == critic.get("output_sha256"),
        "proposal cross-binding failed",
    )
    _require(
        critic_manifest.get("status") == "PRIVATE_MINIMAL_CRITIC_CALL_GREEN"
        and critic_manifest.get("decision") == "PASS"
        and critic_manifest.get("output_exact_contract_token") is True
        and critic_manifest.get("output_sha256") == critic.get("output_sha256")
        and critic_manifest.get("actual_tokens") == critic.get("actual_tokens")
        and critic_manifest.get("provider_calls") == 1
        and critic_manifest.get("automatic_retry") is False,
        "Critic sanitized manifest failed",
    )
    _validate_core_claims(_claims(stage, proposal))

    return {
        "schema_id": "R08BSanitizedPreCutPrivateEvidenceManifest",
        "schema_version": "1.0.0",
        "status": "PASS_PRIVATE_TWO_ROLE_PROPOSAL_EVIDENCE",
        "repository_evidence_head_sha": expected_head,
        "repository_evidence_tree_sha": expected_tree,
        "repository_exact_head_ci_run": payload["repository_exact_head_ci_run"],
        "private_stage_receipt_sha256": stage_sha256,
        "proposal_envelope_sha256": proposal_sha256,
        "critic_sanitized_manifest_sha256": critic_manifest_sha256,
        "source": {
            "source_class": source["source_class"],
            "content_sha256": source["content_sha256"],
            "source_commit_sha": source["source_commit_sha"],
            "fixture_generator": False,
            "fresh_external_source_reads": 0,
        },
        "runtime_subject": {
            name: runtime[name]
            for name in (
                "core_image_id",
                "current_worker_image_id",
                "current_worker_image_platform",
                "current_worker_image_revision",
                "provider_profile_v3_sha256",
                "provider_tool_v3_sha256",
                "model_worker_v3_sha256",
                "runtime_policy_v3_sha256",
                "rendered_config_sha256",
            )
        },
        "worker": {
            name: worker[name]
            for name in (
                "role",
                "binding",
                "declared_family",
                "declared_provenance_group",
                "output_sha256",
                "actual_tokens",
                "provider_calls",
                "budget_reconciled",
                "budget_released",
                "automatic_retry",
            )
        },
        "critic": {
            name: critic[name]
            for name in (
                "role",
                "binding",
                "declared_family",
                "declared_provenance_group",
                "output_sha256",
                "actual_tokens",
                "provider_calls",
                "budget_reconciled",
                "budget_released",
                "automatic_retry",
                "decision",
                "output_exact_contract_token",
            )
        },
        "distinct_declared_model_families": True,
        "distinct_declared_provenance_groups": True,
        "upstream_provider_independence": "NOT_ESTABLISHED",
        "total_provider_calls": 2,
        "all_provider_accounting_reconciled": True,
        "raw_or_credential_bytes_public": False,
        "candidate_sha": None,
        "candidate_tree_sha": None,
        "candidate_exact_head_ci_run": "NOT_CUT",
        "parent_r08b_pre_cut_complete": False,
        "grants_authority": False,
    }


def _payload_integrity(document: dict[str, Any], *, schema_id: str) -> dict[str, Any]:
    _require(document.get("schema_id") == schema_id, f"schema mismatch:{schema_id}")
    payload = document.get("payload")
    integrity = document.get("integrity")
    _require(isinstance(payload, dict) and isinstance(integrity, dict), f"structure invalid:{schema_id}")
    _require(
        integrity.get("profile") == "core-json-sha256-v1"
        and integrity.get("payload_sha256") == _digest_bytes(_canonical(payload)),
        f"integrity invalid:{schema_id}",
    )
    return payload


def _validate_public_r6() -> dict[str, Any]:
    document, digest = _public_json(ROOT / PUBLIC_R6_RECEIPT)
    _require(digest == PUBLIC_R6_RECEIPT_SHA256, "public R6 receipt byte hash drift")
    _require(document.get("schema_id") == "IntegrationReceipt", "public R6 receipt schema")
    payload = document.get("payload")
    integrity = document.get("integrity")
    _require(isinstance(payload, dict) and isinstance(integrity, dict), "public R6 receipt structure")
    _require(
        integrity.get("payload_sha256") == _digest_bytes(_canonical(payload)),
        "public R6 receipt integrity",
    )
    repository = payload.get("repository_evidence")
    private = payload.get("private_evidence")
    delivery = payload.get("delivery_state")
    _require(
        isinstance(repository, dict)
        and repository.get("head_sha") == PRIVATE_EVIDENCE_HEAD
        and repository.get("tree_sha") == PRIVATE_EVIDENCE_TREE
        and repository.get("exact_head_ci_run") == 29708605741,
        "public R6 repository evidence",
    )
    _require(
        isinstance(private, dict)
        and private.get("stage_receipt_sha256") == EXPECTED_PRIVATE_STAGE_SHA256
        and private.get("proposal_envelope_sha256") == EXPECTED_PROPOSAL_SHA256
        and private.get("critic_sanitized_manifest_sha256") == EXPECTED_CRITIC_MANIFEST_SHA256,
        "public R6 private hash binding",
    )
    _require(
        isinstance(delivery, dict)
        and delivery.get("candidate_sha") is None
        and delivery.get("candidate_tree_sha") is None
        and delivery.get("candidate_exact_head_ci_run") == "NOT_CUT"
        and delivery.get("parent_r08b_pre_cut_complete") is False,
        "public R6 candidate boundary",
    )
    return payload


def _validate_packet() -> tuple[dict[str, Any], str]:
    document, digest = _public_json(ROOT / PACKET)
    payload = _payload_integrity(document, schema_id="R08BDeploymentOperatorRollbackPacket")
    _require(
        payload.get("plan_id") == V24_PLAN_ID
        and payload.get("plan_version") == V24_PLAN_VERSION,
        "packet CONTROL identity",
    )
    candidate = payload.get("candidate_resolution")
    authority = payload.get("authority")
    phases = payload.get("phase_boundaries")
    rollback = payload.get("rollback")
    _require(
        isinstance(candidate, dict)
        and candidate.get("candidate_release_sha") is None
        and candidate.get("candidate_tree_sha") is None
        and candidate.get("candidate_exact_head_ci_run") == "NOT_CUT"
        and candidate.get("resolution_source")
        == "post-squash exact-merge-head candidate-cut IntegrationReceipt",
        "packet candidate was cut prematurely",
    )
    _require(isinstance(authority, dict), "packet authority missing")
    forbidden = (
        "live_deployment",
        "vps_mutation",
        "live_restore",
        "live_rollback",
        "host_reboot",
        "canonical_mutation",
        "publication",
        "live_trading",
        "autonomous_live_security",
        "grants_authority",
    )
    _require(all(authority.get(key) is False for key in forbidden), "packet grants forbidden authority")
    _require(
        authority.get("timed_windows") == "OUT_OF_SCOPE"
        and authority.get("physically_deployed") is False
        and authority.get("operationally_proven") is False,
        "packet live/timed boundary",
    )
    _require(
        isinstance(phases, dict)
        and phases.get("R08C") == "LOCAL_ONLY"
        and phases.get("F10") == "AGENT_CREATED_DISPOSABLE_LINUX_ONLY"
        and phases.get("F11") == "AGENT_CREATED_ISOLATED_TARGETS_ONLY"
        and phases.get("F12_B") == "INDEPENDENT_READ_ONLY_OUTSIDE_GIT",
        "packet phase boundary",
    )
    _require(
        isinstance(rollback, dict)
        and rollback.get("target") == "EXACT_F09_FROZEN_RELEASE"
        and rollback.get("requires_distinct_fault_injection_fingerprint") is True
        and rollback.get("same_version_reinstall_counts") is False
        and rollback.get("live_target_allowed") is False,
        "packet rollback semantics",
    )
    inputs = payload.get("static_inputs")
    _require(isinstance(inputs, list) and inputs, "packet static inputs missing")
    seen: set[str] = set()
    for item in inputs:
        _require(isinstance(item, dict), "packet static input shape")
        path = item.get("path")
        expected = item.get("sha256")
        _require(isinstance(path, str) and path not in seen, "packet static input duplicate")
        seen.add(path)
        candidate_path = (ROOT / path).resolve()
        try:
            candidate_path.relative_to(ROOT)
        except ValueError as exc:
            raise ReadinessError("packet static input escapes repository") from exc
        _require(_file_sha(candidate_path) == expected, f"packet static input drift:{path}")
    required = {
        RUNBOOK,
        "README.md",
        "docs/ARCHITECTURE.md",
        "docs/PRODUCT_COMPLETION.md",
        "tools/candidate_image_build.py",
        "tools/verify_final_release_freeze.py",
        "ops/release/Containerfile",
        "ops/release/researchd.config.template.json",
        "ops/release/final-a1-runtime-policy.json",
        "ops/release/monitoring-recovery-policy.json",
        "ops/release/dependency-lock.json",
        "ops/release/THIRD_PARTY_NOTICES.md",
        "ops/release/image_e2e_harness.py",
        "tools/release_backup_restore.py",
        "ops/deploy/research-os-a1-final.service",
        "ops/deploy/research-os-connected-worker@.service",
        "ops/deploy/research-os-runtime-monitor.service",
        "ops/deploy/research-os-runtime-monitor.timer",
        "ops/deploy/research-os-backup.service",
        "ops/deploy/research-os-backup.timer",
    }
    _require(required.issubset(seen), "packet omits a required static input")
    return payload, digest


def verify_parent(args: argparse.Namespace) -> None:
    _require(args.expected_head == PUBLIC_R6_RECEIPT_HEAD, "unexpected accepted predecessor head")
    _require(args.expected_tree == PUBLIC_R6_RECEIPT_TREE, "unexpected accepted predecessor tree")
    _require(subprocess.run(["git", "merge-base", "--is-ancestor", args.expected_head, "HEAD"], cwd=ROOT, check=False).returncode == 0, "accepted predecessor is not an ancestor")
    _require(subprocess.run(["git", "merge-base", "--is-ancestor", R7_AUTHORITY_HEAD, "HEAD"], cwd=ROOT, check=False).returncode == 0, "R7 authority is not an ancestor")
    predecessor_tree = subprocess.run(
        ["git", "rev-parse", f"{args.expected_head}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    authority_tree = subprocess.run(
        ["git", "rev-parse", f"{R7_AUTHORITY_HEAD}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _require(
        predecessor_tree == args.expected_tree,
        "accepted predecessor tree drift",
    )
    _require(
        authority_tree == R7_AUTHORITY_TREE,
        "R7 authority tree drift",
    )
    directory = Path(args.private_evidence_dir).resolve()
    _require(directory.is_dir() and not directory.is_symlink(), "private evidence dir is invalid")
    _require(stat.S_IMODE(directory.stat().st_mode) == 0o700, "private evidence dir is not 0700")
    try:
        directory.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise ReadinessError("private evidence dir must be outside the repository")
    stage, stage_sha = _private_json(directory / STAGE_RECEIPT)
    proposal, proposal_sha = _private_json(directory / PROPOSAL_RECEIPT)
    critic, critic_sha = _private_json(directory / CRITIC_MANIFEST)
    private_manifest = _validate_receipts(
        stage,
        proposal,
        critic,
        expected_head=PRIVATE_EVIDENCE_HEAD,
        expected_tree=PRIVATE_EVIDENCE_TREE,
        stage_sha256=stage_sha,
        proposal_sha256=proposal_sha,
        critic_manifest_sha256=critic_sha,
    )
    public_payload = _validate_public_r6()
    try:
        status_result = verify_v24_status_docs(ROOT)
    except FinalReleaseFreezeError as exc:
        raise ReadinessError(f"V2.4 status validation:{exc}") from exc
    packet_payload, packet_sha = _validate_packet()
    runbook = (ROOT / RUNBOOK).read_text(encoding="utf-8")
    runbook_lower = runbook.lower()
    _require(
        "F10 clean disposable Linux install" in runbook
        and "F11 isolated restore and rollback campaign" in runbook
        and "live/vps" in runbook_lower
        and "out of scope" in runbook_lower,
        "runbook phase or authority boundary missing",
    )
    static_inputs = packet_payload["static_inputs"]
    static_hashes = {str(item["path"]): str(item["sha256"]) for item in static_inputs}
    parent_manifest: dict[str, Any] = {
        "schema_id": "R08BParentPreCutReadinessManifest",
        "schema_version": "1.0.0",
        "status": "PASS_PARENT_PRE_CUT_READINESS",
        "plan_id": V24_PLAN_ID,
        "plan_version": V24_PLAN_VERSION,
        "accepted_predecessor": {
            "head_sha": args.expected_head,
            "tree_sha": args.expected_tree,
            "receipt_sha256": PUBLIC_R6_RECEIPT_SHA256,
            "receipt_exact_head_ci_run": 29709929666,
        },
        "r7_authority": {
            "head_sha": R7_AUTHORITY_HEAD,
            "tree_sha": R7_AUTHORITY_TREE,
            "exact_head_ci_run": R7_AUTHORITY_CI_RUN,
        },
        "private_two_role_component": {
            "status": private_manifest["status"],
            "stage_receipt_sha256": stage_sha,
            "proposal_envelope_sha256": proposal_sha,
            "critic_sanitized_manifest_sha256": critic_sha,
            "sanitized_public_receipt_sha256": PUBLIC_R6_RECEIPT_SHA256,
            "total_provider_calls": private_manifest["total_provider_calls"],
            "upstream_provider_independence": private_manifest["upstream_provider_independence"],
            "fresh_provider_calls": 0,
        },
        "source": public_payload["source"],
        "runtime_subject": public_payload["runtime_subject"],
        "v2_4_status": {
            "status": status_result["status"],
            "document_sha256": status_result["documents"],
            "done_requires": status_result["done_requires"],
            "physically_deployed": False,
            "operationally_proven": False,
            "timed_windows": "OUT_OF_SCOPE",
        },
        "static_release_inputs": {
            "packet_ref": PACKET,
            "packet_sha256": packet_sha,
            "runbook_ref": RUNBOOK,
            "runbook_sha256": static_hashes[RUNBOOK],
            "input_count": len(static_hashes),
            "input_set_sha256": _digest_bytes(_canonical(static_hashes)),
        },
        "candidate_sha": None,
        "candidate_tree_sha": None,
        "candidate_exact_head_ci_run": "NOT_CUT",
        "candidate_cut_permitted_after_parent_pr_merge_head_ci": True,
        "release_claim_issued": False,
        "raw_or_credential_bytes_public": False,
        "live_or_vps_actions": 0,
        "timed_windows": "OUT_OF_SCOPE",
        "grants_authority": False,
    }
    output = Path(args.output).resolve()
    try:
        output.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise ReadinessError("sanitized parent output must remain outside the repository")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output.parent, 0o700)
    output.write_bytes(_canonical(parent_manifest))
    os.chmod(output, 0o600)
    print(
        json.dumps(
            {
                "status": parent_manifest["status"],
                "manifest_sha256": _file_sha(output),
                "packet_sha256": packet_sha,
                "static_input_count": len(static_hashes),
                "candidate_sha": None,
                "candidate_exact_head_ci_run": "NOT_CUT",
                "fresh_provider_calls": 0,
                "private_values_printed": False,
            },
            sort_keys=True,
        )
    )


def verify(args: argparse.Namespace) -> None:
    directory = Path(args.private_evidence_dir).resolve()
    _require(directory.is_dir() and not directory.is_symlink(), "private evidence dir is invalid")
    _require(
        stat.S_IMODE(directory.stat().st_mode) & 0o077 == 0,
        "private evidence dir is not owner-only",
    )
    try:
        directory.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise ReadinessError("private evidence dir must be outside the repository")

    stage, stage_sha = _private_json(directory / STAGE_RECEIPT)
    proposal, proposal_sha = _private_json(directory / PROPOSAL_RECEIPT)
    critic, critic_sha = _private_json(directory / CRITIC_MANIFEST)
    manifest = _validate_receipts(
        stage,
        proposal,
        critic,
        expected_head=args.expected_head,
        expected_tree=args.expected_tree,
        stage_sha256=stage_sha,
        proposal_sha256=proposal_sha,
        critic_manifest_sha256=critic_sha,
    )
    manifest["manifest_sha256"] = _digest_bytes(_canonical(manifest))
    output = Path(args.output).resolve()
    try:
        output.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise ReadinessError("sanitized output must remain outside the repository")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.write_bytes(_canonical(manifest))
    os.chmod(output, 0o600)
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "manifest_sha256": _digest_bytes(output.read_bytes()),
                "private_stage_receipt_sha256": stage_sha,
                "proposal_envelope_sha256": proposal_sha,
                "critic_sanitized_manifest_sha256": critic_sha,
                "total_provider_calls": 2,
                "candidate_sha": None,
                "parent_r08b_pre_cut_complete": False,
                "private_values_printed": False,
            },
            sort_keys=True,
        )
    )


def self_test(_: argparse.Namespace) -> None:
    valid = {
        "candidate_sha": None,
        "candidate_tree_sha": None,
        "candidate_ci": "NOT_CUT",
        "fixture_generator": False,
        "worker_family": "worker-family",
        "worker_group": "worker-group",
        "worker_calls": 1,
        "worker_reconciled": True,
        "worker_released": True,
        "worker_retry": False,
        "critic_family": "critic-family",
        "critic_group": "critic-group",
        "critic_calls": 1,
        "critic_reconciled": True,
        "critic_released": True,
        "critic_retry": False,
        "critic_decision": "PASS",
        "critic_exact_token": True,
        "proposal_status": "PASS_PRE_CUT_TWO_ROLE_PROPOSAL_ENVELOPE",
        "proposal_calls": 2,
        "proposal_maximum_calls": 2,
        "proposal_retry": False,
        "distinct_families": True,
        "distinct_groups": True,
        "upstream_independence": "NOT_ESTABLISHED",
        "raw_public": False,
        "canonical_actions": 0,
        "grants_authority": False,
        "parent_pre_cut_complete": False,
    }
    _validate_core_claims(valid)
    mutations = {
        "candidate": ("candidate_sha", "not-null"),
        "fixture": ("fixture_generator", True),
        "same-family": ("critic_family", "worker-family"),
        "same-group": ("critic_group", "worker-group"),
        "unreconciled": ("critic_reconciled", False),
        "retry": ("critic_retry", True),
        "critic-fail": ("critic_decision", "FAIL"),
        "wrong-count": ("proposal_calls", 3),
        "independence-overclaim": ("upstream_independence", "ESTABLISHED"),
        "parent-overclaim": ("parent_pre_cut_complete", True),
    }
    rejected: list[str] = []
    for name, (field, value) in mutations.items():
        candidate = deepcopy(valid)
        candidate[field] = value
        try:
            _validate_core_claims(candidate)
        except ReadinessError:
            rejected.append(name)
        else:
            raise ReadinessError(f"self-test accepted hostile mutation {name}")
    print(
        json.dumps(
            {
                "status": "R08B_PRE_CUT_READINESS_SELF_TEST_GREEN",
                "hostile_mutations_rejected": rejected,
                "hostile_mutation_count": len(rejected),
            },
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("verify")
    check.add_argument("--private-evidence-dir", required=True)
    check.add_argument("--expected-head", required=True)
    check.add_argument("--expected-tree", required=True)
    check.add_argument("--output", required=True)
    check.set_defaults(func=verify)
    test = subparsers.add_parser("self-test")
    test.set_defaults(func=self_test)
    parent = subparsers.add_parser("verify-parent")
    parent.add_argument("--private-evidence-dir", required=True)
    parent.add_argument("--expected-head", required=True)
    parent.add_argument("--expected-tree", required=True)
    parent.add_argument("--output", required=True)
    parent.set_defaults(func=verify_parent)
    args = parser.parse_args()
    try:
        args.func(args)
    except (OSError, ReadinessError, KeyError, subprocess.SubprocessError, TypeError) as exc:
        print(f"R08B pre-cut readiness failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
