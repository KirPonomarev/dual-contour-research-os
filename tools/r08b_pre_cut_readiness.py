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
from typing import Any


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


class ReadinessError(RuntimeError):
    """Raised when private evidence cannot support the sanitized claim."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
    args = parser.parse_args()
    try:
        args.func(args)
    except (OSError, ReadinessError, KeyError, TypeError) as exc:
        print(f"R08B pre-cut readiness failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
