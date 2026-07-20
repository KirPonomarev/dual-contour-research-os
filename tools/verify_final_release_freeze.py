#!/usr/bin/env python3
"""Verify the S38 final source candidate freeze without granting deployment."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping

from capability_proof import CapabilityProofError, validate_capability_proof
from release_currentness import (
    ReleaseCurrentnessError,
    assess_capability_for_release,
    validate_release_currentness_context,
)


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = "b2c2e6a8c4e0a364ef82e8e51540433aa91430d4"
TREE = "7d6bd1e13d651950cced23dfe75a24946a3218fc"
CATALOGS = {"core": ("contracts/catalog.json", "13bdac3a60227826550771635d7367854a8a5477240ed06b2c31198dbd6f5c50"), "a1": ("contracts/a1/v1/catalog.json", "eab6401e6fc1460433a7b45b052c0218f3d26a90e6489a234bf2d51d2269dbe1"), "e5": ("contracts/e5/v1/catalog.json", "254e6cd624f91e37b0d186937f4b71acb7177c216e44e782540d76ba8c33696b")}
MANIFEST = "docs/receipts/release/s38-final-release-manifest.json"
INVENTORY = "docs/receipts/release/s38-dependency-notice-inventory.json"
PACKET = "ops/deploy/s38-final-deployment-packet.json"

V24_PLAN_ID = "DCR_OS_AUTONOMOUS_V2_3_NO_BRAKES_20260719"
V24_PLAN_VERSION = "2.4.0-fast-working-release"
V24_STATUS_DOCS = (
    "README.md",
    "docs/ARCHITECTURE.md",
    "docs/PRODUCT_COMPLETION.md",
)
V24_STATUS_KEYS = (
    "PLAN_ID",
    "PLAN_VERSION",
    "STATUS",
    "PRODUCT_CODE_COMPLETE",
    "PRODUCT_DONE",
    "RELEASE_DONE",
    "REAL_BOUNDED_RESEARCH_OPERATION_READY",
    "MASTER_PLAN_DONE",
    "PHYSICALLY_DEPLOYED",
    "OPERATIONALLY_PROVEN",
    "TIMED_WINDOWS",
    "LIVE_VPS_DEPLOYMENT",
    "DONE_REQUIRES",
)
V24_IN_PROGRESS_STATUS = {
    "PLAN_ID": V24_PLAN_ID,
    "PLAN_VERSION": V24_PLAN_VERSION,
    "STATUS": "IN_PROGRESS",
    "PRODUCT_CODE_COMPLETE": "true",
    "PRODUCT_DONE": "false",
    "RELEASE_DONE": "false",
    "REAL_BOUNDED_RESEARCH_OPERATION_READY": "false",
    "MASTER_PLAN_DONE": "false",
    "PHYSICALLY_DEPLOYED": "false",
    "OPERATIONALLY_PROVEN": "false",
    "TIMED_WINDOWS": "OUT_OF_SCOPE",
    "LIVE_VPS_DEPLOYMENT": "OUT_OF_SCOPE",
    "DONE_REQUIRES": "F12_B_INDEPENDENT_AUDIT_PASS",
}


class FinalReleaseFreezeError(RuntimeError):
    pass


def _status_values(value: Mapping[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key in V24_STATUS_KEYS:
        item = value.get(key)
        if isinstance(item, bool):
            result[key] = str(item).lower()
        elif isinstance(item, str):
            result[key] = item
        else:
            raise FinalReleaseFreezeError(f"V2.4 status field missing or invalid:{key}")
    extras = set(value) - set(V24_STATUS_KEYS) - {"F12_A_STATUS", "F12_B_STATUS"}
    if extras:
        raise FinalReleaseFreezeError(f"V2.4 status has unexpected fields:{sorted(extras)}")
    return result


def validate_v24_status(
    value: Mapping[str, object],
    *,
    require_in_progress: bool = False,
) -> dict[str, str]:
    """Validate exact V2.4 identity and the only permitted terminal transition."""

    values = _status_values(value)
    if values["PLAN_ID"] != V24_PLAN_ID:
        raise FinalReleaseFreezeError("V2.4 PLAN_ID mismatch")
    if values["PLAN_VERSION"] != V24_PLAN_VERSION:
        raise FinalReleaseFreezeError("V2.4 PLAN_VERSION mismatch")
    invariant = {
        "PRODUCT_CODE_COMPLETE": "true",
        "PHYSICALLY_DEPLOYED": "false",
        "OPERATIONALLY_PROVEN": "false",
        "TIMED_WINDOWS": "OUT_OF_SCOPE",
        "LIVE_VPS_DEPLOYMENT": "OUT_OF_SCOPE",
        "DONE_REQUIRES": "F12_B_INDEPENDENT_AUDIT_PASS",
    }
    for key, expected in invariant.items():
        if values[key] != expected:
            raise FinalReleaseFreezeError(f"V2.4 invariant mismatch:{key}")
    completion_keys = (
        "PRODUCT_DONE",
        "RELEASE_DONE",
        "REAL_BOUNDED_RESEARCH_OPERATION_READY",
        "MASTER_PLAN_DONE",
    )
    status = values["STATUS"]
    if require_in_progress and status != "IN_PROGRESS":
        raise FinalReleaseFreezeError("frozen status document is not IN_PROGRESS")
    if status == "IN_PROGRESS":
        if any(values[key] != "false" for key in completion_keys):
            raise FinalReleaseFreezeError("premature V2.4 completion claim")
    elif status == "DONE":
        if any(values[key] != "true" for key in completion_keys):
            raise FinalReleaseFreezeError("V2.4 DONE is not atomic")
        if value.get("F12_A_STATUS") != "SEALED" or value.get("F12_B_STATUS") != "PASS":
            raise FinalReleaseFreezeError("V2.4 DONE lacks sealed F12-A/F12-B PASS")
    else:
        raise FinalReleaseFreezeError("invalid V2.4 STATUS")
    return values


def _extract_v24_status(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    blocks = re.findall(r"```text\n(.*?)\n```", text, flags=re.DOTALL)
    matches = [block for block in blocks if f"PLAN_ID={V24_PLAN_ID}" in block]
    if len(matches) != 1:
        raise FinalReleaseFreezeError(f"expected one V2.4 status block:{path}")
    values: dict[str, str] = {}
    for line in matches[0].splitlines():
        if "=" not in line:
            raise FinalReleaseFreezeError(f"malformed V2.4 status line:{path}")
        key, item = line.split("=", 1)
        if key in values:
            raise FinalReleaseFreezeError(f"duplicate V2.4 status key:{path}:{key}")
        values[key] = item
    if tuple(values) != V24_STATUS_KEYS:
        raise FinalReleaseFreezeError(f"V2.4 status field order/set mismatch:{path}")
    return values


def verify_v24_status_docs(root: Path = ROOT) -> dict[str, object]:
    digests: dict[str, str] = {}
    for ref in V24_STATUS_DOCS:
        path = root / ref
        values = _extract_v24_status(path)
        validate_v24_status(values, require_in_progress=True)
        if values != V24_IN_PROGRESS_STATUS:
            raise FinalReleaseFreezeError(f"V2.4 status value mismatch:{ref}")
        digests[ref] = _sha(path)
    return {
        "status": "V2.4_STATUS_DOCS_GREEN",
        "plan_id": V24_PLAN_ID,
        "plan_version": V24_PLAN_VERSION,
        "documents": digests,
        "done_requires": "F12_B_INDEPENDENT_AUDIT_PASS",
        "physically_deployed": False,
        "operationally_proven": False,
    }


def self_test_v24_status() -> dict[str, object]:
    validate_v24_status(V24_IN_PROGRESS_STATUS, require_in_progress=True)
    terminal = dict(V24_IN_PROGRESS_STATUS)
    terminal.update(
        {
            "STATUS": "DONE",
            "PRODUCT_DONE": "true",
            "RELEASE_DONE": "true",
            "REAL_BOUNDED_RESEARCH_OPERATION_READY": "true",
            "MASTER_PLAN_DONE": "true",
            "F12_A_STATUS": "SEALED",
            "F12_B_STATUS": "PASS",
        }
    )
    validate_v24_status(terminal)
    mutations: dict[str, tuple[str, object | None]] = {
        "missing-field": ("RELEASE_DONE", None),
        "plan-id-mismatch": ("PLAN_ID", "wrong"),
        "plan-version-mismatch": ("PLAN_VERSION", "2.4"),
        "premature-done": ("PRODUCT_DONE", "true"),
        "physical-live-overclaim": ("PHYSICALLY_DEPLOYED", "true"),
        "timed-window-overclaim": ("TIMED_WINDOWS", "IN_SCOPE"),
    }
    rejected: list[str] = []
    for name, (field, replacement) in mutations.items():
        candidate = deepcopy(V24_IN_PROGRESS_STATUS)
        if replacement is None:
            candidate.pop(field)
        else:
            candidate[field] = replacement
        try:
            validate_v24_status(candidate)
        except FinalReleaseFreezeError:
            rejected.append(name)
        else:
            raise FinalReleaseFreezeError(f"accepted hostile V2.4 status:{name}")
    for name, field, replacement in (
        ("done-without-f12b", "F12_B_STATUS", "PENDING"),
        ("done-non-atomic", "MASTER_PLAN_DONE", "false"),
    ):
        candidate = deepcopy(terminal)
        candidate[field] = replacement
        try:
            validate_v24_status(candidate)
        except FinalReleaseFreezeError:
            rejected.append(name)
        else:
            raise FinalReleaseFreezeError(f"accepted hostile terminal status:{name}")
    return {
        "status": "V2.4_STATUS_SELF_TEST_GREEN",
        "hostile_mutations_rejected": rejected,
        "hostile_mutation_count": len(rejected),
    }


def _load(path: Path) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value: raise FinalReleaseFreezeError(f"duplicate key:{path.name}")
            value[key] = item
        return value
    try: value = json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=lambda token: (_ for _ in ()).throw(FinalReleaseFreezeError("non-finite JSON")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: raise FinalReleaseFreezeError(f"invalid JSON:{path}") from exc
    if not isinstance(value, dict): raise FinalReleaseFreezeError(f"not object:{path}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def validate_manifest_historical(root: Path, manifest: Mapping[str, object]) -> dict[str, object]:
    payload, integrity = manifest.get("payload"), manifest.get("integrity")
    if not isinstance(payload, dict) or not isinstance(integrity, dict) or integrity.get("payload_sha256") != _payload_sha(payload):
        raise FinalReleaseFreezeError("manifest integrity")
    if manifest.get("schema_id") != "FinalCandidateReleaseManifest" or payload.get("candidate_release_sha") != CANDIDATE or payload.get("candidate_tree_sha") != TREE:
        raise FinalReleaseFreezeError("manifest candidate identity")
    if payload.get("release_state") != "FROZEN_AWAITING_HUMAN_DEPLOYMENT_APPROVAL" or payload.get("deployment_allowed") is not False or payload.get("grants_authority") is not False or payload.get("deployment_approval_receipt_ref") is not None:
        raise FinalReleaseFreezeError("manifest authority boundary")
    if payload.get("unresolved_critical_debt") != []:
        raise FinalReleaseFreezeError("critical debt unresolved")
    expected_catalogs = {key: digest for key, (_, digest) in CATALOGS.items()}
    if payload.get("catalog_sha256") != expected_catalogs:
        raise FinalReleaseFreezeError("catalog binding")
    inventory_ref = payload.get("dependency_notice_inventory_ref")
    if inventory_ref != INVENTORY or payload.get("dependency_notice_inventory_sha256") != _sha(root / INVENTORY):
        raise FinalReleaseFreezeError("dependency inventory binding")
    refs = payload.get("phase_integration_receipts")
    if not isinstance(refs, list) or len(refs) != 16 or len(set(refs)) != len(refs):
        raise FinalReleaseFreezeError("phase receipt set")
    for ref in refs:
        receipt = _load(root / str(ref)); body = receipt.get("payload"); receipt_integrity = receipt.get("integrity")
        if receipt.get("schema_id") != "IntegrationReceipt" or not isinstance(body, dict) or not isinstance(receipt_integrity, dict) or receipt_integrity.get("payload_sha256") != _payload_sha(body):
            raise FinalReleaseFreezeError(f"phase receipt integrity:{ref}")
        commit = body.get("integration_commit_sha")
        if not isinstance(commit, str) or subprocess.run(["git", "merge-base", "--is-ancestor", commit, CANDIDATE], cwd=root, capture_output=True, check=False).returncode:
            raise FinalReleaseFreezeError(f"phase receipt ancestry:{ref}")
    for ref in payload.get("capability_proof_refs", []):
        proof = _load(root / str(ref)); body = proof.get("payload"); integrity_value = proof.get("integrity")
        if not isinstance(body, dict) or not isinstance(integrity_value, dict) or integrity_value.get("payload_sha256") != _payload_sha(body):
            raise FinalReleaseFreezeError(f"capability proof integrity:{ref}")
    return dict(payload)


def validate_manifest(root: Path, manifest: Mapping[str, object]) -> dict[str, object]:
    """Validate a release only when every current-subject dimension is present."""

    payload = validate_manifest_historical(root, manifest)
    context_value = payload.get("currentness_context")
    if not isinstance(context_value, Mapping):
        raise FinalReleaseFreezeError("manifest currentness context missing")
    try:
        context = validate_release_currentness_context(root, context_value)
    except ReleaseCurrentnessError as exc:
        raise FinalReleaseFreezeError("manifest currentness context invalid") from exc
    if (
        payload.get("candidate_release_sha") != context["release_sha"]
        or payload.get("candidate_tree_sha") != context["tree_sha"]
    ):
        raise FinalReleaseFreezeError("manifest and current release subject differ")
    refs = payload.get("capability_proof_refs")
    if not isinstance(refs, list) or not refs:
        raise FinalReleaseFreezeError("current capability proof set missing")
    aggregate_ids = {
        "EVOLUTION_KERNEL_V1": "e1",
        "AUTONOMOUS_RESEARCH_E2_SHADOW": "e2",
        "EVOLUTION_E3_SHADOW": "e3",
    }
    seen: set[str] = set()
    for ref in refs:
        proof = _load(root / str(ref))
        try:
            structured = validate_capability_proof(proof)
        except CapabilityProofError as exc:
            raise FinalReleaseFreezeError(f"current capability proof invalid:{ref}") from exc
        body = structured["payload"]
        capability_id = str(body["capability_id"])
        if capability_id in seen:
            raise FinalReleaseFreezeError("duplicate current capability proof")
        seen.add(capability_id)
        aggregate = aggregate_ids.get(capability_id)
        try:
            if aggregate == "e1":
                from e1_aggregate_gate import validate_aggregate_receipt as validate_aggregate
                validate_aggregate(root, structured, currentness_context=context)
            elif aggregate == "e2":
                from e2_aggregate_gate import validate_aggregate_receipt as validate_aggregate
                validate_aggregate(root, structured, currentness_context=context)
            elif aggregate == "e3":
                from e3_aggregate_gate import validate_aggregate_receipt as validate_aggregate
                validate_aggregate(root, structured, currentness_context=context)
            elif capability_id == "REAL_PROVIDER_ROUTE_R04D":
                assess_capability_for_release(
                    root,
                    structured,
                    context,
                    code_sha256=str(body["code_sha256"]),
                    config_sha256=str(body["config_sha256"]),
                    policy_sha256=str(body["policy_sha256"]),
                    schema_sha256=str(body["schema_sha256"]),
                )
            else:
                raise FinalReleaseFreezeError(
                    f"capability is not accepted by the current release gate:{capability_id}"
                )
        except ReleaseCurrentnessError as exc:
            raise FinalReleaseFreezeError(f"capability proof is not current:{ref}") from exc
    if set(aggregate_ids) | {"REAL_PROVIDER_ROUTE_R04D"} != seen:
        raise FinalReleaseFreezeError("current capability proof coverage incomplete")
    return payload


def validate_inventory(root: Path, inventory: Mapping[str, object]) -> None:
    if inventory.get("candidate_release_sha") != CANDIDATE or inventory.get("private_or_domain_payloads") != 0 or inventory.get("grants_authority") is not False:
        raise FinalReleaseFreezeError("inventory boundary")
    records = [inventory.get("python_dependency_manifest"), inventory.get("release_dependency_lock"), inventory.get("notices")]
    records += list(inventory.get("licenses", [])) + list(inventory.get("sboms", []))
    for record in records:
        if not isinstance(record, Mapping) or _sha(root / str(record.get("path"))) != record.get("sha256"):
            raise FinalReleaseFreezeError("dependency inventory artifact drift")
    python = inventory.get("python_dependency_manifest")
    if not isinstance(python, Mapping) or python.get("new_runtime_dependencies_S23_S37") != 0:
        raise FinalReleaseFreezeError("unexpected runtime dependency")


def validate_packet(root: Path, packet: Mapping[str, object]) -> None:
    integrity = packet.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("profile") != "core-json-sha256-v1" or integrity.get("payload_sha256") != _payload_sha({key: value for key, value in packet.items() if key != "integrity"}):
        raise FinalReleaseFreezeError("deployment packet integrity")
    authority = packet.get("authority"); release = packet.get("release_manifest")
    if packet.get("candidate_release_sha") != CANDIDATE or packet.get("candidate_tree_sha") != TREE or not isinstance(release, Mapping) or release.get("ref") != MANIFEST or release.get("sha256") != _sha(root / MANIFEST):
        raise FinalReleaseFreezeError("deployment packet release binding")
    if not isinstance(authority, Mapping) or authority.get("status") != "WAIT_HUMAN_APPROVAL_REBIND_REQUIRED" or authority.get("requires_rebind_to_candidate") is not True or authority.get("deployment_approval_receipt_ref") is not None:
        raise FinalReleaseFreezeError("deployment approval state")
    forbidden = ("deployment_allowed", "reboot_allowed", "restore_allowed", "VPS_mutation_allowed", "canonical_mutation_allowed", "live_action_allowed", "grants_authority")
    if any(authority.get(key) is not False for key in forbidden):
        raise FinalReleaseFreezeError("deployment packet grants authority")


def inspect_historical(root: Path = ROOT) -> dict[str, object]:
    if subprocess.run(["git", "cat-file", "-e", CANDIDATE + "^{commit}"], cwd=root, capture_output=True, check=False).returncode:
        raise FinalReleaseFreezeError("candidate commit missing")
    tree = subprocess.run(["git", "rev-parse", CANDIDATE + "^{tree}"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    if tree != TREE: raise FinalReleaseFreezeError("candidate tree drift")
    for _, (path, digest) in CATALOGS.items():
        if _sha(root / path) != digest: raise FinalReleaseFreezeError("live catalog drift")
    inventory = _load(root / INVENTORY); manifest = _load(root / MANIFEST); packet = _load(root / PACKET)
    validate_inventory(root, inventory); payload = validate_manifest_historical(root, manifest); validate_packet(root, packet)
    sensitive = re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|/Users/|/Volumes/|sk-[A-Za-z0-9]{12,}")
    for ref in (MANIFEST, INVENTORY, PACKET):
        if sensitive.search((root / ref).read_text(encoding="utf-8")): raise FinalReleaseFreezeError("public safety scan")
    return {"status": "FINAL_CANDIDATE_FROZEN_WAIT_HUMAN_APPROVAL", "candidate_release_sha": CANDIDATE, "candidate_tree_sha": TREE, "phase_receipts": len(payload["phase_integration_receipts"]), "critical_debt": 0, "deployment_allowed": False, "grants_authority": False}


def inspect(root: Path = ROOT) -> dict[str, object]:
    """Validate current release eligibility; historical S38 must fail here."""

    if subprocess.run(["git", "cat-file", "-e", CANDIDATE + "^{commit}"], cwd=root, capture_output=True, check=False).returncode:
        raise FinalReleaseFreezeError("candidate commit missing")
    tree = subprocess.run(["git", "rev-parse", CANDIDATE + "^{tree}"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    if tree != TREE:
        raise FinalReleaseFreezeError("candidate tree drift")
    for _, (path, digest) in CATALOGS.items():
        if _sha(root / path) != digest:
            raise FinalReleaseFreezeError("live catalog drift")
    inventory = _load(root / INVENTORY)
    manifest = _load(root / MANIFEST)
    packet = _load(root / PACKET)
    validate_inventory(root, inventory)
    payload = validate_manifest(root, manifest)
    validate_packet(root, packet)
    return {
        "status": "CURRENT_FINAL_CANDIDATE_FROZEN_WAIT_HUMAN_APPROVAL",
        "candidate_release_sha": payload["candidate_release_sha"],
        "candidate_tree_sha": payload["candidate_tree_sha"],
        "phase_receipts": len(payload["phase_integration_receipts"]),
        "critical_debt": 0,
        "deployment_allowed": False,
        "grants_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    status_parser = subparsers.add_parser("verify-v2.4-status")
    status_parser.add_argument("--state-file")
    subparsers.add_parser("self-test-v2.4-status")
    args = parser.parse_args()
    try:
        if args.command == "verify-v2.4-status":
            result = verify_v24_status_docs()
            if args.state_file:
                state = _load(Path(args.state_file))
                result["external_state"] = validate_v24_status(state)
        elif args.command == "self-test-v2.4-status":
            result = self_test_v24_status()
        else:
            result = inspect()
    except FinalReleaseFreezeError as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, sort_keys=True)); return 1
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())
