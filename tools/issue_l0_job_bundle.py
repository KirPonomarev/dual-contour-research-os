#!/usr/bin/env python3
"""Issue one exact, short-lived, offline L0 submit bundle without executing it."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(TOOLS))

from build_pre_soak_capsule import (  # noqa: E402
    ALLOWED_CLASSIFICATIONS,
    CONFIG_NAME,
    IMAGE_DIGEST,
    INPUT_QUOTA_BYTES,
    L0_PROTOCOL_REF,
    L0_TEMPLATE_SHA256,
    MANIFEST_NAME,
    RELEASE_MANIFEST_SHA256,
    RELEASE_SHA,
    RUNNER_IDENTITY,
    CapsuleError,
    _file_hashes,
    _reject_constant,
    _strict_object,
    _write_owner_file,
)
from research_bridge import l0 as l0_module  # noqa: E402
from research_bridge.admission import admit, canonical_json_sha256  # noqa: E402
from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.researchd import _service_config_from_path  # noqa: E402


_CONTOURS = frozenset({"market", "security"})
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_CAS_REF_RE = re.compile(r"^cas:sha256:([a-f0-9]{64})$")
_MAX_JSON_BYTES = 262_144
_MANIFEST_FIELDS = frozenset(
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
_MANIFEST_PAYLOAD_FIELDS = frozenset(
    {
        "release_manifest_sha256",
        "release_manifest_ref",
        "release_sha",
        "image_digest",
        "release_policy_sha256",
        "release_config_sha256",
        "runtime_config_sha256",
        "authority_policy_sha256",
        "resume_approval_ref",
        "runner_identity",
        "network_class",
        "external_action_authority",
        "inputs",
        "file_hashes",
    }
)
_INPUT_RECORD_FIELDS = frozenset({"classification", "cas_ref", "sha256", "size_bytes"})


class BundleError(RuntimeError):
    """A capsule binding or bounded bundle issuance operation failed."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise BundleError("command arguments are invalid")


def _positive_sequence(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("sequence is invalid") from exc
    if parsed < 1 or parsed > 9_007_199_254_740_991:
        raise argparse.ArgumentTypeError("sequence is invalid")
    return parsed


def _lifetime(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("lifetime is invalid") from exc
    if parsed < 1 or parsed > 300:
        raise argparse.ArgumentTypeError("lifetime is invalid")
    return parsed


def _owner_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = os.lstat(path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_JSON_BYTES
        ):
            raise BundleError(f"{label} ownership, mode, or size is invalid")
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (CapsuleError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"{label} is invalid") from exc
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be an object")
    return value, raw


def _capsule_root(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise BundleError("capsule root is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise BundleError("capsule root ownership or mode is invalid")


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise BundleError(f"{label} is not a SHA-256 digest")
    return value


def _input_record(value: object, contour: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _INPUT_RECORD_FIELDS:
        raise BundleError(f"{contour} input record is invalid")
    classification = value.get("classification")
    digest = _sha256(value.get("sha256"), f"{contour} input digest")
    cas_ref = value.get("cas_ref")
    match = _CAS_REF_RE.fullmatch(cas_ref) if isinstance(cas_ref, str) else None
    size = value.get("size_bytes")
    if (
        classification not in ALLOWED_CLASSIFICATIONS
        or match is None
        or match.group(1) != digest
        or type(size) is not int
        or size < 0
    ):
        raise BundleError(f"{contour} input binding is invalid")
    return value


def _manifest(value: dict[str, Any]) -> Mapping[str, object]:
    if set(value) != _MANIFEST_FIELDS:
        raise BundleError("capsule manifest shape is invalid")
    payload = value.get("payload")
    integrity = value.get("integrity")
    if (
        value.get("schema_id") != "PreSoakCapsuleManifest"
        or value.get("schema_version") != "1.0.0"
        or value.get("contour") != "governance"
        or value.get("classification") != "D1_INTERNAL_SANITIZED"
        or not isinstance(payload, dict)
        or set(payload) != _MANIFEST_PAYLOAD_FIELDS
        or not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256", "parent_refs"}
        or integrity.get("payload_sha256") != canonical_json_sha256(payload)
        or value.get("object_id") != "pre-soak-capsule-" + canonical_json_sha256(payload)
    ):
        raise BundleError("capsule manifest identity or integrity is invalid")
    if (
        payload.get("release_manifest_sha256") != RELEASE_MANIFEST_SHA256
        or payload.get("release_sha") != RELEASE_SHA
        or payload.get("image_digest") != IMAGE_DIGEST
        or payload.get("runner_identity") != RUNNER_IDENTITY
        or payload.get("network_class") != "offline"
        or payload.get("external_action_authority") is not False
    ):
        raise BundleError("capsule release or runtime binding is invalid")
    _sha256(payload.get("release_policy_sha256"), "release policy digest")
    _sha256(payload.get("release_config_sha256"), "release config digest")
    _sha256(payload.get("runtime_config_sha256"), "runtime config digest")
    _sha256(payload.get("authority_policy_sha256"), "authority policy digest")
    inputs = payload.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != _CONTOURS:
        raise BundleError("capsule input map is invalid")
    for contour in sorted(_CONTOURS):
        _input_record(inputs[contour], contour)
    file_hashes = payload.get("file_hashes")
    if not isinstance(file_hashes, list) or not file_hashes:
        raise BundleError("capsule file inventory is empty")
    return payload


def _config_context(capsule: Path, manifest_payload: Mapping[str, object], now: datetime):
    config_path = capsule / CONFIG_NAME
    config, raw = _owner_json(config_path, "runtime config")
    if hashlib.sha256(raw).hexdigest() != manifest_payload["runtime_config_sha256"]:
        raise BundleError("runtime config digest differs from the capsule manifest")
    service = _service_config_from_path(str(config_path))
    if service.runtime_root != "runtime" or service.runner_identity != RUNNER_IDENTITY:
        raise BundleError("runtime config is not the frozen portable profile")
    policies = config.get("policy_snapshots")
    approvals = config.get("approval_receipts")
    policy_sha256 = manifest_payload["authority_policy_sha256"]
    approval_ref = manifest_payload["resume_approval_ref"]
    if (
        not isinstance(policies, dict)
        or set(policies) != {policy_sha256}
        or not isinstance(approvals, dict)
        or set(approvals) != {approval_ref}
    ):
        raise BundleError("runtime authority resolver differs from the capsule manifest")
    service.authority.verify_resume(str(approval_ref), now=now)
    return config, service


def _seal(document: dict[str, object]) -> dict[str, object]:
    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        raise BundleError("bundle authority integrity is invalid")
    integrity["payload_sha256"] = canonical_json_sha256(document["payload"])
    return document


def _issuer(config: Mapping[str, object], schema_id: str) -> dict[str, object]:
    trusted = config.get("trusted_issuers")
    if not isinstance(trusted, Mapping):
        raise BundleError("trusted issuer config is invalid")
    record = trusted.get(schema_id)
    if not isinstance(record, Mapping) or set(record) != {"issuer_id", "authority_class"}:
        raise BundleError("trusted issuer record is invalid")
    issuer_id = record.get("issuer_id")
    authority_class = record.get("authority_class")
    if not isinstance(issuer_id, str) or not isinstance(authority_class, str):
        raise BundleError("trusted issuer identity is invalid")
    return {"id": issuer_id, "authority_class": authority_class}


def _documents(
    *,
    config: Mapping[str, object],
    manifest: Mapping[str, object],
    manifest_sha256: str,
    contour: str,
    sequence: int,
    issued: datetime,
    lifetime_seconds: int,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    inputs = manifest["inputs"]
    assert isinstance(inputs, Mapping)
    record = _input_record(inputs[contour], contour)
    classification = str(record["classification"])
    input_refs = [str(record["cas_ref"])]
    token = manifest_sha256[:16]
    sequence_text = str(sequence)
    issued_at = issued.isoformat().replace("+00:00", "Z")
    expires_at = (issued + timedelta(seconds=lifetime_seconds)).isoformat().replace("+00:00", "Z")
    idempotency_key = f"pre-soak-{contour}-{sequence_text}-{token}"
    job_object_id = f"job-{idempotency_key}"
    permit_object_id = f"permit-{idempotency_key}"
    lease_object_id = f"lease-{idempotency_key}"
    authority_seed = {
        "capsule_manifest_sha256": manifest_sha256,
        "contour": contour,
        "sequence": sequence,
        "issued_at": issued_at,
    }
    job = _seal(
        {
            "schema_id": "JobSpec",
            "schema_version": "1.0.0",
            "object_id": job_object_id,
            "issued_at": issued_at,
            "issuer": _issuer(config, "JobSpec"),
            "contour": contour,
            "classification": classification,
            "payload": {
                "protocol_ref": L0_PROTOCOL_REF,
                "code_ref": f"sha256:{L0_TEMPLATE_SHA256}",
                "input_refs": input_refs,
                "image_digest": IMAGE_DIGEST,
                "runner_profile": "L0",
                "network_policy": "offline",
                "resource_limits": {"cost_units": 1},
                "checkpoint_strategy": "single-final-checkpoint",
                "expected_output_contract": "StagingEnvelope@1.0.0",
                "idempotency_key": idempotency_key,
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [f"capsule:sha256:{manifest_sha256}"],
            },
        }
    )
    policy_sha256 = str(manifest["authority_policy_sha256"])
    budget_scope_sha256 = canonical_json_sha256(
        {
            "capsule_manifest_sha256": manifest_sha256,
            "contour": contour,
            "sequence": sequence,
            "cost_units": 1,
        }
    )
    permit = _seal(
        {
            "schema_id": "Permit",
            "schema_version": "1.0.0",
            "object_id": permit_object_id,
            "issued_at": issued_at,
            "issuer": _issuer(config, "Permit"),
            "contour": contour,
            "classification": classification,
            "payload": {
                "subject": RUNNER_IDENTITY,
                "job_spec_sha256": canonical_json_sha256(job),
                "policy_snapshot_sha256": policy_sha256,
                "code_sha256": L0_TEMPLATE_SHA256,
                "input_sha256": canonical_json_sha256(input_refs),
                "image_digest": IMAGE_DIGEST,
                "quotas": {
                    "accounting_policy_ref": f"budget-policy:sha256:{policy_sha256}",
                    "budget_scope_ref": f"budget-scope:sha256:{budget_scope_sha256}",
                    "claims": 1,
                    "provider": "L0",
                    "scope_limit": {"cost_units": 1},
                    "trial_ref": f"trial:pre-soak-{contour}-{sequence_text}-{token}",
                },
                "network_class": "offline",
                "not_before": issued_at,
                "expires_at": expires_at,
                "max_uses": 1,
                "nonce": "sha256:" + canonical_json_sha256({**authority_seed, "kind": "permit"}),
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [job_object_id, f"policy:sha256:{policy_sha256}"],
            },
        }
    )
    lease = _seal(
        {
            "schema_id": "AttemptLease",
            "schema_version": "1.0.0",
            "object_id": lease_object_id,
            "issued_at": issued_at,
            "issuer": _issuer(config, "AttemptLease"),
            "contour": contour,
            "classification": classification,
            "payload": {
                "attempt_id": f"attempt-{idempotency_key}",
                "permit_ref": permit_object_id,
                "job_ref": job_object_id,
                "runner_identity": RUNNER_IDENTITY,
                "fencing_epoch": sequence,
                "fencing_token": "fence-" + canonical_json_sha256({**authority_seed, "kind": "fence"}),
                "issued_at": issued_at,
                "expires_at": expires_at,
                "checkpoint_parent_ref": "cas:sha256:" + "0" * 64,
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [job_object_id, permit_object_id],
            },
        }
    )
    return job, permit, lease


def issue_bundle(
    *,
    capsule: Path,
    contour: str,
    sequence: int,
    lifetime_seconds: int,
    output: Path,
    observed: datetime | None = None,
) -> dict[str, object]:
    if contour not in _CONTOURS:
        raise BundleError("contour must be market or security")
    if type(sequence) is not int or sequence < 1 or sequence > 9_007_199_254_740_991:
        raise BundleError("sequence is invalid")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
        raise BundleError("lifetime is invalid")
    if ".." in output.parts or output.name in {"", ".", ".."}:
        raise BundleError("bundle output path is unsafe")
    _capsule_root(capsule)
    try:
        capsule_resolved = capsule.resolve(strict=True)
        output_resolved = output.resolve(strict=False)
    except OSError as exc:
        raise BundleError("capsule or bundle output path is invalid") from exc
    if output_resolved == capsule_resolved or capsule_resolved in output_resolved.parents:
        raise BundleError("bundle output must remain outside the frozen capsule")

    manifest, manifest_raw = _owner_json(capsule / MANIFEST_NAME, "capsule manifest")
    manifest_payload = _manifest(manifest)
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if _file_hashes(capsule) != manifest_payload["file_hashes"]:
        raise BundleError("capsule file inventory differs from the manifest")
    moment = (observed or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    config, service = _config_context(capsule, manifest_payload, moment)

    inputs = manifest_payload["inputs"]
    assert isinstance(inputs, Mapping)
    record = _input_record(inputs[contour], contour)
    store = ContentAddressedStore(capsule / "runtime" / "input-cas", quota_bytes=INPUT_QUOTA_BYTES)
    stored = store.inspect(str(record["cas_ref"]))
    if stored.sha256 != record["sha256"] or stored.size_bytes != record["size_bytes"]:
        raise BundleError("capsule CAS object differs from the input binding")

    job, permit, lease = _documents(
        config=config,
        manifest=manifest_payload,
        manifest_sha256=manifest_sha256,
        contour=contour,
        sequence=sequence,
        issued=moment,
        lifetime_seconds=lifetime_seconds,
    )
    grant = admit(job, permit, lease, now=moment, authority=service.authority)
    validated_job = l0_module._validate_job(job)
    l0_module._validate_lease(lease, validated_job, RUNNER_IDENTITY)
    if (
        grant.contour != contour
        or grant.classification != record["classification"]
        or grant.runner_identity != RUNNER_IDENTITY
        or grant.fencing_epoch != sequence
        or grant.provider != "L0"
        or grant.reservation_cost_units != 1
        or grant.scope_limit_cost_units != 1
    ):
        raise BundleError("existing admission projection differs from requested authority")

    bundle = {"job_spec": job, "permit": permit, "lease": lease}
    bundle_sha256, _bundle_size = _write_owner_file(output, bundle)
    return {
        "status": "CREATED",
        "contour": contour,
        "sequence": sequence,
        "bundle_sha256": bundle_sha256,
        "expires_at": permit["payload"]["expires_at"],  # type: ignore[index]
        "external_action_authority": False,
    }


def _parser() -> _Parser:
    parser = _Parser(description="Issue one frozen offline L0 submit bundle")
    parser.add_argument("--capsule", required=True, type=Path)
    parser.add_argument("--contour", required=True)
    parser.add_argument("--sequence", required=True, type=_positive_sequence)
    parser.add_argument("--lifetime-seconds", type=_lifetime, default=300)
    parser.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = issue_bundle(
            capsule=args.capsule,
            contour=args.contour,
            sequence=args.sequence,
            lifetime_seconds=args.lifetime_seconds,
            output=args.out,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"status": "STOP", "error": "bundle issuance rejected"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
