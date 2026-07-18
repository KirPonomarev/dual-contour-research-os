#!/usr/bin/env python3
"""Build one sanitized, owner-local, frozen pre-soak runtime capsule."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.admission import canonical_json_sha256  # noqa: E402
from research_bridge.cas import CASError, ContentAddressedStore  # noqa: E402
from research_bridge.researchd import _service_config_from_mapping  # noqa: E402


RELEASE_MANIFEST_SHA256 = "9ceae0bda066cf52577cec0fdc1d7230e92b3e4010f65b81613abf6a0a8a90dd"
RELEASE_SHA = "5c2bd7c090fada6e5b65dc955e80b256d88252de"
IMAGE_DIGEST = "sha256:36069ee7a9db78af747d7fad65f9e33073824f27be898cdc0b7dd3b77ac5c235"
L0_TEMPLATE_SHA256 = "53e75c79888c60b304c0e7e5392a53c0ef508146dfd51c5dcb195a648a54f0c6"
L0_PROTOCOL_REF = "research-bridge:l0:chunk-sha256:v1"
RUNNER_IDENTITY = "pre-soak-offline-l0"
DEPLOY_RUNTIME_ROOT = "/var/lib/research-os"
DEPLOY_UID = 10001
CONFIG_NAME = "researchd.config.json"
MANIFEST_NAME = "capsule-manifest.json"
INPUT_QUOTA_BYTES = 16 * 1024 * 1024
MAXIMUM_INPUT_BYTES = 4 * 1024 * 1024
CHECKPOINT_QUOTA_BYTES = 16 * 1024 * 1024
ARTIFACT_QUOTA_BYTES = 16 * 1024 * 1024
AUTHORITY_VALID_SECONDS = 4 * 24 * 60 * 60
ALLOWED_CLASSIFICATIONS = frozenset({"D0_PUBLIC", "D1_INTERNAL_SANITIZED"})
_COMMON_FIELDS = frozenset(
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
_RELEASE_FIELDS = frozenset(
    {
        "release_sha",
        "image_digests",
        "policy_sha256",
        "config_sha256",
        "schema_sha256",
        "dependency_lock_sha256",
        "sbom_ref",
        "previous_release_ref",
    }
)


class CapsuleError(RuntimeError):
    """A capsule input, binding, or exclusive filesystem operation failed."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise CapsuleError("command arguments are invalid")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CapsuleError("JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    del value
    raise CapsuleError("JSON contains a non-finite number")


def _canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CapsuleError("value is not canonical JSON") from exc


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_release_manifest(path: Path) -> dict[str, Any]:
    try:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CapsuleError("release manifest must be a regular file")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != RELEASE_MANIFEST_SHA256:
            raise CapsuleError("release manifest is not the frozen candidate")
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except CapsuleError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CapsuleError("release manifest is invalid") from exc
    if not isinstance(value, dict) or set(value) != _COMMON_FIELDS:
        raise CapsuleError("release manifest shape is invalid")
    payload = value.get("payload")
    integrity = value.get("integrity")
    if (
        value.get("schema_id") != "ReleaseManifest"
        or value.get("schema_version") != "1.0.0"
        or value.get("classification") not in ALLOWED_CLASSIFICATIONS
        or not isinstance(payload, dict)
        or set(payload) != _RELEASE_FIELDS
        or not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256", "parent_refs"}
        or integrity.get("payload_sha256") != canonical_json_sha256(payload)
    ):
        raise CapsuleError("release manifest identity or integrity is invalid")
    if payload.get("release_sha") != RELEASE_SHA or payload.get("image_digests") != [IMAGE_DIGEST]:
        raise CapsuleError("release manifest candidate binding is invalid")
    return value


def _inspect_regular_input(path: Path, label: str) -> tuple[str, int]:
    if ".." in path.parts or not hasattr(os, "O_NOFOLLOW"):
        raise CapsuleError(f"{label} input path is unsafe")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        before_path = os.lstat(path)
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
            raise CapsuleError(f"{label} input must be a regular file")
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)
            or before.st_size > MAXIMUM_INPUT_BYTES
        ):
            raise CapsuleError(f"{label} input is invalid or exceeds its bound")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, min(65_536, MAXIMUM_INPUT_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            if total > MAXIMUM_INPUT_BYTES:
                raise CapsuleError(f"{label} input exceeds its bound")
            digest.update(block)
        after = os.fstat(descriptor)
        after_path = os.lstat(path)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            getattr(before, "st_mtime_ns", None),
            getattr(before, "st_ctime_ns", None),
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            getattr(after, "st_mtime_ns", None),
            getattr(after, "st_ctime_ns", None),
        )
        if (
            before_identity != after_identity
            or (after.st_dev, after.st_ino) != (after_path.st_dev, after_path.st_ino)
            or total != before.st_size
        ):
            raise CapsuleError(f"{label} input changed during inspection")
        return digest.hexdigest(), total
    except CapsuleError:
        raise
    except OSError as exc:
        raise CapsuleError(f"{label} input is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sealed_document(document: dict[str, object]) -> dict[str, object]:
    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        raise CapsuleError("authority document integrity is invalid")
    integrity["payload_sha256"] = canonical_json_sha256(document["payload"])
    return document


def _authority_documents(
    release: Mapping[str, object],
    observed: datetime,
) -> tuple[dict[str, object], str, dict[str, object], str]:
    payload = release["payload"]
    assert isinstance(payload, Mapping)
    issued_at = _timestamp(observed)
    valid_until = _timestamp(observed + timedelta(seconds=AUTHORITY_VALID_SECONDS))
    policy_basis = {
        "release_sha": RELEASE_SHA,
        "image_digest": IMAGE_DIGEST,
        "network_class": "offline",
        "runner_profile": "L0",
        "contours": ["market", "security"],
    }
    policy = _sealed_document(
        {
            "schema_id": "PolicySnapshot",
            "schema_version": "1.0.0",
            "object_id": "policy-pre-soak-offline-" + RELEASE_SHA[:12],
            "issued_at": issued_at,
            "issuer": {
                "id": "pre-soak-policy-authority",
                "authority_class": "policy-authority",
            },
            "contour": "governance",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": {
                "source_repo": "dual-contour-research-os-public",
                "commit_sha": RELEASE_SHA,
                "aggregate_sha256": canonical_json_sha256(policy_basis),
                "covered_action_classes": ["offline_execution", "resume_global"],
                "allow_rules": [
                    {
                        "contours": ["market", "security"],
                        "network_class": "offline",
                        "runner_profile": "L0",
                    }
                ],
                "deny_rules": [
                    {"network_class": "connected"},
                    {"external_action_authority": True},
                ],
                "valid_from": issued_at,
                "valid_until": valid_until,
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [str(release["object_id"])],
            },
        }
    )
    policy_sha256 = canonical_json_sha256(policy)
    approval_seed = {
        "release_sha": RELEASE_SHA,
        "policy_sha256": policy_sha256,
        "issued_at": issued_at,
        "purpose": "resume_global",
    }
    approval_ref = "approval:pre-soak-resume-" + canonical_json_sha256(approval_seed)[:24]
    approval = _sealed_document(
        {
            "schema_id": "ApprovalReceipt",
            "schema_version": "1.0.0",
            "object_id": approval_ref,
            "issued_at": issued_at,
            "issuer": {
                "id": "pre-soak-operator-authority",
                "authority_class": "operator-authority",
            },
            "contour": "governance",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": {
                "action_class": "resume_global",
                "job_spec_sha256": canonical_json_sha256(
                    {"release_sha": RELEASE_SHA, "purpose": "pre-soak-resume"}
                ),
                "protocol_sha256": L0_TEMPLATE_SHA256,
                "policy_sha256": policy_sha256,
                "quotas": {"resume_uses": 1},
                "stop_conditions": ["global_pause", "policy_expiry"],
                "expires_at": valid_until,
                "nonce": "sha256:" + canonical_json_sha256(approval_seed),
                "revoked": False,
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [str(release["object_id"]), f"policy:sha256:{policy_sha256}"],
            },
        }
    )
    return policy, policy_sha256, approval, approval_ref


def _config(
    policy: dict[str, object],
    policy_sha256: str,
    approval: dict[str, object],
    approval_ref: str,
) -> dict[str, object]:
    return {
        "schema_id": "ResearchdServiceConfig",
        "schema_version": "1.0.0",
        "runtime_root": DEPLOY_RUNTIME_ROOT,
        "runner_identity": RUNNER_IDENTITY,
        "allowed_uids": [DEPLOY_UID],
        "input_quota_bytes": INPUT_QUOTA_BYTES,
        "checkpoint_quota_bytes": CHECKPOINT_QUOTA_BYTES,
        "artifact_quota_bytes": ARTIFACT_QUOTA_BYTES,
        "maximum_input_bytes": MAXIMUM_INPUT_BYTES,
        "deadline_seconds": 5,
        "trusted_issuers": {
            "JobSpec": {
                "issuer_id": "pre-soak-admission-controller",
                "authority_class": "admission-controller",
            },
            "Permit": {
                "issuer_id": "pre-soak-permit-authority",
                "authority_class": "permit-authority",
            },
            "AttemptLease": {
                "issuer_id": "researchd",
                "authority_class": "researchd",
            },
            "PolicySnapshot": {
                "issuer_id": "pre-soak-policy-authority",
                "authority_class": "policy-authority",
            },
            "ApprovalReceipt": {
                "issuer_id": "pre-soak-operator-authority",
                "authority_class": "operator-authority",
            },
        },
        "policy_snapshots": {policy_sha256: policy},
        "approval_receipts": {approval_ref: approval},
    }


def _parse_host_authority_projection(config: Mapping[str, object]):
    """Parse the final config's shape and authority using the local owner UID."""

    projected = dict(config)
    projected["allowed_uids"] = [os.geteuid()]
    return _service_config_from_mapping(projected)


def _write_owner_file(path: Path, value: object) -> tuple[str, int]:
    encoded = _canonical_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CapsuleError("owner file write made no progress")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except (OSError, CapsuleError) as exc:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        if isinstance(exc, CapsuleError):
            raise
        raise CapsuleError("owner file could not be created") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _file_hashes(capsule: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    try:
        paths = sorted(capsule.rglob("*"), key=lambda item: item.as_posix())
        for path in paths:
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                raise CapsuleError("capsule contains a symbolic link")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if path == capsule / MANIFEST_NAME:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise CapsuleError("capsule contains an unsupported entry")
            records.append(
                {
                    "relative_path": path.relative_to(capsule).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": metadata.st_size,
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                }
            )
    except CapsuleError:
        raise
    except OSError as exc:
        raise CapsuleError("capsule file inventory failed") from exc
    return records


def build_capsule(
    *,
    release_manifest_path: Path,
    market_input_path: Path,
    market_classification: str,
    security_input_path: Path,
    security_classification: str,
    output: Path,
    observed: datetime | None = None,
) -> dict[str, object]:
    if market_classification not in ALLOWED_CLASSIFICATIONS or security_classification not in ALLOWED_CLASSIFICATIONS:
        raise CapsuleError("input classification must be D0 or D1")
    if ".." in output.parts or output.name in {"", ".", ".."}:
        raise CapsuleError("capsule output path is unsafe")
    release = _load_release_manifest(release_manifest_path)
    market_sha, market_size = _inspect_regular_input(market_input_path, "market")
    security_sha, security_size = _inspect_regular_input(security_input_path, "security")
    if market_size + security_size > INPUT_QUOTA_BYTES:
        raise CapsuleError("combined inputs exceed the capsule quota")
    moment = (observed or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    created_identity: tuple[int, int] | None = None
    success = False
    try:
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
        output_stat = os.lstat(output)
        created_identity = (output_stat.st_dev, output_stat.st_ino)
        if (
            stat.S_ISLNK(output_stat.st_mode)
            or not stat.S_ISDIR(output_stat.st_mode)
            or stat.S_IMODE(output_stat.st_mode) != 0o700
            or output_stat.st_uid != os.geteuid()
        ):
            raise CapsuleError("capsule root ownership or mode is invalid")
        runtime = output / "runtime"
        runtime.mkdir(mode=0o700)
        os.chmod(runtime, 0o700)
        store = ContentAddressedStore(runtime / "input-cas", quota_bytes=INPUT_QUOTA_BYTES)
        market_object = store.publish(
            market_input_path,
            expected_sha256=market_sha,
            expected_size_bytes=market_size,
        )
        security_object = store.publish(
            security_input_path,
            expected_sha256=security_sha,
            expected_size_bytes=security_size,
        )
        policy, policy_sha256, approval, approval_ref = _authority_documents(release, moment)
        config = _config(policy, policy_sha256, approval, approval_ref)
        config_sha256, _config_size = _write_owner_file(output / CONFIG_NAME, config)

        if (
            config.get("runtime_root") != DEPLOY_RUNTIME_ROOT
            or config.get("allowed_uids") != [DEPLOY_UID]
        ):
            raise CapsuleError("generated config deploy binding is invalid")
        service = _parse_host_authority_projection(config)
        if (
            service.runtime_root != DEPLOY_RUNTIME_ROOT
            or service.runner_identity != RUNNER_IDENTITY
        ):
            raise CapsuleError("generated config runner binding is invalid")
        service.authority.verify_resume(approval_ref, now=moment)

        release_payload = release["payload"]
        assert isinstance(release_payload, Mapping)
        files = _file_hashes(output)
        manifest_payload: dict[str, object] = {
            "release_manifest_sha256": RELEASE_MANIFEST_SHA256,
            "release_manifest_ref": str(release["object_id"]),
            "release_sha": RELEASE_SHA,
            "image_digest": IMAGE_DIGEST,
            "release_policy_sha256": release_payload["policy_sha256"],
            "release_config_sha256": release_payload["config_sha256"],
            "runtime_config_sha256": config_sha256,
            "authority_policy_sha256": policy_sha256,
            "resume_approval_ref": approval_ref,
            "runner_identity": RUNNER_IDENTITY,
            "network_class": "offline",
            "external_action_authority": False,
            "inputs": {
                "market": {
                    "classification": market_classification,
                    "cas_ref": market_object.ref,
                    "sha256": market_sha,
                    "size_bytes": market_size,
                },
                "security": {
                    "classification": security_classification,
                    "cas_ref": security_object.ref,
                    "sha256": security_sha,
                    "size_bytes": security_size,
                },
            },
            "file_hashes": files,
        }
        payload_sha256 = canonical_json_sha256(manifest_payload)
        manifest = {
            "schema_id": "PreSoakCapsuleManifest",
            "schema_version": "1.0.0",
            "object_id": "pre-soak-capsule-" + payload_sha256,
            "issued_at": _timestamp(moment),
            "issuer": {
                "id": "pre-soak-capsule-builder",
                "authority_class": "local-release-capsule-builder",
            },
            "contour": "governance",
            "classification": "D1_INTERNAL_SANITIZED",
            "payload": manifest_payload,
            "integrity": {
                "payload_sha256": payload_sha256,
                "parent_refs": [
                    str(release["object_id"]),
                    f"image:{IMAGE_DIGEST}",
                    f"policy:sha256:{policy_sha256}",
                    market_object.ref,
                    security_object.ref,
                ],
            },
        }
        manifest_sha256, _manifest_size = _write_owner_file(output / MANIFEST_NAME, manifest)
        if _file_hashes(output) != files:
            raise CapsuleError("capsule file inventory changed before completion")
        success = True
        return {
            "status": "CREATED",
            "release_sha": RELEASE_SHA,
            "image_digest": IMAGE_DIGEST,
            "runtime_config_sha256": config_sha256,
            "authority_policy_sha256": policy_sha256,
            "capsule_manifest_sha256": manifest_sha256,
            "external_action_authority": False,
        }
    except FileExistsError as exc:
        raise CapsuleError("capsule output already exists") from exc
    except (CASError, OSError) as exc:
        raise CapsuleError("capsule construction failed closed") from exc
    finally:
        if not success and created_identity is not None:
            try:
                current = os.lstat(output)
                if (
                    not stat.S_ISLNK(current.st_mode)
                    and stat.S_ISDIR(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    shutil.rmtree(output)
            except OSError:
                pass


def _parser() -> _Parser:
    parser = _Parser(description="Build one owner-only frozen pre-soak capsule")
    parser.add_argument("--release-manifest", required=True, type=Path)
    parser.add_argument("--market-input", required=True, type=Path)
    parser.add_argument("--market-classification", required=True)
    parser.add_argument("--security-input", required=True, type=Path)
    parser.add_argument("--security-classification", required=True)
    parser.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = build_capsule(
            release_manifest_path=args.release_manifest,
            market_input_path=args.market_input,
            market_classification=args.market_classification,
            security_input_path=args.security_input,
            security_classification=args.security_classification,
            output=args.out,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"status": "STOP", "error": "capsule build rejected"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
