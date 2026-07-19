#!/usr/bin/env python3
"""Ed25519 selected-receipt attestation and Git commit anchor verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Mapping


_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_GIT_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_DOMAIN = b"DCAROS-ATTESTATION-V1\x00"


class AttestationError(RuntimeError):
    """Selected receipt signing, verification or anchoring failed closed."""


@dataclass(frozen=True, slots=True)
class AttestationVerification:
    status: str
    receipt_sha256: str
    attestation_sha256: str
    key_id: str
    signature_verified: bool
    anchor_verified: bool
    grants_authority: bool = False


class AttestationPolicy:
    def __init__(self, path: str | Path, *, expected_sha256: str) -> None:
        value = _load_json(path, expected_sha256, "attestation policy")
        if set(value) != {
            "profile_id", "schema_version", "status", "signature_algorithm",
            "signing_backend", "domain_separator", "selected_receipts", "validity",
            "integrity", "key_policy", "anchor_policy", "invariants",
        }:
            raise AttestationError("attestation policy keys drifted")
        if (
            value["profile_id"] != "selected-receipt-attestation-v1"
            or value["schema_version"] != "1.0.0"
            or value["status"] != "frozen-selected-scope"
            or value["signature_algorithm"] != "ED25519"
            or value["signing_backend"] != "OPENSSL_CLI_3_PLUS"
            or value["domain_separator"] != "DCAROS-ATTESTATION-V1"
            or value["selected_receipts"] != [
                {"schema_id": "CapabilityProofReceipt", "object_id_prefix": "capability-proof:"},
                {"schema_id": "IntegrationReceipt", "object_id_prefix": "integration-s32-"},
                {"schema_id": "IntegrationReceipt", "object_id_prefix": "integration-s33-"},
            ]
            or value["validity"] != {
                "max_attestation_days": 30, "clock_skew_seconds": 60,
                "anchor_required": True,
            }
            or value["integrity"] != {
                "bind_exact_receipt_bytes_sha256": True,
                "bind_existing_payload_sha256": True,
                "canonicalization_migration": False, "JCS_required": False,
            }
            or value["key_policy"] != {
                "private_key_in_repository": False, "minimum_active_keys": 1,
                "maximum_active_keys": 2, "rotation_overlap_days": 7,
                "revoked_key_fails_closed": True, "unknown_key_fails_closed": True,
            }
            or value["anchor_policy"] != {
                "allowed_backends": ["GITHUB_GIT_COMMIT"],
                "missing_anchor_state": "WAIT_ANCHOR",
                "invalid_anchor_state": "REJECTED_ANCHOR",
            }
            or value["invariants"] != {
                "signature_grants_authority": False, "anchor_grants_authority": False,
                "automatic_promotion": False, "canonical_mutation": False,
                "private_key_output": False, "universal_receipt_rewrite": False,
                "grants_authority": False,
            }
        ):
            raise AttestationError("attestation policy semantics drifted")
        self.profile_sha256 = expected_sha256
        self.selected_receipts = tuple(
            (item["schema_id"], item["object_id_prefix"])
            for item in value["selected_receipts"]
        )
        self.max_days = 30
        self.clock_skew_seconds = 60


class PublicKeyRegistry:
    def __init__(self, path: str | Path, *, expected_sha256: str) -> None:
        value = _load_json(path, expected_sha256, "public key registry")
        if set(value) != {"registry_id", "schema_version", "status", "keys"} or (
            value["registry_id"] != "attestation-public-keys-v1"
            or value["schema_version"] != "1.0.0"
            or value["status"] != "frozen-public-verification-registry"
            or not isinstance(value["keys"], list)
            or not 1 <= len(value["keys"]) <= 2
        ):
            raise AttestationError("public key registry shape drifted")
        keys: dict[str, dict[str, object]] = {}
        for item in value["keys"]:
            if not isinstance(item, dict) or set(item) != {
                "key_id", "algorithm", "public_key_der_sha256", "public_key_pem",
                "active_from", "active_until", "revoked_at", "purpose",
                "private_key_present",
            }:
                raise AttestationError("public key record shape drifted")
            key_id = item["key_id"]
            digest = _sha256(item["public_key_der_sha256"], "public key digest")
            if (
                key_id != "ed25519:" + digest
                or item["algorithm"] != "ED25519"
                or item["purpose"] != "selected-high-value-receipt-attestation"
                or item["private_key_present"] is not False
                or not isinstance(item["public_key_pem"], str)
            ):
                raise AttestationError("public key record semantics drifted")
            _timestamp(item["active_from"], "active_from")
            _timestamp(item["active_until"], "active_until")
            if item["revoked_at"] is not None:
                _timestamp(item["revoked_at"], "revoked_at")
            actual = _public_key_der_digest(item["public_key_pem"])
            if not hmac.compare_digest(actual, digest):
                raise AttestationError("public key material digest mismatch")
            if key_id in keys:
                raise AttestationError("public key identity duplicated")
            keys[str(key_id)] = dict(item)
        self.registry_sha256 = expected_sha256
        self._keys = keys

    def key(self, key_id: str, *, at: datetime) -> dict[str, object]:
        try:
            item = self._keys[key_id]
        except KeyError as exc:
            raise AttestationError("attestation key is unknown") from exc
        active_from = _timestamp(item["active_from"], "active_from")
        active_until = _timestamp(item["active_until"], "active_until")
        revoked = item["revoked_at"]
        if not active_from <= at < active_until or revoked is not None:
            raise AttestationError("attestation key is inactive or revoked")
        return dict(item)


def sign_receipt(
    policy: AttestationPolicy,
    registry: PublicKeyRegistry,
    receipt_bytes: bytes,
    *,
    key_id: str,
    private_key_path: str | Path,
    signed_at: str,
    expires_at: str,
) -> dict[str, object]:
    receipt = _selected_receipt(policy, receipt_bytes)
    signed = _timestamp(signed_at, "signed_at")
    expires = _timestamp(expires_at, "expires_at")
    if not signed < expires <= signed + timedelta(days=policy.max_days):
        raise AttestationError("attestation validity window is invalid")
    key = registry.key(key_id, at=signed)
    key_path = Path(private_key_path)
    if not key_path.is_absolute() or not key_path.is_file():
        raise AttestationError("private key path must be an existing external absolute file")
    try:
        if key_path.resolve().is_relative_to(Path.cwd().resolve()):
            raise AttestationError("private key must remain outside repository worktree")
    except OSError as exc:
        raise AttestationError("private key path cannot be resolved") from exc
    statement = {
        "attestation_profile_sha256": policy.profile_sha256,
        "key_registry_sha256": registry.registry_sha256,
        "receipt_schema_id": receipt["schema_id"],
        "receipt_object_id": receipt["object_id"],
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "payload_sha256": receipt["integrity"]["payload_sha256"],
        "key_id": key_id, "signature_algorithm": "ED25519",
        "signed_at": signed_at, "expires_at": expires_at,
        "anchor_required": True, "grants_authority": False,
    }
    message = _DOMAIN + _canonical_bytes(statement)
    signature = _openssl_sign(key_path, message)
    _openssl_verify(str(key["public_key_pem"]), message, signature)
    body = {
        "schema_id": "SelectedReceiptAttestation", "schema_version": "1.0.0",
        "statement": statement,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "private_key_present": False, "grants_authority": False,
    }
    digest = _sha(body)
    return {
        **body,
        "object_id": "selected-attestation:sha256:" + digest,
        "integrity": {
            "statement_sha256": _sha(statement), "document_sha256": digest,
        },
    }


def verify_attestation(
    policy: AttestationPolicy,
    registry: PublicKeyRegistry,
    receipt_bytes: bytes,
    attestation: Mapping[str, object],
    *,
    now: str,
    anchor: Mapping[str, object] | None = None,
    repository_root: str | Path | None = None,
) -> AttestationVerification:
    receipt = _selected_receipt(policy, receipt_bytes)
    document = _attestation_document(attestation)
    statement = document["statement"]
    assert isinstance(statement, dict)
    current = _timestamp(now, "now")
    signed = _timestamp(statement["signed_at"], "signed_at")
    expires = _timestamp(statement["expires_at"], "expires_at")
    if current + timedelta(seconds=policy.clock_skew_seconds) < signed or current >= expires:
        raise AttestationError("attestation is not currently valid")
    if (
        statement["attestation_profile_sha256"] != policy.profile_sha256
        or statement["key_registry_sha256"] != registry.registry_sha256
        or statement["receipt_schema_id"] != receipt["schema_id"]
        or statement["receipt_object_id"] != receipt["object_id"]
        or statement["receipt_sha256"] != hashlib.sha256(receipt_bytes).hexdigest()
        or statement["payload_sha256"] != receipt["integrity"]["payload_sha256"]
        or statement["signature_algorithm"] != "ED25519"
        or statement["anchor_required"] is not True
        or statement["grants_authority"] is not False
    ):
        raise AttestationError("attestation statement binding mismatch")
    key = registry.key(str(statement["key_id"]), at=signed)
    try:
        signature = base64.b64decode(str(document["signature_b64"]), validate=True)
    except (ValueError, TypeError) as exc:
        raise AttestationError("attestation signature is not canonical base64") from exc
    _openssl_verify(
        str(key["public_key_pem"]), _DOMAIN + _canonical_bytes(statement), signature
    )
    attestation_sha = _sha(document)
    if anchor is None:
        return AttestationVerification(
            "WAIT_ANCHOR", statement["receipt_sha256"], attestation_sha,
            str(statement["key_id"]), True, False,
        )
    if repository_root is None or not _verify_anchor(
        anchor, attestation=document, repository_root=Path(repository_root)
    ):
        return AttestationVerification(
            "REJECTED_ANCHOR", statement["receipt_sha256"], attestation_sha,
            str(statement["key_id"]), True, False,
        )
    return AttestationVerification(
        "VERIFIED_AND_ANCHORED", statement["receipt_sha256"], attestation_sha,
        str(statement["key_id"]), True, True,
    )


def build_git_anchor_receipt(
    attestation: Mapping[str, object],
    *,
    attestation_path: str,
    git_commit_sha: str,
    anchor_ref: str,
    branch: str,
    issued_at: str,
) -> dict[str, object]:
    document = _attestation_document(attestation)
    if _GIT_SHA_RE.fullmatch(git_commit_sha) is None:
        raise AttestationError("anchor git commit sha is invalid")
    if not attestation_path.startswith("docs/receipts/attestation/") or ".." in Path(attestation_path).parts:
        raise AttestationError("anchor attestation path is outside selected directory")
    if not anchor_ref.startswith("https://github.com/") or "/commit/" + git_commit_sha not in anchor_ref:
        raise AttestationError("anchor reference is not the exact GitHub commit")
    if not branch.startswith("codex/"):
        raise AttestationError("anchor branch is not stage-scoped")
    _timestamp(issued_at, "issued_at")
    payload = {
        "attestation_object_id": document["object_id"],
        "attestation_sha256": _sha(document),
        "receipt_sha256": document["statement"]["receipt_sha256"],
        "backend": "GITHUB_GIT_COMMIT", "attestation_path": attestation_path,
        "git_commit_sha": git_commit_sha, "anchor_ref": anchor_ref,
        "branch": branch, "anchored_at": issued_at, "grants_authority": False,
    }
    digest = _sha(payload)
    return {
        "schema_id": "AnchorReceipt", "schema_version": "1.0.0",
        "object_id": "anchor-receipt:sha256:" + digest,
        "issued_at": issued_at, "payload": payload,
        "integrity": {"payload_sha256": digest},
    }


def _verify_anchor(
    anchor: Mapping[str, object], *, attestation: dict[str, object], repository_root: Path
) -> bool:
    try:
        if set(anchor) != {"schema_id", "schema_version", "object_id", "issued_at", "payload", "integrity"}:
            return False
        payload = anchor["payload"]; integrity = anchor["integrity"]
        if not isinstance(payload, Mapping) or not isinstance(integrity, Mapping):
            return False
        digest = _sha(payload)
        if (
            anchor["schema_id"] != "AnchorReceipt"
            or anchor["schema_version"] != "1.0.0"
            or anchor["object_id"] != "anchor-receipt:sha256:" + digest
            or integrity.get("payload_sha256") != digest
            or payload.get("backend") != "GITHUB_GIT_COMMIT"
            or payload.get("attestation_object_id") != attestation["object_id"]
            or payload.get("attestation_sha256") != _sha(attestation)
            or payload.get("receipt_sha256") != attestation["statement"]["receipt_sha256"]
            or payload.get("grants_authority") is not False
        ):
            return False
        commit = str(payload["git_commit_sha"]); path = str(payload["attestation_path"])
        if _GIT_SHA_RE.fullmatch(commit) is None:
            return False
        result = subprocess.run(
            ["git", "show", f"{commit}:{path}"], cwd=repository_root,
            capture_output=True, check=False,
        )
        if result.returncode != 0:
            return False
        anchored = _strict_json(result.stdout, "anchored attestation")
        return _sha(anchored) == _sha(attestation)
    except (KeyError, TypeError, AttestationError):
        return False


def _selected_receipt(policy: AttestationPolicy, raw: bytes) -> dict[str, object]:
    value = _strict_json(raw, "selected receipt")
    if not any(
        value.get("schema_id") == schema and str(value.get("object_id", "")).startswith(prefix)
        for schema, prefix in policy.selected_receipts
    ):
        raise AttestationError("receipt class is outside selected attestation scope")
    payload = value.get("payload"); integrity = value.get("integrity")
    if not isinstance(payload, Mapping) or not isinstance(integrity, Mapping):
        raise AttestationError("selected receipt payload or integrity is invalid")
    digest = _sha(payload)
    if integrity.get("payload_sha256") != digest:
        raise AttestationError("selected receipt existing integrity profile failed")
    return value


def _attestation_document(value: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_id", "schema_version", "object_id", "statement", "signature_b64",
        "private_key_present", "grants_authority", "integrity",
    }:
        raise AttestationError("attestation document shape mismatch")
    document = _copy(value)
    statement = document["statement"]; integrity = document["integrity"]
    if not isinstance(statement, dict) or not isinstance(integrity, dict):
        raise AttestationError("attestation statement or integrity is invalid")
    body = {
        "schema_id": document["schema_id"], "schema_version": document["schema_version"],
        "statement": statement, "signature_b64": document["signature_b64"],
        "private_key_present": document["private_key_present"],
        "grants_authority": document["grants_authority"],
    }
    digest = _sha(body)
    if (
        document["schema_id"] != "SelectedReceiptAttestation"
        or document["schema_version"] != "1.0.0"
        or document["object_id"] != "selected-attestation:sha256:" + digest
        or document["private_key_present"] is not False
        or document["grants_authority"] is not False
        or integrity != {"statement_sha256": _sha(statement), "document_sha256": digest}
    ):
        raise AttestationError("attestation document integrity mismatch")
    return document


def _openssl_sign(private_key_path: Path, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        message_path = Path(directory) / "message.bin"
        signature_path = Path(directory) / "signature.bin"
        message_path.write_bytes(message)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key_path),
             "-in", str(message_path), "-out", str(signature_path)],
            capture_output=True, check=False,
        )
        if result.returncode != 0:
            raise AttestationError("external Ed25519 signing failed")
        return signature_path.read_bytes()


def _openssl_verify(public_key_pem: str, message: bytes, signature: bytes) -> None:
    with tempfile.TemporaryDirectory() as directory:
        public_path = Path(directory) / "public.pem"
        message_path = Path(directory) / "message.bin"
        signature_path = Path(directory) / "signature.bin"
        public_path.write_text(public_key_pem, encoding="ascii")
        message_path.write_bytes(message); signature_path.write_bytes(signature)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_path),
             "-rawin", "-in", str(message_path), "-sigfile", str(signature_path)],
            capture_output=True, check=False,
        )
        if result.returncode != 0:
            raise AttestationError("Ed25519 signature verification failed")


def _public_key_der_digest(public_key_pem: str) -> str:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "public.pem"; path.write_text(public_key_pem, encoding="ascii")
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
            capture_output=True, check=False,
        )
        if result.returncode != 0:
            raise AttestationError("public key is not a valid OpenSSL key")
        return hashlib.sha256(result.stdout).hexdigest()


def _load_json(path: str | Path, expected_sha256: str, label: str) -> dict[str, object]:
    _sha256(expected_sha256, f"{label} expected sha256")
    try: raw = Path(path).read_bytes()
    except OSError as exc: raise AttestationError(f"{label} unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise AttestationError(f"{label} digest mismatch")
    return _strict_json(raw, label)


def _strict_json(raw: bytes, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result: raise AttestationError(f"{label} contains duplicate keys")
            result[key] = value
        return result
    try: value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(AttestationError(f"{label} contains {x}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise AttestationError(f"{label} invalid JSON") from exc
    if not isinstance(value, dict): raise AttestationError(f"{label} must be an object")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AttestationError(f"{label} must be RFC3339 UTC")
    try: result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc: raise AttestationError(f"{label} must be RFC3339 UTC") from exc
    if result.utcoffset() != timezone.utc.utcoffset(result): raise AttestationError(f"{label} must be UTC")
    return result


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AttestationError(f"{label} must be sha256")
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _copy(value: object) -> object:
    if isinstance(value, Mapping): return {str(key): _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)): return [_copy(item) for item in value]
    return value


__all__ = [
    "AttestationError", "AttestationVerification", "AttestationPolicy",
    "PublicKeyRegistry", "sign_receipt", "verify_attestation",
    "build_git_anchor_receipt",
]
