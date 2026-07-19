from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from tools.attestation import (
    AttestationError,
    AttestationPolicy,
    PublicKeyRegistry,
    build_git_anchor_receipt,
    sign_receipt,
    verify_attestation,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "provenance" / "selected-receipt-attestation-v1.json"
POLICY_SHA256 = "2f31ee0636d17975bc944931ed8830eb1562bf6ddc983788b2032ea6cce14d6b"
RECEIPT_PATH = ROOT / "docs" / "receipts" / "capability" / "e3-evolution-shadow.json"
REGISTRY_PATH = ROOT / "provenance" / "attestation-public-keys-v1.json"
REGISTRY_SHA256 = "f85e71a3e472b431d50379a3f6789ea6fb526ade63b87329d119cca3b5d965e5"
ATTESTATION_PATH = (
    ROOT / "docs" / "receipts" / "attestation" / "e3-evolution-shadow.attestation.json"
)
ANCHOR_PATH = ROOT / "docs" / "receipts" / "attestation" / "e3-evolution-shadow.anchor.json"
SIGNED_AT = "2026-07-19T00:40:00Z"
EXPIRES_AT = "2026-08-01T00:40:00Z"
VERIFY_AT = "2026-07-20T00:40:00Z"


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(args, cwd=cwd, capture_output=True, check=False)
    assert result.returncode == 0, f"command failed without exposing subprocess output: {args[0]}"
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _registry(tmp_path: Path, *, revoked_at: str | None = None) -> tuple[Path, str, str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    key_path = tmp_path / "external-private-key.pem"
    public_path = tmp_path / "public-key.pem"
    _run("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key_path))
    _run(
        "openssl", "pkey", "-in", str(key_path), "-pubout", "-out", str(public_path)
    )
    private_mode = key_path.stat().st_mode & 0o777
    assert private_mode & 0o077 == 0
    public_pem = public_path.read_text(encoding="ascii")
    der = _run(
        "openssl", "pkey", "-pubin", "-in", str(public_path), "-outform", "DER"
    ).stdout
    digest = hashlib.sha256(der).hexdigest()
    key_id = "ed25519:" + digest
    registry = {
        "registry_id": "attestation-public-keys-v1",
        "schema_version": "1.0.0",
        "status": "frozen-public-verification-registry",
        "keys": [
            {
                "key_id": key_id,
                "algorithm": "ED25519",
                "public_key_der_sha256": digest,
                "public_key_pem": public_pem,
                "active_from": "2026-07-19T00:00:00Z",
                "active_until": "2027-07-19T00:00:00Z",
                "revoked_at": revoked_at,
                "purpose": "selected-high-value-receipt-attestation",
                "private_key_present": False,
            }
        ],
    }
    raw = json.dumps(registry, indent=2, ensure_ascii=True).encode("ascii") + b"\n"
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(raw)
    return registry_path, hashlib.sha256(raw).hexdigest(), key_id, key_path


def _signed(tmp_path: Path) -> tuple[AttestationPolicy, PublicKeyRegistry, bytes, dict[str, object]]:
    policy = AttestationPolicy(POLICY_PATH, expected_sha256=POLICY_SHA256)
    path, digest, key_id, private_key = _registry(tmp_path)
    registry = PublicKeyRegistry(path, expected_sha256=digest)
    receipt = RECEIPT_PATH.read_bytes()
    attestation = sign_receipt(
        policy,
        registry,
        receipt,
        key_id=key_id,
        private_key_path=private_key,
        signed_at=SIGNED_AT,
        expires_at=EXPIRES_AT,
    )
    return policy, registry, receipt, attestation


def test_signature_binds_exact_receipt_and_waits_for_anchor(tmp_path: Path) -> None:
    policy, registry, receipt, attestation = _signed(tmp_path)
    result = verify_attestation(
        policy, registry, receipt, attestation, now=VERIFY_AT
    )
    assert result.status == "WAIT_ANCHOR"
    assert result.signature_verified is True
    assert result.anchor_verified is False
    assert result.grants_authority is False
    assert attestation["private_key_present"] is False
    assert "PRIVATE KEY" not in json.dumps(attestation)

    with pytest.raises(AttestationError, match="binding mismatch"):
        verify_attestation(
            policy, registry, receipt + b" ", attestation, now=VERIFY_AT
        )


def test_frozen_public_attestation_verifies_offline_and_waits_for_anchor() -> None:
    policy = AttestationPolicy(POLICY_PATH, expected_sha256=POLICY_SHA256)
    registry = PublicKeyRegistry(REGISTRY_PATH, expected_sha256=REGISTRY_SHA256)
    attestation = json.loads(ATTESTATION_PATH.read_text(encoding="ascii"))
    result = verify_attestation(
        policy, registry, RECEIPT_PATH.read_bytes(), attestation, now=VERIFY_AT
    )
    assert result.status == "WAIT_ANCHOR"
    assert result.signature_verified and not result.anchor_verified
    assert result.grants_authority is False

    anchor = json.loads(ANCHOR_PATH.read_text(encoding="ascii"))
    anchored = verify_attestation(
        policy, registry, RECEIPT_PATH.read_bytes(), attestation, now=VERIFY_AT,
        anchor=anchor, repository_root=ROOT,
    )
    assert anchored.status == "VERIFIED_AND_ANCHORED"
    assert anchored.signature_verified and anchored.anchor_verified
    assert anchored.grants_authority is False


def test_signature_substitution_and_expiry_fail_closed(tmp_path: Path) -> None:
    policy, registry, receipt, attestation = _signed(tmp_path)
    replaced = deepcopy(attestation)
    signature = bytearray(base64.b64decode(replaced["signature_b64"]))
    signature[0] ^= 1
    replaced["signature_b64"] = base64.b64encode(signature).decode("ascii")
    body = {key: replaced[key] for key in (
        "schema_id", "schema_version", "statement", "signature_b64",
        "private_key_present", "grants_authority",
    )}
    document_sha = hashlib.sha256(_canonical(body)).hexdigest()
    replaced["object_id"] = "selected-attestation:sha256:" + document_sha
    replaced["integrity"] = {
        "statement_sha256": hashlib.sha256(_canonical(replaced["statement"])).hexdigest(),
        "document_sha256": document_sha,
    }
    with pytest.raises(AttestationError, match="signature verification failed"):
        verify_attestation(policy, registry, receipt, replaced, now=VERIFY_AT)
    with pytest.raises(AttestationError, match="not currently valid"):
        verify_attestation(
            policy, registry, receipt, attestation, now="2026-08-02T00:40:00Z"
        )


def test_revoked_and_substituted_keys_fail_closed(tmp_path: Path) -> None:
    revoked_path, revoked_sha, key_id, _ = _registry(
        tmp_path / "revoked", revoked_at="2026-07-20T00:00:00Z"
    )
    revoked = PublicKeyRegistry(revoked_path, expected_sha256=revoked_sha)
    with pytest.raises(AttestationError, match="inactive or revoked"):
        revoked.key(key_id, at=datetime(2026, 7, 19, 1, tzinfo=timezone.utc))

    first_path, first_sha, _, _ = _registry(tmp_path / "first")
    value = json.loads(first_path.read_text(encoding="ascii"))
    second_path, _, _, _ = _registry(tmp_path / "second")
    other = json.loads(second_path.read_text(encoding="ascii"))
    value["keys"][0]["public_key_pem"] = other["keys"][0]["public_key_pem"]
    substituted = tmp_path / "substituted.json"
    raw = json.dumps(value, indent=2).encode("ascii") + b"\n"
    substituted.write_bytes(raw)
    with pytest.raises(AttestationError, match="material digest mismatch"):
        PublicKeyRegistry(substituted, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert first_sha != hashlib.sha256(raw).hexdigest()


def test_invalid_and_exact_git_anchor_states(tmp_path: Path) -> None:
    material = tmp_path / "material"
    material.mkdir()
    policy, registry, receipt, attestation = _signed(material)
    invalid = {
        "schema_id": "AnchorReceipt", "schema_version": "1.0.0",
        "object_id": "anchor-receipt:sha256:" + "0" * 64,
        "issued_at": SIGNED_AT, "payload": {},
        "integrity": {"payload_sha256": "0" * 64},
    }
    result = verify_attestation(
        policy, registry, receipt, attestation, now=VERIFY_AT,
        anchor=invalid, repository_root=tmp_path,
    )
    assert result.status == "REJECTED_ANCHOR"

    repository = tmp_path / "anchor-repository"
    path = repository / "docs" / "receipts" / "attestation"
    path.mkdir(parents=True)
    attestation_path = path / "fixture.attestation.json"
    attestation_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="ascii")
    _run("git", "init", "-q", cwd=repository)
    _run("git", "config", "user.name", "S34 Test", cwd=repository)
    _run("git", "config", "user.email", "s34@example.invalid", cwd=repository)
    _run("git", "add", ".", cwd=repository)
    _run("git", "commit", "-q", "-m", "fixture", cwd=repository)
    commit = _run("git", "rev-parse", "HEAD", cwd=repository).stdout.decode().strip()
    anchor = build_git_anchor_receipt(
        attestation,
        attestation_path="docs/receipts/attestation/fixture.attestation.json",
        git_commit_sha=commit,
        anchor_ref=f"https://github.com/example/repository/commit/{commit}",
        branch="codex/test-s34-anchor",
        issued_at=SIGNED_AT,
    )
    result = verify_attestation(
        policy, registry, receipt, attestation, now=VERIFY_AT,
        anchor=anchor, repository_root=repository,
    )
    assert result.status == "VERIFIED_AND_ANCHORED"
    assert result.signature_verified and result.anchor_verified
    assert result.grants_authority is False


def test_private_key_inside_current_repository_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = AttestationPolicy(POLICY_PATH, expected_sha256=POLICY_SHA256)
    repository = tmp_path / "repository"
    repository.mkdir()
    path, digest, key_id, private_key = _registry(repository)
    registry = PublicKeyRegistry(path, expected_sha256=digest)
    monkeypatch.chdir(repository)
    with pytest.raises(AttestationError, match="outside repository"):
        sign_receipt(
            policy, registry, RECEIPT_PATH.read_bytes(), key_id=key_id,
            private_key_path=private_key, signed_at=SIGNED_AT, expires_at=EXPIRES_AT,
        )


def test_policy_scope_and_subprocess_non_disclosure_guards(tmp_path: Path) -> None:
    policy = AttestationPolicy(POLICY_PATH, expected_sha256=POLICY_SHA256)
    path, digest, key_id, private_key = _registry(tmp_path)
    registry = PublicKeyRegistry(path, expected_sha256=digest)
    outside = {
        "schema_id": "IntegrationReceipt", "object_id": "integration-s31-outside",
        "payload": {}, "integrity": {
            "payload_sha256": hashlib.sha256(b"{}").hexdigest()
        },
    }
    with pytest.raises(AttestationError, match="outside selected"):
        sign_receipt(
            policy, registry, _canonical(outside), key_id=key_id,
            private_key_path=private_key, signed_at=SIGNED_AT, expires_at=EXPIRES_AT,
        )
    source = (ROOT / "tools" / "attestation.py").read_text(encoding="utf-8")
    assert "capture_output=True" in source
    assert "private_key_path.read" not in source
    assert "print(" not in source
