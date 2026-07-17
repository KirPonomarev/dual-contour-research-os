#!/usr/bin/env python3
"""Issue one short-lived deployment approval without logging key or nonce data."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.deployment import (  # noqa: E402
    DeploymentGateError,
    issue_deployment_approval,
)


_HEX_KEY_RE = re.compile(r"^[a-fA-F0-9]{64,512}$")
_MAX_INPUT_BYTES = 1_048_576
_MAX_KEY_INPUT_BYTES = 513


def _positive_ttl(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("TTL must be an integer") from exc
    if parsed < 1 or parsed > 300:
        raise argparse.ArgumentTypeError("TTL must be between 1 and 300 seconds")
    return parsed


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > _MAX_INPUT_BYTES:
            raise DeploymentGateError(f"{label} exceeds the safe input limit")
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentGateError(f"could not read {label}") from exc
    if not isinstance(decoded, dict):
        raise DeploymentGateError(f"{label} must be a JSON object")
    return decoded


def _read_hex_key(file_descriptor: int) -> bytes:
    if isinstance(file_descriptor, bool) or not isinstance(file_descriptor, int) or file_descriptor < 0:
        raise DeploymentGateError("key file descriptor is invalid")
    chunks: list[bytes] = []
    total = 0
    while total <= _MAX_KEY_INPUT_BYTES:
        chunk = os.read(file_descriptor, _MAX_KEY_INPUT_BYTES + 1 - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    encoded = b"".join(chunks).strip()
    if len(encoded) > 512:
        raise DeploymentGateError("operator key input is invalid")
    try:
        text = encoded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DeploymentGateError("operator key input is invalid") from exc
    if len(text) % 2 or _HEX_KEY_RE.fullmatch(text) is None:
        raise DeploymentGateError("operator key input is invalid")
    return bytes.fromhex(text)


def _write_receipt_exclusive(path: Path, receipt: dict[str, object]) -> None:
    parent = path.parent
    if not parent.is_dir():
        raise DeploymentGateError("approval output parent does not exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        encoded = (
            json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600, follow_symlinks=False)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except (OSError, TypeError, ValueError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise DeploymentGateError("could not write deployment approval") from exc


def _release_sha(document: dict[str, Any]) -> str:
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise DeploymentGateError("release manifest payload is invalid")
    value = payload.get("release_sha")
    if not isinstance(value, str):
        raise DeploymentGateError("release manifest SHA is invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Issue one exact-bound HMAC-authenticated DeploymentApprovalReceipt"
    )
    parser.add_argument("--release-manifest", required=True, type=Path)
    parser.add_argument("--restore-receipt", required=True, type=Path)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--remote-ci-ref", required=True)
    parser.add_argument("--issuer-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument(
        "--key-hex-fd",
        type=int,
        default=0,
        help="file descriptor containing a hex-encoded key (default: stdin)",
    )
    parser.add_argument("--ttl-seconds", type=_positive_ttl, default=300)
    parser.add_argument(
        "--confirm-release-sha",
        required=True,
        help="must exactly repeat the release SHA being approved",
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        release_manifest = _load_json_object(args.release_manifest, "release manifest")
        restore_receipt = _load_json_object(args.restore_receipt, "restore receipt")
        release_sha = _release_sha(release_manifest)
        if args.confirm_release_sha != release_sha:
            raise DeploymentGateError("operator release confirmation mismatch")

        observed = datetime.now(timezone.utc).replace(microsecond=0)
        expires = observed + timedelta(seconds=args.ttl_seconds)
        operator_key = _read_hex_key(args.key_hex_fd)
        nonce_token = "sha256:" + hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        receipt = issue_deployment_approval(
            release_manifest=release_manifest,
            restore_receipt=restore_receipt,
            environment=args.environment,
            exact_remote_ci_ref=args.remote_ci_ref,
            issuer_id=args.issuer_id,
            key_id=args.key_id,
            operator_key=operator_key,
            issued_at=observed.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
            approval_object_id="deployment-approval-" + secrets.token_hex(16),
            nonce=nonce_token,
        )
        _write_receipt_exclusive(args.out, receipt)
        print(
            json.dumps(
                {
                    "status": "CREATED",
                    "output": str(args.out),
                    "release_sha": release_sha,
                    "issuer_id": args.issuer_id,
                    "key_id": args.key_id,
                },
                sort_keys=True,
            )
        )
        return 0
    except (DeploymentGateError, OSError) as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
