#!/usr/bin/env python3
"""Verify the additive R08B trailer-identity correction without rewriting history."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RECEIPT = ROOT / "docs/receipts/integration/r08b-r5-trailer-identity-correction.json"
KEYS = ("PLAN-ID", "PLAN-VERSION", "AMENDMENT-ID", "SPRINT-ID")
CANONICAL = {
    "PLAN-ID": "DCR_OS_AUTONOMOUS_V2_3_NO_BRAKES_20260719",
    "PLAN-VERSION": "2.4.0-fast-working-release",
    "AMENDMENT-ID": "FAST_RELEASE_NO_TIMED_WINDOWS_NO_HUMAN_WAIT_20260719",
}


class TrailerIdentityError(RuntimeError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return completed.stdout


def parse_terminal_block(message: str) -> dict[str, str]:
    lines = message.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    occurrences: dict[str, list[int]] = {key: [] for key in KEYS}
    for index, line in enumerate(lines):
        for key in KEYS:
            if line.startswith(key + ":"):
                occurrences[key].append(index)
    if any(len(occurrences[key]) != 1 for key in KEYS):
        raise TrailerIdentityError("trailer block has a missing or duplicate key")
    if len(lines) < 4 or tuple(
        line.split(":", 1)[0] for line in lines[-4:]
    ) != KEYS:
        raise TrailerIdentityError("trailer block is not the final contiguous four lines")
    parsed: dict[str, str] = {}
    for key, line in zip(KEYS, lines[-4:], strict=True):
        value = line.split(":", 1)[1].strip()
        if not value:
            raise TrailerIdentityError(f"{key} is empty")
        parsed[key] = value
    return parsed


def negative_self_check() -> None:
    good = "subject\n\n" + "\n".join(
        [
            f"PLAN-ID: {CANONICAL['PLAN-ID']}",
            f"PLAN-VERSION: {CANONICAL['PLAN-VERSION']}",
            f"AMENDMENT-ID: {CANONICAL['AMENDMENT-ID']}",
            "SPRINT-ID: SELF-CHECK",
        ]
    )
    bad = (
        good.replace("PLAN-ID:", "PLAN-X:", 1),
        good.replace("PLAN-VERSION: 2.4.0-fast-working-release", "PLAN-VERSION: 2.4"),
        good.replace("PLAN-VERSION:", "\nPLAN-VERSION:", 1),
        good + f"\nPLAN-ID: {CANONICAL['PLAN-ID']}",
    )
    if parse_terminal_block(good)["SPRINT-ID"] != "SELF-CHECK":
        raise TrailerIdentityError("valid canonical self-check block was rejected")
    for message in bad:
        rejected = False
        try:
            parsed = parse_terminal_block(message)
        except TrailerIdentityError:
            rejected = True
        else:
            rejected = any(
                parsed.get(key) != value for key, value in CANONICAL.items()
            )
        if not rejected:
            raise TrailerIdentityError("negative trailer self-check was accepted")


def verify(receipt_path: Path) -> dict[str, object]:
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("schema_id") != "IntegrationReceipt":
        raise TrailerIdentityError("correction receipt schema is invalid")
    payload = receipt.get("payload")
    integrity = receipt.get("integrity")
    if not isinstance(payload, dict) or not isinstance(integrity, dict):
        raise TrailerIdentityError("correction receipt shape is invalid")
    payload_sha = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    if integrity.get("payload_sha256") != payload_sha:
        raise TrailerIdentityError("correction receipt payload digest drifted")
    if payload.get("canonical_control_values") != CANONICAL:
        raise TrailerIdentityError("canonical CONTROL values drifted")
    affected = payload.get("affected_historical_commits")
    if not isinstance(affected, list) or len(affected) != 17:
        raise TrailerIdentityError("affected historical commit inventory is not exact")
    expected_shas = [item.get("sha") for item in affected if isinstance(item, dict)]
    actual_shas = git(
        "rev-list",
        "--reverse",
        payload["inclusive_first_sha"] + "^.." + payload["last_affected_sha"],
    ).splitlines()
    if expected_shas != actual_shas or len(set(actual_shas)) != 17:
        raise TrailerIdentityError("affected historical SHA order or membership drifted")
    for item in affected:
        if not isinstance(item, dict) or item.get("canonical_match") is not False:
            raise TrailerIdentityError("historical correction item is invalid")
        observed = item.get("parsed_trailers")
        if not isinstance(observed, dict):
            raise TrailerIdentityError("historical parsed trailer record is missing")
        actual = parse_terminal_block(git("show", "-s", "--format=%B", item["sha"]))
        if actual != observed:
            raise TrailerIdentityError("historical parsed trailers drifted")
        if all(actual.get(key) == value for key, value in CANONICAL.items()):
            raise TrailerIdentityError("historical commit unexpectedly matches canonical CONTROL")
    canonical_shas = git(
        "rev-list",
        "--reverse",
        payload["canonical_history_start_sha"] + "^..HEAD",
    ).splitlines()
    if not canonical_shas or canonical_shas[0] != payload["canonical_history_start_sha"]:
        raise TrailerIdentityError("canonical future-history boundary is invalid")
    for sha in canonical_shas:
        parsed = parse_terminal_block(git("show", "-s", "--format=%B", sha))
        if any(parsed.get(key) != value for key, value in CANONICAL.items()):
            raise TrailerIdentityError(f"canonical trailer value mismatch at {sha}")
    correction = payload.get("correction_semantics")
    expected_correction = {
        "defect_additively_corrected": True,
        "historical_commits_still_noncanonical": True,
        "historical_commits_rewritten": False,
        "history_rewrite_authority": False,
        "candidate_cut_permitted_by_this_receipt": False,
        "release_claim_issued": False,
    }
    if correction != expected_correction:
        raise TrailerIdentityError("correction semantics overclaim or drift")
    negative_self_check()
    return {
        "status": "PASS_R08B_TRAILER_IDENTITY_ADDITIVELY_CORRECTED",
        "affected_historical_commits": len(affected),
        "canonical_commits_verified": len(canonical_shas),
        "canonical_value_match_required": True,
        "parse_only_acceptance": False,
        "history_rewritten": False,
        "candidate_cut_permitted": False,
        "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    args = parser.parse_args()
    print(json.dumps(verify(args.receipt), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
