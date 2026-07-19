#!/usr/bin/env python3
"""Pure paired recipient-shadow evaluation; never writes or adopts a MethodCard."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Mapping, Sequence

from tools.method_card import MethodTransferPolicy, recipient_eligibility


class RecipientShadowError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ShadowObservation:
    case_id: str
    arm: str
    score_milli: int
    benchmark_sha256: str
    recipient_snapshot_sha256: str
    context_sha256: str
    method_card_id: str
    poison_present: bool = False
    negative_transfer: bool = False
    recipient_write_count: int = 0
    classification: str = "D0_PUBLIC"


@dataclass(frozen=True, slots=True)
class RecipientShadowReport:
    status: str
    method_card_id: str
    recipient_class: str
    paired_cases: int
    mean_delta_milli: int
    interval_min_milli: int
    interval_max_milli: int
    failure_memory: Mapping[str, object]
    rollback_proposal: Mapping[str, object]
    recipient_registry_writes: int = 0
    canonical_adoption: bool = False
    grants_authority: bool = False


class RecipientShadowPolicy:
    def __init__(self, path: str | Path, *, expected_sha256: str) -> None:
        raw = Path(path).read_bytes()
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
            raise RecipientShadowError("recipient shadow profile digest mismatch")
        value = json.loads(raw)
        if set(value) != {"profile_id", "schema_version", "status", "method_policy_sha256", "benchmark", "states", "invariants"} or value["profile_id"] != "recipient-shadow-evaluation-v1":
            raise RecipientShadowError("recipient shadow profile shape drifted")
        benchmark = value["benchmark"]
        cases = benchmark.get("case_ids")
        if not isinstance(cases, list) or len(cases) != 4 or len(set(cases)) != len(cases) or benchmark.get("minimum_paired_cases") != 4:
            raise RecipientShadowError("recipient benchmark drifted")
        if hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != benchmark.get("case_set_sha256"):
            raise RecipientShadowError("recipient benchmark case digest mismatch")
        expected_invariants = {"synthetic_D0_only": True, "paired_control_treatment": True, "exact_context_binding": True, "poison_can_promote": False, "recipient_registry_writes": 0, "canonical_adoption": False, "automatic_promotion": False, "rollback_is_proposal_only": True, "grants_authority": False}
        if value["invariants"] != expected_invariants:
            raise RecipientShadowError("recipient shadow invariants drifted")
        self.profile_sha256 = expected_sha256
        self.method_policy_sha256 = value["method_policy_sha256"]
        self.case_ids = tuple(cases)
        self.case_set_sha256 = benchmark["case_set_sha256"]
        self.score_min = benchmark["score_min"]
        self.score_max = benchmark["score_max"]


def evaluate_recipient_shadow(
    policy: RecipientShadowPolicy,
    method_policy: MethodTransferPolicy,
    method_card: Mapping[str, object],
    declassification_receipt: Mapping[str, object],
    *,
    recipient_class: str,
    control: Sequence[ShadowObservation],
    treatment: Sequence[ShadowObservation],
    at: str,
) -> RecipientShadowReport:
    eligibility = recipient_eligibility(method_policy, method_card, declassification_receipt, recipient_class=recipient_class, at=at)
    if eligibility.status != "ELIGIBLE_FOR_RECIPIENT_SHADOW_ONLY":
        raise RecipientShadowError("recipient is not eligible for shadow")
    card_id = eligibility.method_card_id
    try:
        controls = {item.case_id: item for item in control}
        treatments = {item.case_id: item for item in treatment}
    except AttributeError as exc:
        raise RecipientShadowError("typed shadow observations required") from exc
    if len(controls) != len(control) or len(treatments) != len(treatment) or tuple(sorted(controls)) != tuple(sorted(policy.case_ids)) or set(controls) != set(treatments):
        return _report("REJECTED_CONFOUND", card_id, recipient_class, (), "CASE_SET_MISMATCH")
    deltas: list[int] = []
    poisoned = False
    negative = False
    for case_id in policy.case_ids:
        left, right = controls[case_id], treatments[case_id]
        common = (policy.case_set_sha256, left.recipient_snapshot_sha256, left.context_sha256, card_id)
        if left.arm != "CONTROL" or right.arm != "TREATMENT" or left.benchmark_sha256 != policy.case_set_sha256 or right.benchmark_sha256 != common[0] or right.recipient_snapshot_sha256 != common[1] or right.context_sha256 != common[2] or left.method_card_id != card_id or right.method_card_id != common[3] or left.classification != "D0_PUBLIC" or right.classification != "D0_PUBLIC":
            return _report("REJECTED_CONFOUND", card_id, recipient_class, tuple(deltas), "PAIR_BINDING_MISMATCH")
        if any(not isinstance(score, int) or isinstance(score, bool) or not policy.score_min <= score <= policy.score_max for score in (left.score_milli, right.score_milli)):
            return _report("REJECTED_BOUNDARY", card_id, recipient_class, tuple(deltas), "SCORE_BOUNDARY")
        if left.recipient_write_count or right.recipient_write_count:
            return _report("REJECTED_BOUNDARY", card_id, recipient_class, tuple(deltas), "RECIPIENT_WRITE_ATTEMPT")
        poisoned = poisoned or left.poison_present or right.poison_present
        negative = negative or right.negative_transfer
        deltas.append(right.score_milli - left.score_milli)
    if poisoned:
        return _report("REJECTED_POISONED_MEMORY", card_id, recipient_class, tuple(deltas), "POISON_PRESENT")
    if negative or any(delta < 0 for delta in deltas):
        return _report("NEGATIVE_TRANSFER", card_id, recipient_class, tuple(deltas), "NEGATIVE_TRANSFER")
    if min(deltas) <= 0:
        return _report("NOT_ESTABLISHED", card_id, recipient_class, tuple(deltas), "INTERVAL_INCLUDES_ZERO")
    return _report("POSITIVE_SHADOW_EFFECT_NOT_ADOPTED", card_id, recipient_class, tuple(deltas), "NONE")


def _report(status: str, card_id: str, recipient: str, deltas: tuple[int, ...], reason: str) -> RecipientShadowReport:
    mean = sum(deltas) // len(deltas) if deltas else 0
    low = min(deltas) if deltas else 0
    high = max(deltas) if deltas else 0
    failed = status != "POSITIVE_SHADOW_EFFECT_NOT_ADOPTED"
    failure = {"reusable": failed, "reason_code": reason, "method_card_id": card_id, "classification": "D0_PUBLIC"}
    rollback = {"status": "WAIT_AUTHORITY" if failed else "NOT_REQUIRED", "action": "REMOVE_METHOD_FROM_RECIPIENT_SHADOW" if failed else "NONE", "applied": False, "grants_authority": False}
    return RecipientShadowReport(status, card_id, recipient, len(deltas), mean, low, high, failure, rollback)


__all__ = ["RecipientShadowError", "RecipientShadowPolicy", "ShadowObservation", "RecipientShadowReport", "evaluate_recipient_shadow"]
