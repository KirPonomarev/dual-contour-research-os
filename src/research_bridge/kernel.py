"""Minimal Bridge kernel boundary with an injected canonical ledger."""

from __future__ import annotations

import re
from typing import Any

from .admission import admit
from .authority import AuthorityError, PinnedOfflineAuthority, require_pinned_authority


_A1_RESERVATION_REF = re.compile(r"^budget-reservation:[a-f0-9]{64}$")


class BridgeKernel:
    """Admit authority completely before making the sole ledger claim call."""

    def __init__(
        self,
        ledger: Any,
        *,
        authority: PinnedOfflineAuthority | None = None,
    ) -> None:
        if not callable(getattr(ledger, "claim", None)):
            raise TypeError("ledger must expose a callable claim method")
        try:
            self._authority = require_pinned_authority(authority)
        except AuthorityError as exc:
            raise TypeError("pinned authority verifier is required") from exc
        self._ledger = ledger

    def claim(
        self,
        job_spec: dict[str, Any],
        permit: dict[str, Any],
        lease: dict[str, Any],
        *,
        now: Any,
    ) -> Any:
        """Validate authority, then call the injected ledger exactly once."""

        grant = admit(
            job_spec,
            permit,
            lease,
            now=now,
            authority=self._authority,
        )
        keywords = dict(
            job_id=grant.job_id,
            attempt_id=grant.attempt_id,
            permit_id=grant.permit_id,
            permit_nonce_sha256=grant.permit_nonce_sha256,
            runner_identity=grant.runner_identity,
            fencing_epoch=grant.fencing_epoch,
            fencing_token=grant.fencing_token,
            admitted_at=grant.admitted_at,
            admission_digest=grant.admission_digest,
            accounting_policy_ref=grant.accounting_policy_ref,
            budget_scope_ref=grant.budget_scope_ref,
            scope_limit_cost_units=grant.scope_limit_cost_units,
            trial_ref=grant.trial_ref,
            provider=grant.provider,
            job_idempotency_key=grant.job_idempotency_key,
            reservation_cost_units=grant.reservation_cost_units,
            reservation_expires_at=grant.reservation_expires_at,
            contour=grant.contour,
            classification=grant.classification,
        )
        reservation_refs = [
            reference
            for reference in permit["integrity"]["parent_refs"]
            if _A1_RESERVATION_REF.fullmatch(reference) is not None
        ]
        if reservation_refs:
            keywords["admission_reservation_ref"] = reservation_refs[0]
        return self._ledger.claim(**keywords)
