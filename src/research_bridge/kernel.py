"""Minimal Bridge kernel boundary with an injected canonical ledger."""

from __future__ import annotations

from typing import Any

from .admission import admit


class BridgeKernel:
    """Admit authority completely before making the sole ledger claim call."""

    def __init__(self, ledger: Any) -> None:
        if not callable(getattr(ledger, "claim", None)):
            raise TypeError("ledger must expose a callable claim method")
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

        grant = admit(job_spec, permit, lease, now=now)
        return self._ledger.claim(
            job_id=grant.job_id,
            attempt_id=grant.attempt_id,
            permit_id=grant.permit_id,
            runner_identity=grant.runner_identity,
            fencing_epoch=grant.fencing_epoch,
            fencing_token=grant.fencing_token,
            admitted_at=grant.admitted_at,
            admission_digest=grant.admission_digest,
        )
