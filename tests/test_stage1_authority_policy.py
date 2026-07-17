from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.admission import (  # noqa: E402
    AdmissionError,
    admit,
    canonical_json_sha256,
)
from research_bridge.authority import (  # noqa: E402
    AuthorityError,
    PinnedOfflineAuthority,
    TrustedIssuer,
)
from research_bridge.control import (  # noqa: E402
    ControlError,
    ControlRequest,
    ControlRouter,
)
from research_bridge.kernel import BridgeKernel  # noqa: E402


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
CONTROL_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
_POLICY_ISSUER = ("synthetic-policy-authority", "policy-authority")
_APPROVAL_ISSUER = ("synthetic-operator-authority", "operator-authority")
_DEFAULT_APPROVAL_REFS = (
    "approval:offline-a",
    "approval:synthetic-router-authority",
)
_ACCOUNTING_POLICY_REF = f"budget-policy:sha256:{'a' * 64}"
_BUDGET_SCOPE_REF = f"budget-scope:sha256:{'b' * 64}"


def _seal(document: dict[str, object]) -> dict[str, object]:
    integrity = document["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = canonical_json_sha256(document["payload"])
    return document


def synthetic_policy() -> dict[str, object]:
    return _seal(
        {
            "schema_id": "PolicySnapshot",
            "schema_version": "1.0.0",
            "object_id": "policy-synthetic-offline-stage1",
            "issued_at": "2024-12-31T00:00:00Z",
            "issuer": {
                "id": _POLICY_ISSUER[0],
                "authority_class": _POLICY_ISSUER[1],
            },
            "contour": "governance",
            "classification": "D0_PUBLIC",
            "payload": {
                "source_repo": "public-synthetic-policy-source",
                "commit_sha": "synthetic-policy-commit",
                "aggregate_sha256": "a" * 64,
                "covered_action_classes": ["offline_execution", "resume_global"],
                "allow_rules": [{"network_class": "offline"}],
                "deny_rules": [{"network_class": "connected"}],
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )


SYNTHETIC_POLICY_SHA256 = canonical_json_sha256(synthetic_policy())


def synthetic_approval(approval_ref: str) -> dict[str, object]:
    return _seal(
        {
            "schema_id": "ApprovalReceipt",
            "schema_version": "1.0.0",
            "object_id": approval_ref,
            "issued_at": "2025-01-01T00:00:00Z",
            "issuer": {
                "id": _APPROVAL_ISSUER[0],
                "authority_class": _APPROVAL_ISSUER[1],
            },
            "contour": "governance",
            "classification": "D0_PUBLIC",
            "payload": {
                "action_class": "resume_global",
                "job_spec_sha256": "b" * 64,
                "protocol_sha256": "c" * 64,
                "policy_sha256": SYNTHETIC_POLICY_SHA256,
                "quotas": {"resume_uses": 1},
                "stop_conditions": ["global_pause"],
                "expires_at": "2027-01-01T00:00:00Z",
                "nonce": f"synthetic-{approval_ref}",
                "revoked": False,
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )


def synthetic_authority(
    *,
    job_issuer: tuple[str, str] = (
        "synthetic-admission-controller",
        "admission-controller",
    ),
    permit_issuer: tuple[str, str] = (
        "synthetic-permit-authority",
        "permit-authority",
    ),
    lease_issuer: tuple[str, str] = ("synthetic-researchd", "researchd"),
    policy: dict[str, object] | None = None,
    approval_receipts: dict[str, dict[str, object]] | None = None,
) -> PinnedOfflineAuthority:
    resolved_policy = copy.deepcopy(policy) if policy is not None else synthetic_policy()
    policy_digest = canonical_json_sha256(resolved_policy)
    approvals = (
        {
            approval_ref: synthetic_approval(approval_ref)
            for approval_ref in _DEFAULT_APPROVAL_REFS
        }
        if approval_receipts is None
        else copy.deepcopy(approval_receipts)
    )
    return PinnedOfflineAuthority(
        trusted_issuers={
            "JobSpec": TrustedIssuer(*job_issuer),
            "Permit": TrustedIssuer(*permit_issuer),
            "AttemptLease": TrustedIssuer(*lease_issuer),
            "PolicySnapshot": TrustedIssuer(*_POLICY_ISSUER),
            "ApprovalReceipt": TrustedIssuer(*_APPROVAL_ISSUER),
        },
        policy_snapshots={policy_digest: resolved_policy},
        approval_receipts=approvals,
    )


def _authority_documents() -> tuple[dict[str, object], ...]:
    job = _seal(
        {
            "schema_id": "JobSpec",
            "schema_version": "1.0.0",
            "object_id": "job-authority-policy-synthetic",
            "issued_at": "2026-07-16T10:00:00Z",
            "issuer": {
                "id": "synthetic-admission-controller",
                "authority_class": "admission-controller",
            },
            "contour": "bridge",
            "classification": "D0_PUBLIC",
            "payload": {
                "protocol_ref": "protocol:synthetic",
                "code_ref": f"sha256:{'1' * 64}",
                "input_refs": ["fixture:synthetic"],
                "image_digest": "image:synthetic",
                "runner_profile": "offline-test",
                "network_policy": "offline",
                "resource_limits": {"cost_units": 2},
                "checkpoint_strategy": "append-only",
                "expected_output_contract": "SyntheticReceipt",
                "idempotency_key": "authority-policy-synthetic",
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )
    permit = _seal(
        {
            "schema_id": "Permit",
            "schema_version": "1.0.0",
            "object_id": "permit-authority-policy-synthetic",
            "issued_at": "2026-07-16T10:30:00Z",
            "issuer": {
                "id": "synthetic-permit-authority",
                "authority_class": "permit-authority",
            },
            "contour": "governance",
            "classification": "D0_PUBLIC",
            "payload": {
                "subject": "runner-authority-policy-synthetic",
                "job_spec_sha256": canonical_json_sha256(job),
                "policy_snapshot_sha256": SYNTHETIC_POLICY_SHA256,
                "code_sha256": "1" * 64,
                "input_sha256": canonical_json_sha256(
                    job["payload"]["input_refs"]  # type: ignore[index]
                ),
                "image_digest": "image:synthetic",
                "quotas": {
                    "accounting_policy_ref": _ACCOUNTING_POLICY_REF,
                    "budget_scope_ref": _BUDGET_SCOPE_REF,
                    "claims": 1,
                    "provider": job["payload"]["runner_profile"],  # type: ignore[index]
                    "scope_limit": {"cost_units": 3},
                    "trial_ref": "trial:authority-policy-synthetic",
                },
                "network_class": "offline",
                "not_before": "2026-07-16T11:00:00Z",
                "expires_at": "2026-07-16T13:00:00Z",
                "max_uses": 1,
                "nonce": "authority-policy-synthetic",
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )
    lease = _seal(
        {
            "schema_id": "AttemptLease",
            "schema_version": "1.0.0",
            "object_id": "lease-authority-policy-synthetic",
            "issued_at": "2026-07-16T11:30:00Z",
            "issuer": {"id": "synthetic-researchd", "authority_class": "researchd"},
            "contour": "bridge",
            "classification": "D0_PUBLIC",
            "payload": {
                "attempt_id": "attempt-authority-policy-synthetic",
                "permit_ref": permit["object_id"],
                "job_ref": job["object_id"],
                "runner_identity": "runner-authority-policy-synthetic",
                "fencing_epoch": 1,
                "fencing_token": "fence-authority-policy-synthetic",
                "issued_at": "2026-07-16T11:30:00Z",
                "expires_at": "2026-07-16T12:30:00Z",
                "checkpoint_parent_ref": "checkpoint:none",
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )
    return job, permit, lease


class _RecordingLedger:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def claim(self, **keywords: object) -> str:
        self.calls.append(dict(keywords))
        return "claimed"


class _RecordingBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def pause_snapshot(self) -> dict[str, object]:
        self.calls.append(("pause_snapshot", {}))
        return {"paused": False}

    def pause_global(self, **keywords: object) -> object:
        self.calls.append(("pause_global", dict(keywords)))
        return object()

    def resume_global(self, **keywords: object) -> object:
        self.calls.append(("resume_global", dict(keywords)))
        return object()


def _resume_request(approval_ref: str) -> ControlRequest:
    return ControlRequest(
        version="1.1",
        request_id="request-authority-policy-resume",
        idempotency_key="idempotency-authority-policy-resume",
        command="resume_global",
        payload={"approval_ref": approval_ref},
    )


class AdmissionAuthorityBoundaryTests(unittest.TestCase):
    def test_valid_pinned_authority_calls_ledger_once(self) -> None:
        ledger = _RecordingLedger()
        result = BridgeKernel(ledger, authority=synthetic_authority()).claim(
            *_authority_documents(),
            now=NOW,
        )
        self.assertEqual(result, "claimed")
        self.assertEqual(len(ledger.calls), 1)

    def test_missing_or_substituted_verifier_fails_before_ledger(self) -> None:
        ledger = _RecordingLedger()
        documents = _authority_documents()
        with self.assertRaises(TypeError):
            BridgeKernel(ledger)
        with self.assertRaises(AdmissionError):
            admit(*documents, now=NOW, authority=None)
        with self.assertRaises(AdmissionError):
            admit(*documents, now=NOW, authority=lambda _: True)  # type: ignore[arg-type]
        self.assertEqual(ledger.calls, [])

    def test_each_self_issued_document_is_rejected_before_ledger(self) -> None:
        for index, field in ((0, "id"), (1, "authority_class"), (2, "id")):
            with self.subTest(document=index, field=field):
                documents = list(_authority_documents())
                issuer = documents[index]["issuer"]
                assert isinstance(issuer, dict)
                issuer[field] = "self-issued-synthetic"
                ledger = _RecordingLedger()
                with self.assertRaises(AdmissionError):
                    BridgeKernel(ledger, authority=synthetic_authority()).claim(
                        *documents,
                        now=NOW,
                    )
                self.assertEqual(ledger.calls, [])

    def test_unknown_policy_reference_is_rejected_before_ledger(self) -> None:
        documents = list(_authority_documents())
        permit_payload = documents[1]["payload"]
        assert isinstance(permit_payload, dict)
        permit_payload["policy_snapshot_sha256"] = "d" * 64
        _seal(documents[1])
        ledger = _RecordingLedger()
        with self.assertRaises(AdmissionError):
            BridgeKernel(ledger, authority=synthetic_authority()).claim(
                *documents,
                now=NOW,
            )
        self.assertEqual(ledger.calls, [])

    def test_changed_expired_and_wrong_issuer_policy_are_rejected(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []
        changed = synthetic_policy()
        changed_payload = changed["payload"]
        assert isinstance(changed_payload, dict)
        changed_payload["allow_rules"] = [{"network_class": "changed"}]
        cases.append(("changed-without-reseal", changed))

        expired = synthetic_policy()
        expired_payload = expired["payload"]
        assert isinstance(expired_payload, dict)
        expired_payload["valid_until"] = "2026-01-01T00:00:00Z"
        _seal(expired)
        cases.append(("expired", expired))

        wrong_issuer = synthetic_policy()
        policy_issuer = wrong_issuer["issuer"]
        assert isinstance(policy_issuer, dict)
        policy_issuer["id"] = "untrusted-policy-authority"
        cases.append(("wrong-issuer", wrong_issuer))

        for label, policy in cases:
            with self.subTest(case=label):
                documents = list(_authority_documents())
                permit_payload = documents[1]["payload"]
                assert isinstance(permit_payload, dict)
                permit_payload["policy_snapshot_sha256"] = canonical_json_sha256(policy)
                _seal(documents[1])
                ledger = _RecordingLedger()
                with self.assertRaises(AdmissionError):
                    BridgeKernel(
                        ledger,
                        authority=synthetic_authority(policy=policy),
                    ).claim(*documents, now=NOW)
                self.assertEqual(ledger.calls, [])


class ResumeAuthorityBoundaryTests(unittest.TestCase):
    def test_valid_typed_approval_calls_backend_once(self) -> None:
        backend = _RecordingBackend()
        router = ControlRouter(
            backend,
            authority=synthetic_authority(),
            clock=lambda: CONTROL_NOW,
        )
        response = router.dispatch(_resume_request("approval:offline-a"), peer_uid=1001)
        self.assertTrue(response.ok)
        self.assertEqual([name for name, _ in backend.calls], ["resume_global", "pause_snapshot"])

    def test_missing_verifier_and_unknown_approval_make_zero_backend_calls(self) -> None:
        backend = _RecordingBackend()
        with self.assertRaises(ControlError):
            ControlRouter(backend, clock=lambda: CONTROL_NOW)
        router = ControlRouter(
            backend,
            authority=synthetic_authority(),
            clock=lambda: CONTROL_NOW,
        )
        with self.assertRaises(ControlError):
            router.dispatch(_resume_request("approval:fabricated"), peer_uid=1001)
        self.assertEqual(backend.calls, [])

    def test_invalid_typed_approvals_make_zero_backend_calls(self) -> None:
        mutations = {
            "expired": lambda receipt: receipt["payload"].__setitem__(  # type: ignore[union-attr]
                "expires_at", "2025-01-01T00:00:01Z"
            ),
            "revoked": lambda receipt: receipt["payload"].__setitem__(  # type: ignore[union-attr]
                "revoked", True
            ),
            "wrong-action": lambda receipt: receipt["payload"].__setitem__(  # type: ignore[union-attr]
                "action_class", "pause_global"
            ),
            "wrong-policy": lambda receipt: receipt["payload"].__setitem__(  # type: ignore[union-attr]
                "policy_sha256", "d" * 64
            ),
            "wrong-issuer": lambda receipt: receipt["issuer"].__setitem__(  # type: ignore[union-attr]
                "id", "untrusted-operator"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(case=label):
                approval_ref = f"approval:invalid-{label}"
                receipt = synthetic_approval(approval_ref)
                mutate(receipt)
                if label not in {"wrong-issuer"}:
                    _seal(receipt)
                backend = _RecordingBackend()
                verifier = synthetic_authority(
                    approval_receipts={approval_ref: receipt}
                )
                router = ControlRouter(
                    backend,
                    authority=verifier,
                    clock=lambda: CONTROL_NOW,
                )
                with self.assertRaises(ControlError):
                    router.dispatch(_resume_request(approval_ref), peer_uid=1001)
                self.assertEqual(backend.calls, [])

    def test_approval_payload_integrity_and_shape_are_required(self) -> None:
        for label in ("integrity", "shape"):
            with self.subTest(case=label):
                approval_ref = f"approval:invalid-{label}"
                receipt = synthetic_approval(approval_ref)
                if label == "integrity":
                    receipt["integrity"]["payload_sha256"] = "0" * 64  # type: ignore[index]
                else:
                    receipt["payload"]["unexpected"] = "synthetic"  # type: ignore[index]
                    _seal(receipt)
                backend = _RecordingBackend()
                router = ControlRouter(
                    backend,
                    authority=synthetic_authority(
                        approval_receipts={approval_ref: receipt}
                    ),
                    clock=lambda: CONTROL_NOW,
                )
                with self.assertRaises(ControlError):
                    router.dispatch(_resume_request(approval_ref), peer_uid=1001)
                self.assertEqual(backend.calls, [])

    def test_incomplete_trust_configuration_is_rejected(self) -> None:
        with self.assertRaises(AuthorityError):
            PinnedOfflineAuthority(
                trusted_issuers={
                    "JobSpec": TrustedIssuer("synthetic", "synthetic")
                },
                policy_snapshots={},
                approval_receipts={},
            )


if __name__ == "__main__":
    unittest.main()
