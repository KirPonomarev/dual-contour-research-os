from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge.admission import (
    AdmissionError,
    AdmissionGrant,
    admit,
    canonical_json_sha256,
)
from research_bridge.kernel import BridgeKernel
from tests.test_stage1_authority_policy import (  # noqa: E402
    SYNTHETIC_POLICY_SHA256,
    synthetic_authority,
)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
ZERO = "0" * 64
ONE = "1" * 64
TWO = "2" * 64
MAX_SAFE_INTEGER = 9_007_199_254_740_991
ACCOUNTING_POLICY_REF = f"budget-policy:sha256:{'a' * 64}"
BUDGET_SCOPE_REF = f"budget-scope:sha256:{'b' * 64}"


class IntegerSubclass(int):
    pass


def trusted_authority():
    return synthetic_authority(
        job_issuer=("admission-test", "job-authority"),
        permit_issuer=("permit-test", "permit-authority"),
        lease_issuer=("researchd-test", "lease-authority"),
    )


def with_integrity(document: dict) -> dict:
    document["integrity"] = {
        "payload_sha256": canonical_json_sha256(document["payload"]),
        "parent_refs": [],
    }
    return document


def authority_documents() -> tuple[dict, dict, dict]:
    job = with_integrity(
        {
            "schema_id": "JobSpec",
            "schema_version": "1.0.0",
            "object_id": "job-public-synthetic-1",
            "issued_at": "2026-07-16T10:00:00Z",
            "issuer": {"id": "admission-test", "authority_class": "job-authority"},
            "contour": "bridge",
            "classification": "D0_PUBLIC",
            "payload": {
                "protocol_ref": "protocol:synthetic",
                "code_ref": f"sha256:{ONE}",
                "input_refs": ["fixture:synthetic"],
                "image_digest": "image:synthetic",
                "runner_profile": "offline-test",
                "network_policy": "offline",
                "resource_limits": {"cost_units": 2},
                "checkpoint_strategy": "append-only",
                "expected_output_contract": "SyntheticReceipt",
                "idempotency_key": "synthetic-idempotency-1",
            },
        }
    )
    permit = with_integrity(
        {
            "schema_id": "Permit",
            "schema_version": "1.0.0",
            "object_id": "permit-public-synthetic-1",
            "issued_at": "2026-07-16T10:30:00Z",
            "issuer": {"id": "permit-test", "authority_class": "permit-authority"},
            "contour": "governance",
            "classification": "D0_PUBLIC",
            "payload": {
                "subject": "runner-public-synthetic-1",
                "job_spec_sha256": canonical_json_sha256(job),
                "policy_snapshot_sha256": SYNTHETIC_POLICY_SHA256,
                "code_sha256": ONE,
                "input_sha256": canonical_json_sha256(job["payload"]["input_refs"]),
                "image_digest": job["payload"]["image_digest"],
                "quotas": {
                    "accounting_policy_ref": ACCOUNTING_POLICY_REF,
                    "budget_scope_ref": BUDGET_SCOPE_REF,
                    "claims": 1,
                    "provider": job["payload"]["runner_profile"],
                    "scope_limit": {"cost_units": 3},
                    "trial_ref": "trial:public-synthetic-1",
                },
                "network_class": "offline",
                "not_before": "2026-07-16T11:00:00Z",
                "expires_at": "2026-07-16T13:00:00Z",
                "max_uses": 1,
                "nonce": "synthetic-nonce-1",
            },
        }
    )
    lease = with_integrity(
        {
            "schema_id": "AttemptLease",
            "schema_version": "1.0.0",
            "object_id": "lease-public-synthetic-1",
            "issued_at": "2026-07-16T11:30:00Z",
            "issuer": {"id": "researchd-test", "authority_class": "lease-authority"},
            "contour": "bridge",
            "classification": "D0_PUBLIC",
            "payload": {
                "attempt_id": "attempt-public-synthetic-1",
                "permit_ref": permit["object_id"],
                "job_ref": job["object_id"],
                "runner_identity": "runner-public-synthetic-1",
                "fencing_epoch": 7,
                "fencing_token": "fence-public-synthetic-1",
                "issued_at": "2026-07-16T11:30:00Z",
                "expires_at": "2026-07-16T12:30:00Z",
                "checkpoint_parent_ref": "checkpoint:none",
            },
        }
    )
    return job, permit, lease


class CountingLedger:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def claim(self, **keywords):
        self.calls.append(keywords)
        return "claimed"


class AdmissionTests(unittest.TestCase):
    def test_canonical_json_sha256_is_deterministic_utf8_json(self) -> None:
        value = {"z": "synthetic", "a": [1, True, None]}
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.assertEqual(canonical_json_sha256(value), hashlib.sha256(encoded).hexdigest())

    def test_valid_authority_returns_exact_immutable_grant(self) -> None:
        job, permit, lease = authority_documents()
        grant = admit(job, permit, lease, now=NOW, authority=trusted_authority())
        self.assertEqual(
            [field.name for field in fields(AdmissionGrant)],
            [
                "job_id",
                "attempt_id",
                "permit_id",
                "permit_nonce_sha256",
                "accounting_policy_ref",
                "budget_scope_ref",
                "claims",
                "provider",
                "scope_limit_cost_units",
                "trial_ref",
                "reservation_cost_units",
                "reservation_expires_at",
                "job_idempotency_key",
                "contour",
                "classification",
                "runner_identity",
                "fencing_epoch",
                "fencing_token",
                "admitted_at",
                "admission_digest",
            ],
        )
        self.assertEqual(grant.job_id, job["object_id"])
        self.assertEqual(grant.permit_id, permit["object_id"])
        self.assertEqual(
            grant.permit_nonce_sha256,
            hashlib.sha256(permit["payload"]["nonce"].encode("utf-8")).hexdigest(),
        )
        self.assertEqual(grant.attempt_id, lease["payload"]["attempt_id"])
        self.assertEqual(grant.accounting_policy_ref, ACCOUNTING_POLICY_REF)
        self.assertEqual(grant.budget_scope_ref, BUDGET_SCOPE_REF)
        self.assertEqual(grant.claims, 1)
        self.assertEqual(grant.provider, job["payload"]["runner_profile"])
        self.assertEqual(grant.scope_limit_cost_units, 3)
        self.assertEqual(grant.trial_ref, "trial:public-synthetic-1")
        self.assertEqual(grant.reservation_cost_units, 2)
        self.assertEqual(grant.reservation_expires_at, lease["payload"]["expires_at"])
        self.assertEqual(grant.job_idempotency_key, job["payload"]["idempotency_key"])
        self.assertEqual(grant.contour, job["contour"])
        self.assertEqual(grant.classification, job["classification"])
        self.assertRegex(grant.admission_digest, r"^[a-f0-9]{64}$")
        job["payload"]["resource_limits"]["cost_units"] = 99
        permit["payload"]["quotas"]["scope_limit"]["cost_units"] = 99
        self.assertEqual(grant.reservation_cost_units, 2)
        self.assertEqual(grant.scope_limit_cost_units, 3)
        with self.assertRaises(FrozenInstanceError):
            grant.job_id = "changed"  # type: ignore[misc]

    def test_budget_profile_shape_values_and_bindings_are_fail_closed(self) -> None:
        invalid_resource_limits = (
            [],
            {},
            {"cost_units": 0},
            {"cost_units": -1},
            {"cost_units": True},
            {"cost_units": IntegerSubclass(1)},
            {"cost_units": 1.0},
            {"cost_units": "1"},
            {"cost_units": MAX_SAFE_INTEGER + 1},
            {"cost_units": 1, "extra": 1},
        )
        for resource_limits in invalid_resource_limits:
            with self.subTest(resource_limits=resource_limits):
                job, permit, lease = authority_documents()
                job["payload"]["resource_limits"] = resource_limits
                with_integrity(job)
                permit["payload"]["job_spec_sha256"] = canonical_json_sha256(job)
                with_integrity(permit)
                with self.assertRaises(AdmissionError):
                    admit(job, permit, lease, now=NOW, authority=trusted_authority())

        invalid_quotas = (
            [],
            {},
            {**authority_documents()[1]["payload"]["quotas"], "extra": 1},
            {**authority_documents()[1]["payload"]["quotas"], "claims": 0},
            {**authority_documents()[1]["payload"]["quotas"], "claims": 2},
            {**authority_documents()[1]["payload"]["quotas"], "claims": True},
            {
                **authority_documents()[1]["payload"]["quotas"],
                "claims": IntegerSubclass(1),
            },
            {**authority_documents()[1]["payload"]["quotas"], "provider": "other"},
            {**authority_documents()[1]["payload"]["quotas"], "trial_ref": ""},
            {
                **authority_documents()[1]["payload"]["quotas"],
                "accounting_policy_ref": f"budget-policy:sha256:{'A' * 64}",
            },
            {
                **authority_documents()[1]["payload"]["quotas"],
                "budget_scope_ref": f"budget-scope:sha256:{'b' * 63}",
            },
            {**authority_documents()[1]["payload"]["quotas"], "scope_limit": []},
            {
                **authority_documents()[1]["payload"]["quotas"],
                "scope_limit": {"cost_units": 0},
            },
            {
                **authority_documents()[1]["payload"]["quotas"],
                "scope_limit": {"cost_units": True},
            },
            {
                **authority_documents()[1]["payload"]["quotas"],
                "scope_limit": {"cost_units": IntegerSubclass(1)},
            },
            {
                **authority_documents()[1]["payload"]["quotas"],
                "scope_limit": {"cost_units": MAX_SAFE_INTEGER + 1},
            },
            {
                **authority_documents()[1]["payload"]["quotas"],
                "scope_limit": {"cost_units": 1, "extra": 1},
            },
        )
        for quotas in invalid_quotas:
            with self.subTest(quotas=quotas):
                job, permit, lease = authority_documents()
                permit["payload"]["quotas"] = quotas
                with_integrity(permit)
                with self.assertRaises(AdmissionError):
                    admit(job, permit, lease, now=NOW, authority=trusted_authority())

        job, permit, lease = authority_documents()
        permit["payload"]["quotas"]["scope_limit"]["cost_units"] = 1
        with_integrity(permit)
        with self.assertRaises(AdmissionError):
            admit(job, permit, lease, now=NOW, authority=trusted_authority())

    def test_reservation_expiry_is_the_earliest_authority_expiry(self) -> None:
        job, permit, lease = authority_documents()
        permit["payload"]["expires_at"] = "2026-07-16T12:15:00Z"
        with_integrity(permit)
        grant = admit(job, permit, lease, now=NOW, authority=trusted_authority())
        self.assertEqual(grant.reservation_expires_at, "2026-07-16T12:15:00Z")

    def test_unknown_and_missing_fields_fail_closed(self) -> None:
        for document_index, location in ((0, None), (1, "payload"), (2, "issuer")):
            with self.subTest(document_index=document_index, location=location):
                documents = list(authority_documents())
                target = documents[document_index]
                container = target if location is None else target[location]
                container["unknown"] = "rejected"
                if location == "payload":
                    with_integrity(target)
                with self.assertRaises(AdmissionError):
                    admit(*documents, now=NOW, authority=trusted_authority())

        job, permit, lease = authority_documents()
        del job["payload"]["runner_profile"]
        with_integrity(job)
        with self.assertRaises(AdmissionError):
            admit(job, permit, lease, now=NOW, authority=trusted_authority())

    def test_payload_integrity_mismatch_fails_closed(self) -> None:
        for index in range(3):
            with self.subTest(index=index):
                documents = list(authority_documents())
                documents[index]["integrity"]["payload_sha256"] = ZERO
                with self.assertRaises(AdmissionError):
                    admit(*documents, now=NOW, authority=trusted_authority())

    def test_job_permit_and_lease_bindings_fail_closed(self) -> None:
        mutations = (
            (1, "subject", "other-job"),
            (1, "job_spec_sha256", ZERO),
            (1, "image_digest", "other-image"),
            (2, "job_ref", "other-job"),
            (2, "permit_ref", "other-permit"),
        )
        for document_index, field, value in mutations:
            with self.subTest(field=field):
                documents = list(authority_documents())
                documents[document_index]["payload"][field] = value
                with_integrity(documents[document_index])
                with self.assertRaises(AdmissionError):
                    admit(*documents, now=NOW, authority=trusted_authority())

    def test_only_single_use_offline_authority_is_admitted(self) -> None:
        mutations = (
            (0, "network_policy", "connected"),
            (1, "network_class", "connected"),
            (1, "max_uses", 0),
            (1, "max_uses", 2),
        )
        for document_index, field, value in mutations:
            with self.subTest(field=field, value=value):
                documents = list(authority_documents())
                documents[document_index]["payload"][field] = value
                with_integrity(documents[document_index])
                if document_index == 0:
                    documents[1]["payload"]["job_spec_sha256"] = canonical_json_sha256(
                        documents[0]
                    )
                    with_integrity(documents[1])
                with self.assertRaises(AdmissionError):
                    admit(*documents, now=NOW, authority=trusted_authority())

    def test_invalid_time_windows_fail_closed(self) -> None:
        mutations = (
            (0, "issued_at", "2026-07-16T12:00:01Z", False),
            (1, "not_before", "2026-07-16T12:00:01Z", True),
            (1, "expires_at", "2026-07-16T12:00:00Z", True),
            (2, "issued_at", "2026-07-16T12:00:01Z", True),
            (2, "expires_at", "2026-07-16T12:00:00Z", True),
        )
        for document_index, field, value, payload_field in mutations:
            with self.subTest(document_index=document_index, field=field):
                documents = list(authority_documents())
                target = documents[document_index]
                if payload_field:
                    target["payload"][field] = value
                    if document_index == 2 and field == "issued_at":
                        target["issued_at"] = value
                    with_integrity(target)
                else:
                    target[field] = value
                    documents[1]["payload"]["job_spec_sha256"] = canonical_json_sha256(
                        target
                    )
                    with_integrity(documents[1])
                with self.assertRaises(AdmissionError):
                    admit(*documents, now=NOW, authority=trusted_authority())

    def test_lease_issued_at_fields_must_match(self) -> None:
        job, permit, lease = authority_documents()
        lease["issued_at"] = "2026-07-16T11:29:59Z"
        with self.assertRaises(AdmissionError):
            admit(job, permit, lease, now=NOW, authority=trusted_authority())

    def test_malformed_timestamp_and_naive_now_fail_closed(self) -> None:
        job, permit, lease = authority_documents()
        permit["payload"]["not_before"] = "2026-07-16 11:00:00"
        with_integrity(permit)
        with self.assertRaises(AdmissionError):
            admit(job, permit, lease, now=NOW, authority=trusted_authority())

        job, permit, lease = authority_documents()
        with self.assertRaises(AdmissionError):
            admit(
                job,
                permit,
                lease,
                now=datetime(2026, 7, 16, 12, 0),
                authority=trusted_authority(),
            )


class KernelTests(unittest.TestCase):
    def test_valid_authority_calls_ledger_once_with_exact_keywords(self) -> None:
        job, permit, lease = authority_documents()
        ledger = CountingLedger()
        result = BridgeKernel(ledger, authority=trusted_authority()).claim(
            job, permit, lease, now=NOW
        )
        self.assertEqual(result, "claimed")
        self.assertEqual(len(ledger.calls), 1)
        self.assertEqual(
            set(ledger.calls[0]),
            {
                "job_id",
                "attempt_id",
                "permit_id",
                "permit_nonce_sha256",
                "runner_identity",
                "fencing_epoch",
                "fencing_token",
                "admitted_at",
                "admission_digest",
            },
        )

    def test_subject_code_and_input_mismatches_never_call_ledger(self) -> None:
        def subject_mismatch(documents: list[dict]) -> None:
            documents[1]["payload"]["subject"] = "other-runner"
            with_integrity(documents[1])

        def code_mismatch(documents: list[dict]) -> None:
            documents[0]["payload"]["code_ref"] = f"sha256:{TWO}"
            with_integrity(documents[0])
            documents[1]["payload"]["job_spec_sha256"] = canonical_json_sha256(
                documents[0]
            )
            with_integrity(documents[1])

        def input_mismatch(documents: list[dict]) -> None:
            documents[0]["payload"]["input_refs"].append("fixture:synthetic-2")
            with_integrity(documents[0])
            documents[1]["payload"]["job_spec_sha256"] = canonical_json_sha256(
                documents[0]
            )
            with_integrity(documents[1])

        for name, mutate in (
            ("subject_runner", subject_mismatch),
            ("code", code_mismatch),
            ("ordered_inputs", input_mismatch),
        ):
            with self.subTest(binding=name):
                documents = list(authority_documents())
                mutate(documents)
                ledger = CountingLedger()
                with self.assertRaises(AdmissionError):
                    BridgeKernel(ledger, authority=trusted_authority()).claim(
                        *documents, now=NOW
                    )
                self.assertEqual(ledger.calls, [])

    def test_ledger_requires_claim_method(self) -> None:
        with self.assertRaises(TypeError):
            BridgeKernel(object())


if __name__ == "__main__":
    unittest.main()
