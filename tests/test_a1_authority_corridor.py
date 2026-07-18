from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.admission import AdmissionError, canonical_json_sha256  # noqa: E402
from research_bridge.authority import (  # noqa: E402
    A1AuthorityCorridor,
    AuthorityError,
    CorridorExecutorProfile,
)
from research_bridge.kernel import BridgeKernel  # noqa: E402
from research_bridge.ledger import JobLedger, LedgerError  # noqa: E402
from tests.test_a1_admission_fixture import (  # noqa: E402
    A1_CATALOG_SHA256,
    CORE_CATALOG_SHA256,
    _candidate,
    _kernel,
    _snapshot,
)
from tests.test_stage1_authority_policy import (  # noqa: E402
    SYNTHETIC_POLICY_SHA256,
    synthetic_authority,
)


AT = "2026-07-18T12:00:00Z"
CAS_REF = "cas:sha256:" + "9" * 64
L0_CODE_SHA256 = hashlib.sha256(
    b"research-bridge:l0:chunk-sha256:v1"
).hexdigest()


def _admitted_candidate(*, cost_units: int | float = 2):
    candidate = _candidate(
        payload_overrides={
            "policy_sha256": SYNTHETIC_POLICY_SHA256,
            "evidence_refs": [CAS_REF],
            "evidence_independence_groups": [[CAS_REF]],
            "resource_request": {
                "wall_seconds": 60,
                "cpu_seconds": 60,
                "memory_mib": 128,
                "output_bytes": 100_000,
                "tokens": 1_000,
                "cost_units": cost_units,
            },
        }
    )
    kernel = _kernel()
    decision = kernel.evaluate_candidate(candidate, _snapshot(kernel, candidate))
    if decision.decision != "ADMIT":
        raise AssertionError(f"synthetic candidate was not admitted: {decision.decision}")
    return candidate, decision.to_mapping()


def _profile() -> CorridorExecutorProfile:
    return CorridorExecutorProfile(
        capability_ref="capability:executor-fixture",
        protocol_ref="protocol:registered-offline-l0-v1",
        code_sha256=L0_CODE_SHA256,
        image_digest="image:synthetic-offline-l0",
        runner_identity="runner-authority-policy-synthetic",
    )


def _corridor(receipt: dict[str, object], *, authority=None) -> A1AuthorityCorridor:
    return A1AuthorityCorridor(
        authority=authority or synthetic_authority(),
        executor_profile=_profile(),
        trusted_admission_receipts={receipt["object_id"]: receipt},
        expected_core_catalog_sha256=CORE_CATALOG_SHA256,
        expected_a1_catalog_sha256=A1_CATALOG_SHA256,
    )


def _reseal(document: dict[str, object]) -> None:
    integrity = document["integrity"]
    if not isinstance(integrity, dict):
        raise AssertionError("test document integrity is not mutable")
    integrity["payload_sha256"] = canonical_json_sha256(document["payload"])


class A1AuthorityCorridorTests(unittest.TestCase):
    def test_valid_admission_derives_one_deterministic_bounded_chain(self) -> None:
        candidate, receipt = _admitted_candidate()
        corridor = _corridor(receipt)
        first = corridor.issue(
            receipt, candidate, input_refs=[CAS_REF], lifetime_seconds=120
        )
        second = corridor.issue(
            receipt, candidate, input_refs=[CAS_REF], lifetime_seconds=120
        )
        documents = first.to_mapping()

        self.assertEqual(documents, second.to_mapping())
        self.assertNotEqual(receipt["schema_id"], documents["permit"]["schema_id"])
        self.assertIsNot(first.authority, synthetic_authority())
        self.assertEqual(
            documents["job_spec"]["issuer"]["authority_class"],
            "admission-controller",
        )
        self.assertEqual(
            documents["permit"]["issuer"]["authority_class"], "permit-authority"
        )
        self.assertEqual(
            documents["lease"]["issuer"]["authority_class"], "researchd"
        )
        self.assertEqual(
            documents["job_spec"]["payload"]["resource_limits"],
            {"cost_units": 2},
        )
        self.assertEqual(documents["job_spec"]["payload"]["input_refs"], [CAS_REF])
        self.assertEqual(documents["permit"]["payload"]["network_class"], "offline")
        self.assertEqual(documents["permit"]["payload"]["max_uses"], 1)
        self.assertEqual(documents["permit"]["payload"]["quotas"]["claims"], 1)
        self.assertIn(first.reservation_ref, documents["permit"]["integrity"]["parent_refs"])
        self.assertIn(first.reservation_ref, documents["lease"]["integrity"]["parent_refs"])

        documents["permit"]["payload"]["network_class"] = "connected"
        self.assertEqual(
            first.to_mapping()["permit"]["payload"]["network_class"], "offline"
        )

    def test_activation_creates_bound_budget_reservation_and_exact_replay_only(self) -> None:
        candidate, receipt = _admitted_candidate()
        bundle = _corridor(receipt).issue(
            receipt, candidate, input_refs=[CAS_REF], lifetime_seconds=120
        )
        documents = bundle.to_mapping()
        with tempfile.TemporaryDirectory() as temporary:
            ledger = JobLedger(Path(temporary) / "corridor.sqlite3")
            kernel = BridgeKernel(ledger, authority=bundle.authority)
            try:
                first = kernel.claim(
                    documents["job_spec"],
                    documents["permit"],
                    documents["lease"],
                    now=AT,
                )
                replay = kernel.claim(
                    documents["job_spec"],
                    documents["permit"],
                    documents["lease"],
                    now=AT,
                )
                reservation = first.payload["budget_reservation"]
                self.assertEqual(replay.event_sha256, first.event_sha256)
                self.assertEqual(ledger.event_count(), 1)
                self.assertEqual(first.payload["admission_reservation_ref"], bundle.reservation_ref)
                self.assertIn(
                    bundle.reservation_ref, reservation["integrity"]["parent_refs"]
                )
                self.assertTrue(reservation["object_id"].startswith("budget-reservation:sha256:"))
                self.assertTrue(ledger.verify_chain())
            finally:
                ledger.close()

    def test_transferred_resealed_or_expired_permit_and_lease_fail_before_claim(self) -> None:
        candidate, receipt = _admitted_candidate()
        bundle = _corridor(receipt).issue(
            receipt, candidate, input_refs=[CAS_REF], lifetime_seconds=120
        )
        mutations = []

        transferred = bundle.to_mapping()
        transferred["permit"]["payload"]["subject"] = "attacker-runner"
        transferred["lease"]["payload"]["runner_identity"] = "attacker-runner"
        _reseal(transferred["permit"])
        _reseal(transferred["lease"])
        mutations.append(("transferred", transferred, AT))

        refenced = bundle.to_mapping()
        refenced["lease"]["payload"]["fencing_token"] = "attacker-fence"
        _reseal(refenced["lease"])
        mutations.append(("refenced", refenced, AT))
        mutations.append(("expired", bundle.to_mapping(), "2026-07-18T12:02:00Z"))

        for label, documents, now in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                ledger = JobLedger(Path(temporary) / "rejected.sqlite3")
                try:
                    with self.assertRaises((AdmissionError, LedgerError)):
                        BridgeKernel(ledger, authority=bundle.authority).claim(
                            documents["job_spec"],
                            documents["permit"],
                            documents["lease"],
                            now=now,
                        )
                    self.assertEqual(ledger.event_count(), 0)
                finally:
                    ledger.close()

    def test_forged_or_non_admit_receipt_is_not_execution_authority(self) -> None:
        candidate, receipt = _admitted_candidate()
        corridor = _corridor(receipt)
        forged = deepcopy(receipt)
        payload = forged["payload"]
        self.assertIsInstance(payload, dict)
        decision_key = "7" * 64
        payload["decision_key_sha256"] = decision_key
        payload["receipt_id"] = f"admission-receipt:{decision_key}"
        payload["reservation_ref"] = f"budget-reservation:{decision_key}"
        payload["transport_idempotency_key"] = f"admission:{decision_key}"
        forged["integrity"]["payload_sha256"] = canonical_json_sha256(payload)
        forged["object_id"] = "admission-object:" + canonical_json_sha256(payload)
        with self.assertRaisesRegex(AuthorityError, "trusted durable resolver"):
            corridor.issue(
                forged, candidate, input_refs=[CAS_REF], lifetime_seconds=120
            )

        rejected = deepcopy(receipt)
        rejected_payload = rejected["payload"]
        self.assertIsInstance(rejected_payload, dict)
        rejected_payload["decision"] = "PARK"
        rejected_payload["reason_codes"] = ["BUDGET_EXHAUSTED"]
        rejected_payload["public_reason_codes"] = ["BUDGET_EXHAUSTED"]
        rejected_payload["budget_action"] = "PARKED"
        rejected_payload["reservation_ref"] = None
        rejected["integrity"]["payload_sha256"] = canonical_json_sha256(rejected_payload)
        rejected["object_id"] = "admission-object:" + canonical_json_sha256(rejected_payload)
        rejected_corridor = _corridor(rejected)
        with self.assertRaisesRegex(AuthorityError, "does not authorize"):
            rejected_corridor.issue(
                rejected, candidate, input_refs=[CAS_REF], lifetime_seconds=120
            )

    def test_child_scope_and_issuer_roles_cannot_expand(self) -> None:
        candidate, receipt = _admitted_candidate()
        corridor = _corridor(receipt)
        with self.assertRaises(AuthorityError):
            corridor.issue(
                receipt,
                candidate,
                input_refs=["cas:sha256:" + "8" * 64],
                lifetime_seconds=120,
            )
        with self.assertRaises(AuthorityError):
            corridor.issue(
                receipt, candidate, input_refs=[CAS_REF], lifetime_seconds=301
            )

        fractional_candidate, fractional_receipt = _admitted_candidate(cost_units=1.5)
        with self.assertRaisesRegex(AuthorityError, "integer budget ledger"):
            _corridor(fractional_receipt).issue(
                fractional_receipt,
                fractional_candidate,
                input_refs=[CAS_REF],
                lifetime_seconds=120,
            )

        with self.assertRaisesRegex(AuthorityError, "frozen corridor role"):
            _corridor(
                receipt,
                authority=synthetic_authority(
                    permit_issuer=("synthetic-model", "model-proposer")
                ),
            )

    def test_researchctl_has_no_flag_or_command_that_issues_authority(self) -> None:
        source = (ROOT / "src" / "research_bridge" / "researchctl.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "A1AuthorityCorridor",
            "CorridorExecutorProfile",
            "issue_permit",
            "grant_authority",
            "--permit",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
