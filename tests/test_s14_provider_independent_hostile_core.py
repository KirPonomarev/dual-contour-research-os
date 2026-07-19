from __future__ import annotations

import concurrent.futures
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.admission import (  # noqa: E402
    A1AdmissionError,
    AdmissionError,
    canonical_json_sha256,
)
from research_bridge.discovery import DiscoveryError, ParserLimits, StrictProposalParser  # noqa: E402
from research_bridge.ipc import IPCError, decode_message  # noqa: E402
from research_bridge.kernel import BridgeKernel  # noqa: E402
from research_bridge.ledger import FeedbackBundleRecord, JobLedger, LedgerError  # noqa: E402
from research_bridge.validation import DeterministicL0Validator, ValidationBoundaryError  # noqa: E402
from tests.test_a1_admission_fixture import (  # noqa: E402
    _candidate as admission_candidate,
    _kernel as admission_kernel,
    _snapshot as admission_snapshot,
)
from tests.test_a1_authority_corridor import (  # noqa: E402
    AT as AUTHORITY_AT,
    CAS_REF,
    _admitted_candidate,
    _corridor,
    _reseal,
)
from tests.test_a1_scout_ipc_fixture import (  # noqa: E402
    NOW_TEXT,
    _claim,
    _critique,
    _envelope,
    _materialize,
    _model_body,
    _service,
)
from tests.test_a1_storage_v2 import projection_states  # noqa: E402
from tests.test_s07_l0_independent_validation import MemoryStore, plain  # noqa: E402
from tests.test_s08_atomic_feedback import BASE_DOCUMENTS, feedback_kwargs  # noqa: E402
from tests.test_stage1_reference_vertical import (  # noqa: E402
    INPUT_A,
    INPUT_B,
    INPUT_REFS,
    NOW as EXECUTION_NOW,
    PROTOCOL_REF,
    VALIDATOR_ID,
    VALIDATOR_SHA256,
    _environment,
)


class ProviderIndependentHostileCoreTests(unittest.TestCase):
    def test_parser_and_ipc_attack_corpus_fails_closed(self) -> None:
        parser = StrictProposalParser(
            ParserLimits(maximum_bytes=4_096, maximum_depth=8, maximum_references=2)
        )
        model_attacks: tuple[str | bytes, ...] = (
            b'{"candidate_id":"a","candidate_id":"b"}',
            b'{"candidate_id":NaN}',
            b'{"candidate_id":Infinity}',
            json.dumps({"nested": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}}),
            json.dumps({"oversize": "x" * 5_000}),
            b"\xff\xfe",
            json.dumps({**_model_body(), "issuer": "attacker"}),
        )
        for attack in model_attacks:
            with self.subTest(model_attack=str(attack)[:64]):
                with self.assertRaises(DiscoveryError):
                    parser.parse_model_body(attack)

        ipc_attacks = (
            b'{"x":1,"x":2}\n',
            b'{"x":NaN}\n',
            b'{"x":1}\r\n',
            b'{"x":1}\n{"x":2}\n',
            b"[]\n",
            b"\xff\n",
            b'{"x":1}',
        )
        for attack in ipc_attacks:
            with self.subTest(ipc_attack=attack[:32]):
                with self.assertRaises(IPCError):
                    decode_message(attack)

    def test_forbidden_or_unknown_fallback_requests_never_reserve_or_grant(self) -> None:
        attacks: tuple[dict[str, object], ...] = tuple(
            {field: True}
            for field in (
                "network_required",
                "holdout_access_requested",
                "canonical_write_requested",
                "private_api_requested",
                "live_execution_requested",
            )
        )
        for payload_override in attacks:
            with self.subTest(payload_override=payload_override):
                kernel = admission_kernel()
                candidate = admission_candidate(payload_overrides=payload_override)
                decision = kernel.evaluate_candidate(
                    candidate, admission_snapshot(kernel, candidate)
                ).to_mapping()
                payload = decision["payload"]
                self.assertEqual(payload["decision"], "REJECT")
                self.assertIsNone(payload["reservation_ref"])
                self.assertIsNone(payload["spec_sha256"])
                encoded = json.dumps(decision, sort_keys=True)
                for forbidden in ("Permit", "AttemptLease", '"grants_authority":true'):
                    self.assertNotIn(forbidden, encoded)

        unknown = admission_candidate(
            payload_overrides={"fallback_provider": "attacker-controlled-provider"}
        )
        with self.assertRaises(A1AdmissionError):
            admission_snapshot(admission_kernel(), unknown)

    def test_authority_spoofing_and_resealed_transfer_create_zero_writes(self) -> None:
        candidate, receipt = _admitted_candidate()
        bundle = _corridor(receipt).issue(
            receipt, candidate, input_refs=[CAS_REF], lifetime_seconds=120
        )
        transferred = bundle.to_mapping()
        transferred["permit"]["payload"]["subject"] = "attacker-runner"
        transferred["lease"]["payload"]["runner_identity"] = "attacker-runner"
        _reseal(transferred["permit"])
        _reseal(transferred["lease"])
        with tempfile.TemporaryDirectory() as temporary:
            with JobLedger(Path(temporary) / "authority-spoof.sqlite3") as ledger:
                with self.assertRaises((AdmissionError, LedgerError)):
                    BridgeKernel(ledger, authority=bundle.authority).claim(
                        transferred["job_spec"],
                        transferred["permit"],
                        transferred["lease"],
                        now=AUTHORITY_AT,
                    )
                self.assertEqual(ledger.event_count(), 0)
                self.assertTrue(ledger.verify_chain())

    def test_colluding_scouts_cannot_transfer_claim_or_mint_authority(self) -> None:
        service = _service()
        event_ref = _materialize(service)["material_event"]["object_id"]
        claim = _claim(service, event_ref, actor="scout:uid:3001")
        envelope = _envelope(event_ref, claim["claim_token"])

        def submit(actor: str) -> object:
            try:
                return service.submit_proposal(
                    proposal_envelope=envelope,
                    actor=actor,
                    idempotency_key=f"collusion-{actor}",
                    now=NOW_TEXT,
                )
            except DiscoveryError as exc:
                return exc

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, ("scout:uid:3001", "scout:uid:3002")))
        accepted = [value for value in results if not isinstance(value, Exception)]
        rejected = [value for value in results if isinstance(value, DiscoveryError)]
        self.assertEqual(len(accepted), 1, results)
        self.assertEqual(len(rejected), 1, results)
        candidate = accepted[0]["candidate_spec_draft"]  # type: ignore[index]
        encoded = json.dumps(plain(candidate), sort_keys=True)
        for forbidden in ("AdmissionReceipt", "Permit", "AttemptLease", "grants_authority"):
            self.assertNotIn(forbidden, encoded)

    def test_critique_failure_cannot_leak_diagnostics_or_widen_retry(self) -> None:
        service = _service(maximum_reason_feedback=1)
        event_ref = _materialize(service)["material_event"]["object_id"]
        claim = _claim(service, event_ref)
        envelope = _envelope(
            event_ref,
            claim["claim_token"],
            critique_output=json.dumps(
                _critique(accepted=False, critique="private evaluator diagnostic")
            ),
        )
        first = service.submit_proposal(
            proposal_envelope=envelope,
            actor="scout:uid:3001",
            idempotency_key="hostile-critique-a",
            now=NOW_TEXT,
        )
        second = service.submit_proposal(
            proposal_envelope=envelope,
            actor="scout:uid:3001",
            idempotency_key="hostile-critique-b",
            now=NOW_TEXT,
        )
        self.assertEqual(first["decision"], "REJECTED")
        self.assertEqual(second["decision"], "PARKED")
        self.assertNotIn(
            "private evaluator diagnostic", json.dumps(plain((first, second)))
        )
        self.assertEqual(second["feedback_remaining"], 0)

    def test_poisoned_shadow_memory_cannot_launder_learning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with JobLedger(Path(temporary) / "poisoned-memory.sqlite3") as ledger:
                ledger.append_a1_bundle(
                    objects=BASE_DOCUMENTS,
                    projections=projection_states("hostile-base"),
                    idempotency_key="hostile-base",
                    event_at=feedback_kwargs()["event_at"],  # type: ignore[arg-type]
                )
                attacks = (
                    {"classification": "D2"},
                    {
                        "shadow_taint": "SHADOW_UNAPPLIED",
                        "domain_application_ref": "outcome:forged-domain-application",
                    },
                    {"proposed_outcome": "LEARNED"},
                    {
                        "next_event_candidate": {
                            "reason_code": "FALLBACK",
                            "policy_ref": "file:/tmp/attacker-policy",
                            "remaining_energy": 1,
                            "causal_depth": 0,
                        }
                    },
                )
                for attack in attacks:
                    with self.subTest(attack=attack):
                        before = ledger.event_count()
                        with self.assertRaises(LedgerError):
                            ledger.append_feedback_bundle(
                                **feedback_kwargs(**attack)  # type: ignore[arg-type]
                            )
                        self.assertEqual(ledger.event_count(), before)
                        self.assertEqual(ledger.feedback_projection_coverage(), {})

                record = ledger.append_feedback_bundle(
                    **feedback_kwargs(idempotency_key="valid-shadow-feedback")  # type: ignore[arg-type]
                )
                self.assertEqual(record.outcome_disposition["disposition"], "SHADOW_UNAPPLIED")
                self.assertEqual(record.outcome_disposition["epistemic_axis"], "UNRESOLVED")
                self.assertFalse(record.outcome_disposition["claims_scientific_truth"])
                self.assertFalse(record.experience_record["claims_learning"])
                self.assertFalse(record.idea_node["learned"])
                self.assertEqual(record.idea_node["shadow_taint"], "SHADOW_UNAPPLIED")

    def test_transaction_crash_rolls_back_all_feedback_and_recovers_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with JobLedger(Path(temporary) / "transaction-crash.sqlite3") as ledger:
                ledger.append_a1_bundle(
                    objects=BASE_DOCUMENTS,
                    projections=projection_states("crash-base"),
                    idempotency_key="crash-base",
                    event_at=feedback_kwargs()["event_at"],  # type: ignore[arg-type]
                )
                base_coverage = ledger.projection_coverage()
                ledger._connection.execute(
                    """CREATE TRIGGER hostile_feedback_fault
                    BEFORE INSERT ON bridge_a1_projection_state
                    WHEN NEW.projection_name = 'experiences'
                    BEGIN SELECT RAISE(ABORT, 'hostile feedback fault'); END"""
                )
                with self.assertRaisesRegex(LedgerError, "hostile feedback fault"):
                    ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
                self.assertEqual(ledger.event_count(), 1)
                self.assertEqual(ledger.feedback_projection_coverage(), {})
                self.assertEqual(ledger.projection_coverage(), base_coverage)
                self.assertTrue(ledger.verify_chain())
                ledger._connection.execute("DROP TRIGGER hostile_feedback_fault")
                recovered = ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
                replay = ledger.append_feedback_bundle(**feedback_kwargs())  # type: ignore[arg-type]
                self.assertEqual(recovered.event.sequence, 2)
                self.assertEqual(replay.event.event_sha256, recovered.event.event_sha256)
                self.assertEqual(ledger.event_count(), 2)

    def test_feedback_race_fences_duplicate_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with JobLedger(Path(temporary) / "feedback-race.sqlite3") as ledger:
                ledger.append_a1_bundle(
                    objects=BASE_DOCUMENTS,
                    projections=projection_states("race-base"),
                    idempotency_key="race-base",
                    event_at=feedback_kwargs()["event_at"],  # type: ignore[arg-type]
                )

                def append(key: str) -> object:
                    try:
                        return ledger.append_feedback_bundle(
                            **feedback_kwargs(idempotency_key=key)  # type: ignore[arg-type]
                        )
                    except LedgerError as exc:
                        return exc

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(append, ("race-a", "race-b")))
                accepted = [value for value in results if isinstance(value, FeedbackBundleRecord)]
                rejected = [value for value in results if isinstance(value, LedgerError)]
                self.assertEqual(len(accepted), 1, results)
                self.assertEqual(len(rejected), 1, results)
                self.assertEqual(ledger.event_count(), 2)
                self.assertTrue(ledger.verify_chain())
                self.assertTrue(ledger.verify_a1_coverage())

    def test_known_invalid_control_prevents_a_vacuous_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = _environment(Path(temporary), "D1_INTERNAL_SANITIZED")
            try:
                record = environment.coordinator.execute(
                    environment.job_spec,
                    environment.permit,
                    environment.lease,
                    environment.staging_root,
                    now=EXECUTION_NOW,
                )
                artifact_ref = record.artifact_records[0].artifact_ref
                valid_artifact = environment.artifact_store.read_bytes(
                    artifact_ref, maximum_size_bytes=8_388_608
                )
                invalid_artifact = valid_artifact.replace(
                    b'"chunk_index":0', b'"chunk_index":9', 1
                )
                inputs = MemoryStore(dict(zip(INPUT_REFS, (INPUT_A, INPUT_B), strict=True)))

                def validator(store: object) -> DeterministicL0Validator:
                    return DeterministicL0Validator(
                        validator_id=VALIDATOR_ID,
                        validator_sha256=VALIDATOR_SHA256,
                        protocol_ref=PROTOCOL_REF,
                        artifact_store=store,  # type: ignore[arg-type]
                        input_store=inputs,
                        chunk_size=7,
                    )

                valid = validator(environment.artifact_store).validate(record.execution_receipt)
                self.assertIn("chunk-byte-recomputation", valid["payload"]["checks_performed"])
                self.assertEqual(valid["payload"]["tolerances"]["byte_mismatches"], 0)
                invalid_ref_store = MemoryStore({artifact_ref: invalid_artifact})
                with self.assertRaises(ValidationBoundaryError):
                    validator(invalid_ref_store).validate(record.execution_receipt)
                self.assertEqual(invalid_ref_store.calls, [(artifact_ref, 8_388_608)])
                self.assertEqual(
                    valid["integrity"]["payload_sha256"],
                    canonical_json_sha256(valid["payload"]),
                )
            finally:
                environment.raw_ledger.close()


if __name__ == "__main__":
    unittest.main()
