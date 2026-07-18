from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from adapters.market.synthetic_fixture import (  # noqa: E402
    PinnedSyntheticDomainAuthority,
    SyntheticDomainError,
    SyntheticMarketDomainWriter,
)
from research_bridge.admission import canonical_json_sha256  # noqa: E402
from research_bridge.discovery import (  # noqa: E402
    DiscoveryError,
    FreezeProjection,
    FreezeProjectionConfig,
    FreezeProjector,
)
from tests.test_a1_scout_ipc_fixture import (  # noqa: E402
    A1_SHA,
    BASE_SHA,
    CONTEXT_SHA,
    CORE_SHA,
    HEAD_SHA,
    NOW,
    POLICY_SHA,
    RELEASE_SHA,
    _claim,
    _envelope,
    _kernel,
    _materialize,
    _service,
)


NOW_TEXT = "2026-07-18T12:00:00Z"
INPUT_SHA = "7" * 64
CODE_SHA = "8" * 64
VALIDATOR_SHA = "9" * 64
HYPOTHESIS_WRITER = "synthetic-market-domain-adapter"
PROTOCOL_WRITER = "synthetic-market-domain-registry-writer"


def _thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _candidate() -> dict[str, object]:
    service = _service()
    event_ref = _materialize(service)["material_event"]["object_id"]
    claim = _claim(service, event_ref)
    response = service.submit_proposal(
        proposal_envelope=_envelope(event_ref, claim["claim_token"]),
        actor="scout:uid:3001",
        idempotency_key="s03-proposal",
        now=NOW_TEXT,
    )
    return _thaw(response["candidate_spec_draft"])  # type: ignore[return-value]


def _projection_config(**overrides: object) -> FreezeProjectionConfig:
    values: dict[str, object] = {
        "domain_contour": "market",
        "hypothesis_writer_id": HYPOTHESIS_WRITER,
        "protocol_writer_id": PROTOCOL_WRITER,
        "input_manifest_sha256": INPUT_SHA,
        "code_sha256": CODE_SHA,
        "environment_digest": "synthetic-python-stdlib-fixture-v1",
        "seed_set": (11, 29),
        "validator_sha256": VALIDATOR_SHA,
        "trial_family_prefix": "synthetic-market-shadow",
        "holdout_policy_ref": "synthetic-no-true-holdout-v1",
    }
    values.update(overrides)
    return FreezeProjectionConfig(**values)  # type: ignore[arg-type]


def _authority(**overrides: object) -> PinnedSyntheticDomainAuthority:
    values: dict[str, object] = {
        "contour": "market",
        "classification": "D0_PUBLIC",
        "hypothesis_writer_id": HYPOTHESIS_WRITER,
        "protocol_writer_id": PROTOCOL_WRITER,
        "expected_core_catalog_sha256": CORE_SHA,
    }
    values.update(overrides)
    return PinnedSyntheticDomainAuthority(**values)  # type: ignore[arg-type]


def _writer(**authority_overrides: object) -> SyntheticMarketDomainWriter:
    return SyntheticMarketDomainWriter(
        ROOT / "contracts",
        authority=_authority(**authority_overrides),
    )


def _snapshot(candidate: dict[str, object]):
    return _kernel().freeze_admission_snapshot(
        candidate,
        ledger_revision=9,
        as_of=NOW,
        current_head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        worktree_clean=True,
        release_manifest_sha256=RELEASE_SHA,
        context_sha256=CONTEXT_SHA,
        available_cost_units=50,
        available_tokens=50_000,
        cycle_admitted=0,
        daily_admitted=0,
        wip_available=True,
        active_reservations=[],
        executor_capability_refs=["capability:executor-fixture"],
        evaluator_capability_refs=["capability:evaluator-fixture"],
        model_route_proof_ref="capability:model-route-fixture",
    )


class SyntheticDomainFreezeTests(unittest.TestCase):
    def test_end_to_end_freeze_has_exact_domain_writers_and_shadow_binding(self) -> None:
        candidate = _candidate()
        projection = FreezeProjector(_projection_config()).project(candidate)
        bundle = _writer().freeze(projection, issued_at=NOW_TEXT)
        result = bundle.to_mapping()
        hypothesis = result["hypothesis_card"]
        protocol = result["protocol_snapshot"]
        self.assertEqual(hypothesis["schema_id"], "HypothesisCard")
        self.assertEqual(protocol["schema_id"], "ProtocolSnapshot")
        self.assertEqual(hypothesis["issuer"], {
            "id": HYPOTHESIS_WRITER,
            "authority_class": "domain-adapter",
        })
        self.assertEqual(protocol["issuer"], {
            "id": PROTOCOL_WRITER,
            "authority_class": "domain-registry-writer",
        })
        self.assertEqual(hypothesis["contour"], "market")
        self.assertEqual(protocol["classification"], "D0_PUBLIC")
        self.assertEqual(result["shadow_taint"], "SHADOW_UNAPPLIED")
        self.assertEqual(result["candidate_sha256"], canonical_json_sha256(candidate))
        self.assertEqual(
            protocol["payload"]["hypothesis_sha256"],
            canonical_json_sha256(hypothesis),
        )
        self.assertEqual(protocol["payload"]["holdout_policy_ref"], "synthetic-no-true-holdout-v1")

    def test_output_matches_frozen_core_contract_shapes(self) -> None:
        candidate = _candidate()
        bundle = _writer().freeze(
            FreezeProjector(_projection_config()).project(candidate), issued_at=NOW_TEXT
        ).to_mapping()
        catalog = json.loads((ROOT / "contracts" / "catalog.json").read_text())
        common = {
            "schema_id", "schema_version", "object_id", "issued_at", "issuer",
            "contour", "classification", "payload", "integrity",
        }
        for name, key in (
            ("HypothesisCard", "hypothesis_card"),
            ("ProtocolSnapshot", "protocol_snapshot"),
        ):
            value = bundle[key]
            self.assertEqual(set(value), common)
            self.assertEqual(
                set(value["payload"]),
                set(catalog["contracts"][name]["required_payload"]),
            )
            self.assertEqual(
                value["integrity"]["payload_sha256"],
                canonical_json_sha256(value["payload"]),
            )

    def test_projection_and_writer_replay_are_deterministic_and_immutable(self) -> None:
        candidate = _candidate()
        projector = FreezeProjector(_projection_config())
        first_projection = projector.project(candidate)
        second_projection = projector.project(deepcopy(candidate))
        self.assertEqual(first_projection.sha256, second_projection.sha256)
        first = _writer().freeze(first_projection, issued_at=NOW_TEXT)
        second = _writer().freeze(second_projection, issued_at=NOW_TEXT)
        self.assertEqual(first.to_mapping(), second.to_mapping())
        with self.assertRaises(TypeError):
            first.hypothesis_card["issuer"] = "spoof"  # type: ignore[index]
        mutable = first.to_mapping()
        mutable["hypothesis_card"]["payload"]["thesis"] = "changed"
        self.assertNotEqual(mutable, first.to_mapping())

    def test_projection_binds_exact_candidate_to_admission_snapshot(self) -> None:
        candidate = _candidate()
        projector = FreezeProjector(_projection_config())
        projection = projector.project(candidate)
        binding = dict(projector.bind_admission_snapshot(projection, _snapshot(candidate)))
        self.assertEqual(binding["candidate_sha256"], canonical_json_sha256(candidate))
        self.assertEqual(binding["freeze_projection_sha256"], projection.sha256)
        self.assertEqual(binding["shadow_taint"], "SHADOW_UNAPPLIED")

        different = deepcopy(candidate)
        different["payload"]["candidate_id"] = "candidate-public-different"
        different["integrity"]["payload_sha256"] = canonical_json_sha256(different["payload"])
        other_projection = projector.project(different)
        with self.assertRaises(DiscoveryError):
            projector.bind_admission_snapshot(other_projection, _snapshot(candidate))

    def test_shadow_candidate_is_parked_and_never_promoted_by_fixture(self) -> None:
        candidate = _candidate()
        candidate["payload"]["shadow_taint"] = "SHADOW_UNAPPLIED"
        candidate["integrity"]["payload_sha256"] = canonical_json_sha256(candidate["payload"])
        projection = FreezeProjector(_projection_config()).project(candidate)
        bundle = _writer().freeze(projection, issued_at=NOW_TEXT).to_mapping()
        decision = _kernel().evaluate_candidate(candidate, _snapshot(candidate))
        self.assertEqual(bundle["shadow_taint"], "SHADOW_UNAPPLIED")
        self.assertEqual(decision.decision, "PARK")
        self.assertEqual(
            decision.receipt["payload"]["reason_codes"],
            ("SHADOW_TAINT_RESTRICTED",),
        )
        encoded = json.dumps(bundle, sort_keys=True)
        for forbidden in ("LearningDecision", "Permit", "promotion", "canonical_write"):
            self.assertNotIn(forbidden, encoded)

    def test_writer_identity_spoof_is_rejected_even_with_valid_projection_digest(self) -> None:
        projection = FreezeProjector(_projection_config()).project(_candidate())
        value = projection.to_mapping()
        value["required_writers"]["ProtocolSnapshot"] = "bridge"
        spoofed = FreezeProjection(payload=value, sha256=canonical_json_sha256(value))
        with self.assertRaises(SyntheticDomainError):
            _writer().freeze(spoofed, issued_at=NOW_TEXT)

    def test_scope_escape_and_true_holdout_are_rejected(self) -> None:
        with self.assertRaises(DiscoveryError):
            _projection_config(domain_contour="security")
        with self.assertRaises(DiscoveryError):
            _projection_config(holdout_policy_ref="true-unseen-holdout")
        candidate = _candidate()
        candidate["classification"] = "D1"
        with self.assertRaises(DiscoveryError):
            FreezeProjector(_projection_config()).project(candidate)

    def test_candidate_integrity_and_unknown_fields_fail_closed(self) -> None:
        candidate = _candidate()
        candidate["payload"]["policy_sha256"] = "0" * 64
        with self.assertRaises(DiscoveryError):
            FreezeProjector(_projection_config()).project(candidate)
        candidate = _candidate()
        candidate["payload"]["domain_writer"] = "bridge"
        candidate["integrity"]["payload_sha256"] = canonical_json_sha256(candidate["payload"])
        with self.assertRaises(DiscoveryError):
            FreezeProjector(_projection_config()).project(candidate)

    def test_authority_and_catalog_are_mandatory_and_pinned(self) -> None:
        with self.assertRaises(SyntheticDomainError):
            SyntheticMarketDomainWriter(ROOT / "contracts", authority=None)  # type: ignore[arg-type]
        with self.assertRaises(SyntheticDomainError):
            _writer(expected_core_catalog_sha256="0" * 64)
        with self.assertRaises(SyntheticDomainError):
            _authority(classification="D1_INTERNAL_SANITIZED")

    def test_bridge_projector_has_no_domain_issuer_or_io_surface(self) -> None:
        source = (ROOT / "src" / "research_bridge" / "discovery.py").read_text()
        self.assertNotIn('"schema_id": "HypothesisCard"', source)
        self.assertNotIn('"schema_id": "ProtocolSnapshot"', source)
        self.assertNotIn("SyntheticMarketDomainWriter", source)
        for forbidden in ("open(", "socket.", "requests.", "subprocess.", "sqlite"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
