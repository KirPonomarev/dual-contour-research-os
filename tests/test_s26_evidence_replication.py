from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from research_bridge.evolution import (  # noqa: E402
    DeclassificationCandidate,
    EvidenceDescriptor,
    EvaluatorExposureRecord,
    EvolutionError,
    ReplicationDimensionClaim,
    ReplicationPairClaim,
    ReplicationPolicy,
    ResearchIslandSpec,
    build_evidence_sidecar,
    build_replication_matrix,
    build_research_islands,
    declassification_dry_run,
)


PROFILE = ROOT / "provenance" / "evidence-replication-matrix-v1.json"
PROFILE_SHA = "4af1043d70a41950b8688806d96ae844cfdc33f6240c3fae8d82a7fcf2aa2966"
EXPOSURE = ROOT / "contracts" / "a1" / "v1" / "profiles" / "evaluator_exposure_v1.json"
EXPOSURE_SHA = "646ef26b37a277b9abb2912f4000d5f9b6c5c754e239ffbbd9aac076c2727f9d"
DIMENSIONS = ("data", "code", "environment", "temporal", "model")


def descriptor(index: int, *, source: str | None = None, shared_model: bool = False) -> EvidenceDescriptor:
    groups = tuple(
        (
            dimension,
            "group:" + ("shared-model" if shared_model and dimension == "model" else f"{dimension}-{index}"),
        )
        for dimension in DIMENSIONS
    )
    return EvidenceDescriptor(
        evidence_ref=f"evidence:public-{index}",
        classification="D0_PUBLIC",
        content_sha256=f"{index:064x}",
        source_group=f"source:{source or f'public-{index}'}",
        dimension_groups=groups,
        synthetic=index % 2 == 0,
        shadow_taint="SHADOW_UNAPPLIED" if index % 2 == 0 else "NONE",
    )


def pair(parent: EvidenceDescriptor, child: EvidenceDescriptor) -> ReplicationPairClaim:
    parent_groups = dict(parent.dimension_groups)
    child_groups = dict(child.dimension_groups)
    return ReplicationPairClaim(
        parent_trial_ref="trial:parent",
        child_trial_ref="trial:child",
        original_outcome_ref="outcome:parent",
        replication_outcome_ref="outcome:child",
        dimensions=tuple(
            ReplicationDimensionClaim(
                dimension=name,
                parent_group=parent_groups[name],
                child_group=child_groups[name],
                verification_refs=(parent.evidence_ref, child.evidence_ref),
            )
            for name in DIMENSIONS
        ),
    )


def exposure(*, count: int = 1, holdout: bool = False, feedback: str = "binary-pass-fail") -> EvaluatorExposureRecord:
    return EvaluatorExposureRecord(
        evaluator_ref="evaluator:public-fixture",
        candidate_lineage="lineage:one",
        trial_family_ref="trial-family:one",
        day_bucket="2026-07-18",
        feedback_class=feedback,
        query_count=count,
        true_holdout=holdout,
    )


class EvidenceReplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = ReplicationPolicy(
            PROFILE,
            expected_profile_sha256=PROFILE_SHA,
            exposure_profile_path=EXPOSURE,
            expected_exposure_sha256=EXPOSURE_SHA,
        )
        self.parent = descriptor(1)
        self.child = descriptor(2)
        self.sidecar = build_evidence_sidecar(self.policy, (self.child, self.parent))

    def test_profile_is_exact_digest_bound_and_domain_contract_is_not_reimplemented(self) -> None:
        self.assertEqual(self.policy.profile_sha256, PROFILE_SHA)
        self.assertEqual(self.policy.exposure_profile_sha256, EXPOSURE_SHA)
        value = json.loads(PROFILE.read_text())
        value["limits"]["max_evidence_items"] = 65
        path = self.root / "mutated.json"
        path.write_text(json.dumps(value))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(EvolutionError):
            ReplicationPolicy(
                path,
                expected_profile_sha256=digest,
                exposure_profile_path=EXPOSURE,
                expected_exposure_sha256=EXPOSURE_SHA,
            )
        source = inspect.getsource(sys.modules["research_bridge.evolution"])
        self.assertNotIn("ReplicationReceipt", source)
        self.assertNotIn("class ReplicationLevel", source)

    def test_sidecar_is_d0_ref_hash_group_only_deterministic_and_zero_authority(self) -> None:
        replay = build_evidence_sidecar(self.policy, (self.parent, self.child))
        self.assertEqual(self.sidecar, replay)
        self.assertEqual(
            tuple(item.evidence_ref for item in self.sidecar.descriptors),
            ("evidence:public-1", "evidence:public-2"),
        )
        self.assertFalse(self.sidecar.raw_payloads_present)
        self.assertFalse(self.sidecar.side_effects)
        self.assertFalse(self.sidecar.grants_authority)
        self.assertNotIn("payload", inspect.signature(EvidenceDescriptor).parameters)
        with self.assertRaises(EvolutionError):
            replace(self.parent, classification="D2_DOMAIN_CONFIDENTIAL")
        with self.assertRaises(EvolutionError):
            replace(self.parent, evidence_ref="file:///private/evidence")
        with self.assertRaises(EvolutionError):
            build_evidence_sidecar(self.policy, (self.parent, self.parent))

    def test_five_distinct_dimensions_pass_only_for_frozen_scope(self) -> None:
        matrix = build_replication_matrix(self.policy, self.sidecar, (pair(self.parent, self.child),))
        result = matrix.pairs[0]
        self.assertEqual(
            tuple(item.dimension for item in result.dimensions), DIMENSIONS
        )
        self.assertEqual(
            {item.status for item in result.dimensions},
            {"DISTINCT_FOR_FROZEN_SCOPE"},
        )
        self.assertEqual(result.overall_status, "MULTIDIMENSIONAL_PASS_FOR_FROZEN_SCOPE")
        self.assertFalse(matrix.absolute_independence_claimed)
        self.assertIsNone(matrix.linear_replication_level)
        self.assertFalse(matrix.side_effects)
        self.assertFalse(matrix.grants_authority)
        replay = build_replication_matrix(self.policy, self.sidecar, (pair(self.parent, self.child),))
        self.assertEqual(matrix, replay)

    def test_same_group_and_same_source_correlation_never_become_independence(self) -> None:
        shared_model_child = descriptor(3, shared_model=True)
        shared_model_parent = descriptor(4, shared_model=True)
        same_group_sidecar = build_evidence_sidecar(
            self.policy, (shared_model_parent, shared_model_child)
        )
        same_group = build_replication_matrix(
            self.policy,
            same_group_sidecar,
            (pair(shared_model_parent, shared_model_child),),
        ).pairs[0]
        self.assertEqual(same_group.dimensions[-1].status, "CORRELATED_SAME_GROUP")
        self.assertEqual(same_group.overall_status, "CORRELATED")

        same_source_parent = descriptor(5, source="shared")
        same_source_child = descriptor(6, source="shared")
        same_source_sidecar = build_evidence_sidecar(
            self.policy, (same_source_parent, same_source_child)
        )
        same_source = build_replication_matrix(
            self.policy,
            same_source_sidecar,
            (pair(same_source_parent, same_source_child),),
        ).pairs[0]
        self.assertEqual(
            {item.status for item in same_source.dimensions},
            {"DISTINCT_DECLARED_CORRELATED_SOURCE"},
        )
        self.assertEqual(same_source.overall_status, "INDEPENDENCE_NOT_ESTABLISHED")

    def test_matrix_rejects_missing_sidecar_evidence_and_forged_integrity(self) -> None:
        claim = pair(self.parent, self.child)
        broken_dimension = replace(
            claim.dimensions[0], verification_refs=(self.parent.evidence_ref,)
        )
        broken = replace(claim, dimensions=(broken_dimension,) + claim.dimensions[1:])
        with self.assertRaises(EvolutionError):
            build_replication_matrix(self.policy, self.sidecar, (broken,))
        forged = replace(self.sidecar, sidecar_sha256="0" * 64)
        with self.assertRaises(EvolutionError):
            build_replication_matrix(self.policy, forged, (claim,))

    def test_research_islands_are_disjoint_and_exposure_bounded(self) -> None:
        first = ResearchIslandSpec(
            island_id="island:one",
            workspace_namespace_ref="namespace:one",
            model_context_ref="model-context:one",
            classification="D0_PUBLIC",
            trial_refs=("trial:parent",),
            evidence_refs=(self.parent.evidence_ref,),
            exposures=(exposure(),),
        )
        second = ResearchIslandSpec(
            island_id="island:two",
            workspace_namespace_ref="namespace:two",
            model_context_ref="model-context:two",
            classification="D0_PUBLIC",
            trial_refs=("trial:child",),
            evidence_refs=(self.child.evidence_ref,),
            exposures=(),
        )
        snapshot = build_research_islands(self.policy, self.sidecar, (second, first))
        self.assertEqual(snapshot.status, "READY_METADATA_ONLY")
        self.assertEqual(snapshot.weighted_exposure_units, 1)
        self.assertFalse(snapshot.side_effects)
        self.assertFalse(snapshot.grants_authority)
        with self.assertRaises(EvolutionError):
            build_research_islands(
                self.policy,
                self.sidecar,
                (first, replace(second, trial_refs=("trial:parent",))),
            )
        with self.assertRaises(EvolutionError):
            replace(first, network_enabled=True)

    def test_exposure_or_true_holdout_parks_entire_island_snapshot(self) -> None:
        for record, reason in (
            (exposure(count=4), "CANDIDATE_EXPOSURE_BUDGET_EXHAUSTED"),
            (exposure(holdout=True), "TRUE_HOLDOUT_AUTONOMOUS_DENIED"),
            (exposure(feedback="metric-vector"), "CANDIDATE_EXPOSURE_BUDGET_EXHAUSTED"),
        ):
            island = ResearchIslandSpec(
                island_id="island:exposure",
                workspace_namespace_ref="namespace:exposure",
                model_context_ref="model-context:exposure",
                classification="D0_PUBLIC",
                trial_refs=("trial:exposure",),
                evidence_refs=(self.parent.evidence_ref,),
                exposures=(record,),
            )
            with self.subTest(reason=reason):
                snapshot = build_research_islands(self.policy, self.sidecar, (island,))
                self.assertEqual(snapshot.status, "PARKED_EXPOSURE")
                self.assertIn(reason, snapshot.reason_codes)

    def test_declassification_is_dry_run_only_and_denies_forbidden_metadata(self) -> None:
        island = ResearchIslandSpec(
            island_id="island:one",
            workspace_namespace_ref="namespace:one",
            model_context_ref="model-context:one",
            classification="D0_PUBLIC",
            trial_refs=("trial:parent",),
            evidence_refs=(self.parent.evidence_ref,),
            exposures=(),
        )
        islands = build_research_islands(self.policy, self.sidecar, (island,))
        matrix = build_replication_matrix(self.policy, self.sidecar, (pair(self.parent, self.child),))
        candidate = DeclassificationCandidate(
            candidate_ref="declassification:public-candidate",
            source_island_id="island:one",
            classification="D0_PUBLIC",
            public_manifest_sha256="a" * 64,
            evidence_refs=(self.parent.evidence_ref,),
            replication_matrix_ref="replication-matrix:sha256:" + matrix.matrix_sha256,
            metadata_labels=("synthetic", "public"),
        )
        passed = declassification_dry_run(self.policy, candidate, islands, matrix)
        self.assertEqual(passed.status, "PASS_DRY_RUN_NO_AUTHORITY")
        self.assertEqual((passed.bytes_exported, passed.network_calls, passed.canonical_writes), (0, 0, 0))
        self.assertFalse(passed.forbidden_bytes_or_metadata_detected)
        self.assertFalse(passed.grants_authority)
        denied = declassification_dry_run(
            self.policy,
            replace(candidate, classification="D3_RESTRICTED"),
            islands,
            matrix,
        )
        self.assertEqual(denied.status, "DENIED")
        self.assertTrue(denied.forbidden_bytes_or_metadata_detected)
        self.assertIn("CLASSIFICATION_NOT_PUBLIC", denied.reason_codes)
        wrong_binding = declassification_dry_run(
            self.policy,
            replace(candidate, replication_matrix_ref="replication-matrix:sha256:" + "0" * 64),
            islands,
            matrix,
        )
        self.assertEqual(wrong_binding.status, "DENIED")
        self.assertIn("REPLICATION_MATRIX_BINDING_MISMATCH", wrong_binding.reason_codes)


if __name__ == "__main__":
    unittest.main()
