from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

from src.research_bridge.organism import (  # noqa: E402
    OrganismManifestError,
    build_manifest_from_files,
    build_organism_manifest,
    canonical_json_sha256,
    load_json_document,
    validate_organism_manifest,
)


SOURCE_PATH = ROOT / "ops" / "organism" / "component-declarations.json"
PROJECTION_PATH = ROOT / "ops" / "organism" / "deployment-projection.json"
ISSUED_AT = "2026-07-18T16:00:00Z"


def _source() -> dict[str, object]:
    return json.loads(SOURCE_PATH.read_text())


def _projection() -> dict[str, object]:
    return json.loads(PROJECTION_PATH.read_text())


def _thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _thaw(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _build(
    source: dict[str, object] | None = None,
    projection: dict[str, object] | None = None,
):
    return build_organism_manifest(
        source or _source(), projection or _projection(), issued_at=ISSUED_AT, repository_root=ROOT
    )


def _components(source: dict[str, object]) -> list[dict[str, object]]:
    value = source["components"]
    assert isinstance(value, list)
    return value  # type: ignore[return-value]


def _processes(projection: dict[str, object]) -> list[dict[str, object]]:
    value = projection["processes"]
    assert isinstance(value, list)
    return value  # type: ignore[return-value]


def _resign(manifest: object) -> dict[str, object]:
    value = _thaw(manifest)
    assert isinstance(value, dict)
    payload = value["payload"]
    assert isinstance(payload, dict)
    digest = canonical_json_sha256(payload)
    value["object_id"] = f"organism-manifest:{digest}"
    integrity = value["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = digest
    return value


class ManifestTopologyTests(unittest.TestCase):
    def test_static_sources_build_one_immutable_non_authoritative_manifest(self) -> None:
        first = build_manifest_from_files(
            SOURCE_PATH, PROJECTION_PATH, issued_at=ISSUED_AT, repository_root=ROOT
        )
        second = build_manifest_from_files(
            SOURCE_PATH, PROJECTION_PATH, issued_at=ISSUED_AT, repository_root=ROOT
        )
        self.assertEqual(_thaw(first), _thaw(second))
        payload = first["payload"]
        self.assertEqual(payload["manifest_status"], "DECLARATIVE_NON_AUTHORITATIVE")
        self.assertFalse(payload["grants_authority"])
        self.assertEqual(sum(payload["evidence_stage_summary"].values()), len(payload["components"]))
        self.assertEqual(validate_organism_manifest(first, repository_root=ROOT)["object_id"], first["object_id"])
        with self.assertRaises(TypeError):
            payload["manifest_status"] = "MUTATED"  # type: ignore[index]

    def test_cardinality_is_data_driven_not_hardcoded(self) -> None:
        source = _source()
        projection = _projection()
        template = deepcopy(_components(source)[-1])
        template.update(
            {
                "component_id": "synthetic-count-probe",
                "inputs": ["external:synthetic-count-probe"],
                "outputs": ["terminal:synthetic-count-probe"],
                "dependencies": ["capability-proof-issuer"],
                "evidence": {
                    "stage": "DECLARED",
                    "observed_ref": None,
                    "negative_probe_ref": None,
                    "enforcement_ref": None,
                },
            }
        )
        _components(source).append(template)
        _processes(projection)[-1]["component_ids"].append("synthetic-count-probe")  # type: ignore[index]
        manifest = _build(source, projection)
        self.assertEqual(len(manifest["payload"]["components"]), len(_components(source)))
        self.assertEqual(len(manifest["payload"]["processes"]), len(_processes(projection)))
        self.assertEqual(manifest["payload"]["evidence_stage_summary"]["DECLARED"], 1)

    def test_deployment_projection_must_cover_each_component_exactly_once(self) -> None:
        projection = _projection()
        _processes(projection)[0]["component_ids"].remove("materiality-gate")  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "every component exactly once"):
            _build(projection=projection)

        projection = _projection()
        _processes(projection)[1]["component_ids"].append("materiality-gate")  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "every component exactly once"):
            _build(projection=projection)

        projection = _projection()
        _processes(projection)[0]["component_ids"].append("ghost-component")  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "every component exactly once"):
            _build(projection=projection)

    def test_orphan_dependency_is_rejected(self) -> None:
        source = _source()
        _components(source)[1]["dependencies"] = ["missing-cell"]
        with self.assertRaisesRegex(OrganismManifestError, "orphan component dependency"):
            _build(source=source)

    def test_orphan_input_and_output_channels_are_rejected(self) -> None:
        source = _source()
        _components(source)[1]["inputs"] = ["missing-channel", "external:candidate-spec-draft"]
        with self.assertRaisesRegex(OrganismManifestError, "orphan input channel"):
            _build(source=source)

        source = _source()
        _components(source)[0]["outputs"].append("unconsumed-channel")  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "orphan output channel"):
            _build(source=source)

    def test_multiple_channel_producers_are_rejected(self) -> None:
        source = _source()
        _components(source)[1]["outputs"].append("material-event")  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "multiple producers"):
            _build(source=source)

    def test_existing_feedback_loop_has_one_shared_frozen_bound(self) -> None:
        manifest = _build()
        components = manifest["payload"]["components"]
        bounded = [component["cycle_bound"] for component in components if component["cycle_bound"]]
        self.assertTrue(bounded)
        self.assertEqual(len({canonical_json_sha256(bound) for bound in bounded}), 1)

    def test_unbounded_or_inconsistently_bounded_cycle_is_rejected(self) -> None:
        source = _source()
        _components(source)[0]["cycle_bound"] = None
        with self.assertRaisesRegex(OrganismManifestError, "unbounded topology cycle"):
            _build(source=source)

        source = _source()
        _components(source)[0]["cycle_bound"]["max_iterations"] = 15  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "one frozen bound"):
            _build(source=source)

    def test_evidence_sequence_accepts_each_stage_without_skipping(self) -> None:
        source = _source()
        evidence = _components(source)[0]["evidence"]
        assert isinstance(evidence, dict)
        refs = {
            "observed_ref": "repo:docs/receipts/integration/s02-scout-ipc-runtime.json",
            "negative_probe_ref": "repo:docs/receipts/integration/s02-scout-ipc-assurance.json",
            "enforcement_ref": "repo:docs/receipts/capability/e1a-discovery-admission-fixture.json",
        }
        stages = (
            ("DECLARED", None, None, None),
            ("OBSERVED", refs["observed_ref"], None, None),
            ("NEGATIVE_PROBE_PASSED", refs["observed_ref"], refs["negative_probe_ref"], None),
            (
                "ENFORCEMENT_PROVEN",
                refs["observed_ref"],
                refs["negative_probe_ref"],
                refs["enforcement_ref"],
            ),
        )
        for stage, observed, negative, enforcement in stages:
            with self.subTest(stage=stage):
                candidate = deepcopy(source)
                target = _components(candidate)[0]["evidence"]
                assert isinstance(target, dict)
                target.update(
                    {
                        "stage": stage,
                        "observed_ref": observed,
                        "negative_probe_ref": negative,
                        "enforcement_ref": enforcement,
                    }
                )
                manifest = _build(source=candidate)
                self.assertEqual(
                    manifest["payload"]["evidence_stage_summary"][stage],
                    sum(1 for component in manifest["payload"]["components"] if component["evidence"]["stage"] == stage),
                )

    def test_evidence_stage_cannot_skip_or_claim_extra_evidence(self) -> None:
        source = _source()
        evidence = _components(source)[0]["evidence"]
        assert isinstance(evidence, dict)
        evidence.update({"stage": "ENFORCEMENT_PROVEN", "observed_ref": None})
        with self.assertRaises(OrganismManifestError):
            _build(source=source)

        source = _source()
        evidence = _components(source)[0]["evidence"]
        assert isinstance(evidence, dict)
        evidence.update({"stage": "DECLARED", "observed_ref": "repo:docs/ARCHITECTURE.md"})
        with self.assertRaisesRegex(OrganismManifestError, "skips the progressive evidence sequence"):
            _build(source=source)

    def test_authority_ceiling_and_manifest_status_fail_closed(self) -> None:
        source = _source()
        _components(source)[0]["authority_ceiling"] = "LIVE_CANONICAL_ADMIN"
        with self.assertRaisesRegex(OrganismManifestError, "overbroad"):
            _build(source=source)

        manifest = _thaw(_build())
        assert isinstance(manifest, dict)
        manifest["payload"]["grants_authority"] = True  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "cannot grant authority"):
            validate_organism_manifest(_resign(manifest), repository_root=ROOT)

    def test_source_and_projection_subject_mismatch_is_rejected(self) -> None:
        projection = _projection()
        projection["subject_ref"] = "git:" + "0" * 40
        with self.assertRaisesRegex(OrganismManifestError, "different subjects"):
            _build(projection=projection)

    def test_repository_references_must_exist_and_cannot_escape(self) -> None:
        source = _source()
        _components(source)[0]["proof_ref"] = "repo:docs/receipts/integration/missing.json"
        with self.assertRaisesRegex(OrganismManifestError, "does not exist"):
            _build(source=source)

        source = _source()
        _components(source)[0]["proof_ref"] = "repo:../outside"
        with self.assertRaisesRegex(OrganismManifestError, "escapes"):
            _build(source=source)

    def test_manifest_edges_and_summary_are_recomputed(self) -> None:
        manifest = _thaw(_build())
        assert isinstance(manifest, dict)
        manifest["payload"]["edges"] = []  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "edge projection mismatch"):
            validate_organism_manifest(_resign(manifest), repository_root=ROOT)

        manifest = _thaw(_build())
        assert isinstance(manifest, dict)
        manifest["payload"]["evidence_stage_summary"]["DECLARED"] = 99  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "summary mismatch"):
            validate_organism_manifest(_resign(manifest), repository_root=ROOT)

    def test_payload_tamper_without_resigning_is_rejected(self) -> None:
        manifest = _thaw(_build())
        assert isinstance(manifest, dict)
        manifest["payload"]["policy_ref"] = "policy:tampered"  # type: ignore[index]
        with self.assertRaisesRegex(OrganismManifestError, "object identity mismatch"):
            validate_organism_manifest(manifest, repository_root=ROOT)

    def test_duplicate_json_keys_and_symlink_sources_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schema_id":"x","schema_id":"y"}')
            with self.assertRaisesRegex(OrganismManifestError, "duplicate JSON key"):
                load_json_document(duplicate)

            symlink = root / "source-link.json"
            symlink.symlink_to(SOURCE_PATH)
            with self.assertRaisesRegex(OrganismManifestError, "not a regular file"):
                load_json_document(symlink)

    def test_build_is_read_only_for_source_documents(self) -> None:
        before = (SOURCE_PATH.read_bytes(), PROJECTION_PATH.read_bytes())
        _build()
        after = (SOURCE_PATH.read_bytes(), PROJECTION_PATH.read_bytes())
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
