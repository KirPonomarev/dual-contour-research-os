from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import e1_aggregate_gate  # noqa: E402
import e2_aggregate_gate  # noqa: E402
import e3_aggregate_gate  # noqa: E402
from capability_proof import canonical_json_sha256  # noqa: E402
from release_currentness import (  # noqa: E402
    ReleaseCurrentnessError,
    validate_release_currentness_context,
)
from tools.verify_final_release_freeze import (  # noqa: E402
    FinalReleaseFreezeError,
    inspect,
)


CATALOG_PATHS = {
    "core": "contracts/catalog.json",
    "a1": "contracts/a1/v1/catalog.json",
    "e5": "contracts/e5/v1/catalog.json",
}
DEFAULT_BUNDLES = {
    "code": ["src/research_bridge/researchd.py"],
    "config": ["ops/release/researchd.config.template.json"],
    "policy": ["ops/release/final-a1-runtime-policy.json"],
    "provider": ["provenance/model-role-evaluation-v2.json"],
}
DEFAULT_SBOM = "docs/receipts/release/s4-release-sbom.spdx.json"
DEFAULT_DEPENDENCY = "docs/receipts/release/s38-dependency-notice-inventory.json"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def _blob(root: Path, commit: str, path: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=root)


def _context(
    root: Path,
    *,
    release_sha: str | None = None,
    evidence_head: str | None = None,
    bundles: dict[str, list[str]] | None = None,
    sbom_path: str = DEFAULT_SBOM,
    dependency_path: str = DEFAULT_DEPENDENCY,
) -> dict[str, object]:
    release = release_sha or _git(root, "rev-parse", "HEAD")
    evidence = evidence_head or _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", f"{release}^{{tree}}")
    selected = bundles or DEFAULT_BUNDLES

    def bundle(paths: list[str]) -> dict[str, object]:
        ordered = sorted(paths)
        material = {
            path: hashlib.sha256(_blob(root, release, path)).hexdigest()
            for path in ordered
        }
        return {"paths": ordered, "sha256": canonical_json_sha256(material)}

    release_bundles = {name: bundle(paths) for name, paths in selected.items()}
    images = ["sha256:" + "1" * 64]
    environment = "profile:synthetic-currentness-v1"
    return {
        "schema_id": "ReleaseCurrentnessContext",
        "schema_version": "1.0.0",
        "release_sha": release,
        "tree_sha": tree,
        "repository_evidence_head_sha": evidence,
        "release_bundles": release_bundles,
        "catalog_sha256": {
            name: hashlib.sha256(_blob(root, release, path)).hexdigest()
            for name, path in CATALOG_PATHS.items()
        },
        "image_digests": images,
        "sbom": {
            "path": sbom_path,
            "sha256": hashlib.sha256(_blob(root, evidence, sbom_path)).hexdigest(),
        },
        "dependency_inventory": {
            "path": dependency_path,
            "sha256": hashlib.sha256(_blob(root, evidence, dependency_path)).hexdigest(),
        },
        "environment_compatibility_ref": environment,
        "observed_at": "2026-07-19T17:30:00Z",
        "ci": {
            "head_sha": evidence,
            "workflow": "exact-head-ci",
            "run_id": 1,
            "conclusion": "success",
            "ref": "ci:synthetic-currentness",
            "grants_authority": False,
        },
        "e2e": {
            "proof_ref": "proof:synthetic-functional-e2e",
            "release_sha": release,
            "tree_sha": tree,
            "image_digests": images,
            "config_sha256": release_bundles["config"]["sha256"],
            "policy_sha256": release_bundles["policy"]["sha256"],
            "provider_sha256": release_bundles["provider"]["sha256"],
            "environment_compatibility_ref": environment,
            "status": "PASS",
            "valid_until": "2026-07-20T17:30:00Z",
            "grants_authority": False,
        },
        "invalidation_refs": [],
        "grants_authority": False,
    }


def _load(path: str) -> dict[str, object]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class ProofCurrentnessTests(unittest.TestCase):
    def test_exact_current_release_context_passes(self) -> None:
        context = _context(ROOT)
        value = validate_release_currentness_context(ROOT, context)
        self.assertEqual(value["release_sha"], _git(ROOT, "rev-parse", "HEAD"))
        self.assertFalse(value["grants_authority"])

    def test_every_release_dimension_is_fail_closed(self) -> None:
        base = _context(ROOT)
        mutations = (
            lambda value: value.__setitem__("tree_sha", "0" * 40),
            lambda value: value["release_bundles"]["code"].__setitem__("sha256", "0" * 64),
            lambda value: value["release_bundles"].pop("provider"),
            lambda value: value["catalog_sha256"].__setitem__("core", "0" * 64),
            lambda value: value.__setitem__("image_digests", []),
            lambda value: value["sbom"].__setitem__("sha256", "0" * 64),
            lambda value: value["dependency_inventory"].__setitem__("sha256", "0" * 64),
            lambda value: value["ci"].__setitem__("conclusion", "failure"),
            lambda value: value["e2e"].__setitem__("config_sha256", "0" * 64),
            lambda value: value["e2e"].__setitem__("valid_until", value["observed_at"]),
            lambda value: value["invalidation_refs"].append("incident:current-release"),
            lambda value: value.__setitem__("grants_authority", True),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = copy.deepcopy(base)
                mutate(value)
                with self.assertRaises(ReleaseCurrentnessError):
                    validate_release_currentness_context(ROOT, value)

    def test_relevant_path_change_after_release_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            files = {
                "src/code.py": "before\n",
                "config/app.json": "{}\n",
                "policy/policy.json": "{}\n",
                "provider/routes.json": "{}\n",
                "contracts/catalog.json": "{}\n",
                "contracts/a1/v1/catalog.json": "{}\n",
                "contracts/e5/v1/catalog.json": "{}\n",
                "sbom/release.spdx.json": "{}\n",
                "inventory/dependencies.json": "{}\n",
            }
            for relative, content in files.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "release"],
                cwd=root, check=True,
            )
            release = _git(root, "rev-parse", "HEAD")
            (root / "src/code.py").write_text("after\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/code.py"], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "drift"],
                cwd=root, check=True,
            )
            evidence = _git(root, "rev-parse", "HEAD")
            context = _context(
                root,
                release_sha=release,
                evidence_head=evidence,
                bundles={
                    "code": ["src/code.py"],
                    "config": ["config/app.json"],
                    "policy": ["policy/policy.json"],
                    "provider": ["provider/routes.json"],
                },
                sbom_path="sbom/release.spdx.json",
                dependency_path="inventory/dependencies.json",
            )
            with self.assertRaisesRegex(ReleaseCurrentnessError, "changed after"):
                validate_release_currentness_context(root, context)

    def test_historical_aggregate_proofs_fail_current_entrypoints(self) -> None:
        context = _context(ROOT)
        cases = (
            (
                e1_aggregate_gate,
                "docs/receipts/capability/e1-evolution-kernel-v1-shadow.json",
            ),
            (
                e2_aggregate_gate,
                "docs/receipts/capability/e2-autonomous-research-shadow.json",
            ),
            (
                e3_aggregate_gate,
                "docs/receipts/capability/e3-evolution-shadow.json",
            ),
        )
        for module, path in cases:
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.__dict__[module.__name__.split("_")[0].upper() + "AggregateError"]):
                    module.validate_aggregate_receipt(
                        ROOT, _load(path), currentness_context=context
                    )

    def test_historical_final_freeze_fails_current_entrypoint(self) -> None:
        with self.assertRaisesRegex(FinalReleaseFreezeError, "currentness context missing"):
            inspect(ROOT)


if __name__ == "__main__":
    unittest.main()
