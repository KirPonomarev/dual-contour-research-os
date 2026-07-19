from __future__ import annotations

import ast
import copy
import inspect as python_inspect
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import e1_aggregate_gate  # noqa: E402
import e2_aggregate_gate  # noqa: E402
import e3_aggregate_gate  # noqa: E402
import verify_final_release_freeze  # noqa: E402
from capability_proof import (  # noqa: E402
    canonical_json_sha256,
    issue_e2_autonomous_research_proof,
    issue_e3_evolution_proof,
    issue_evolution_kernel_v1_proof,
)
from release_currentness import (  # noqa: E402
    ReleaseCurrentnessError,
    validate_release_currentness_context,
)
from tests.test_r07a_proof_currentness import _context, _load  # noqa: E402


CASES = (
    (
        e1_aggregate_gate,
        "docs/receipts/capability/e1-evolution-kernel-v1-shadow.json",
        issue_evolution_kernel_v1_proof,
    ),
    (
        e2_aggregate_gate,
        "docs/receipts/capability/e2-autonomous-research-shadow.json",
        issue_e2_autonomous_research_proof,
    ),
    (
        e3_aggregate_gate,
        "docs/receipts/capability/e3-evolution-shadow.json",
        issue_e3_evolution_proof,
    ),
)


def _thaw(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _current_proof(module: object, path: str, issuer: object, context: dict[str, object]) -> dict[str, object]:
    source = _load(path)
    payload = copy.deepcopy(source["payload"])
    subject_ref = f"git:{context['release_sha']}"
    evidence = module.validate_e1_evidence(ROOT, subject_ref=subject_ref) if module is e1_aggregate_gate else (
        module.validate_e2_evidence(ROOT, subject_ref=subject_ref) if module is e2_aggregate_gate
        else module.validate_e3_evidence(ROOT, subject_ref=subject_ref)
    )
    payload["subject_ref"] = subject_ref
    for field in ("code_sha256", "config_sha256", "policy_sha256", "schema_sha256"):
        payload[field] = evidence[field]
    payload["environment_compatibility_ref"] = context["environment_compatibility_ref"]
    payload["receipt_id"] = f"synthetic-current:{payload['capability_id']}"
    payload["valid_from"] = context["observed_at"]
    payload["valid_until"] = "2026-07-20T17:30:00Z"
    issued = issuer(payload, issued_at=context["observed_at"], classification="D1")
    value = _thaw(issued)
    assert isinstance(value, dict)
    return value


def _resign(document: dict[str, object]) -> dict[str, object]:
    value = copy.deepcopy(document)
    payload = value["payload"]
    digest = canonical_json_sha256(payload)
    value["object_id"] = f"capability-proof:{digest}"
    value["integrity"]["payload_sha256"] = digest
    parents = value["integrity"]["parent_refs"]
    parents[:] = [item for item in parents if not str(item).startswith("git:")]
    parents.append(payload["subject_ref"])
    parents.sort()
    return value


class CurrentnessPathAssuranceTests(unittest.TestCase):
    def test_all_current_aggregate_entrypoints_accept_exact_synthetic_proofs(self) -> None:
        context = _context(ROOT)
        for module, path, issuer in CASES:
            with self.subTest(module=module.__name__):
                proof = _current_proof(module, path, issuer, context)
                result = module.validate_aggregate_receipt(
                    ROOT, proof, currentness_context=context
                )
                self.assertEqual(result["payload"]["subject_ref"], f"git:{context['release_sha']}")

    def test_current_proof_mutation_matrix_fails_every_aggregate(self) -> None:
        context = _context(ROOT)
        for module, path, issuer in CASES:
            exact = _current_proof(module, path, issuer, context)
            error = getattr(module, module.__name__.split("_")[0].upper() + "AggregateError")
            mutations = (
                lambda value: value["payload"].__setitem__("subject_ref", "git:" + "0" * 40),
                lambda value: value["payload"].__setitem__("code_sha256", "0" * 64),
                lambda value: value["payload"].__setitem__("valid_until", value["payload"]["valid_from"]),
                lambda value: value["payload"].__setitem__("grants_authority", True),
                lambda value: value.__setitem__("schema_version", "9.9.9"),
                lambda value: value["payload"].__setitem__("unknown_field", True),
            )
            for index, mutate in enumerate(mutations):
                with self.subTest(module=module.__name__, index=index):
                    changed = copy.deepcopy(exact)
                    mutate(changed)
                    changed = _resign(changed)
                    with self.assertRaises(error):
                        module.validate_aggregate_receipt(
                            ROOT, changed, currentness_context=context
                        )

    def test_context_rejects_wrong_ancestry_clock_and_unknown_shape(self) -> None:
        base = _context(ROOT)
        parent = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=ROOT, text=True
        ).strip()
        values = []
        wrong_ancestry = copy.deepcopy(base)
        wrong_ancestry["repository_evidence_head_sha"] = parent
        wrong_ancestry["ci"]["head_sha"] = parent
        values.append(wrong_ancestry)
        expired = copy.deepcopy(base)
        expired["e2e"]["valid_until"] = expired["observed_at"]
        values.append(expired)
        unknown_version = copy.deepcopy(base)
        unknown_version["schema_version"] = "2.0.0"
        values.append(unknown_version)
        unknown_field = copy.deepcopy(base)
        unknown_field["extra"] = True
        values.append(unknown_field)
        vacuous = copy.deepcopy(base)
        vacuous["release_bundles"]["code"]["paths"] = []
        values.append(vacuous)
        for index, value in enumerate(values):
            with self.subTest(index=index), self.assertRaises(ReleaseCurrentnessError):
                validate_release_currentness_context(ROOT, value)

    def test_cli_receipt_entrypoints_require_currentness_context(self) -> None:
        commands = (
            ("tools/e1_aggregate_gate.py", "docs/receipts/capability/e1-evolution-kernel-v1-shadow.json"),
            ("tools/e2_aggregate_gate.py", "docs/receipts/capability/e2-autonomous-research-shadow.json"),
            ("tools/e3_aggregate_gate.py", "docs/receipts/capability/e3-evolution-shadow.json"),
        )
        for tool, receipt in commands:
            result = subprocess.run(
                ["python3", tool, "--receipt", receipt],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0, tool)
            self.assertIn("--currentness is required", result.stderr, tool)

    def test_current_final_freeze_path_never_calls_historical_helpers(self) -> None:
        source = python_inspect.getsource(verify_final_release_freeze.inspect)
        calls = {
            node.func.id
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn("validate_manifest", calls)
        self.assertNotIn("validate_manifest_historical", calls)
        self.assertNotIn("inspect_historical", calls)
        result = subprocess.run(
            ["python3", "tools/verify_final_release_freeze.py"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "manifest currentness context missing")


if __name__ == "__main__":
    unittest.main()
