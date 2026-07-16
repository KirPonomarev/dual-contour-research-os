import ast
import copy
import hashlib
import inspect
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import research_bridge.validation as validation_module  # noqa: E402
from research_bridge.validation import (  # noqa: E402
    ValidationBoundary,
    ValidationBoundaryError,
    ValidationProjection,
)


VALIDATOR_ID = "synthetic-validator-v1"
VALIDATOR_SHA256 = hashlib.sha256(b"synthetic-validator-v1").hexdigest()
REGISTRY_IDENTITY = "synthetic-domain-registry"
ARTIFACT_REFS = (
    f"cas:sha256:{hashlib.sha256(b'synthetic-artifact-a').hexdigest()}",
    f"cas:sha256:{hashlib.sha256(b'synthetic-artifact-b').hexdigest()}",
)
PROTOCOL_REF = f"cas:sha256:{hashlib.sha256(b'synthetic-protocol').hexdigest()}"
POLICY_REF = f"cas:sha256:{hashlib.sha256(b'synthetic-policy').hexdigest()}"
HOLDOUT_REF = f"cas:sha256:{hashlib.sha256(b'synthetic-holdout-reference').hexdigest()}"
OUTCOME_REF = f"cas:sha256:{hashlib.sha256(b'synthetic-outcome-reference').hexdigest()}"
CHECKPOINT_SHA256 = hashlib.sha256(b"synthetic-checkpoint-manifest").hexdigest()
EVENT_CHAIN_HEAD = hashlib.sha256(b"synthetic-event-chain-head").hexdigest()
PROJECTION_FIELDS = (
    "execution_ref",
    "validation_ref",
    "domain_link_ref",
    "protocol_ref",
    "artifact_refs",
    "registry_identity",
    "registry_revision",
    "applied_outcome_ref",
    "policy_ref",
    "contour",
    "classification",
)
SCIENTIFIC_FIELDS = {
    "proposed_outcome",
    "checks_performed",
    "metrics",
    "tolerances",
    "reasons",
    "payload",
}


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _seal(receipt: dict[str, object]) -> dict[str, object]:
    integrity = receipt["integrity"]
    assert isinstance(integrity, dict)
    integrity["payload_sha256"] = _canonical_sha256(receipt["payload"])
    return receipt


def _chain(
    classification: str = "D0_PUBLIC",
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    execution_payload = {
        "permit_ref": "permit-synthetic-001",
        "lease_ref": "lease-synthetic-001",
        "job_spec_ref": "job-synthetic-001",
        "code_sha256": hashlib.sha256(b"synthetic-code").hexdigest(),
        "input_sha256": hashlib.sha256(b"synthetic-input").hexdigest(),
        "environment_digest": "sha256:synthetic-offline-environment",
        "started_at": "2026-01-15T11:59:00Z",
        "ended_at": "2026-01-15T12:00:00Z",
        "exit_classification": "mechanical-success",
        "artifact_refs": list(ARTIFACT_REFS),
        "resource_usage": {"synthetic_units": 1},
        "event_chain_head": EVENT_CHAIN_HEAD,
    }
    execution_payload_sha256 = _canonical_sha256(execution_payload)
    execution = _seal(
        {
            "schema_id": "ExecutionReceipt",
            "schema_version": "1.0.0",
            "object_id": f"execution-receipt-{execution_payload_sha256}",
            "issued_at": "2026-01-15T12:00:00Z",
            "issuer": {"id": "researchd", "authority_class": "researchd"},
            "contour": "bridge",
            "classification": classification,
            "payload": execution_payload,
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [
                    f"checkpoint-manifest-{CHECKPOINT_SHA256}",
                    *ARTIFACT_REFS,
                    f"ledger:{EVENT_CHAIN_HEAD}",
                ],
            },
        }
    )
    execution_ref = f"execution:{execution['object_id']}"
    validation = _seal(
        {
            "schema_id": "ValidationReceipt",
            "schema_version": "1.0.0",
            "object_id": "validation-synthetic-001",
            "issued_at": "2026-01-15T12:01:00Z",
            "issuer": {
                "id": VALIDATOR_ID,
                "authority_class": "pinned-validator",
            },
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "protocol_ref": PROTOCOL_REF,
                "execution_ref": execution_ref,
                "artifact_refs": list(ARTIFACT_REFS),
                "validator_id": VALIDATOR_ID,
                "validator_sha256": VALIDATOR_SHA256,
                "holdout_access_ref": HOLDOUT_REF,
                "checks_performed": ["synthetic-check"],
                "metrics": {"synthetic_metric": 1},
                "tolerances": {"synthetic_tolerance": 0},
                "proposed_outcome": "synthetic-proposal-only",
                "reasons": ["synthetic-reason"],
                "reproducibility_class": "synthetic-reproducible",
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [execution_ref, *ARTIFACT_REFS],
            },
        }
    )
    validation_ref = f"validation:{validation['object_id']}"
    domain_link = _seal(
        {
            "schema_id": "DomainTrialLinkReceipt",
            "schema_version": "1.0.0",
            "object_id": "domain-link-synthetic-001",
            "issued_at": "2026-01-15T12:02:00Z",
            "issuer": {
                "id": REGISTRY_IDENTITY,
                "authority_class": "domain-registry-writer",
            },
            "contour": "bridge",
            "classification": classification,
            "payload": {
                "domain_trial_id": "synthetic-trial-001",
                "bridge_execution_ref": execution_ref,
                "protocol_ref": PROTOCOL_REF,
                "registry_identity": REGISTRY_IDENTITY,
                "registry_revision": "synthetic-revision-001",
                "applied_outcome_ref": OUTCOME_REF,
                "policy_ref": POLICY_REF,
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [execution_ref, validation_ref],
            },
        }
    )
    return execution, validation, domain_link


def _boundary() -> ValidationBoundary:
    return ValidationBoundary(
        expected_validator_id=VALIDATOR_ID,
        expected_validator_sha256=VALIDATOR_SHA256,
        expected_registry_identity=REGISTRY_IDENTITY,
    )


def _rebind_execution_reference(
    chain: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    execution, validation, domain_link = chain
    execution_ref = f"execution:{execution['object_id']}"
    validation_payload = validation["payload"]
    validation_integrity = validation["integrity"]
    domain_payload = domain_link["payload"]
    domain_integrity = domain_link["integrity"]
    assert isinstance(validation_payload, dict)
    assert isinstance(validation_integrity, dict)
    assert isinstance(domain_payload, dict)
    assert isinstance(domain_integrity, dict)
    validation_payload["execution_ref"] = execution_ref
    validation_integrity["parent_refs"] = [
        execution_ref,
        *validation_payload["artifact_refs"],
    ]
    domain_payload["bridge_execution_ref"] = execution_ref
    domain_integrity["parent_refs"] = [
        execution_ref,
        f"validation:{validation['object_id']}",
    ]
    _seal(validation)
    _seal(domain_link)


def _refresh_execution_identity(
    chain: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> None:
    execution = chain[0]
    execution["object_id"] = f"execution-receipt-{_canonical_sha256(execution['payload'])}"
    _seal(execution)
    _rebind_execution_reference(chain)


def _verify(
    chain: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> ValidationProjection:
    return _boundary().verify(
        *chain,
        expected_protocol_ref=PROTOCOL_REF,
        expected_policy_ref=POLICY_REF,
    )


class ValidationBoundaryConformanceTests(unittest.TestCase):
    def test_exact_d0_and_d1_chains_return_reference_only_projection(self) -> None:
        for classification in ("D0_PUBLIC", "D1_INTERNAL_SANITIZED"):
            with self.subTest(classification=classification):
                execution, validation, domain_link = _chain(classification)
                projection = _verify((execution, validation, domain_link))
                expected = {
                    "execution_ref": f"execution:{execution['object_id']}",
                    "validation_ref": f"validation:{validation['object_id']}",
                    "domain_link_ref": f"domain-link:{domain_link['object_id']}",
                    "protocol_ref": PROTOCOL_REF,
                    "artifact_refs": ARTIFACT_REFS,
                    "registry_identity": REGISTRY_IDENTITY,
                    "registry_revision": "synthetic-revision-001",
                    "applied_outcome_ref": OUTCOME_REF,
                    "policy_ref": POLICY_REF,
                    "contour": "bridge",
                    "classification": classification,
                }
                self.assertEqual(
                    tuple(ValidationProjection.__annotations__), PROJECTION_FIELDS
                )
                self.assertEqual(
                    {field: getattr(projection, field) for field in PROJECTION_FIELDS},
                    expected,
                )
                self.assertEqual(set(PROJECTION_FIELDS) & SCIENTIFIC_FIELDS, set())
                self.assertFalse(hasattr(projection, "__dict__"))
                with self.assertRaises((AttributeError, TypeError)):
                    projection.protocol_ref = "changed"  # type: ignore[misc]
                with self.assertRaises((AttributeError, TypeError)):
                    projection.artifact_refs += (ARTIFACT_REFS[0],)  # type: ignore[misc]

    def test_each_receipt_requires_canonical_payload_integrity(self) -> None:
        for receipt_index, payload_key in (
            (0, "environment_digest"),
            (1, "proposed_outcome"),
            (2, "registry_revision"),
        ):
            with self.subTest(receipt_index=receipt_index):
                chain = list(_chain())
                payload = chain[receipt_index]["payload"]
                assert isinstance(payload, dict)
                payload[payload_key] = "tampered-after-seal"
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]

    def test_each_receipt_rejects_non_exact_shapes(self) -> None:
        for receipt_index in range(3):
            with self.subTest(receipt_index=receipt_index, shape="top-level"):
                chain = list(_chain())
                chain[receipt_index]["unexpected"] = "synthetic"
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]
            with self.subTest(receipt_index=receipt_index, shape="payload"):
                chain = list(_chain())
                payload = chain[receipt_index]["payload"]
                assert isinstance(payload, dict)
                payload["unexpected"] = "synthetic"
                _seal(chain[receipt_index])
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]
            with self.subTest(receipt_index=receipt_index, shape="integrity"):
                chain = list(_chain())
                integrity = chain[receipt_index]["integrity"]
                assert isinstance(integrity, dict)
                integrity["unexpected"] = "synthetic"
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]

    def test_execution_identity_and_canonical_parent_bindings_are_exact(self) -> None:
        execution, validation, domain_link = _chain()
        execution["object_id"] = f"execution-receipt-{'f' * 64}"
        _rebind_execution_reference((execution, validation, domain_link))
        with self.assertRaises(ValidationBoundaryError):
            _verify((execution, validation, domain_link))

        parent_mutations = (
            [],
            [*ARTIFACT_REFS, f"ledger:{EVENT_CHAIN_HEAD}"],
            [
                f"checkpoint-manifest-{CHECKPOINT_SHA256}",
                *reversed(ARTIFACT_REFS),
                f"ledger:{EVENT_CHAIN_HEAD}",
            ],
            [
                "checkpoint-manifest-short",
                *ARTIFACT_REFS,
                f"ledger:{EVENT_CHAIN_HEAD}",
            ],
            [
                f"checkpoint-manifest-{CHECKPOINT_SHA256}",
                *ARTIFACT_REFS,
                f"ledger:{'f' * 64}",
            ],
        )
        for parent_refs in parent_mutations:
            with self.subTest(parent_refs=parent_refs):
                chain = list(_chain())
                integrity = chain[0]["integrity"]
                assert isinstance(integrity, dict)
                integrity["parent_refs"] = parent_refs
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]

    def test_non_mechanical_execution_and_artifact_mismatch_fail_closed(self) -> None:
        execution, validation, domain_link = _chain()
        execution_payload = execution["payload"]
        assert isinstance(execution_payload, dict)
        execution_payload["exit_classification"] = "mechanical-failure"
        _refresh_execution_identity((execution, validation, domain_link))
        with self.assertRaises(ValidationBoundaryError):
            _verify((execution, validation, domain_link))

        execution, validation, domain_link = _chain()
        validation_payload = validation["payload"]
        assert isinstance(validation_payload, dict)
        validation_payload["artifact_refs"] = list(reversed(ARTIFACT_REFS))
        _seal(validation)
        with self.assertRaises(ValidationBoundaryError):
            _verify((execution, validation, domain_link))

    def test_validator_and_registry_writer_authority_are_pinned(self) -> None:
        for key, value in (
            ("validator_id", "synthetic-unpinned-validator"),
            ("validator_sha256", "f" * 64),
        ):
            with self.subTest(key=key):
                execution, validation, domain_link = _chain()
                payload = validation["payload"]
                assert isinstance(payload, dict)
                payload[key] = value
                _seal(validation)
                with self.assertRaises(ValidationBoundaryError):
                    _verify((execution, validation, domain_link))

        execution, validation, domain_link = _chain()
        issuer = domain_link["issuer"]
        assert isinstance(issuer, dict)
        issuer["id"] = "synthetic-unexpected-registry"
        with self.assertRaises(ValidationBoundaryError):
            _verify((execution, validation, domain_link))

    def test_receipt_issuer_identity_and_authority_classes_are_exact(self) -> None:
        mutations = (
            (0, "id", "synthetic-not-researchd"),
            (0, "authority_class", "mechanical-result"),
            (1, "id", "synthetic-unpinned-validator"),
            (1, "authority_class", "validator"),
            (2, "authority_class", "registry-writer"),
        )
        for receipt_index, key, value in mutations:
            with self.subTest(receipt_index=receipt_index, key=key):
                chain = list(_chain())
                issuer = chain[receipt_index]["issuer"]
                assert isinstance(issuer, dict)
                issuer[key] = value
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]

    def test_execution_and_validation_parent_bindings_are_mandatory(self) -> None:
        for receipt_index, parent_refs in ((1, list(ARTIFACT_REFS)), (2, [])):
            with self.subTest(receipt_index=receipt_index):
                chain = list(_chain())
                integrity = chain[receipt_index]["integrity"]
                assert isinstance(integrity, dict)
                integrity["parent_refs"] = parent_refs
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]

    def test_protocol_policy_contour_classification_and_time_must_bind(self) -> None:
        mutations = (
            (1, "payload", "protocol_ref", f"cas:sha256:{'f' * 64}", True),
            (2, "payload", "policy_ref", f"cas:sha256:{'f' * 64}", True),
            (1, None, "contour", "governance", False),
            (2, None, "classification", "D1_INTERNAL_SANITIZED", False),
            (1, None, "issued_at", "2026-01-15T11:59:59Z", False),
            (2, None, "issued_at", "2026-01-15T12:00:30Z", False),
        )
        for receipt_index, container, key, value, reseal in mutations:
            with self.subTest(receipt_index=receipt_index, key=key):
                chain = list(_chain())
                target = chain[receipt_index]
                if container is not None:
                    nested = target[container]
                    assert isinstance(nested, dict)
                    nested[key] = value
                else:
                    target[key] = value
                if reseal:
                    _seal(target)
                with self.assertRaises(ValidationBoundaryError):
                    _verify(tuple(chain))  # type: ignore[arg-type]

    def test_execution_time_binding_is_exact(self) -> None:
        for key, value in (
            ("started_at", "2026-01-15T12:00:01Z"),
            ("ended_at", "2026-01-15T12:00:01Z"),
        ):
            with self.subTest(key=key):
                execution, validation, domain_link = _chain()
                payload = execution["payload"]
                assert isinstance(payload, dict)
                payload[key] = value
                _refresh_execution_identity((execution, validation, domain_link))
                with self.assertRaises(ValidationBoundaryError):
                    _verify((execution, validation, domain_link))

    def test_d2_and_d3_labels_are_denied_before_projection(self) -> None:
        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            with self.subTest(classification=classification):
                chain = _chain()
                for receipt in chain:
                    receipt["classification"] = classification
                with self.assertRaises(ValidationBoundaryError):
                    _verify(chain)

    def test_nonportable_file_and_host_references_are_denied(self) -> None:
        execution, validation, domain_link = _chain()
        execution_payload = execution["payload"]
        validation_payload = validation["payload"]
        execution_integrity = execution["integrity"]
        validation_integrity = validation["integrity"]
        assert isinstance(execution_payload, dict)
        assert isinstance(validation_payload, dict)
        assert isinstance(execution_integrity, dict)
        assert isinstance(validation_integrity, dict)
        file_ref = "file:synthetic-artifact"
        execution_payload["artifact_refs"] = [file_ref, ARTIFACT_REFS[1]]
        validation_payload["artifact_refs"] = [file_ref, ARTIFACT_REFS[1]]
        execution_integrity["parent_refs"] = [
            f"checkpoint-manifest-{CHECKPOINT_SHA256}",
            file_ref,
            ARTIFACT_REFS[1],
            f"ledger:{EVENT_CHAIN_HEAD}",
        ]
        validation_integrity["parent_refs"] = [
            f"execution:{execution['object_id']}",
            file_ref,
            ARTIFACT_REFS[1],
        ]
        _refresh_execution_identity((execution, validation, domain_link))
        _seal(validation)
        with self.assertRaises(ValidationBoundaryError):
            _verify((execution, validation, domain_link))

        for nonportable_ref in (
            "host:synthetic-node:outcome",
            "C:/synthetic-outcome",
        ):
            with self.subTest(nonportable_ref=nonportable_ref):
                execution, validation, domain_link = _chain()
                domain_payload = domain_link["payload"]
                assert isinstance(domain_payload, dict)
                domain_payload["applied_outcome_ref"] = nonportable_ref
                _seal(domain_link)
                with self.assertRaises(ValidationBoundaryError):
                    _verify((execution, validation, domain_link))

    def test_projection_is_detached_from_subsequent_input_mutation(self) -> None:
        execution, validation, domain_link = _chain()
        projection = _verify((execution, validation, domain_link))
        snapshot = {field: copy.deepcopy(getattr(projection, field)) for field in PROJECTION_FIELDS}

        for receipt in (execution, validation, domain_link):
            receipt["object_id"] = "mutated-after-verification"
            receipt["contour"] = "governance"
            receipt["classification"] = "D3_RESTRICTED"
            payload = receipt["payload"]
            integrity = receipt["integrity"]
            assert isinstance(payload, dict)
            assert isinstance(integrity, dict)
            payload.clear()
            integrity.clear()

        self.assertEqual(
            {field: getattr(projection, field) for field in PROJECTION_FIELDS},
            snapshot,
        )
        self.assertIsInstance(projection.artifact_refs, tuple)


class ValidationBoundaryStaticAssuranceTests(unittest.TestCase):
    def test_declared_interface_has_no_callback_or_writer_surface(self) -> None:
        constructor = inspect.signature(ValidationBoundary)
        self.assertEqual(
            tuple(constructor.parameters),
            (
                "expected_validator_id",
                "expected_validator_sha256",
                "expected_registry_identity",
            ),
        )
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                for parameter in constructor.parameters.values()
            )
        )
        verify = inspect.signature(_boundary().verify)
        self.assertEqual(
            tuple(verify.parameters),
            (
                "execution_receipt",
                "validation_receipt",
                "domain_link_receipt",
                "expected_protocol_ref",
                "expected_policy_ref",
            ),
        )
        self.assertEqual(
            verify.parameters["expected_protocol_ref"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            verify.parameters["expected_policy_ref"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        public_methods = {
            name
            for name, value in vars(ValidationBoundary).items()
            if callable(value) and not name.startswith("_")
        }
        self.assertEqual(public_methods, {"verify"})

    def test_module_has_no_io_process_dynamic_code_or_domain_mutation_import(self) -> None:
        source_path = Path(validation_module.__file__).resolve()
        self.assertEqual(source_path.name, "validation.py")
        self.assertEqual(source_path.parent.name, "research_bridge")
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_import_roots = {
            "asyncio",
            "http",
            "importlib",
            "multiprocessing",
            "os",
            "pathlib",
            "requests",
            "research_bridge.cas",
            "research_bridge.ingestion",
            "research_bridge.ledger",
            "socket",
            "sqlite3",
            "subprocess",
            "tempfile",
            "urllib",
        }
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for module_name in imported:
            self.assertFalse(
                any(
                    module_name == root or module_name.startswith(f"{root}.")
                    for root in forbidden_import_roots
                ),
                module_name,
            )

        forbidden_calls = {"__import__", "compile", "eval", "exec", "open"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, forbidden_calls)
            if isinstance(node.func, ast.Attribute):
                self.assertNotEqual(node.func.attr, "import_module")


if __name__ == "__main__":
    unittest.main()
