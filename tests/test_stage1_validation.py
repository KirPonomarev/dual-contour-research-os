from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, FrozenInstanceError
import ast
import hashlib
import inspect
import json
from pathlib import Path
from types import MappingProxyType
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge.validation import (
    ValidationBoundary,
    ValidationBoundaryError,
    ValidationProjection,
)


VALIDATOR_ID = "validator-synthetic"
VALIDATOR_SHA256 = "7" * 64
REGISTRY_ID = "registry-synthetic"
PROTOCOL_REF = "protocol:synthetic-offline-v1"
POLICY_REF = "policy:synthetic-v1"
ARTIFACT_REFS = [f"cas:sha256:{'1' * 64}", f"cas:sha256:{'2' * 64}"]
EVENT_CHAIN_HEAD = "3" * 64
CHECKPOINT_PARENT = f"checkpoint-manifest-{'4' * 64}"
COMMON_KEYS = {
    "schema_id",
    "schema_version",
    "object_id",
    "issued_at",
    "issuer",
    "contour",
    "classification",
    "payload",
    "integrity",
}


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def seal(
    document: dict[str, object], parent_refs: list[str]
) -> dict[str, object]:
    document["integrity"] = {
        "payload_sha256": canonical_sha256(document["payload"]),
        "parent_refs": list(parent_refs),
    }
    return document


def reseal(document: dict[str, object]) -> None:
    document["integrity"]["payload_sha256"] = canonical_sha256(  # type: ignore[index]
        document["payload"]
    )


def execution_receipt(
    *, classification: str = "D1_INTERNAL_SANITIZED"
) -> dict[str, object]:
    payload = {
        "permit_ref": "permit-synthetic",
        "lease_ref": "lease-synthetic",
        "job_spec_ref": "job-synthetic",
        "code_sha256": "5" * 64,
        "input_sha256": "6" * 64,
        "environment_digest": f"sha256:{'8' * 64}",
        "started_at": "2026-07-16T21:59:00Z",
        "ended_at": "2026-07-16T22:00:00Z",
        "exit_classification": "mechanical-success",
        "artifact_refs": list(ARTIFACT_REFS),
        "resource_usage": {"synthetic_bytes": 42},
        "event_chain_head": EVENT_CHAIN_HEAD,
    }
    document: dict[str, object] = {
        "schema_id": "ExecutionReceipt",
        "schema_version": "1.0.0",
        "object_id": f"execution-receipt-{canonical_sha256(payload)}",
        "issued_at": "2026-07-16T22:00:00Z",
        "issuer": {"id": "researchd", "authority_class": "researchd"},
        "contour": "bridge",
        "classification": classification,
        "payload": payload,
    }
    return seal(
        document,
        [CHECKPOINT_PARENT, *ARTIFACT_REFS, f"ledger:{EVENT_CHAIN_HEAD}"],
    )


def validation_receipt(
    execution: dict[str, object],
    *,
    classification: str = "D1_INTERNAL_SANITIZED",
) -> dict[str, object]:
    execution_ref = f"execution:{execution['object_id']}"
    artifacts = list(execution["payload"]["artifact_refs"])  # type: ignore[index]
    payload = {
        "protocol_ref": PROTOCOL_REF,
        "execution_ref": execution_ref,
        "artifact_refs": artifacts,
        "validator_id": VALIDATOR_ID,
        "validator_sha256": VALIDATOR_SHA256,
        "holdout_access_ref": "holdout:none-synthetic",
        "checks_performed": [{"synthetic_check": "opaque"}],
        "metrics": {"synthetic_metric": 0.5},
        "tolerances": {"synthetic_tolerance": 0.1},
        "proposed_outcome": "synthetic-proposal-sentinel",
        "reasons": ["synthetic-reason-sentinel"],
        "reproducibility_class": "synthetic-reproducible",
    }
    document: dict[str, object] = {
        "schema_id": "ValidationReceipt",
        "schema_version": "1.0.0",
        "object_id": "validation-synthetic",
        "issued_at": "2026-07-16T22:01:00Z",
        "issuer": {
            "id": VALIDATOR_ID,
            "authority_class": "pinned-validator",
        },
        "contour": "bridge",
        "classification": classification,
        "payload": payload,
    }
    return seal(document, [execution_ref, *artifacts])


def domain_link_receipt(
    execution: dict[str, object],
    validation: dict[str, object],
    *,
    classification: str = "D1_INTERNAL_SANITIZED",
) -> dict[str, object]:
    execution_ref = f"execution:{execution['object_id']}"
    validation_ref = f"validation:{validation['object_id']}"
    payload = {
        "domain_trial_id": "trial-synthetic",
        "bridge_execution_ref": execution_ref,
        "protocol_ref": PROTOCOL_REF,
        "registry_identity": REGISTRY_ID,
        "registry_revision": "revision-synthetic-1",
        "applied_outcome_ref": "outcome:synthetic-applied-1",
        "policy_ref": POLICY_REF,
    }
    document: dict[str, object] = {
        "schema_id": "DomainTrialLinkReceipt",
        "schema_version": "1.0.0",
        "object_id": "domain-link-synthetic",
        "issued_at": "2026-07-16T22:02:00Z",
        "issuer": {
            "id": REGISTRY_ID,
            "authority_class": "domain-registry-writer",
        },
        "contour": "bridge",
        "classification": classification,
        "payload": payload,
    }
    return seal(document, [execution_ref, validation_ref])


def chain(
    *, classification: str = "D1_INTERNAL_SANITIZED"
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    execution = execution_receipt(classification=classification)
    validation = validation_receipt(execution, classification=classification)
    link = domain_link_receipt(
        execution, validation, classification=classification
    )
    return execution, validation, link


def deep_freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(deep_freeze(item) for item in value)
    return value


class ValidationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.boundary = ValidationBoundary(
            expected_validator_id=VALIDATOR_ID,
            expected_validator_sha256=VALIDATOR_SHA256,
            expected_registry_identity=REGISTRY_ID,
        )

    def verify(
        self,
        execution: object,
        validation: object,
        link: object,
        *,
        protocol_ref: str = PROTOCOL_REF,
        policy_ref: str = POLICY_REF,
    ) -> ValidationProjection:
        return self.boundary.verify(
            execution,  # type: ignore[arg-type]
            validation,  # type: ignore[arg-type]
            link,  # type: ignore[arg-type]
            expected_protocol_ref=protocol_ref,
            expected_policy_ref=policy_ref,
        )

    def test_public_interface_and_projection_fields_are_exact(self) -> None:
        import research_bridge.validation as module

        self.assertEqual(
            module.__all__,
            ["ValidationBoundaryError", "ValidationProjection", "ValidationBoundary"],
        )
        self.assertEqual(
            [field.name for field in fields(ValidationProjection)],
            [
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
            ],
        )
        signature = inspect.signature(ValidationBoundary)
        self.assertEqual(
            list(signature.parameters),
            [
                "expected_validator_id",
                "expected_validator_sha256",
                "expected_registry_identity",
            ],
        )
        self.assertTrue(
            all(parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in signature.parameters.values())
        )

    def test_valid_chain_returns_only_deeply_immutable_references(self) -> None:
        execution, validation, link = chain()
        projection = self.verify(execution, validation, link)
        self.assertEqual(
            projection.execution_ref,
            f"execution:{execution['object_id']}",
        )
        self.assertEqual(
            projection.validation_ref,
            f"validation:{validation['object_id']}",
        )
        self.assertEqual(
            projection.domain_link_ref,
            f"domain-link:{link['object_id']}",
        )
        self.assertEqual(projection.protocol_ref, PROTOCOL_REF)
        self.assertEqual(projection.artifact_refs, tuple(ARTIFACT_REFS))
        self.assertEqual(projection.registry_identity, REGISTRY_ID)
        self.assertEqual(projection.registry_revision, "revision-synthetic-1")
        self.assertEqual(projection.applied_outcome_ref, "outcome:synthetic-applied-1")
        self.assertEqual(projection.policy_ref, POLICY_REF)
        self.assertEqual(projection.contour, "bridge")
        self.assertEqual(projection.classification, "D1_INTERNAL_SANITIZED")
        with self.assertRaises(FrozenInstanceError):
            projection.registry_revision = "changed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            projection.artifact_refs[0] = ARTIFACT_REFS[1]  # type: ignore[index]
        rendered = repr(projection)
        for forbidden_value in (
            "synthetic-proposal-sentinel",
            "synthetic-reason-sentinel",
            "synthetic_metric",
            "synthetic_tolerance",
            "synthetic_check",
        ):
            self.assertNotIn(forbidden_value, rendered)

    def test_d0_is_allowed_and_d2_d3_are_denied_for_each_receipt(self) -> None:
        d0 = chain(classification="D0_PUBLIC")
        self.assertEqual(self.verify(*d0).classification, "D0_PUBLIC")

        for classification in ("D2_DOMAIN_CONFIDENTIAL", "D3_RESTRICTED"):
            for index in range(3):
                receipts = list(chain())
                receipts[index]["classification"] = classification
                with self.subTest(classification=classification, index=index):
                    with self.assertRaises(ValidationBoundaryError):
                        self.verify(*receipts)

    def test_exact_shapes_schema_identity_and_integrity_are_required(self) -> None:
        cases = []
        execution, validation, link = chain()
        execution["extra"] = True
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        validation["payload"]["extra"] = True  # type: ignore[index]
        reseal(validation)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["schema_version"] = "2.0.0"
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        validation["integrity"]["payload_sha256"] = "0" * 64  # type: ignore[index]
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["integrity"]["extra"] = True  # type: ignore[index]
        cases.append((execution, validation, link))

        for index, receipts in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(*receipts)

    def test_execution_identity_and_parent_chain_are_canonical_and_ordered(self) -> None:
        cases = []
        execution, validation, link = chain()
        execution["object_id"] = "execution-receipt-replayed"
        cases.append((execution, validation, link))
        for parents in (
            [*ARTIFACT_REFS, f"ledger:{EVENT_CHAIN_HEAD}"],
            [CHECKPOINT_PARENT, ARTIFACT_REFS[1], ARTIFACT_REFS[0], f"ledger:{EVENT_CHAIN_HEAD}"],
            [CHECKPOINT_PARENT, *ARTIFACT_REFS],
            [f"checkpoint-manifest-{'x' * 64}", *ARTIFACT_REFS, f"ledger:{EVENT_CHAIN_HEAD}"],
            [CHECKPOINT_PARENT, *ARTIFACT_REFS, f"ledger:{'9' * 64}"],
        ):
            execution, validation, link = chain()
            execution["integrity"]["parent_refs"] = parents  # type: ignore[index]
            cases.append((execution, validation, link))

        for index, receipts in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(*receipts)

    def test_mechanical_validator_and_registry_authorities_are_exact(self) -> None:
        mutations = [
            (0, ("issuer", "id"), "other-researchd"),
            (0, ("issuer", "authority_class"), "worker"),
            (0, ("payload", "exit_classification"), "scientific-success"),
            (1, ("issuer", "id"), "other-validator"),
            (1, ("issuer", "authority_class"), "validator"),
            (1, ("payload", "validator_id"), "other-validator"),
            (1, ("payload", "validator_sha256"), "9" * 64),
            (2, ("issuer", "id"), "other-registry"),
            (2, ("issuer", "authority_class"), "registry-reader"),
            (2, ("payload", "registry_identity"), "other-registry"),
        ]
        for receipt_index, path, value in mutations:
            receipts = list(chain())
            receipts[receipt_index][path[0]][path[1]] = value  # type: ignore[index]
            if path[0] == "payload":
                reseal(receipts[receipt_index])
                if receipt_index == 0:
                    receipts[receipt_index]["object_id"] = (  # type: ignore[index]
                        f"execution-receipt-{canonical_sha256(receipts[receipt_index]['payload'])}"
                    )
            with self.subTest(receipt_index=receipt_index, path=path):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(*receipts)

    def test_execution_artifact_protocol_policy_and_parent_bindings_are_exact(self) -> None:
        cases = []
        execution, validation, link = chain()
        validation["payload"]["execution_ref"] = "execution:other"  # type: ignore[index]
        reseal(validation)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        validation["payload"]["artifact_refs"] = list(reversed(ARTIFACT_REFS))  # type: ignore[index]
        reseal(validation)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        validation["payload"]["protocol_ref"] = "protocol:other"  # type: ignore[index]
        reseal(validation)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        validation["integrity"]["parent_refs"] = [f"execution:{execution['object_id']}"]  # type: ignore[index]
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["payload"]["bridge_execution_ref"] = "execution:other"  # type: ignore[index]
        reseal(link)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["payload"]["protocol_ref"] = "protocol:other"  # type: ignore[index]
        reseal(link)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["payload"]["policy_ref"] = "policy:other"  # type: ignore[index]
        reseal(link)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["integrity"]["parent_refs"] = [
            f"validation:{validation['object_id']}",
            f"execution:{execution['object_id']}",
        ]  # type: ignore[index]
        cases.append((execution, validation, link))

        for index, receipts in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(*receipts)

    def test_timestamp_scope_and_execution_issued_at_bindings_are_monotonic(self) -> None:
        cases = []
        execution, validation, link = chain()
        execution["payload"]["started_at"] = "2026-07-16T22:00:01Z"  # type: ignore[index]
        reseal(execution)
        execution["object_id"] = f"execution-receipt-{canonical_sha256(execution['payload'])}"
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        execution["issued_at"] = "2026-07-16T22:00:01Z"
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        validation["issued_at"] = "2026-07-16T21:59:59Z"
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["issued_at"] = "2026-07-16T22:00:30Z"
        validation["issued_at"] = "2026-07-16T22:01:00Z"
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["contour"] = "market"
        cases.append((execution, validation, link))

        for index, receipts in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(*receipts)

    def test_cas_and_projected_references_must_be_portable(self) -> None:
        cases = []
        execution, validation, link = chain()
        execution["payload"]["artifact_refs"] = ["cas:sha256:short"]  # type: ignore[index]
        reseal(execution)
        execution["object_id"] = f"execution-receipt-{canonical_sha256(execution['payload'])}"
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        validation["payload"]["holdout_access_ref"] = "file:///synthetic"  # type: ignore[index]
        reseal(validation)
        cases.append((execution, validation, link))
        execution, validation, link = chain()
        link["payload"]["applied_outcome_ref"] = "/synthetic-outcome"  # type: ignore[index]
        reseal(link)
        cases.append((execution, validation, link))

        for index, receipts in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(*receipts)

        execution, validation, link = chain()
        for protocol_ref, policy_ref in (
            ("file:///synthetic", POLICY_REF),
            ("host:synthetic-local", POLICY_REF),
            ("C:/synthetic-local", POLICY_REF),
            (PROTOCOL_REF, "/synthetic-policy"),
        ):
            with self.subTest(protocol_ref=protocol_ref, policy_ref=policy_ref):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(
                        execution,
                        validation,
                        link,
                        protocol_ref=protocol_ref,
                        policy_ref=policy_ref,
                    )

    def test_opaque_scientific_fields_do_not_change_projection_or_repr(self) -> None:
        execution, validation, link = chain()
        first = self.verify(execution, validation, link)
        validation["payload"].update(  # type: ignore[union-attr]
            {
                "checks_performed": [{"different": [1, 2, 3]}],
                "metrics": {"opaque": 999},
                "tolerances": {"opaque": -1},
                "proposed_outcome": "different-proposal-sentinel",
                "reasons": ["different-reason-sentinel"],
            }
        )
        reseal(validation)
        second = self.verify(execution, validation, link)
        self.assertEqual(first, second)
        self.assertNotIn("different-proposal-sentinel", repr(second))
        self.assertNotIn("different-reason-sentinel", repr(second))

    def test_opaque_fields_are_only_structurally_checked(self) -> None:
        for field, invalid in (
            ("checks_performed", {}),
            ("metrics", []),
            ("tolerances", []),
            ("proposed_outcome", ""),
            ("reasons", {}),
            ("reproducibility_class", ""),
        ):
            execution, validation, link = chain()
            validation["payload"][field] = invalid  # type: ignore[index]
            reseal(validation)
            with self.subTest(field=field):
                with self.assertRaises(ValidationBoundaryError):
                    self.verify(execution, validation, link)

    def test_deeply_frozen_receipt_inputs_are_accepted_without_mutation(self) -> None:
        receipts = chain()
        snapshots = [canonical_sha256(receipt) for receipt in receipts]
        projection = self.verify(*(deep_freeze(receipt) for receipt in receipts))
        self.assertEqual(projection.artifact_refs, tuple(ARTIFACT_REFS))
        self.assertEqual(
            snapshots,
            [canonical_sha256(receipt) for receipt in receipts],
        )

    def test_constructor_pins_are_strict_and_no_error_returns_projection(self) -> None:
        invalid_arguments = (
            {"expected_validator_id": " validator", "expected_validator_sha256": VALIDATOR_SHA256, "expected_registry_identity": REGISTRY_ID},
            {"expected_validator_id": VALIDATOR_ID, "expected_validator_sha256": "short", "expected_registry_identity": REGISTRY_ID},
            {"expected_validator_id": VALIDATOR_ID, "expected_validator_sha256": VALIDATOR_SHA256, "expected_registry_identity": "/registry"},
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValidationBoundaryError):
                    ValidationBoundary(**arguments)

    def test_module_has_no_io_callback_process_network_or_dynamic_code_capability(self) -> None:
        source_path = Path(__file__).resolve().parents[1] / "src" / "research_bridge" / "validation.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imported.isdisjoint(
                {
                    "os",
                    "pathlib",
                    "subprocess",
                    "socket",
                    "urllib",
                    "http",
                    "sqlite3",
                    "requests",
                    "httpx",
                }
            )
        )
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(called_names.isdisjoint({"open", "eval", "exec", "__import__"}))
        constructor_parameters = inspect.signature(ValidationBoundary).parameters
        self.assertNotIn("callback", constructor_parameters)
        self.assertNotIn("validator", constructor_parameters)
        self.assertNotIn("writer", constructor_parameters)


if __name__ == "__main__":
    unittest.main()
