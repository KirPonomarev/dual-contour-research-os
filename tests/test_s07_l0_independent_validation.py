from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from research_bridge.validation import (  # noqa: E402
    DeterministicL0Validator,
    ValidationBoundary,
    ValidationBoundaryError,
)
from tests.test_stage1_reference_vertical import (  # noqa: E402
    INPUT_A,
    INPUT_B,
    INPUT_REFS,
    NOW,
    PROTOCOL_REF,
    REGISTRY_IDENTITY,
    VALIDATION_POLICY_REF,
    VALIDATOR_ID,
    VALIDATOR_SHA256,
    _environment,
    _seal,
    _synthetic_external_receipts,
)


class MemoryStore:
    def __init__(self, values: dict[str, object]) -> None:
        self.values = values
        self.calls: list[tuple[str, int]] = []

    def read_bytes(self, ref: str, *, maximum_size_bytes: int) -> bytes:
        self.calls.append((ref, maximum_size_bytes))
        value = self.values[ref]
        if isinstance(value, Exception):
            raise value
        return value  # type: ignore[return-value]


def plain(value: object) -> object:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {key: plain(item) for key, item in value.items()}  # type: ignore[union-attr]
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    return value


class IndependentL0ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.environment = _environment(
            Path(self.temporary.name), "D1_INTERNAL_SANITIZED"
        )
        self.record = self.environment.coordinator.execute(
            self.environment.job_spec,
            self.environment.permit,
            self.environment.lease,
            self.environment.staging_root,
            now=NOW,
        )
        self.artifact_ref = self.record.artifact_records[0].artifact_ref
        self.input_store = MemoryStore(
            dict(zip(INPUT_REFS, (INPUT_A, INPUT_B), strict=True))
        )

    def validator(
        self,
        *,
        artifact_store: object | None = None,
        input_store: object | None = None,
    ) -> DeterministicL0Validator:
        return DeterministicL0Validator(
            validator_id=VALIDATOR_ID,
            validator_sha256=VALIDATOR_SHA256,
            protocol_ref=PROTOCOL_REF,
            artifact_store=artifact_store or self.environment.artifact_store,  # type: ignore[arg-type]
            input_store=input_store or self.input_store,  # type: ignore[arg-type]
            chunk_size=7,
        )

    def test_real_durable_l0_vertical_is_independently_recomputed(self) -> None:
        receipt = self.validator().validate(self.record.execution_receipt)
        payload = receipt["payload"]

        self.assertIsInstance(receipt, MappingProxyType)
        self.assertEqual(receipt["schema_id"], "ValidationReceipt")
        self.assertEqual(receipt["issuer"], {"id": VALIDATOR_ID, "authority_class": "pinned-validator"})
        self.assertEqual(payload["holdout_access_ref"], "holdout:none")
        self.assertEqual(payload["proposed_outcome"], "VALIDATED_MECHANICAL")
        self.assertEqual(payload["reasons"], ("L0_BYTES_RECOMPUTED",))
        self.assertEqual(payload["artifact_refs"], (self.artifact_ref,))
        self.assertEqual(
            self.input_store.calls,
            [(INPUT_REFS[0], 67_108_864), (INPUT_REFS[1], 67_108_864)],
        )
        serialized = json.dumps(plain(receipt), sort_keys=True)
        for forbidden in ("LearningDecision", "DomainTrialLinkReceipt", "D2_", "D3_", "private", "live"):
            self.assertNotIn(forbidden, serialized)

        _, domain_link = _synthetic_external_receipts(self.record.execution_receipt)
        mutable_link = deepcopy(plain(domain_link))
        mutable_link["integrity"]["parent_refs"][-1] = f"validation:{receipt['object_id']}"  # type: ignore[index]
        _seal(mutable_link)  # type: ignore[arg-type]
        projection = ValidationBoundary(
            expected_validator_id=VALIDATOR_ID,
            expected_validator_sha256=VALIDATOR_SHA256,
            expected_registry_identity=REGISTRY_IDENTITY,
        ).verify(
            self.record.execution_receipt,
            receipt,
            mutable_link,  # type: ignore[arg-type]
            expected_protocol_ref=PROTOCOL_REF,
            expected_policy_ref=VALIDATION_POLICY_REF,
        )
        self.assertEqual(projection.artifact_refs, (self.artifact_ref,))

    def test_known_invalid_artifact_produces_no_receipt(self) -> None:
        valid = self.environment.artifact_store.read_bytes(
            self.artifact_ref, maximum_size_bytes=8_388_608
        )
        invalid = valid.replace(b'"chunk_index":0', b'"chunk_index":9', 1)
        store = MemoryStore({self.artifact_ref: invalid})
        with self.assertRaises(ValidationBoundaryError):
            self.validator(artifact_store=store).validate(
                self.record.execution_receipt
            )
        self.assertEqual(self.input_store.calls, [])

    def test_input_and_chunk_claims_are_recomputed_not_trusted(self) -> None:
        wrong_input = MemoryStore(
            {
                INPUT_REFS[0]: INPUT_A + b"tampered",
                INPUT_REFS[1]: INPUT_B,
            }
        )
        with self.assertRaises(ValidationBoundaryError):
            self.validator(input_store=wrong_input).validate(
                self.record.execution_receipt
            )

        artifact = self.environment.artifact_store.read_bytes(
            self.artifact_ref, maximum_size_bytes=8_388_608
        )
        document = json.loads(artifact)
        document["chunks"][0]["sha256"] = hashlib.sha256(b"forged").hexdigest()
        forged = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        forged_ref = f"cas:sha256:{hashlib.sha256(forged).hexdigest()}"
        execution = deepcopy(plain(self.record.execution_receipt))
        execution["payload"]["artifact_refs"] = [forged_ref]  # type: ignore[index]
        execution["integrity"]["parent_refs"][1] = forged_ref  # type: ignore[index]
        execution["integrity"]["payload_sha256"] = hashlib.sha256(  # type: ignore[index]
            json.dumps(execution["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")  # type: ignore[index]
        ).hexdigest()
        execution["object_id"] = f"execution-receipt-{execution['integrity']['payload_sha256']}"  # type: ignore[index]
        with self.assertRaises(ValidationBoundaryError):
            self.validator(artifact_store=MemoryStore({forged_ref: forged})).validate(execution)  # type: ignore[arg-type]

    def test_fail_closed_on_store_error_nonbytes_duplicate_keys_and_bad_limits(self) -> None:
        for value in (RuntimeError("unavailable"), "not-bytes"):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ValidationBoundaryError):
                    self.validator(
                        artifact_store=MemoryStore({self.artifact_ref: value})
                    ).validate(self.record.execution_receipt)

        valid = self.environment.artifact_store.read_bytes(
            self.artifact_ref, maximum_size_bytes=8_388_608
        )
        duplicate = valid.replace(b'{"chunks":', b'{"chunks":[],"chunks":', 1)
        duplicate_ref = f"cas:sha256:{hashlib.sha256(duplicate).hexdigest()}"
        execution = deepcopy(plain(self.record.execution_receipt))
        execution["payload"]["artifact_refs"] = [duplicate_ref]  # type: ignore[index]
        execution["integrity"]["parent_refs"][1] = duplicate_ref  # type: ignore[index]
        execution["integrity"]["payload_sha256"] = hashlib.sha256(  # type: ignore[index]
            json.dumps(execution["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")  # type: ignore[index]
        ).hexdigest()
        execution["object_id"] = f"execution-receipt-{execution['integrity']['payload_sha256']}"  # type: ignore[index]
        with self.assertRaises(ValidationBoundaryError):
            self.validator(artifact_store=MemoryStore({duplicate_ref: duplicate})).validate(execution)  # type: ignore[arg-type]

        for bad in (0, True, 9_007_199_254_740_992):
            with self.subTest(limit=bad):
                with self.assertRaises(ValidationBoundaryError):
                    DeterministicL0Validator(
                        validator_id=VALIDATOR_ID,
                        validator_sha256=VALIDATOR_SHA256,
                        protocol_ref=PROTOCOL_REF,
                        artifact_store=self.environment.artifact_store,
                        input_store=self.input_store,
                        maximum_artifact_bytes=bad,
                    )


if __name__ == "__main__":
    unittest.main()
