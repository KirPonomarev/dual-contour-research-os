import ast
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from research_bridge.admission import (  # noqa: E402
    AdmissionError,
    canonical_json_sha256,
)
from research_bridge.kernel import BridgeKernel  # noqa: E402
from research_bridge.ledger import JobLedger, LedgerError  # noqa: E402
from tests.test_stage1_authority_policy import (  # noqa: E402
    SYNTHETIC_POLICY_SHA256,
    synthetic_authority,
)


NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
CODE_SHA256 = "1" * 64
INPUT_REF_SHA256 = "2" * 64
IMAGE_SHA256 = "3" * 64
POLICY_SHA256 = SYNTHETIC_POLICY_SHA256
STATE_SHA256 = "5" * 64
RESULT_SHA256 = "6" * 64
ADMISSION_SHA256 = "7" * 64
PERMIT_NONCE_SHA256 = hashlib.sha256(b"synthetic-permit-nonce-001").hexdigest()
MAX_SAFE_INTEGER = 9_007_199_254_740_991
ACCOUNTING_POLICY_REF = f"budget-policy:sha256:{'a' * 64}"
BUDGET_SCOPE_REF = f"budget-scope:sha256:{'b' * 64}"


def _authority_verifier():
    return synthetic_authority()


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _seal(document: dict) -> dict:
    document["integrity"]["payload_sha256"] = canonical_json_sha256(document["payload"])
    return document


def _valid_authority() -> tuple[dict, dict, dict]:
    job_spec = _seal(
        {
            "schema_id": "JobSpec",
            "schema_version": "1.0.0",
            "object_id": "job-synthetic-001",
            "issued_at": _timestamp(NOW - timedelta(minutes=2)),
            "issuer": {
                "id": "synthetic-admission-controller",
                "authority_class": "admission-controller",
            },
            "contour": "bridge",
            "classification": "D0_PUBLIC",
            "payload": {
                "protocol_ref": f"cas:{'8' * 64}",
                "code_ref": f"sha256:{CODE_SHA256}",
                "input_refs": [f"sha256:{INPUT_REF_SHA256}"],
                "image_digest": f"sha256:{IMAGE_SHA256}",
                "runner_profile": "offline-synthetic-runner",
                "network_policy": "offline",
                "resource_limits": {"cost_units": 2},
                "checkpoint_strategy": "append-only",
                "expected_output_contract": "ValidationReceipt",
                "idempotency_key": "synthetic-idempotency-001",
            },
            "integrity": {"payload_sha256": "0" * 64, "parent_refs": []},
        }
    )
    permit = _seal(
        {
            "schema_id": "Permit",
            "schema_version": "1.0.0",
            "object_id": "permit-synthetic-001",
            "issued_at": _timestamp(NOW - timedelta(minutes=1)),
            "issuer": {
                "id": "synthetic-permit-authority",
                "authority_class": "permit-authority",
            },
            "contour": "bridge",
            "classification": "D0_PUBLIC",
            "payload": {
                "subject": "runner-synthetic-001",
                "job_spec_sha256": canonical_json_sha256(job_spec),
                "policy_snapshot_sha256": POLICY_SHA256,
                "code_sha256": CODE_SHA256,
                "input_sha256": canonical_json_sha256(
                    job_spec["payload"]["input_refs"]
                ),
                "image_digest": f"sha256:{IMAGE_SHA256}",
                "quotas": {
                    "accounting_policy_ref": ACCOUNTING_POLICY_REF,
                    "budget_scope_ref": BUDGET_SCOPE_REF,
                    "claims": 1,
                    "provider": job_spec["payload"]["runner_profile"],
                    "scope_limit": {"cost_units": 3},
                    "trial_ref": "trial:synthetic-assurance-001",
                },
                "network_class": "offline",
                "not_before": _timestamp(NOW - timedelta(seconds=30)),
                "expires_at": _timestamp(NOW + timedelta(minutes=10)),
                "max_uses": 1,
                "nonce": "synthetic-nonce-001",
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [job_spec["object_id"]],
            },
        }
    )
    lease = _seal(
        {
            "schema_id": "AttemptLease",
            "schema_version": "1.0.0",
            "object_id": "lease-synthetic-001",
            "issued_at": _timestamp(NOW - timedelta(seconds=15)),
            "issuer": {
                "id": "synthetic-researchd",
                "authority_class": "researchd",
            },
            "contour": "bridge",
            "classification": "D0_PUBLIC",
            "payload": {
                "attempt_id": "attempt-synthetic-001",
                "permit_ref": permit["object_id"],
                "job_ref": job_spec["object_id"],
                "runner_identity": permit["payload"]["subject"],
                "fencing_epoch": 7,
                "fencing_token": "fence-synthetic-007",
                "issued_at": _timestamp(NOW - timedelta(seconds=15)),
                "expires_at": _timestamp(NOW + timedelta(minutes=5)),
                "checkpoint_parent_ref": f"cas:{'9' * 64}",
            },
            "integrity": {
                "payload_sha256": "0" * 64,
                "parent_refs": [job_spec["object_id"], permit["object_id"]],
            },
        }
    )
    return job_spec, permit, lease


def _rebind_permit_to_job(job_spec: dict, permit: dict) -> None:
    permit["payload"]["job_spec_sha256"] = canonical_json_sha256(job_spec)
    _seal(permit)


def _claim_keywords() -> dict:
    return {
        "job_id": "job-synthetic-ledger-001",
        "attempt_id": "attempt-synthetic-ledger-001",
        "permit_id": "permit-synthetic-ledger-001",
        "permit_nonce_sha256": PERMIT_NONCE_SHA256,
        "runner_identity": "runner-synthetic-ledger-001",
        "fencing_epoch": 7,
        "fencing_token": "fence-synthetic-ledger-007",
        "admitted_at": _timestamp(NOW),
        "admission_digest": ADMISSION_SHA256,
        "accounting_policy_ref": ACCOUNTING_POLICY_REF,
        "budget_scope_ref": BUDGET_SCOPE_REF,
        "scope_limit_cost_units": 100,
        "trial_ref": "trial:synthetic-ledger-001",
        "provider": "runner-synthetic-ledger-001",
        "job_idempotency_key": "idempotency:synthetic-ledger-001",
        "reservation_cost_units": 1,
        "reservation_expires_at": _timestamp(NOW + timedelta(minutes=10)),
        "contour": "bridge",
        "classification": "D0_PUBLIC",
    }


def _checkpoint_keywords(**overrides: object) -> dict:
    values = {
        "job_id": "job-synthetic-ledger-001",
        "attempt_id": "attempt-synthetic-ledger-001",
        "fencing_epoch": 7,
        "fencing_token": "fence-synthetic-ledger-007",
        "sequence": 0,
        "state_sha256": STATE_SHA256,
        "payload_ref": f"cas:{STATE_SHA256}",
        "payload_stored_in_domain_vault": False,
        "event_at": _timestamp(NOW + timedelta(seconds=1)),
    }
    values.update(overrides)
    return values


class _RecordingLedger:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def claim(self, **keywords: object) -> dict:
        self.calls.append(dict(keywords))
        return dict(keywords)


class Stage1AdmissionAssuranceTests(unittest.TestCase):
    def assert_denied_without_ledger_write(
        self,
        job_spec: dict,
        permit: dict,
        lease: dict,
    ) -> None:
        ledger = _RecordingLedger()
        kernel = BridgeKernel(ledger, authority=_authority_verifier())
        with self.assertRaises(AdmissionError):
            kernel.claim(job_spec, permit, lease, now=NOW)
        self.assertEqual(ledger.calls, [])

    def test_valid_authority_reaches_ledger_exactly_once(self) -> None:
        job_spec, permit, lease = _valid_authority()
        ledger = _RecordingLedger()

        BridgeKernel(ledger, authority=_authority_verifier()).claim(
            job_spec, permit, lease, now=NOW
        )

        self.assertEqual(len(ledger.calls), 1)
        self.assertEqual(
            set(ledger.calls[0]),
            {
                "job_id",
                "attempt_id",
                "permit_id",
                "permit_nonce_sha256",
                "runner_identity",
                "fencing_epoch",
                "fencing_token",
                "admitted_at",
                "admission_digest",
                "accounting_policy_ref",
                "budget_scope_ref",
                "scope_limit_cost_units",
                "trial_ref",
                "provider",
                "job_idempotency_key",
                "reservation_cost_units",
                "reservation_expires_at",
                "contour",
                "classification",
            },
        )

    def test_unknown_fields_are_fail_closed_before_the_ledger(self) -> None:
        mutations = []

        job_spec, permit, lease = _valid_authority()
        job_spec["unexpected"] = "synthetic"
        _rebind_permit_to_job(job_spec, permit)
        mutations.append(("job top-level", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        job_spec["payload"]["unexpected"] = "synthetic"
        _seal(job_spec)
        _rebind_permit_to_job(job_spec, permit)
        mutations.append(("job payload", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        permit["payload"]["unexpected"] = "synthetic"
        _seal(permit)
        mutations.append(("permit payload", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        lease["unexpected"] = "synthetic"
        mutations.append(("lease top-level", job_spec, permit, lease))

        for label, candidate_job, candidate_permit, candidate_lease in mutations:
            with self.subTest(label=label):
                self.assert_denied_without_ledger_write(
                    candidate_job, candidate_permit, candidate_lease
                )

    def test_invalid_budget_profiles_are_fail_closed_before_the_ledger(self) -> None:
        candidates = []

        job_spec, permit, lease = _valid_authority()
        job_spec["payload"]["resource_limits"] = {"cost_units": True}
        _seal(job_spec)
        _rebind_permit_to_job(job_spec, permit)
        candidates.append(("boolean reservation", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        job_spec["payload"]["resource_limits"] = {
            "cost_units": MAX_SAFE_INTEGER + 1
        }
        _seal(job_spec)
        _rebind_permit_to_job(job_spec, permit)
        candidates.append(("unsafe reservation", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        permit["payload"]["quotas"]["scope_limit"]["cost_units"] = 1
        _seal(permit)
        candidates.append(("reservation over scope", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        permit["payload"]["quotas"]["provider"] = "other-provider"
        _seal(permit)
        candidates.append(("provider mismatch", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        permit["payload"]["quotas"]["scope_limit"]["extra"] = 1
        _seal(permit)
        candidates.append(("extra scope field", job_spec, permit, lease))

        for label, candidate_job, candidate_permit, candidate_lease in candidates:
            with self.subTest(label=label):
                self.assert_denied_without_ledger_write(
                    candidate_job, candidate_permit, candidate_lease
                )

    def test_invalid_payload_integrity_is_fail_closed(self) -> None:
        for index, label in enumerate(("job", "permit", "lease")):
            job_spec, permit, lease = _valid_authority()
            documents = [job_spec, permit, lease]
            documents[index]["integrity"]["payload_sha256"] = "f" * 64
            with self.subTest(document=label):
                self.assert_denied_without_ledger_write(job_spec, permit, lease)

    def test_expired_and_future_authority_is_fail_closed(self) -> None:
        candidates = []

        job_spec, permit, lease = _valid_authority()
        permit["payload"]["expires_at"] = _timestamp(NOW - timedelta(seconds=1))
        _seal(permit)
        candidates.append(("expired permit", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        permit["payload"]["not_before"] = _timestamp(NOW + timedelta(seconds=1))
        _seal(permit)
        candidates.append(("future permit", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        lease["payload"]["expires_at"] = _timestamp(NOW - timedelta(seconds=1))
        _seal(lease)
        candidates.append(("expired lease", job_spec, permit, lease))

        job_spec, permit, lease = _valid_authority()
        lease["payload"]["issued_at"] = _timestamp(NOW + timedelta(seconds=1))
        lease["issued_at"] = lease["payload"]["issued_at"]
        _seal(lease)
        candidates.append(("future lease", job_spec, permit, lease))

        for label, candidate_job, candidate_permit, candidate_lease in candidates:
            with self.subTest(label=label):
                self.assert_denied_without_ledger_write(
                    candidate_job, candidate_permit, candidate_lease
                )

    def test_mismatched_authority_is_fail_closed(self) -> None:
        mutations = (
            ("permit job digest", "permit", "job_spec_sha256", "a" * 64),
            ("permit code digest", "permit", "code_sha256", "b" * 64),
            ("permit input digest", "permit", "input_sha256", "c" * 64),
            ("lease job reference", "lease", "job_ref", "job-synthetic-other"),
            ("lease permit reference", "lease", "permit_ref", "permit-synthetic-other"),
            ("lease runner", "lease", "runner_identity", "runner-synthetic-other"),
        )
        for label, owner, field, value in mutations:
            job_spec, permit, lease = _valid_authority()
            document = permit if owner == "permit" else lease
            document["payload"][field] = value
            _seal(document)
            with self.subTest(label=label):
                self.assert_denied_without_ledger_write(job_spec, permit, lease)

    def test_non_offline_policy_is_fail_closed(self) -> None:
        job_spec, permit, lease = _valid_authority()
        job_spec["payload"]["network_policy"] = "connected"
        _seal(job_spec)
        _rebind_permit_to_job(job_spec, permit)
        self.assert_denied_without_ledger_write(job_spec, permit, lease)

        job_spec, permit, lease = _valid_authority()
        permit["payload"]["network_class"] = "connected"
        _seal(permit)
        self.assert_denied_without_ledger_write(job_spec, permit, lease)

    def test_replayed_authority_adds_no_second_ledger_event(self) -> None:
        job_spec, permit, lease = _valid_authority()
        with tempfile.TemporaryDirectory() as temporary_directory:
            ledger = JobLedger(Path(temporary_directory) / "synthetic-ledger.sqlite3")
            kernel = BridgeKernel(ledger, authority=_authority_verifier())
            try:
                kernel.claim(job_spec, permit, lease, now=NOW)
                self.assertEqual(ledger.event_count(), 1)
                persisted_payload = ledger._connection.execute(
                    "SELECT payload_json FROM bridge_job_ledger WHERE event_type = 'claim'"
                ).fetchone()[0]
                self.assertNotIn(permit["payload"]["nonce"], persisted_payload)
                self.assertIn(
                    hashlib.sha256(
                        permit["payload"]["nonce"].encode("utf-8")
                    ).hexdigest(),
                    persisted_payload,
                )

                replay = kernel.claim(job_spec, permit, lease, now=NOW)

                self.assertEqual(ledger.event_count(), 1)
                self.assertEqual(replay.sequence, 1)
                self.assertTrue(ledger.verify_chain())
            finally:
                ledger.close()


class Stage1LedgerAssuranceTests(unittest.TestCase):
    def test_concurrent_identical_claims_replay_one_append(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "synthetic-ledger.sqlite3"
            JobLedger(database).close()
            barrier = Barrier(8)

            def claim_once() -> int:
                ledger = JobLedger(database)
                try:
                    barrier.wait(timeout=10)
                    return ledger.claim(**_claim_keywords()).sequence
                finally:
                    ledger.close()

            with ThreadPoolExecutor(max_workers=8) as executor:
                outcomes = list(executor.map(lambda _: claim_once(), range(8)))

            self.assertEqual(outcomes, [1] * 8)
            ledger = JobLedger(database)
            try:
                self.assertEqual(ledger.event_count(), 1)
                self.assertTrue(ledger.verify_chain())
            finally:
                ledger.close()

    def test_stale_fence_causes_zero_extra_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            ledger = JobLedger(Path(temporary_directory) / "synthetic-ledger.sqlite3")
            try:
                ledger.claim(**_claim_keywords())
                before = ledger.event_count()
                for label, overrides in (
                    ("epoch", {"fencing_epoch": 6}),
                    ("token", {"fencing_token": "fence-synthetic-stale"}),
                ):
                    with self.subTest(label=label):
                        with self.assertRaises(LedgerError):
                            ledger.checkpoint(**_checkpoint_keywords(**overrides))
                        self.assertEqual(ledger.event_count(), before)
            finally:
                ledger.close()

    def test_checkpoint_sequence_and_portable_reference_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            ledger = JobLedger(Path(temporary_directory) / "synthetic-ledger.sqlite3")
            try:
                ledger.claim(**_claim_keywords())

                with self.assertRaises(LedgerError):
                    ledger.checkpoint(
                        **_checkpoint_keywords(payload_ref="file:local-state")
                    )
                self.assertEqual(ledger.event_count(), 1)

                first = ledger.checkpoint(**_checkpoint_keywords())
                self.assertEqual(ledger.event_count(), 2)

                replay = ledger.checkpoint(**_checkpoint_keywords())
                self.assertEqual(replay, first)
                self.assertEqual(ledger.event_count(), 2)

                with self.assertRaises(LedgerError):
                    ledger.checkpoint(
                        **_checkpoint_keywords(state_sha256="9" * 64)
                    )
                self.assertEqual(ledger.event_count(), 2)

                with self.assertRaises(LedgerError):
                    ledger.checkpoint(
                        **_checkpoint_keywords(
                            sequence=1,
                            payload_ref=f"vault:{STATE_SHA256}",
                            payload_stored_in_domain_vault=False,
                        )
                    )
                self.assertEqual(ledger.event_count(), 2)
                self.assertTrue(ledger.verify_chain())
            finally:
                ledger.close()

    def test_update_delete_are_denied_and_chain_survives_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "synthetic-ledger.sqlite3"
            ledger = JobLedger(database)
            ledger.claim(**_claim_keywords())
            ledger.checkpoint(**_checkpoint_keywords())
            ledger.complete(
                job_id=_claim_keywords()["job_id"],
                attempt_id=_claim_keywords()["attempt_id"],
                fencing_epoch=_claim_keywords()["fencing_epoch"],
                fencing_token=_claim_keywords()["fencing_token"],
                result_sha256=RESULT_SHA256,
                event_at=_timestamp(NOW + timedelta(seconds=2)),
            )
            self.assertEqual(ledger.event_count(), 3)
            self.assertTrue(ledger.verify_chain())
            ledger.close()

            connection = sqlite3.connect(database)
            try:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertIn("bridge_job_ledger", tables)
                columns = [
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(bridge_job_ledger)"
                    )
                ]
                self.assertIn("payload_json", columns)
                payloads = [
                    row[0]
                    for row in connection.execute(
                        "SELECT payload_json FROM bridge_job_ledger"
                    )
                ]
                self.assertEqual(len(payloads), 3)
                raw_fencing_token = _claim_keywords()["fencing_token"]
                for payload in payloads:
                    self.assertNotIn(raw_fencing_token, payload)

                column = columns[0]
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(
                        f'UPDATE bridge_job_ledger SET "{column}" = "{column}"'
                    )
                connection.rollback()
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("DELETE FROM bridge_job_ledger")
                connection.rollback()
            finally:
                connection.close()

            reopened = JobLedger(database)
            try:
                self.assertEqual(reopened.event_count(), 3)
                self.assertTrue(reopened.verify_chain())
            finally:
                reopened.close()


class Stage1StaticBoundaryTests(unittest.TestCase):
    def test_static_surface_excludes_live_and_domain_outcome_authority(self) -> None:
        modules = {
            "admission.py": {
                "AdmissionError",
                "AdmissionGrant",
                "canonical_json_sha256",
                "admit",
            },
            "kernel.py": {"BridgeKernel"},
            "ledger.py": {
                "A1BundleRecord",
                "FeedbackBundleRecord",
                "FeedbackReplayReport",
                "ModelCallTransitionRecord",
                "JobLedger",
                "LedgerError",
                "LedgerEvent",
            },
            "model_broker.py": {
                "FixtureProviderAdapter",
                "KnownProviderFailure",
                "ModelBinding",
                "ModelBrokerError",
                "ModelBudgetPolicy",
                "ModelCallBroker",
                "ModelCallHandle",
                "ModelCallSpec",
                "ModelCorrelationSnapshot",
                "ModelCouncilPlan",
                "ModelErrorObservation",
                "ModelProviderAdapter",
                "ModelProviderRouting",
                "ModelRoleRegistry",
                "ModelRoute",
                "ModelRouteDecision",
                "ProviderResult",
                "ResponseCommitter",
            },
        }
        forbidden_imports = {
            "ftplib",
            "http",
            "httpx",
            "requests",
            "smtplib",
            "socket",
            "subprocess",
            "urllib",
        }
        forbidden_identifier_fragments = {
            "deploy",
            "domain_registry",
            "exchange",
            "exploit",
            "live_trade",
            "order_submit",
            "publish",
            "registry_writer",
            "target_scan",
        }

        parsed = {}
        for filename, expected_public_definitions in modules.items():
            tree = ast.parse((SRC / "research_bridge" / filename).read_text())
            parsed[filename] = tree
            public_definitions = {
                node.name
                for node in tree.body
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and not node.name.startswith("_")
            }
            self.assertEqual(public_definitions, expected_public_definitions, filename)

            imported_roots = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_roots.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level:
                    imported_roots.add("research_bridge")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported_roots.add(node.module.split(".")[0])
            self.assertTrue(imported_roots.isdisjoint(forbidden_imports), filename)
            non_stdlib = {
                root
                for root in imported_roots
                if root not in sys.stdlib_module_names and root != "research_bridge"
            }
            self.assertEqual(non_stdlib, set(), filename)

        kernel_class = next(
            node
            for node in parsed["kernel.py"].body
            if isinstance(node, ast.ClassDef) and node.name == "BridgeKernel"
        )
        kernel_methods = {
            node.name
            for node in kernel_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.name.startswith("_")
        }
        self.assertEqual(kernel_methods, {"claim"})

        ledger_class = next(
            node
            for node in parsed["ledger.py"].body
            if isinstance(node, ast.ClassDef) and node.name == "JobLedger"
        )
        ledger_methods = {
            node.name
            for node in ledger_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.name.startswith("_")
        }
        self.assertEqual(
            ledger_methods,
            {
                "append_a1_bundle",
                "append_feedback_bundle",
                "append_model_call_transition",
                "claim",
                "checkpoint",
                "complete",
                "completed_event",
                "event_count",
                "feedback_for_execution",
                "feedback_projection_coverage",
                "replay_feedback",
                "projection_coverage",
                "read_a1_object",
                "storage_coverage_manifest",
                "verify_a1_coverage",
                "verify_chain",
                "close",
                "pause_global",
                "resume_global",
                "is_globally_paused",
                "model_call_history",
                "model_call_state",
                "pause_snapshot",
            },
        )

        identifiers = set()
        for tree in parsed.values():
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    identifiers.add(node.id.lower())
                elif isinstance(node, ast.Attribute):
                    identifiers.add(node.attr.lower())
                elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    identifiers.add(node.name.lower())
        violations = {
            identifier
            for identifier in identifiers
            if any(fragment in identifier for fragment in forbidden_identifier_fragments)
        }
        self.assertEqual(violations, set())


if __name__ == "__main__":
    unittest.main()
