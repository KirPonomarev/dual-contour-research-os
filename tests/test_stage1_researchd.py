from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "src"))

from research_bridge.cas import ContentAddressedStore  # noqa: E402
from research_bridge.researchd import (  # noqa: E402
    ResearchDaemon,
    ResearchdError,
)
from tests.test_stage1_reference_vertical import (  # noqa: E402
    INPUT_A,
    INPUT_B,
    INPUT_REFS,
    NOW,
    _authority,
    _authority_verifier,
)


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _snapshot(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (
            path.relative_to(root).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    )


class ResearchDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.runtime = self.base / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.job_spec, self.permit, self.lease = _authority("D0_PUBLIC")
        self._seed_inputs()
        lease_payload = self.lease["payload"]
        assert isinstance(lease_payload, dict)
        self.runner_identity = str(lease_payload["runner_identity"])
        self.daemons: list[ResearchDaemon] = []

    def tearDown(self) -> None:
        for daemon in reversed(self.daemons):
            daemon.close()
        self.temporary.cleanup()

    def _seed_inputs(self) -> None:
        store = ContentAddressedStore(
            self.runtime / "input-cas",
            quota_bytes=1_048_576,
        )
        for index, (reference, payload) in enumerate(
            zip(INPUT_REFS, (INPUT_A, INPUT_B), strict=True)
        ):
            source = self.base / f"synthetic-input-{index}.bin"
            source.write_bytes(payload)
            publication = store.publish(
                source,
                expected_sha256=reference.removeprefix("cas:sha256:"),
                expected_size_bytes=len(payload),
            )
            self.assertEqual(publication.ref, reference)

    def _daemon(self, root: Path | None = None) -> ResearchDaemon:
        daemon = ResearchDaemon(
            root or self.runtime,
            authority=_authority_verifier(),
            allowed_uids={os.geteuid()},
            runner_identity=self.runner_identity,
            input_quota_bytes=1_048_576,
            checkpoint_quota_bytes=1_048_576,
            artifact_quota_bytes=1_048_576,
            maximum_input_bytes=1_048_576,
            clock=lambda: NOW,
        )
        self.daemons.append(daemon)
        return daemon

    def _submit(self, daemon: ResearchDaemon) -> Mapping[str, object]:
        payload = self.job_spec["payload"]
        assert isinstance(payload, dict)
        return daemon.submit(
            job_spec=self.job_spec,
            permit=self.permit,
            lease=self.lease,
            idempotency_key=str(payload["idempotency_key"]),
            now=NOW,
        )

    def test_start_owns_exact_root_lock_ledger_and_af_unix_socket(self) -> None:
        daemon = self._daemon()
        daemon.start()

        self.assertEqual(stat.S_IMODE(os.lstat(self.runtime).st_mode), 0o700)
        self.assertEqual(os.lstat(self.runtime).st_uid, os.geteuid())
        lock = os.lstat(self.runtime / ".researchd.lock")
        self.assertTrue(stat.S_ISREG(lock.st_mode))
        self.assertEqual(stat.S_IMODE(lock.st_mode), 0o600)
        endpoint = os.lstat(daemon.socket_path)
        self.assertTrue(stat.S_ISSOCK(endpoint.st_mode))
        self.assertEqual(stat.S_IMODE(endpoint.st_mode), 0o660)
        self.assertIsNotNone(daemon._ledger)
        self.assertTrue(daemon._ledger.verify_chain())  # type: ignore[union-attr]

        daemon.close()
        daemon.close()
        self.assertFalse(os.path.lexists(daemon.socket_path))
        self.assertIsNone(daemon._ledger)

    def test_cross_process_runtime_lock_rejects_a_second_writer(self) -> None:
        daemon = self._daemon()
        daemon.start()
        child = os.fork()
        if child == 0:
            try:
                if daemon._lock_fd is not None:
                    os.close(daemon._lock_fd)
                contender = ResearchDaemon(
                    self.runtime,
                    authority=_authority_verifier(),
                    allowed_uids={os.geteuid()},
                    runner_identity=self.runner_identity,
                    clock=lambda: NOW,
                )
                try:
                    contender.start()
                except ResearchdError:
                    os._exit(0)
                contender.close()
                os._exit(1)
            except BaseException:
                os._exit(2)
        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertTrue(daemon._ledger.verify_chain())  # type: ignore[union-attr]

    def test_submit_and_post_reopen_lookup_return_the_same_receipt_without_writes(self) -> None:
        daemon = self._daemon()
        daemon.start()
        submitted = self._submit(daemon)
        job_ref = str(self.job_spec["object_id"])
        immediate = daemon.lookup(job_spec_ref=job_ref)
        self.assertEqual(_canonical(submitted), _canonical(immediate))
        self.assertEqual(submitted["execution_receipt"]["schema_id"], "ExecutionReceipt")  # type: ignore[index]
        self.assertEqual(daemon._ledger.event_count("claim"), 1)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("checkpoint"), 1)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("complete"), 1)  # type: ignore[union-attr]

        before = _snapshot(self.runtime)
        daemon.close()
        reopened = self._daemon()
        reopened.start()
        reopened_before = _snapshot(self.runtime)
        recovered = reopened.lookup(job_spec_ref=job_ref)
        reopened_after = _snapshot(self.runtime)

        self.assertEqual(_canonical(recovered), _canonical(submitted))
        self.assertEqual(reopened_before, reopened_after)
        self.assertNotEqual(before, ())
        self.assertEqual(reopened._ledger.event_count(), 3)  # type: ignore[union-attr]

    def test_duplicate_submit_is_rejected_before_runner_or_ledger_change(self) -> None:
        daemon = self._daemon()
        daemon.start()
        self._submit(daemon)
        before = (
            daemon._ledger.event_count(),  # type: ignore[union-attr]
            _snapshot(self.runtime / "staging-by-attempt-digest"),
        )
        with self.assertRaises(ResearchdError):
            self._submit(daemon)
        after = (
            daemon._ledger.event_count(),  # type: ignore[union-attr]
            _snapshot(self.runtime / "staging-by-attempt-digest"),
        )
        self.assertEqual(before, after)

    def test_pause_before_submit_denies_claim_and_runner_work(self) -> None:
        daemon = self._daemon()
        daemon.start()
        daemon.pause_global(
            actor=f"uid:{os.geteuid()}",
            reason="synthetic offline hold",
            authority_ref="permit:synthetic-offline-hold",
            idempotency_key="pause-synthetic-researchd",
            event_at=NOW.isoformat().replace("+00:00", "Z"),
        )
        with self.assertRaises(ResearchdError):
            self._submit(daemon)
        self.assertEqual(daemon._ledger.event_count("pause"), 1)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("claim"), 0)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("checkpoint"), 0)  # type: ignore[union-attr]
        self.assertEqual(daemon._ledger.event_count("complete"), 0)  # type: ignore[union-attr]

    def test_insecure_root_symlink_and_stale_socket_fail_closed(self) -> None:
        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        with self.assertRaises(ResearchdError):
            self._daemon(insecure).start()
        self.assertFalse(os.path.lexists(insecure / "researchd.sock"))

        real = self.base / "real-root"
        real.mkdir(mode=0o700)
        linked = self.base / "linked-root"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ResearchdError):
            self._daemon(linked).start()
        self.assertFalse(os.path.lexists(real / "researchd.sock"))

        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(self.runtime / "researchd.sock"))
        stale_inode = os.lstat(self.runtime / "researchd.sock").st_ino
        stale.close()
        with self.assertRaises(ResearchdError):
            self._daemon().start()
        current = os.lstat(self.runtime / "researchd.sock")
        self.assertTrue(stat.S_ISSOCK(current.st_mode))
        self.assertEqual(current.st_ino, stale_inode)


if __name__ == "__main__":
    unittest.main()
