from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_s22_authority_request as verifier  # noqa: E402


def request() -> dict[str, object]:
    return json.loads(verifier.REQUEST.read_text())


def resign(value: dict[str, object]) -> dict[str, object]:
    result = deepcopy(value)
    result["integrity"]["payload_sha256"] = verifier.payload_digest(result)  # type: ignore[index]
    return result


class S22AuthorityRequestTests(unittest.TestCase):
    def test_static_request_is_reviewable_and_non_authoritative(self) -> None:
        value = verifier.validate()
        self.assertEqual(value["status"], "WAIT_HUMAN_REVIEW")
        self.assertFalse(value["grants_authority"])
        self.assertFalse(value["release_proposal"]["final_release_rebind_required"])
        self.assertEqual(value["release_proposal"]["release_sha"], verifier.RELEASE_SHA)
        self.assertEqual(value["release_proposal"]["release_tree_sha"], verifier.RELEASE_TREE)

    def test_resealed_approval_or_scope_widening_fails(self) -> None:
        cases = (
            lambda v: v.__setitem__("status", "APPROVED"),
            lambda v: v.__setitem__("grants_authority", True),
            lambda v: v.__setitem__("review_decision", "APPROVE"),
            lambda v: v["release_proposal"].__setitem__("final_release_rebind_required", True),
            lambda v: v["release_proposal"].__setitem__("release_sha", "0" * 40),
            lambda v: v["blast_radius"].__setitem__("network", "host"),
            lambda v: v["hard_denies"].remove("AUTO_EXECUTE"),
        )
        for mutate in cases:
            value = request()
            mutate(value)
            with self.assertRaises(verifier.AuthorityRequestError):
                verifier.validate(request=resign(value))

    def test_request_has_no_host_account_secret_or_private_path(self) -> None:
        serialized = json.dumps(request(), sort_keys=True).lower()
        for forbidden in ("password", "api_key", "private_key", "ssh_alias", "hostname", "sudo -s"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
