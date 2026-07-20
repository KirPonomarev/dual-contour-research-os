import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import candidate_image_build as candidate


SHA = "9" * 40


class ReproducibleCandidateBuildTests(unittest.TestCase):
    def test_source_date_epoch_is_bound_to_exact_candidate_commit(self) -> None:
        with mock.patch.object(candidate, "_git", return_value="1784543661") as git:
            self.assertEqual(candidate._source_date_epoch(SHA), "1784543661")
        git.assert_called_once_with("show", "-s", "--format=%ct", SHA)
        for invalid in ("", "0", "-1", "1.5", "now"):
            with self.subTest(invalid=invalid), mock.patch.object(
                candidate, "_git", return_value=invalid
            ):
                with self.assertRaises(candidate.CandidateBuildError):
                    candidate._source_date_epoch(SHA)

    def test_build_command_requires_no_cache_epoch_and_timestamp_rewrite(self) -> None:
        output = Path("/private/owner-only/image.oci.tar")
        command = candidate._reproducible_build_command(
            SHA,
            "candidate:test",
            "1784543661",
            output,
        )
        self.assertEqual(command[:3], ["docker", "buildx", "build"])
        self.assertIn("--no-cache", command)
        self.assertIn("--pull=false", command)
        self.assertIn("--provenance=false", command)
        self.assertIn("RELEASE_SHA=" + SHA, command)
        self.assertIn("SOURCE_DATE_EPOCH=1784543661", command)
        self.assertIn("BUILDKIT_MULTI_PLATFORM=1", command)
        self.assertIn(
            "--output=type=oci,dest=/private/owner-only/image.oci.tar,rewrite-timestamp=true",
            command,
        )

    def test_build_loads_only_after_the_reproducible_export_exists(self) -> None:
        calls = []

        def run(command, **keywords):
            calls.append((command, keywords))
            if command[:3] == ["docker", "buildx", "build"]:
                output = next(item for item in command if item.startswith("--output="))
                destination = output.split("dest=", 1)[1].split(",", 1)[0]
                Path(destination).write_bytes(b"synthetic OCI archive")
            return mock.Mock(stdout="", stderr="", returncode=0)

        with mock.patch.object(candidate, "_run", side_effect=run):
            candidate._build_reproducible_image(SHA, "candidate:test", "1784543661")
        self.assertEqual(calls[0][0][:3], ["docker", "buildx", "build"])
        self.assertEqual(calls[1][0][:3], ["docker", "load", "--input"])


if __name__ == "__main__":
    unittest.main()
