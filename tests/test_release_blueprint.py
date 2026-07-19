import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from verify_release_blueprint import inspect


class ReleaseBlueprintTests(unittest.TestCase):
    def test_canonical_blueprint_is_rootless_pinned_and_offline(self) -> None:
        result = inspect(ROOT)
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["network_at_runtime"])
        self.assertFalse(result["external_action_authority"])
        self.assertEqual(result["config_mode"], "a1-enabled")
        self.assertEqual(len(result["hashes"]), 6)

    def copied(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        shutil.copytree(ROOT / "ops", root / "ops")
        shutil.copy2(ROOT / ".dockerignore", root / ".dockerignore")
        return temporary, root

    def test_unpinned_install_or_add_is_rejected(self) -> None:
        temporary, root = self.copied()
        with temporary:
            path = root / "ops/release/Containerfile"
            path.write_text(path.read_text() + "\nRUN apt-get update\n", encoding="utf-8")
            self.assertIn("container.unpinned_install_or_add", inspect(root)["failures"])

    def test_runtime_network_or_privilege_drift_is_rejected(self) -> None:
        temporary, root = self.copied()
        with temporary:
            path = root / "ops/release/runtime-policy.json"
            policy = json.loads(path.read_text())
            policy["network"] = "bridge"
            policy["cap_drop"] = []
            path.write_text(json.dumps(policy), encoding="utf-8")
            self.assertIn("runtime_policy.boundary", inspect(root)["failures"])

    def test_authority_or_build_context_expansion_is_rejected(self) -> None:
        temporary, root = self.copied()
        with temporary:
            config_path = root / "ops/release/researchd.config.template.json"
            config = json.loads(config_path.read_text())
            config["approval_receipts"] = {"unexpected": {}}
            config_path.write_text(json.dumps(config), encoding="utf-8")
            (root / ".dockerignore").write_text(".git\n", encoding="utf-8")
            failures = inspect(root)["failures"]
            self.assertIn("config.boundary", failures)
            self.assertIn("build_context.not_minimal", failures)

    def test_dependency_and_notice_drift_is_rejected(self) -> None:
        temporary, root = self.copied()
        with temporary:
            lock_path = root / "ops/release/dependency-lock.json"
            lock = json.loads(lock_path.read_text())
            lock["python_dependencies"] = ["unfrozen"]
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            (root / "ops/release/THIRD_PARTY_NOTICES.md").write_text("missing", encoding="utf-8")
            failures = inspect(root)["failures"]
            self.assertIn("dependency_lock.drift", failures)
            self.assertIn("third_party_notice.incomplete", failures)


if __name__ == "__main__":
    unittest.main()
