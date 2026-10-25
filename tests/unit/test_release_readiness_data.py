"""Exercise the data-only export against real candidate Git objects."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/release_readiness_data.py"


class ReleaseReadinessDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_SYSTEM=os.devnull,
            GIT_AUTHOR_NAME="Fixture",
            GIT_AUTHOR_EMAIL="fixture@example.invalid",
            GIT_COMMITTER_NAME="Fixture",
            GIT_COMMITTER_EMAIL="fixture@example.invalid",
        )
        self.git("init", "-q")
        (self.root / "galaxy.yml").write_text("version: 4.1.0\n")
        self.fragments = self.root / "changelogs/fragments"
        self.fragments.mkdir(parents=True)
        (self.fragments / "next.yml").write_text("bugfixes:\n  - Reviewed fix.\n")

    def git(self, *arguments):
        executable = shutil.which("git")
        assert executable
        return (
            subprocess.check_output(  # noqa: S603 -- isolated local fixture Git.
                [executable, *arguments],
                cwd=self.root,
                env=self.env,
            )
            .decode()
            .strip()
        )

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "candidate")
        return self.git("rev-parse", "HEAD")

    def export(self, revision=None):
        return subprocess.run(  # noqa: S603 -- actual trusted helper against isolated Git data.
            [sys.executable, str(HELPER), "--revision", revision or self.commit(), "--destination", "data"],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_only_yaml_blobs_are_exported_without_executing_candidate_code(self):
        (self.root / "sitecustomize.py").write_text("raise RuntimeError('candidate executed')\n")
        (self.fragments / "README.md").write_text("ignored\n")
        result = self.export()
        self.assertEqual(0, result.returncode, result.stderr)
        exported = sorted(
            str(p.relative_to(self.root / "data")) for p in (self.root / "data").rglob("*") if p.is_file()
        )
        self.assertEqual(["changelogs/fragments/next.yml", "galaxy.yml"], exported)
        self.assertEqual(
            (self.fragments / "next.yml").read_bytes(), (self.root / "data/changelogs/fragments/next.yml").read_bytes()
        )

    def test_symlink_and_nested_fragment_are_rejected_before_directory_creation(self):
        for kind in ("symlink", "nested"):
            with self.subTest(kind=kind):
                fragment = self.fragments / "next.yml"
                fragment.unlink(missing_ok=True)
                if kind == "symlink":
                    fragment.symlink_to("../../galaxy.yml")
                else:
                    (self.fragments / "nested").mkdir()
                    (self.fragments / "nested/next.yml").write_text("bugfixes: []\n")
                result = self.export()
                self.assertNotEqual(0, result.returncode)
                self.assertFalse((self.root / "data").exists())

    def test_oversized_blob_and_fragment_count_are_rejected(self):
        (self.fragments / "next.yml").write_bytes(b"x" * (1024 * 1024 + 1))
        result = self.export()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / "data").exists())
        (self.fragments / "next.yml").write_text("bugfixes: []\n")
        for index in range(256):
            (self.fragments / f"fragment-{index}.yml").write_text("bugfixes: []\n")
        result = self.export()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / "data").exists())

    def test_ref_expression_and_existing_destination_are_rejected(self):
        self.commit()
        self.assertNotEqual(0, self.export("HEAD").returncode)
        destination = self.root / "data"
        destination.mkdir()
        (destination / "preserved").write_text("keep\n")
        self.assertNotEqual(0, self.export(self.git("rev-parse", "HEAD")).returncode)
        self.assertEqual("keep\n", (destination / "preserved").read_text())

    def test_readiness_has_no_candidate_checkout_and_invokes_main_helper(self):
        job = yaml.safe_load((ROOT / ".github/workflows/release-prepare.yml").read_text())["jobs"]["normal-readiness"]
        checkouts = [step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@")]
        self.assertEqual(1, len(checkouts))
        self.assertEqual("${{ github.sha }}", checkouts[0]["with"]["ref"])
        exporter = next(step for step in job["steps"] if "release_readiness_data.py" in step.get("run", ""))
        self.assertEqual("${{ steps.tips.outputs.content_sha }}", exporter["env"]["CONTENT_SHA"])
        self.assertNotIn("PYTHONPATH", str(job))

    @unittest.skipUnless(
        ROOT == Path("/workspace") and (ROOT / ".git").exists(),
        "positive ownership probe requires the actual Devtools Git mount",
    )
    def test_scoped_workspace_git_trust_accepts_only_the_actual_devtools_mount(self):
        executable = shutil.which("git")
        assert executable
        env = self.env | {"GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}
        # The actual Devtools mount is the only admitted differing-owner path.
        raw = subprocess.run(  # noqa: S603 -- fixed read-only ownership regression.
            [executable, "-C", "/workspace", "rev-parse", "HEAD"],
            env=env,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(0, raw.returncode)
        revision = subprocess.check_output(  # noqa: S603 -- exact scoped trust.
            [executable, "-c", "safe.directory=/workspace", "-C", "/workspace", "rev-parse", "HEAD"],
            env=env,
            text=True,
        ).strip()
        destination = self.root / "workspace-data"
        result = subprocess.run(  # noqa: S603 -- actual helper in the read-only EE workspace.
            [sys.executable, str(HELPER), "--revision", revision, "--destination", str(destination)],
            cwd="/workspace",
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((destination / "galaxy.yml").is_file())

    def test_scoped_workspace_git_trust_does_not_trust_an_unrelated_repository(self):
        unrelated = self.export(self.commit())
        self.assertEqual(0, unrelated.returncode, unrelated.stderr)
        # The same helper must not admit this unrelated differing-owner fixture.
        env = self.env | {"GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}
        denied = subprocess.run(  # noqa: S603 -- no global safe.directory exemption.
            [sys.executable, str(HELPER), "--revision", self.git("rev-parse", "HEAD"), "--destination", "forbidden"],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(0, denied.returncode)
        self.assertFalse((self.root / "forbidden").exists())


if __name__ == "__main__":
    unittest.main()
