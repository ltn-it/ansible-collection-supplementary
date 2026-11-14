"""Real Git/Bash regressions for the reserved repository-metadata namespace."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_ROOT = ROOT
GIT = shutil.which("git")
BASH = shutil.which("bash")
if GIT is None or BASH is None:
    raise RuntimeError("git and bash are required for changelog policy tests")


class ChangelogMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repository"
        self.root.mkdir()
        home = Path(temporary.name) / "home"
        home.mkdir()
        self.environment = os.environ.copy()
        for name in ("GIT_COMMON_DIR", "GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"):
            self.environment.pop(name, None)
        self.environment["HOME"] = str(home)
        self.environment["GIT_CONFIG_GLOBAL"] = str(home / ".gitconfig")
        self.environment["GIT_CONFIG_NOSYSTEM"] = "1"
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("devtools-changelog-check.sh", "resolve-changelog-head-ref.sh"):
            source = POLICY_ROOT / "scripts" / name
            if source.exists():
                shutil.copy2(source, scripts)
        # Same shell-boundary fixture as test_changelog_head_ref: run the actual
        # policy body in this already isolated test process. Fragment lint has
        # its own gate; this fixture substitutes only the container/CLI boundary.
        (scripts / "wunder-devtools-ee.sh").write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            'test "$1" = bash\ntest "$2" = -lc\n'
            "body=${3//\\/workspace/$PWD}\n"
            "body=${body//antsibull-changelog lint/true}\n"
            'exec bash -c "$body"\n',
            encoding="utf-8",
        )
        self.write("galaxy.yml", "namespace: lit\nname: fixture\nversion: 1.0.0\n")
        self.write("changelogs/changelog.yaml", "releases: {}\n")
        self.git("init", "--quiet")
        self.git("config", "user.name", "Changelog policy fixture")
        self.git("config", "user.email", "changelog@invalid")
        self.commit()
        self.base = self.git("rev-parse", "HEAD")

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def git(self, *args):
        return subprocess.check_output(  # noqa: S603 -- fixed Git executable and test-owned fixture arguments.
            [GIT, *args],
            cwd=self.root,
            env=self.environment,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture change")

    def policy(self):
        self.commit()
        environment = self.environment | {
            "BASE_SHA": self.base,
            "HEAD_SHA": self.git("rev-parse", "HEAD"),
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": "ltn-it/ansible-collection-supplementary",
            "GITHUB_HEAD_REPOSITORY": "ltn-it/ansible-collection-supplementary",
            "GITHUB_PR_AUTHOR": "litroc",
            "GITHUB_HEAD_REF": "fix/repository-metadata",
            "GITHUB_BASE_REF": "develop",
            "GITHUB_REF_NAME": "fix/repository-metadata",
            "LABELS_JSON": "[]",
            "REQUIRE_FRAGMENT": "true",
        }
        return subprocess.run(  # noqa: S603 -- fixed policy script in a test-owned repository.
            [BASH, "scripts/devtools-changelog-check.sh"],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def test_repository_metadata_namespace_needs_no_release_fragment(self):
        documents = {
            ".lit/workflow-control.json": {
                "version": 2,
                "repository": "ltn-it/ansible-collection-supplementary",
                "mode": "reference",
                "quality": [],
                "accepted_sources": [],
                "distribution_sources": [],
                "artifact_publication": True,
                "supplementary_funding_contract": {
                    "version": 2,
                    "candidate_scope": "repository-head",
                    "legacy_claims": "consumed",
                    "unknown_outcomes": "consumed_uncertain",
                },
            },
            ".lit/main-ancestry.json": {"version": 1, "kind": "ancestry-metadata"},
            ".lit/future-control.json": {"version": 1, "kind": "repository-control"},
            ".lit/controls/nested/audit.json": {"version": 1, "kind": "audit-metadata"},
        }
        for path, document in documents.items():
            self.write(path, json.dumps(document) + "\n")
        result = self.policy()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Only documentation, CI, tests, metadata, or changelog files changed.", result.stdout)
        self.assertNotIn("skipped by PR label", result.stdout)

    def test_metadata_does_not_hide_role_or_plugin_changes(self):
        self.write(".lit/workflow-control.json", '{"version": 2}\n')
        for path, content in (
            ("roles/example/tasks/main.yml", "---\n- name: Example\n  ansible.builtin.debug:\n    msg: changed\n"),
            ("plugins/filter/example.py", 'VALUE = "changed"\n'),
        ):
            with self.subTest(path=path):
                self.write(path, content)
                result = self.policy()
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn("User-visible collection changes require a changelog fragment", result.stdout)
                self.git("reset", "--hard", self.base)
                self.git("clean", "-fd")
                self.write(".lit/workflow-control.json", '{"version": 2}\n')

    def test_user_change_with_metadata_and_fragment_passes(self):
        self.write(".lit/controls/new.json", '{"version": 1}\n')
        self.write("roles/example/defaults/main.yml", "---\nexample_enabled: true\n")
        self.write(
            "changelogs/fragments/example-enabled.yml", "bugfixes:\n  - Preserve the documented example default.\n"
        )
        result = self.policy()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_similar_directory_names_are_not_repository_metadata(self):
        for path in (".literal/control.json", "roles/example/.lit/control.json"):
            with self.subTest(path=path):
                self.write(path, '{"version": 1}\n')
                result = self.policy()
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn("User-visible collection changes require a changelog fragment", result.stdout)
                self.git("reset", "--hard", self.base)
                self.git("clean", "-fd")

    def test_metadata_does_not_authorize_generated_release_files(self):
        self.write(".lit/controls/new.json", '{"version": 1}\n')
        self.write("CHANGELOG.rst", "Generated release notes\n=======================\n")
        result = self.policy()
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Generated changelog files", result.stdout)

    def test_metadata_classification_does_not_validate_malformed_json(self):
        self.write(".lit/workflow-control.json", '{"version": 2,\n')
        result = self.policy()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        # JSON validity remains an independent parser boundary. Do not teach
        # the changelog classifier a competing workflow-control schema.
        validation = subprocess.run(
            [sys.executable, "-m", "json.tool", ".lit/workflow-control.json"],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(0, validation.returncode)
        self.assertIn("Expecting", validation.stderr)


if __name__ == "__main__":
    unittest.main()
