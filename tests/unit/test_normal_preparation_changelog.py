"""Real Git/shell schema3 ingress fixtures; no fixture asserts native acceptance."""

from __future__ import annotations

import ast
import copy
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

from tests.unit import test_normal_release_proof as FIXTURE

ROOT = Path(__file__).resolve().parents[2]
PROOF = FIXTURE.PROOF
REPO = FIXTURE.REPOSITORY


class NormalPreparationChangelogTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FIXTURE.NormalReleaseProofTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.git = self.fixture.git
        self.base = self.fixture.content_base
        self.head = self.fixture.prepared
        self.branch = "release/v1.0.1"
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in (
            "devtools-changelog-check.sh",
            "resolve-changelog-head-ref.sh",
            "normal_release_proof.py",
            "normal_release_archive.py",
            "release-version.py",
            "security_main_promotion.py",
            "security_premerge_proof.py",
            "security_release_contract.py",
        ):
            shutil.copy2(ROOT / "scripts" / name, scripts)
        (scripts / "wunder-devtools-ee.sh").write_text(
            '#!/bin/bash\nset -euo pipefail\ntest "$1" = bash\ntest "$2" = -lc\n'
            'body=${3//\\/workspace/$PWD}\nbody=${body//antsibull-changelog lint/true}\nexec bash -c "$body"\n'
        )
        self.git("update-ref", "refs/remotes/origin/main", self.fixture.main_base)
        self.git("update-ref", "refs/remotes/origin/develop", self.base)
        self.git("checkout", "-q", "--detach", self.head)

    def environment(self):
        return self.fixture.git_env | {
            "HOME": str(self.root),
            "BASE_SHA": self.base,
            "HEAD_SHA": self.head,
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_REPOSITORY_ID": "1103407173",
            "GITHUB_HEAD_REPOSITORY": REPO,
            "GITHUB_PR_AUTHOR": PROOF.APP[0],
            "GITHUB_HEAD_REF": self.branch,
            "GITHUB_BASE_REF": "develop",
            "LABELS_JSON": "[]",
        }

    def policy(self, **overrides):
        return subprocess.run(  # noqa: S603 -- actual guard in isolated offline Git fixture.
            [shutil.which("bash"), "scripts/devtools-changelog-check.sh"],
            cwd=self.root,
            env=self.environment() | overrides,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def test_real_preparation_pr_passes_and_identity_source_or_local_state_drift_fails(self):
        accepted = self.policy()
        self.assertEqual(0, accepted.returncode, accepted.stdout + accepted.stderr)
        for key, value in (
            ("GITHUB_PR_AUTHOR", "litroc"),
            ("GITHUB_REPOSITORY_ID", "1"),
            ("GITHUB_HEAD_REPOSITORY", "foreign/repo"),
            ("GITHUB_HEAD_REF", "release/v1.0.2"),
            ("BASE_SHA", self.fixture.main_base),
            ("GITHUB_BASE_REF", "main"),
        ):
            with self.subTest(key=key):
                self.assertNotEqual(0, self.policy(**{key: value}).returncode)
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.assertNotEqual(0, self.policy().returncode)
        self.git("update-ref", "refs/remotes/origin/main", self.fixture.main_base)
        (self.root / "galaxy.yml").write_text("---\nversion: 99.0.0\n")
        self.assertNotEqual(0, self.policy().returncode)
        self.git("checkout", "--", "galaxy.yml")
        (self.root / "changelogs/fragments/untracked.yml").write_text("bugfixes: [Unbound]\n")
        self.assertNotEqual(0, self.policy().returncode)

    def test_generated_only_fragment_and_schema_contract_is_executed(self):
        original = copy.deepcopy(self.fixture.receipt)
        for defect in ("schema2", "foreign-repository", "foreign-id", "fragment-digest", "product-file"):
            self.git("checkout", "-q", "--detach", self.fixture.prepared)
            receipt = copy.deepcopy(original)
            if defect == "schema2":
                receipt["schema_version"] = 2
            elif defect == "foreign-repository":
                receipt["repository"] = "foreign/repo"
            elif defect == "foreign-id":
                receipt["repository_id"] = "1"
            elif defect == "fragment-digest":
                receipt["fragments"][0]["sha256"] = "0" * 64
            else:
                (self.root / "unreviewed-product.yml").write_text("unreviewed: true\n")
            (self.root / PROOF.RECEIPT).write_bytes(PROOF.git_contract.CONTRACT.canonical_document_bytes(receipt))
            self.git("add", PROOF.RECEIPT)
            if defect == "product-file":
                self.git("add", "unreviewed-product.yml")
            self.head = self.fixture.commit("chore(release): prepare v1.0.1", [self.base])
            self.git("checkout", "-q", "--detach", self.head)
            with self.subTest(defect=defect):
                self.assertNotEqual(0, self.policy().returncode)

    def make_push(self):
        self.head = self.fixture.commit(
            f"Merge pull request #1 from lightning-it/{self.branch}", [self.base, self.fixture.prepared]
        )
        self.git("checkout", "-q", "--detach", self.head)
        self.git("update-ref", "refs/remotes/origin/develop", self.head)
        pull = copy.deepcopy(self.fixture.prep)
        pull["merge_commit_sha"] = self.head
        return pull

    def native_push(self, pull, *, associated=None, **overrides):
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-ci.yml").read_text())
        step = next(s for s in workflow["jobs"]["lint-sanity"]["steps"] if s.get("id") == "release-push")
        binary = self.root / "fixture-bin"
        binary.mkdir(exist_ok=True)
        (binary / "gh").write_text(
            "#!/bin/bash\nset -euo pipefail\n"
            'case "$*" in *"/commits/${SOURCE_SHA}/pulls") cat "$ASSOCIATED" ;; '
            '*"/pulls/1") cat "$PULL" ;; *) exit 1 ;; esac\n'
        )
        (binary / "gh").chmod(0o700)
        detail, pages, output = (self.root / name for name in ("pull.json", "pages.json", "outputs"))
        detail.write_text(json.dumps(pull))
        pages.write_text(json.dumps([associated if associated is not None else [pull]]))
        output.write_text("")
        env = (
            self.environment()
            | {
                "SOURCE_SHA": self.head,
                "TARGET_REF": "develop",
                "PUSH_BEFORE": self.base,
                "PATH": f"{binary}:{os.environ['PATH']}",
                "PULL": str(detail),
                "ASSOCIATED": str(pages),
                "GITHUB_OUTPUT": str(output),
            }
            | overrides
        )
        result = subprocess.run(  # noqa: S603 -- actual CI shell, offline native metadata fixtures.
            [shutil.which("bash"), "-c", step["run"]],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result, output.read_text()

    def test_real_ci_push_and_changelog_shells_bind_both_parents_and_reviewed_tree(self):
        pull = self.make_push()
        result, output = self.native_push(pull)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(f"author={PROOF.APP[0]}\nhead_repository={REPO}\nimport_head_ref={self.branch}\n", output)
        guarded = self.policy(GITHUB_EVENT_NAME="push")
        self.assertEqual(0, guarded.returncode, guarded.stdout + guarded.stderr)
        for key, value in (("PUSH_BEFORE", self.fixture.main_base), ("GITHUB_REPOSITORY_ID", "1")):
            with self.subTest(key=key):
                result, output = self.native_push(pull, **{key: value})
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", output)

    def test_ci_and_guard_reject_squash_wrong_first_parent_or_unreviewed_merge_tree(self):
        pull = self.make_push()
        for defect in ("squash", "first-parent", "tree"):
            self.git("checkout", "-q", "--detach", self.fixture.prepared)
            if defect == "tree":
                (self.root / "galaxy.yml").write_text("---\nversion: 9.9.9\n")
                self.git("add", "galaxy.yml")
            parents = [self.base, self.fixture.prepared]
            if defect == "squash":
                parents = [self.base]
            elif defect == "first-parent":
                parents[0] = self.fixture.main_base
            self.head = self.fixture.commit(f"Merge pull request #1 from lightning-it/{self.branch}", parents)
            self.git("checkout", "-q", "--detach", self.head)
            self.git("update-ref", "refs/remotes/origin/develop", self.head)
            changed = copy.deepcopy(pull)
            changed["merge_commit_sha"] = self.head
            with self.subTest(defect=defect):
                result, output = self.native_push(changed)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", output)
                self.assertNotEqual(0, self.policy(GITHUB_EVENT_NAME="push").returncode)

    def test_ci_duplicate_and_foreign_actual_pull_metadata_is_rejected(self):
        pull = self.make_push()
        result, output = self.native_push(pull, associated=[pull, pull])
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", output)
        for field, value in (
            ("merged", False),
            ("user.id", 1),
            ("user.type", "User"),
            ("base.sha", self.fixture.main_base),
            ("base.repo.full_name", "foreign/repo"),
            ("head.sha", self.base),
            ("head.repo.full_name", "foreign/repo"),
            ("head.ref", "release/v1.0.2"),
        ):
            changed = copy.deepcopy(pull)
            target = changed
            parts = field.split(".")
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
            with self.subTest(field=field):
                result, output = self.native_push(changed)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", output)


def expression(value, facts):
    """Evaluate only the Boolean/constant subset used by actual author projections."""
    source = " ".join(value.removeprefix("${{").removesuffix("}}").split())
    for key, fact in sorted(facts.items(), key=lambda item: -len(item[0])):
        source = source.replace(key, repr(fact))
    tree = ast.parse(source.replace("&&", " and ").replace("||", " or "), mode="eval")

    def evaluate(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Compare):
            left, right = evaluate(node.left), evaluate(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        if isinstance(node, ast.BoolOp):
            result = evaluate(node.values[0])
            for operand in node.values[1:]:
                if isinstance(node.op, ast.And):
                    result = evaluate(operand) if result else result
                else:
                    result = result if result else evaluate(operand)
            return result
        raise AssertionError(ast.dump(node))

    return evaluate(tree.body)


class NativeAuthorProjectionTests(unittest.TestCase):
    def test_actual_workflow_author_projections_require_exact_app_id_type_and_repository(self):
        facts = {
            "github.event_name": "pull_request",
            "github.event.pull_request.user.login": PROOF.APP[0],
            "github.event.pull_request.user.id": PROOF.APP[1],
            "github.event.pull_request.user.type": PROOF.APP[2],
            "github.repository_id": "1103407173",
            "steps.release-push.outputs.author": "",
        }
        for name in ("collection-ci.yml", "changelog.yml"):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
            job = "lint-sanity" if name == "collection-ci.yml" else "changelog"
            env = next(s["env"] for s in workflow["jobs"][job]["steps"] if "GITHUB_PR_AUTHOR" in s.get("env", {}))
            for field in ("GITHUB_PR_AUTHOR", *(["PR_AUTHOR"] if name == "changelog.yml" else [])):
                with self.subTest(workflow=name, field=field):
                    self.assertEqual(PROOF.APP[0], expression(env[field], facts))
                    for key, value in (
                        ("github.event.pull_request.user.id", 1),
                        ("github.event.pull_request.user.type", "User"),
                        ("github.repository_id", "1"),
                    ):
                        self.assertEqual("", expression(env[field], facts | {key: value}))


if __name__ == "__main__":
    unittest.main()
