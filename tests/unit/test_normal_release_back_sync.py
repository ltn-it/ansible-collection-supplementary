"""Actual back-sync shell and Git fixtures; no fixture grants native acceptance."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from tests.unit import test_normal_release_proof as FIXTURE

ROOT = Path(__file__).resolve().parents[2]
PROOF = FIXTURE.PROOF
REPO = FIXTURE.REPOSITORY
TAG = "v1.0.1"
TAGGER = "lightning-it-release-tag-creator"


class NormalBackSyncTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FIXTURE.NormalReleaseProofTests("runTest")
        self.fixture.setUp()
        # Image startup must not reorder PATH ahead of the offline native seam.
        self.fixture.git_env["BASH_ENV"] = os.devnull
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.git = self.fixture.root, self.fixture.git
        FIXTURE.install_ee_dispatcher(
            self.root,
            r"""
if [ "${4:-}" = normal-backsync-proof ]; then
  exec python scripts/normal_release_proof.py baseline --root "$PWD" \
    --control-root "$PWD/back-sync-control-source" --repository "$6" --repository-id "$7" --base "$5"
elif [ "${4:-}" = normal-backsync-freshness ]; then
  printf '{"fresh":true}\n'
  exit 0
fi
""",
        )
        # Writer topology tests retain their explicit native-proof seam. Actual
        # raw collector/ZIP/Core verification is exercised in the proof suite.
        (self.root / "scripts/normal_release_observations.sh").write_text(
            '#!/bin/bash\nset -euo pipefail\ntest "$3" = lightning-it/ansible-collection-supplementary\nmkdir "$2"\n'
        )
        self.release, self.develop = self.fixture.release, self.fixture.develop
        self.tagged_release = self.release
        self.git("config", "gc.auto", "0")
        self.git("config", "maintenance.auto", "false")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.remote = Path(temporary.name) / "origin.git"
        self.git("init", "--bare", "-q", str(self.remote))
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "-q", "origin", f"{self.release}:refs/heads/main", f"{self.develop}:refs/heads/develop")
        self.make_tag()
        self.state_path = self.root / "native-state.json"
        self.calls = self.root / "native-calls"
        self.calls.write_text("")
        self.state = {
            "main": self.release,
            "develop": self.develop,
            "history": [],
            "pull": None,
            "published": {
                "id": 123,
                "tag_name": TAG,
                "target_commitish": "develop",
                "draft": False,
                "prerelease": False,
                "published_at": "2026-10-18T01:00:00Z",
            },
            "proof": {"main_merge": self.release, "develop_merge": self.develop},
            "proof_fail": False,
        }
        self.binaries = self.root / "fixture-bin"
        self.binaries.mkdir()
        python = shutil.which("python3")
        assert python
        gh = self.binaries / "gh"
        gh.write_text(
            "#!"
            + python
            + "\n"
            + r"""
import json,os,subprocess,sys
from pathlib import Path
args=sys.argv[1:]
state_path=Path(os.environ["NATIVE_STATE"])
state=json.loads(state_path.read_text())
with Path(os.environ["NATIVE_CALLS"]).open("a") as log: log.write(json.dumps(args)+"\n")
def output(value): print(json.dumps(value))
if args[0]=="api":
    path=next(a for a in args[1:] if a.startswith(("repos/","/users/")))
    if path.startswith("/users/"):
        output({"id":9876,"login":"lightning-it-release-tag-creator[bot]","type":"Bot"})
    elif "/branches/" in path:
        branch=path.rsplit("/",1)[1]
        output({"protected":not state.get("unprotected",False),"commit":{"sha":state[branch]}})
    elif "/releases/tags/" in path: output(state["published"])
    elif path.endswith("/pulls"):
        output(state["history"] if state["pull"] is None else [state["pull"]])
        if state.get("drift_after_history"):
            state["develop"]="f"*40
            state_path.write_text(json.dumps(state))
    elif path.endswith("/pulls/77"): output(state["pull"])
    else: raise SystemExit("unexpected read-only API fixture locator")
elif args[:2]==["pr","create"]:
    def option(name): return args[args.index(name)+1]
    branch=option("--head")
    head=subprocess.check_output(["git","rev-parse",f"refs/heads/{branch}"],text=True).strip()
    state["pull"]={"number":77,"state":"open","merged":False,"draft":True,
        "auto_merge":None,"title":option("--title"),"body":option("--body"),
        "user":{"login":"lightning-it-release-automation[bot]","id":307565056,"type":"Bot"},
        "base":{"ref":"develop","sha":state["develop"],"repo":{"full_name":os.environ["REPO"],"id":1103407173}},
        "head":{"ref":branch,"sha":head,"repo":{"full_name":os.environ["REPO"],"id":1103407173}}}
    state_path.write_text(json.dumps(state))
    print("https://github.com/lightning-it/ansible-collection-supplementary/pull/77")
elif args[:2]==["pr","ready"]:
    state["pull"]["draft"]=False
    if state.get("drift_after_ready"): state["develop"]="f"*40
    state_path.write_text(json.dumps(state))
else: raise SystemExit("unexpected native mutation forbidden in this fixture")
"""
        )
        gh.chmod(0o700)
        proof = self.binaries / "python"
        proof.write_text(
            "#!"
            + python
            + "\n"
            + r"""
import json,os,subprocess,sys
from pathlib import Path
args=sys.argv[1:]
if args[:2]==["scripts/normal_release_proof.py","publish"]:
    raise SystemExit("Original Actions evidence expired; authenticated published baseline required")
if args[:2]==["scripts/normal_release_proof.py","baseline"]:
    expected=json.loads(os.environ["EXPECTED_PROOF_ARGUMENTS"])
    if args!=expected: raise SystemExit("publication proof arguments drifted")
    state=json.loads(Path(os.environ["NATIVE_STATE"]).read_text())
    with Path(os.environ["NATIVE_CALLS"]).open("a") as log:
        log.write(json.dumps(["read-only-publication-proof",*args])+"\n")
    if state["proof_fail"]: raise SystemExit("native publication proof rejected by offline boundary fixture")
    print(json.dumps(state["proof"]))
    if state.get("drift_after_proof"):
        state["main"]="f"*40
        Path(os.environ["NATIVE_STATE"]).write_text(json.dumps(state))
    if state.get("release_drift_after_proof"):
        state["published"]["id"]+=1
        Path(os.environ["NATIVE_STATE"]).write_text(json.dumps(state))
else:
    raise SystemExit(subprocess.call([os.environ["ACTUAL_PYTHON"],*args]))
"""
        )
        proof.chmod(0o700)

    def make_tag(self):
        self.git("tag", "-d", TAG) if self.git("tag", "-l", TAG) else None
        previous = self.fixture.git_env.copy()
        self.fixture.git_env.update(
            {
                "GIT_COMMITTER_NAME": f"{TAGGER}[bot]",
                "GIT_COMMITTER_EMAIL": f"9876+{TAGGER}[bot]@users.noreply.github.com",
            }
        )
        try:
            self.git("tag", "-a", TAG, self.release, "-m", f"Release {TAG}")
        finally:
            self.fixture.git_env = previous
        self.git("push", "-q", "--force", "origin", f"refs/tags/{TAG}")

    def run_step(self, **overrides):
        # A real Actions checkout cleans the prior job's untracked read-only
        # observations. Preserve the fixture's remote PR/branch state.
        for name in (".normal-backsync-observations", ".normal-backsync-fresh"):
            shutil.rmtree(self.root / name, ignore_errors=True)
        workflow = yaml.safe_load((ROOT / ".github/workflows/release-back-sync.yml").read_text())
        step = next(
            s for s in workflow["jobs"]["back-sync"]["steps"] if s["name"] == "Open or update release back-sync PR"
        )
        script = (
            step["run"]
            .replace("${{ steps.release-bot.outputs.login }}", PROOF.APP[0])
            .replace("${{ steps.release-bot.outputs.email }}", PROOF.git_contract.CONTRACT.RELEASE_APP_EMAIL)
        )
        self.state_path.write_text(json.dumps(self.state))
        self.git("checkout", "-q", "--detach", self.release)
        runner = self.root / "runner-temp"
        runner.mkdir(exist_ok=True)
        expected = [
            "scripts/normal_release_proof.py",
            "baseline",
            "--root",
            str(self.root),
            "--control-root",
            str(self.root / "back-sync-control-source"),
            "--repository",
            REPO,
            "--repository-id",
            "1103407173",
            "--base",
            self.release,
        ]
        env = (
            self.fixture.git_env
            | {
                "PATH": f"{self.binaries}:{os.environ['PATH']}",
                "ACTUAL_PYTHON": shutil.which("python3"),
                "EXPECTED_PROOF_ARGUMENTS": json.dumps(expected),
                "NATIVE_STATE": str(self.state_path),
                "NATIVE_CALLS": str(self.calls),
                "TAG_INPUT": TAG,
                "REPO": REPO,
                "EXPECTED_TAG_APP_SLUG": TAGGER,
                "EXPECTED_TAG_APP_ID": "4344269",
                "EXPECTED_TAG_APP_CLIENT_ID": "Iv23liJnnvOQwajan2Mf",
                "SECURITY_RELEASE": "false",
                "SECURITY_VERSION": "",
                "SECURITY_EVIDENCE_ID": "",
                "WORKFLOW_ACTOR": "fixture-only",
                "NORMAL_TWO_STAGE": "true",
                "GH_TOKEN": "fixture-only",
                "GITHUB_REPOSITORY_ID": "1103407173",
                "GITHUB_SHA": self.release,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_WORKSPACE": str(self.root),
                "GITHUB_REPOSITORY_OWNER": "lightning-it",
                "RUNNER_TEMP": str(runner),
            }
            | overrides
        )
        result = subprocess.run(  # noqa: S603 -- actual workflow shell; local bare Git and native boundary stubs only.
            [shutil.which("bash"), "-c", script],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.state = json.loads(self.state_path.read_text())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return result, calls

    def branches(self):
        return self.git("ls-remote", "--heads", "origin", "refs/heads/backmerge/*")

    def test_real_shell_creates_only_canonical_unchanged_tree_pr_without_paid_dispatch(self):
        result, calls = self.run_step()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        pull = self.state["pull"]
        branch = f"backmerge/ansible-collection-supplementary-{self.release[:12]}-{self.develop[:12]}-main"
        title = f"chore(governance): record main ancestry before {self.release[:12]}"
        self.assertEqual(branch, pull["head"]["ref"])
        self.assertEqual(title, pull["title"])
        self.assertFalse(pull["draft"])
        self.assertEqual(f"{self.develop} {self.release}", self.git("show", "-s", "--format=%P", pull["head"]["sha"]))
        self.assertEqual(
            self.git("rev-parse", f"{self.develop}^{{tree}}"), self.git("rev-parse", f"{pull['head']['sha']}^{{tree}}")
        )
        self.assertEqual("", self.git("diff", "--name-only", self.develop, pull["head"]["sha"]))
        self.assertFalse(any(call[:2] in (["workflow", "run"], ["pr", "merge"]) for call in calls))
        self.assertEqual(1, sum(call[0] == "read-only-publication-proof" for call in calls))
        second, calls = self.run_step()
        self.assertEqual(0, second.returncode, second.stdout + second.stderr)
        self.assertEqual(1, sum(call[:2] == ["pr", "create"] for call in calls))
        self.assertEqual(1, sum(call[:2] == ["pr", "ready"] for call in calls))

    def test_delayed_backsync_consumes_verified_archive_without_original_actions(self):
        # Run the actual baseline reader on the same Git graph before passing
        # its result through the existing offline shell boundary. Signature
        # transport is mocked by baseline_api; no native approval is invented.
        self.git("tag", "-d", TAG)
        self.fixture.baseline_api(self.release)
        self.make_tag()
        self.fixture.tag_ref["object"]["sha"] = self.git("rev-parse", f"refs/tags/{TAG}")
        previous = self.fixture.api.call.side_effect

        def expired_actions(path):
            if "/actions/" in path:
                raise AssertionError("expired historical Actions must not be read")
            return previous(path)

        self.fixture.api.call.side_effect = expired_actions
        self.fixture.api.pages.side_effect = AssertionError("original artifact inventory expired")
        self.fixture.core.artifact_record.side_effect = AssertionError("original artifact downloads expired")
        self.state["proof"] = PROOF.published_baseline(
            self.root, self.fixture.api, self.fixture.core, REPO, "1103407173", self.release
        )
        self.fixture.core.artifact_record.assert_not_called()
        self.fixture.api.pages.assert_not_called()
        result, calls = self.run_step()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        proof_calls = [call for call in calls if call[0] == "read-only-publication-proof"]
        self.assertEqual(1, len(proof_calls))
        self.assertEqual("baseline", proof_calls[0][2])
        self.assertNotIn("--release", proof_calls[0])
        pull = self.state["pull"]
        self.assertEqual(f"{self.develop} {self.release}", self.git("show", "-s", "--format=%P", pull["head"]["sha"]))
        self.assertEqual("", self.git("diff", "--name-only", self.develop, pull["head"]["sha"]))
        self.assertFalse(any("/actions/" in arg for call in calls for arg in call))

    def test_already_ancestor_still_proves_publication_then_noops_without_branch_or_pr(self):
        self.develop = self.release
        self.state["develop"] = self.release
        self.git("push", "-q", "origin", f"{self.develop}:refs/heads/develop")
        result, calls = self.run_step()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("", self.branches())
        self.assertIsNone(self.state["pull"])
        self.assertEqual(1, sum(call[0] == "read-only-publication-proof" for call in calls))

    def test_native_proof_rejection_stops_all_effects(self):
        self.state["proof_fail"] = True
        result, _unused = self.run_step()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", self.branches())
        self.assertIsNone(self.state["pull"])

    def test_native_tip_drift_after_proof_or_history_is_rechecked_before_first_effect(self):
        original = copy.deepcopy(self.state)
        for key in ("drift_after_proof", "drift_after_history", "release_drift_after_proof"):
            self.state = copy.deepcopy(original)
            self.state[key] = True
            with self.subTest(key=key):
                result, _unused = self.run_step()
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", self.branches())
                self.assertIsNone(self.state["pull"])

    def test_native_context_and_tag_target_are_independently_bound(self):
        for key, value in (
            ("GITHUB_SHA", self.fixture.main_base),
            ("GITHUB_REPOSITORY_ID", "1"),
            ("GITHUB_REF", "refs/heads/develop"),
        ):
            with self.subTest(key=key):
                result, _unused = self.run_step(**{key: value})
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", self.branches())
        release = self.release
        self.release = self.fixture.main_base
        self.make_tag()
        self.release = release
        result, _unused = self.run_step()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", self.branches())
        self.assertIsNone(self.state["pull"])

    def test_missing_or_unpublished_release_wrong_main_and_protection_stop_effects(self):
        original = copy.deepcopy(self.state)
        for defect in ("draft", "prerelease", "tag", "unpublished", "missing", "main", "unprotected"):
            self.state = copy.deepcopy(original)
            if defect in {"draft", "prerelease"}:
                self.state["published"][defect] = True
            elif defect == "tag":
                self.state["published"]["tag_name"] = "v9.9.9"
            elif defect == "unpublished":
                self.state["published"]["published_at"] = None
            elif defect == "missing":
                self.state["published"] = {}
            elif defect == "main":
                self.state["main"] = self.fixture.main_base
            else:
                self.state["unprotected"] = True
            with self.subTest(defect=defect):
                result, _unused = self.run_step()
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", self.branches())
                self.assertIsNone(self.state["pull"])

    def test_nonempty_merge_delta_and_develop_without_released_ingress_are_closed(self):
        self.git("checkout", "-q", "--detach", self.release)
        (self.root / "unreviewed.txt").write_text("Unreviewed Main product content\n")
        self.git("add", "unreviewed.txt")
        self.release = self.fixture.commit("changed Main tree", [self.fixture.main_base, self.fixture.develop])
        self.git("checkout", "-q", "--detach", self.release)
        self.git("push", "-q", "--force", "origin", f"{self.release}:refs/heads/main")
        self.make_tag()
        self.state["main"] = self.release
        self.state["proof"]["main_merge"] = self.release
        result, _unused = self.run_step()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", self.branches())
        self.assertIsNone(self.state["pull"])
        self.develop = self.fixture.main_base
        self.state["develop"] = self.develop
        self.git("push", "-q", "--force", "origin", f"{self.develop}:refs/heads/develop")
        result, _unused = self.run_step()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", self.branches())

    def test_closed_or_foreign_history_blocks_before_push(self):
        for user, state in (
            (dict(zip(("login", "id", "type"), PROOF.APP, strict=True)), "closed"),
            ({"login": "foreign", "id": 1, "type": "User"}, "open"),
        ):
            self.state["history"] = [{"user": user, "state": state}]
            with self.subTest(state=state):
                result, _unused = self.run_step()
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", self.branches())
        self.state["history"] = [
            {"state": "open", "user": dict(zip(("login", "id", "type"), PROOF.APP, strict=True))}
        ] * 2
        result, _unused = self.run_step()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", self.branches())


class AdoptedBackSyncSourceContractTests(unittest.TestCase):
    def test_new_case_pins_existing_source_and_needs_no_extra_app_permission(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release-back-sync.yml").read_text())
        steps = workflow["jobs"]["back-sync"]["steps"]
        checkout = next(s for s in steps if s["name"] == "Checkout adopted normal back-sync proof source")
        self.assertEqual(PROOF.CONTROL_SOURCE, checkout["with"]["ref"])
        self.assertEqual("needs.security-classification.outputs.normal-two-stage == 'true'", checkout["if"])
        mint = next(s for s in steps if s.get("id") == "release-app")
        self.assertEqual(
            {"permission-actions": "read", "permission-contents": "write", "permission-pull-requests": "write"},
            {k: v for k, v in mint["with"].items() if k.startswith("permission-")},
        )

    def test_actual_classification_selects_only_schema3_normal_and_keeps_schema2_legacy(self):
        fixture = FIXTURE.NormalReleaseProofTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        workflow = yaml.safe_load((ROOT / ".github/workflows/release-back-sync.yml").read_text())
        step = next(s for s in workflow["jobs"]["security-classification"]["steps"] if s.get("id") == "binding")
        output = fixture.root / "classification-output"
        receipt = fixture.root / PROOF.RECEIPT
        for schema, mode, expected in (
            (3, "normal", "true"),
            (2, "normal", "false"),
            (2, "security", "false"),
            (3, "security", None),
        ):
            value = copy.deepcopy(fixture.receipt)
            value["schema_version"], value["release_mode"] = schema, mode
            receipt.write_bytes(PROOF.git_contract.CONTRACT.canonical_document_bytes(value))
            output.write_text("")
            result = subprocess.run(  # noqa: S603 -- actual data-only classification shell in isolated Git fixture.
                [shutil.which("bash"), "-c", step["run"]],
                cwd=fixture.root,
                env=fixture.git_env | {"TAG_INPUT": TAG, "GITHUB_SHA": fixture.release, "GITHUB_OUTPUT": str(output)},
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            with self.subTest(schema=schema, mode=mode):
                if expected is None:
                    self.assertNotEqual(0, result.returncode)
                else:
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn(f"normal_two_stage={expected}\n", output.read_text())

    def test_real_bb1_ancestry_verifier_accepts_exact_graph_and_rejects_wrong_component_or_tree(self):
        directory = Path(os.environ.get("LIT_RELEASE_CONTROL_FIXTURE", ROOT / ".cache/release-control-source"))
        if not directory.is_dir():
            self.skipTest("immutable bb1 fixture must be staged for qualification")
        fixture = NormalBackSyncTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        result, _unused = fixture.run_step()
        self.assertEqual(0, result.returncode, result.stderr)
        previous = sys.modules.pop("workflow_control", None)
        old_subject = sys.modules.pop("workflow_subject", None)
        try:
            core = PROOF.load_control(directory)
            import workflow_subject

            def local_objects(objects, repository, *refs):
                self.assertEqual(REPO, repository)
                subprocess.run(  # noqa: S603 -- exact test-owned Git objects, no provider transport.
                    [shutil.which("git"), "--git-dir", str(objects), "fetch", "-q", str(fixture.root), *refs],
                    env=fixture.fixture.git_env,
                    check=True,
                    capture_output=True,
                )

            pull = fixture.state["pull"]
            api = type("ReadOnlyAPI", (), {"call": lambda _unused, path: {"object": {"sha": fixture.release}}})()
            with (
                patch.dict(os.environ, fixture.fixture.git_env, clear=True),
                patch.object(workflow_subject, "fetch_objects", side_effect=local_objects),
            ):
                self.assertTrue(core.ancestry_evidence(api, REPO, pull, {})["unchanged_tree"])
                changed = copy.deepcopy(pull)
                changed["head"]["ref"] = changed["head"]["ref"].replace(
                    "ansible-collection-supplementary", "supplementary"
                )
                with self.assertRaisesRegex(core.ControlError, "ancestry-exact-operation"):
                    core.ancestry_evidence(api, REPO, changed, {})
                (fixture.root / "galaxy.yml").write_text("---\nversion: 9.9.9\n")
                fixture.git("add", "galaxy.yml")
                changed["head"] = copy.deepcopy(pull["head"])
                changed["head"]["sha"] = fixture.fixture.commit("altered tree", [fixture.develop, fixture.release])
                with self.assertRaisesRegex(core.ControlError, "ancestry-content-change"):
                    core.ancestry_evidence(api, REPO, changed, {})
        finally:
            sys.modules.pop("workflow_control", None)
            sys.modules.pop("workflow_subject", None)
            if previous is not None:
                sys.modules["workflow_control"] = previous
            if old_subject is not None:
                sys.modules["workflow_subject"] = old_subject


if __name__ == "__main__":
    unittest.main()
