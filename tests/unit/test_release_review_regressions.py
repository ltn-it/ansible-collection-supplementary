"""Execute protected workflow paths for the third native release review findings.

Offline native fixtures exercise data binding only and confer no admission.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from tests.unit import test_normal_release_back_sync as BACKSYNC

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "lightning-it/ansible-collection-supplementary"
APP = {"login": "lightning-it-release-automation[bot]", "id": 307565056, "type": "Bot"}


def step(workflow, job, name):
    """Read the actual workflow rather than maintaining a second shell copy."""
    document = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    return next(value for value in document["jobs"][job]["steps"] if value.get("name") == name)


def environment():
    """Do not inherit linked-worktree Git routing into independent fixtures."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")} | {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "BASH_ENV": os.devnull,
    }


def shell(script, cwd, env):
    return subprocess.run(  # noqa: S603 -- actual fixed workflow shell, private offline fixture.
        ["/bin/bash", "-euo", "pipefail", "-c", script],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


class ProtectedPythonProcessTests(unittest.TestCase):
    def test_candidate_shadow_modules_never_run_in_either_yaml_transform(self):
        script = step("release-prepare.yml", "prepare", "Prepare release branch")["run"]
        blocks = re.findall(r"(?m)^python[^\n]* <<'PY'\n.*?^PY$", script, re.DOTALL)
        transforms = [block for block in blocks if "LintFriendlyDumper" in block]
        self.assertEqual(2, len(transforms))
        for block in transforms:
            with self.subTest(block=block.splitlines()[0]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "changelogs").mkdir()
                (root / "galaxy.yml").write_text("version: 1.0.0\n")
                (root / "changelogs/changelog.yaml").write_text("releases: {}\n")
                (root / "changelogs/.plugin-cache.yaml").write_text("plugins: {}\n")
                marker = root / "candidate-code-ran"
                (root / "yaml.py").write_text(
                    "import os\nfrom pathlib import Path\n"
                    "Path(os.environ['SHADOW_MARKER']).write_text(os.environ['GH_TOKEN'])\n"
                    "raise RuntimeError('candidate module executed')\n"
                )
                result = shell(
                    block,
                    root,
                    environment()
                    | {
                        "PYTHONPATH": str(root),
                        "SHADOW_MARKER": str(marker),
                        "GH_TOKEN": "offline-credential-sentinel",
                        "VERSION": "1.0.1",
                    },
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertFalse(marker.exists(), "Develop module observed the privileged environment")
                expected = "1.0.1" if "version = os.environ" in block else "1.0.0"
                self.assertEqual(expected, yaml.safe_load((root / "galaxy.yml").read_text())["version"])

    def test_two_fresh_control_processes_preserve_the_actual_pinned_checkout(self):
        source = Path(os.environ.get("LIT_RELEASE_CONTROL_FIXTURE", ROOT / ".cache/release-control-source"))
        if not source.is_dir():
            self.skipTest("immutable bb1 fixture not staged; native-control qualification not executed")
        script = yaml.safe_load((ROOT / ".github/workflows/promote-develop-to-main.yml").read_text())
        guard = (
            script["jobs"]["promote"]["steps"][-1]["run"]
            .split("# LI-139 release-state guard:start\n", 1)[1]
            .split("# LI-139 release-state guard:end", 1)[0]
        )
        exports = "\n".join(line for line in guard.splitlines() if line.startswith("export "))
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "control"
            env = environment()
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            subprocess.run(  # noqa: S603 -- immutable local fixture clone, never network.
                ["/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(source), str(clone)],
                env=env,
                check=True,
                capture_output=True,
            )
            loader = (
                "import sys;from pathlib import Path;"
                f"sys.path.insert(0,{str(ROOT / 'scripts')!r});"
                "import normal_release_proof as proof;"
                "core=proof.load_control(Path(sys.argv[1]));"
                "assert callable(core.policy)"
            )
            command = [sys.executable, "-c", loader, str(clone)]

            # Reproduce the reviewed failure with the old two-process path.
            old = shell(shlex.join(command) + "\n" + shlex.join(command), directory, env)
            self.assertNotEqual(0, old.returncode)
            self.assertIn("clean-control-source-required", old.stderr)
            subprocess.run(  # noqa: S603 -- remove only generated fixture bytecode.
                ["/usr/bin/git", "-C", str(clone), "clean", "-fd"],
                env=env,
                check=True,
                capture_output=True,
            )
            actual = exports + "\n" + shlex.join(command) + "\n" + shlex.join(command)
            result = shell(actual, directory, env)
            self.assertEqual(0, result.returncode, result.stderr)
            status = subprocess.check_output(  # noqa: S603 -- read-only local Git fixture.
                ["/usr/bin/git", "-C", str(clone), "status", "--porcelain"],
                env=env,
                text=True,
            )
            self.assertEqual("", status)
            (clone / "untrusted-file").write_text("must still fail\n")
            result = shell(actual, directory, env)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("clean-control-source-required", result.stderr)


class ProtectedGeneratorTests(unittest.TestCase):
    def test_real_git_plugin_or_config_delta_stops_before_credentialed_job(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release-prepare.yml").read_text())
        preflight = next(
            value["run"] for value in workflow["jobs"]["normal-readiness"]["steps"] if value.get("id") == "need"
        )
        guard = preflight.split("# LI-344 generator closure:start\n", 1)[1].split("# LI-344 generator closure:end", 1)[
            0
        ]
        self.assertIn("needs.normal-readiness.outputs.ready == 'true'", workflow["jobs"]["prepare"]["if"])
        for name in (
            "plugins/doc_fragments/new.py",
            "plugins/modules/new.py",
            "collections/ansible_collections/evil/plugin.py",
            "ansible.cfg",
            "changelogs/config.yaml",
            "meta/runtime.yml",
            "roles/new/meta/argument_specs.yml",
            "roles/new/tasks/main.yml",
        ):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env = environment()

                def git(*args, cwd=root, environ=env):
                    return subprocess.check_output(  # noqa: S603 -- local fixed Git fixture.
                        ["/usr/bin/git", *args],
                        cwd=cwd,
                        env=environ,
                        text=True,
                    ).strip()

                git("init", "-q")
                git("config", "user.name", "Fixture")
                git("config", "user.email", "fixture@example.com")
                (root / "ordinary").write_text("base")
                git("add", ".")
                git("commit", "-qm", "base")
                base = git("rev-parse", "HEAD")
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("candidate-controlled code or output escape")
                git("add", ".")
                git("commit", "-qm", "candidate")
                head = git("rev-parse", "HEAD")
                result = shell(guard, root, env | {"GITHUB_SHA": base, "CONTENT_SHA": head})
                self.assertNotEqual(0, result.returncode)
                self.assertIn("ordinary Main convergence", result.stdout)
                result = shell(guard, root, env | {"GITHUB_SHA": head, "CONTENT_SHA": head})
                self.assertEqual(0, result.returncode, result.stderr)

    def test_generator_uses_main_cwd_config_and_only_fixed_candidate_data(self):
        script = step("release-prepare.yml", "prepare", "Prepare release branch")["run"]
        guard = script.split("# LI-344 protected generator:start\n", 1)[1].split("# LI-344 protected generator:end", 1)[
            0
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, tooling, binary = (root / name for name in ("candidate", "main", "bin"))
            for tree in (candidate, tooling):
                (tree / "changelogs/fragments").mkdir(parents=True)
                (tree / "galaxy.yml").write_text("namespace: lit\nname: supplementary\nversion: 1.0.1\n")
                (tree / "changelogs/changelog.yaml").write_text("releases: {}\n")
                (tree / "changelogs/.plugin-cache.yaml").write_text("plugins: {}\n")
                (tree / "changelogs/fragments/change.yml").write_text("bugfixes: [fixture]\n")
                (tree / "CHANGELOG.rst").write_text("old\n")
            (tooling / "changelogs/config.yaml").write_text("output: [{file: CHANGELOG.rst, format: rst}]\n")
            # The untrusted escape and Python module must never reach tooling.
            verifier = tooling / "verifier.py"
            verifier.write_text("trusted Main verifier\n")
            (candidate / "changelogs/config.yaml").write_text(f"output: [{{file: {verifier}, format: rst}}]\n")
            (candidate / "yaml.py").write_text("raise RuntimeError('candidate Python imported')\n")
            binary.mkdir()
            command = binary / "antsibull-changelog"
            command.write_text(
                "#!"
                + sys.executable
                + "\n"
                + r"""
import os,sys
from pathlib import Path
assert Path.cwd()==Path(os.environ['workflow_source'])
assert 'verifier.py' not in Path('changelogs/config.yaml').read_text()
assert not Path('yaml.py').exists()
if sys.argv[1]=='release':
    Path('CHANGELOG.rst').write_text('new generated changelog\n')
    Path('changelogs/changelog.yaml').write_text('releases: {1.0.1: {}}\n')
    Path('changelogs/.plugin-cache.yaml').write_text('plugins: {}\n')
    Path('changelogs/fragments/change.yml').unlink()
"""
            )
            command.chmod(0o700)
            result = shell(
                guard,
                candidate,
                environment()
                | {
                    "PATH": f"{binary}:{os.environ['PATH']}",
                    "workflow_source": str(tooling),
                    "GH_TOKEN": "offline-sentinel",
                },
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("trusted Main verifier\n", verifier.read_text())
            self.assertEqual("new generated changelog\n", (candidate / "CHANGELOG.rst").read_text())
            self.assertFalse((candidate / "changelogs/fragments/change.yml").exists())
            self.assertTrue((candidate / "yaml.py").exists())

    def test_symlink_write_target_fails_before_parser_or_generator(self):
        script = step("release-prepare.yml", "prepare", "Prepare release branch")["run"]
        helper = (ROOT / "scripts/normal_release_environment.sh").read_text()
        guard = helper.split("# LI-344 regular generation inputs:start\n", 1)[1].split(
            "# LI-344 regular generation inputs:end", 1
        )[0]
        self.assertIn('git show "$WORKFLOW_SOURCE_SHA:scripts/normal_release_environment.sh"', script)
        self.assertLess(script.index("# LI-360 normal EE transport:end"), script.index('version_resolution="$('))
        for name in (
            "galaxy.yml",
            "CHANGELOG.rst",
            "changelogs/release-preparation.json",
            "changelogs/fragments/change.yml",
        ):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "changelogs/fragments").mkdir(parents=True)
                outside = root / "protected-verifier"
                outside.write_text("trusted")
                path = root / name
                path.symlink_to(outside)
                result = shell("release_data() { bash -s; }\n" + guard, root, environment())
                self.assertNotEqual(0, result.returncode)
                if name.endswith("change.yml"):
                    self.assertIn("required", result.stderr)
                else:
                    self.assertIn("symlink", result.stderr)
                self.assertEqual("trusted", outside.read_text())


class PublishDispatchNoopTests(unittest.TestCase):
    def run_case(
        self, *, changed_version=False, changed_state=False, bad_author=False, legacy=False, schema=3, mode="normal"
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            BACKSYNC.FIXTURE.install_ee_dispatcher(root)
            binary = root / "gh"
            binary.write_text(
                "#!"
                + sys.executable
                + "\n"
                + r"""
import base64,json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['CALLS']).open('a') as stream: stream.write(json.dumps(args)+'\n')
if args[0]!='api' or any(a in args for a in ['POST','PATCH','DELETE']): raise SystemExit('write forbidden')
path=args[1]; state=json.loads(os.environ['STATE'])
if '/git/ref/' in path: print('a'*40)
elif '/git/commits/' in path: print(json.dumps({'parents':[{'sha':'b'*40},{'sha':'c'*40}]}))
elif '/contents/' in path:
    name=path.split('/contents/',1)[1].split('?')[0]; base=path.endswith('b'*40)
    if name=='galaxy.yml':
        version='1.0.1' if not base and state['changed_version'] else '1.0.0'
        value='version: '+version+'\ndependencies: '+('{}' if base else '{lit.other: 2.0.0}')+'\n'
    else:
        receipt={'schema_version':state['schema'],'release_mode':state['mode'],
            'next_version':('1.0.1' if state['changed_version'] else '1.0.0'),
            'publication':{'github_release':True,'galaxy':True}}
        value=json.dumps(receipt) if name.endswith('.json') else 'generated\n'
    if '--jq' in args:
        expression=args[args.index('--jq')+1]
        encoded=base64.b64encode(value.encode()).decode()
        blob='different' if not base and state['changed_state'] else name
        print(encoded if expression=='.content' else blob)
    else: raise SystemExit('contents must select an explicit data field')
else: raise SystemExit('unexpected API locator '+path)
"""
            )
            binary.chmod(0o700)
            output = root / "output"
            calls = root / "calls"
            calls.write_text("")
            result = shell(
                step("collection-publish.yml", "dispatch", "Verify reviewed merge and derive publishing settings")[
                    "run"
                ],
                root,
                environment()
                | {
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "STATE": json.dumps(
                        {
                            "changed_version": changed_version,
                            "changed_state": changed_state,
                            "schema": schema,
                            "mode": mode,
                        }
                    ),
                    "CALLS": str(calls),
                    "GITHUB_OUTPUT": str(output),
                    "RUNNER_TEMP": str(root),
                    "GITHUB_WORKSPACE": str(root),
                    "GITHUB_REPOSITORY": REPOSITORY,
                    "MERGE_SHA": "a" * 40,
                    "REVIEWED_HEAD_SHA": "c" * 40,
                    "HEAD_REF": "release/v1.0.0" if legacy else "develop",
                    "HEAD_REPOSITORY": REPOSITORY,
                    "PR_AUTHOR": APP["login"],
                    "PR_AUTHOR_TYPE": "Bot",
                    "PR_AUTHOR_ID": "1" if bad_author else str(APP["id"]),
                    "PR_BODY": "",
                    "GH_TOKEN": "offline-read-only",
                },
            )
            return (
                result,
                dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {},
                calls.read_text(),
            )

    def test_metadata_only_main_promotion_noops_before_every_later_step(self):
        result, outputs, _unused = self.run_case()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("false", outputs.get("release_needed"))
        self.assertNotIn("release_version", outputs)
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-publish.yml").read_text())
        steps = workflow["jobs"]["dispatch"]["steps"]
        self.assertEqual("${{ github.sha }}", steps[0]["with"]["ref"])
        self.assertFalse(steps[0]["with"]["persist-credentials"])
        classification = next(index for index, item in enumerate(steps) if item.get("id") == "release")
        for later in steps[classification + 1 :]:
            self.assertEqual("steps.release.outputs.release_needed == 'true'", later.get("if"), later["name"])

    def test_real_release_state_change_and_legacy_dispatch_are_preserved(self):
        for changes in ({"changed_version": True}, {"changed_state": True}, {"legacy": True}):
            with self.subTest(changes=changes):
                result, outputs, _unused = self.run_case(**changes)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("true", outputs.get("release_needed"))
                self.assertIn("release_version", outputs)

    def test_noop_is_not_a_branch_name_or_foreign_author_exemption(self):
        result, outputs, _unused = self.run_case(bad_author=True)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("release_needed", outputs)

    def test_unchanged_schema2_normal_and_security_state_noops_without_writes(self):
        for mode in ("normal", "security"):
            with self.subTest(mode=mode):
                result, outputs, calls = self.run_case(schema=2, mode=mode)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("false", outputs.get("release_needed"))
                self.assertNotIn("POST", calls)
                self.assertNotIn("release_version", outputs)
                result, outputs, _unused = self.run_case(schema=2, mode=mode, changed_version=True)
                self.assertNotEqual(0, result.returncode)
                self.assertNotIn("release_needed", outputs)


class CanonicalAncestryOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.fixture = BACKSYNC.NormalBackSyncTests("runTest")
        self.fixture.setUp()
        self.fixture.fixture.git_env["BASH_ENV"] = os.devnull
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)

    def run_sync_guard(self, *, ordinary=False, schema=3, github_release=True, wrong_app=False):
        fixture = self.fixture
        script = step("sync-main-to-develop.yml", "backmerge", "Create reviewable ancestry backmerge")["run"]
        if "# LI-344 normal ancestry owner:start" not in script:
            self.fail("actual sync still has no normal-release single-writer fence")
        guard = script.split("# LI-344 normal ancestry owner:start\n", 1)[1].split(
            "# LI-344 normal ancestry owner:end", 1
        )[0]
        receipt = fixture.fixture.receipt.copy()
        receipt.update(
            {
                "schema_version": schema,
                "release_mode": "normal",
                "next_version": "1.0.1",
                "publication": {"github_release": github_release},
            }
        )
        # Only the guard's Git inputs are replaced; Git relationships and PR
        # binding come from the same real two-parent release used by back-sync.
        original = fixture.git("show", f"{fixture.release}:changelogs/release-preparation.json")
        self.assertEqual(3, json.loads(original)["schema_version"])
        binary = fixture.root / "sync-gh"
        binary.mkdir(exist_ok=True)
        gh = binary / "gh"
        pr = {
            "number": 12,
            "merged": True,
            "merged_at": "2026-10-18T00:00:00Z",
            "state": "closed",
            "draft": False,
            "merge_commit_sha": fixture.release,
            "user": {**APP, "id": 1 if wrong_app else APP["id"]},
            "base": {
                "ref": "main",
                "sha": fixture.fixture.main_base,
                "repo": {"full_name": REPOSITORY, "id": 1103407173},
            },
            "head": {"ref": "develop", "sha": fixture.develop, "repo": {"full_name": REPOSITORY, "id": 1103407173}},
        }
        gh.write_text(
            "#!"
            + sys.executable
            + "\nimport json,os,sys\np=json.loads(os.environ['SYNC_PR'])\n"
            + "print(json.dumps([[p]] if any('/commits/' in a for a in sys.argv) else p))\n"
        )
        gh.chmod(0o700)
        # Bind a real variant commit for non-release and legacy fallthrough.
        main = fixture.release
        if ordinary or schema != 3:
            fixture.git("checkout", "-q", "--detach", fixture.release)
            if ordinary:
                path = fixture.root / "galaxy.yml"
                path.write_text(path.read_text() + "dependencies: {lit.other: 2.0.0}\n")
                fixture.git("add", str(path))
                product = fixture.fixture.commit("ordinary product metadata", [fixture.release])
                main = fixture.fixture.commit("ordinary reviewed promotion", [fixture.release, product])
            else:
                path = fixture.root / "changelogs/release-preparation.json"
                path.write_text(json.dumps(receipt))
                fixture.git("add", str(path))
                main = fixture.fixture.commit("fixture variant", [fixture.fixture.main_base, fixture.develop])
        result = shell(
            guard + "\necho ORDINARY_ANCESTRY_WRITER\n",
            fixture.root,
            environment()
            | {
                "PATH": f"{binary}:{os.environ['PATH']}",
                "SYNC_PR": json.dumps(pr),
                "REPOSITORY": REPOSITORY,
                "REPOSITORY_ID": "1103407173",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SHA": main,
                "main_sha": main,
                "develop_sha": fixture.develop,
            },
        )
        return result

    def exercise_order(self, sync_first, *, github_release=True):
        # The producer advisory flag does not override enforced publication.
        # Feed the real guard this receipt without changing the proven Git/PR
        # relationships used by the actual publication back-sync fixture.
        if not github_release:
            fixture = self.fixture
            graph = fixture.fixture
            graph.receipt["publication"]["github_release"] = False
            (fixture.root / "changelogs/release-preparation.json").write_text(json.dumps(graph.receipt))
            fixture.git("add", "changelogs/release-preparation.json")
            graph.prepared = graph.commit("chore(release): prepare v1.0.1", [graph.content_base])
            fixture.develop = graph.commit("Merge preparation PR", [graph.content_base, graph.prepared])
            fixture.release = graph.commit("Merge normal promotion PR", [graph.main_base, fixture.develop])
            graph.develop, graph.release = fixture.develop, fixture.release
            fixture.state.update(
                {
                    "main": fixture.release,
                    "develop": fixture.develop,
                    "proof": {"main_merge": fixture.release, "develop_merge": fixture.develop},
                }
            )
            fixture.git(
                "push",
                "-q",
                "--force",
                "origin",
                f"{fixture.release}:refs/heads/main",
                f"{fixture.develop}:refs/heads/develop",
            )
            fixture.make_tag()
        if sync_first:
            result = self.run_sync_guard(github_release=github_release)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("ORDINARY_ANCESTRY_WRITER", result.stdout)
            self.assertEqual("", self.fixture.branches())
        result, _unused = self.fixture.run_step()
        self.assertEqual(0, result.returncode, result.stderr)
        head = self.fixture.state["pull"]["head"]["sha"]
        result = self.run_sync_guard(github_release=github_release)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("ORDINARY_ANCESTRY_WRITER", result.stdout)
        self.assertEqual(head, self.fixture.state["pull"]["head"]["sha"])
        self.assertEqual("", self.fixture.git("diff", "--name-only", self.fixture.develop, head))

    def test_sync_first_leaves_one_fresh_canonical_writer(self):
        self.exercise_order(True)

    def test_publication_first_leaves_one_fresh_canonical_writer(self):
        self.exercise_order(False)

    def test_false_advisory_publication_sync_first_still_has_one_writer(self):
        self.exercise_order(True, github_release=False)

    def test_false_advisory_publication_publication_first_still_has_one_writer(self):
        self.exercise_order(False, github_release=False)

    def test_ordinary_and_legacy_keep_existing_ancestry_path(self):
        for changes in ({"ordinary": True}, {"schema": 2}):
            with self.subTest(changes=changes):
                result = self.run_sync_guard(**changes)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn("ORDINARY_ANCESTRY_WRITER", result.stdout)

    def test_shape_without_real_app_relationship_is_closed_before_any_writer(self):
        result = self.run_sync_guard(wrong_app=True)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn("ORDINARY_ANCESTRY_WRITER", result.stdout)
        self.assertEqual("", self.fixture.branches())


class LegacyPublicationReadOnlyTests(unittest.TestCase):
    def run_publication(self, name, *, present=True, legacy=True, two_stage=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            BACKSYNC.FIXTURE.install_ee_dispatcher(root)
            binary, remote = root / "bin", root / "remote"
            binary.mkdir()
            remote.mkdir()
            (root / "dist/release").mkdir(parents=True)
            (root / "incoming/candidate").mkdir(parents=True)
            (root / "incoming/candidate/collection.tar.gz").write_bytes(b"tested artifact")
            (root / "dist/release/collection.tar.gz").write_bytes(b"tested artifact")
            (root / "dist/release-notes.rst").write_text("published notes\n")
            calls = root / "calls"
            calls.write_text("")
            env = environment() | {
                "PATH": f"{binary}:{os.environ['PATH']}",
                "CALLS": str(calls),
                "REMOTE": str(remote),
                "RUNNER_TEMP": str(root),
                "GITHUB_WORKSPACE": str(root),
                "RELEASE_SHA": "a" * 40,
                "RELEASE_TAG": "v1.0.0",
                "GITHUB_REPOSITORY": REPOSITORY,
                "GH_TOKEN": "offline-read-only",
                "RELEASE_VERSION": "1.0.0",
                "CANDIDATE_NAME": "collection.tar.gz",
                "GALAXY_REQUIRED": "true",
                "SECURITY_RELEASE": "false",
                "LEGACY_NORMAL_RECHECK": str(legacy).lower(),
                "NORMAL_TWO_STAGE": str(two_stage).lower(),
            }
            script = step("collection-publish.yml", "publish", name)["run"]
            transport_prefix = 'set -euo pipefail\nif [ "${NORMAL_TWO_STAGE:-false}" = true ]; then\n'
            if script.startswith(transport_prefix):
                # This fixture executes one real branch before isolating the
                # checksum emitter. The golden-path test checks the outer
                # predicate and complete preserved Security branch separately.
                normal, retained = script[len(transport_prefix) : -len("fi\n")].split(
                    "else\n  # Preserved legacy and Security publication implementation.\n"
                )
                script = normal if two_stage else retained
            if name == "Finalize immutable release attachments and notes":
                # Exercise the actual checksum/signing shell; the following
                # Python block only renders local notes for a later step.
                script = script.split('notes_program="', 1)[0].split("python - <<'PY'\n", 1)[0]
                generated = shell(script.split('publish_identity="', 1)[0], root, env)
                self.assertEqual(0, generated.returncode, generated.stderr)
                if present:
                    shutil.copyfile(root / "dist/release/SHA256SUMS", remote / "SHA256SUMS")
                    (remote / "SHA256SUMS.sigstore.json").write_text("existing bundle")
            elif name == "Attach signed post-publication verification receipt":
                # Generate the existing historical receipt with the actual
                # payload emitter, then make only the remote pair available.
                prefix = script.split('receipt="$receipt_root/post-release-verification.json"', 1)[0]
                generated = shell(prefix, root, env)
                self.assertEqual(0, generated.returncode, generated.stderr)
                if present:
                    shutil.copyfile(
                        root / "dist/post-release/post-release-verification.json",
                        remote / "post-release-verification.json",
                    )
                    (remote / "post-release-verification.json.sigstore.json").write_text("existing bundle")
            elif present:
                shutil.copyfile(root / "dist/release/collection.tar.gz", remote / "collection.tar.gz")
            gh = binary / "gh"
            gh.write_text(
                "#!"
                + sys.executable
                + "\n"
                + r"""
import json,os,shutil,sys
from pathlib import Path
args=sys.argv[1:]; remote=Path(os.environ['REMOTE'])
with Path(os.environ['CALLS']).open('a') as stream: stream.write(json.dumps(['gh',*args])+'\n')
if args[:2]==['release','view']:
    if '--json' not in args: raise SystemExit(0)
    fields=args[args.index('--json')+1]
    if fields!='assets':
        print(json.dumps({'body':'published notes','isDraft':False,'isPrerelease':False,
                          'name':'v1.0.0','tagName':'v1.0.0'}))
    else:
        assets=[{'name':p.name} for p in sorted(remote.iterdir())]
        if '--jq' not in args: print(json.dumps({'assets':assets}))
        else:
            query=args[args.index('--jq')+1]
            if '| length' in query: print(sum(p['name'].startswith('post-release-') for p in assets))
            else:
                for p in assets:
                    if 'select(' not in query or not p['name'].startswith('post-release-'): print(p['name'])
elif args[:2]==['release','download']:
    target=Path(args[args.index('--dir')+1])
    for index,arg in enumerate(args):
        if arg=='--pattern': shutil.copyfile(remote/args[index+1],target/args[index+1])
elif args[:2]==['release','upload']:
    for name in args[3:args.index('--repo')]: shutil.copyfile(name,remote/Path(name).name)
else: raise SystemExit('unexpected fixture command')
"""
            )
            gh.chmod(0o700)
            curl = binary / "curl"
            curl.write_text(
                "#!"
                + sys.executable
                + "\n"
                + r"""
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['CALLS']).open('a') as stream: stream.write(json.dumps(['curl',*args])+'\n')
assert '--request' not in args and '-X' not in args
Path(args[args.index('--output')+1]).write_text(json.dumps(
    {'assets':[{'name':p.name} for p in Path(os.environ['REMOTE']).iterdir()]}))
print('200')
"""
            )
            curl.chmod(0o700)
            cosign = binary / "cosign"
            cosign.write_text(
                "#!"
                + sys.executable
                + "\n"
                + r"""
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['CALLS']).open('a') as stream: stream.write(json.dumps(['cosign',*args])+'\n')
if args[0]=='sign-blob': Path(args[args.index('--bundle')+1]).write_text('new bundle')
elif args[0]!='verify-blob': raise SystemExit('unexpected cosign operation')
"""
            )
            cosign.chmod(0o700)
            git = binary / "git"
            git.write_text("#!/bin/sh\nprintf '%s\\trefs/heads/main\\n' \"$RELEASE_SHA\"\n")
            git.chmod(0o700)
            result = shell(script, root, env)
            return result, [json.loads(line) for line in calls.read_text().splitlines()]

    def test_legacy_missing_assets_and_receipts_fail_without_publication_writes(self):
        for name in (
            "Finalize immutable release attachments and notes",
            "Create or verify GitHub Release and immutable assets",
            "Attach signed post-publication verification receipt",
        ):
            with self.subTest(step=name):
                result, calls = self.run_publication(name, present=False)
                writes = [
                    call
                    for call in calls
                    if call[:2] == ["cosign", "sign-blob"] or call[:3] == ["gh", "release", "upload"]
                ]
                self.assertEqual([], writes)
                self.assertNotEqual(0, result.returncode)

    def test_existing_legacy_assets_and_signed_receipts_are_verified_without_replacement(self):
        for name in (
            "Finalize immutable release attachments and notes",
            "Create or verify GitHub Release and immutable assets",
            "Attach signed post-publication verification receipt",
        ):
            with self.subTest(step=name):
                result, calls = self.run_publication(name)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(any(call[:3] == ["gh", "release", "download"] for call in calls))
                self.assertFalse(
                    any(
                        call[:2] == ["cosign", "sign-blob"] or call[:3] == ["gh", "release", "upload"] for call in calls
                    )
                )

    def test_legacy_recheck_neither_mints_nor_dispatches_backsync(self):
        for name in ("Mint exact back-sync dispatch App token", "Trigger release back-sync after verified publication"):
            condition = step("collection-publish.yml", "publish", name)["if"]
            self.assertIn("env.LEGACY_NORMAL_RECHECK != 'true'", condition)
            # These comparisons/operators have the same string/boolean
            # semantics in the job predicate and the offline shell harness.
            condition = re.sub(r"env\.([A-Z_]+)", r'"$\1"', condition)
            for security, galaxy, legacy in (
                ("false", "true", "true"),
                ("false", "true", "false"),
                ("true", "true", "false"),
                ("true", "false", "false"),
            ):
                result = shell(
                    f"if [[ {condition} ]]; then echo EFFECT_ENABLED; fi",
                    ROOT,
                    environment()
                    | {"SECURITY_RELEASE": security, "GALAXY_REQUIRED": galaxy, "LEGACY_NORMAL_RECHECK": legacy},
                )
                self.assertEqual(0, result.returncode, result.stderr)
                enabled = legacy != "true" and (security != "true" or galaxy != "true")
                self.assertEqual(enabled, "EFFECT_ENABLED" in result.stdout)

    def test_current_publication_keeps_its_existing_signing_and_upload_effects(self):
        for name in (
            "Finalize immutable release attachments and notes",
            "Create or verify GitHub Release and immutable assets",
            "Attach signed post-publication verification receipt",
        ):
            with self.subTest(step=name):
                result, calls = self.run_publication(name, present=False, legacy=False)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(
                    any(
                        call[:2] == ["cosign", "sign-blob"] or call[:3] == ["gh", "release", "upload"] for call in calls
                    )
                )

    def test_normal_ee_transport_preserves_existing_assets_and_rejects_missing_legacy_evidence(self):
        for name in (
            "Finalize immutable release attachments and notes",
            "Create or verify GitHub Release and immutable assets",
        ):
            for present, legacy in ((True, True), (False, True), (False, False)):
                with self.subTest(step=name, present=present, legacy=legacy):
                    result, calls = self.run_publication(name, present=present, legacy=legacy, two_stage=True)
                    writes = [
                        call
                        for call in calls
                        if call[:2] == ["cosign", "sign-blob"] or call[:3] == ["gh", "release", "upload"]
                    ]
                    if not present and legacy:
                        self.assertNotEqual(0, result.returncode)
                        self.assertEqual([], writes)
                    else:
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual(not present, bool(writes))


class NormalPreparationEnvironmentTests(unittest.TestCase):
    """Actual workflow operations use the installed release toolchain.

    The fixture substitutes only the outer container mount/launch, because an
    offline EE cannot and must not receive a Docker socket for nested launches.
    Hosted unit tests install the same changelog-tool version explicitly.
    """

    def fixture(self, directory):
        root = Path(directory) / "repository"
        root.mkdir()
        (root / "scripts").mkdir()
        for name in (
            "release-version.py",
            "security_release_contract.py",
            "normal_release_environment.sh",
            "normal_release_proof.py",
            "normal_release_archive.py",
            "security_main_promotion.py",
        ):
            shutil.copyfile(ROOT / "scripts" / name, root / "scripts" / name)
        launcher = root / "scripts/wunder-devtools-ee.sh"
        launcher.write_text(
            "#!/bin/bash\nset -euo pipefail\n"
            'test "$WUNDER_DEVTOOLS_WORKSPACE_MODE" = rw\n'
            'test "$WUNDER_DEVTOOLS_RUN_AS_HOST_UID" = 1\n'
            'test "$1" = bash && test "$2" = -c\n'
            'program="${3//\\/workspace/$PWD}"\nshift 3\n'
            'exec env -i PATH="$PATH" HOME="$HOME" bash -c "$program" "$@"\n'
        )
        (root / "changelogs/fragments").mkdir(parents=True)
        (root / "changelogs/fragments/.gitkeep").write_text("")
        (root / "galaxy.yml").write_text(
            "namespace: lit\nname: supplementary\nversion: 1.0.0\n"
            "readme: README.md\nauthors: [Fixture]\nlicense: [MIT]\ndependencies: {}\n"
        )
        (root / "README.md").write_text("Fixture\n")
        (root / "CHANGELOG.rst").write_text("Initial\n=======\n")
        (root / "changelogs/changelog.yaml").write_text("releases: {}\n")
        (root / "changelogs/.plugin-cache.yaml").write_text("version: 1.0.0\nplugins: {}\nobjects: {}\n")
        shutil.copyfile(ROOT / "changelogs/config.yaml", root / "changelogs/config.yaml")
        (root / "meta").mkdir()
        (root / "meta/runtime.yml").write_text("requires_ansible: '>=2.18.0'\n")
        env = environment() | {
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GITHUB_WORKSPACE": str(root),
            "RUNNER_TEMP": str(Path(directory) / "runner"),
            "workflow_source": str(root),
            "SECURITY_RELEASE": "false",
            "VERSION": "",
            "VERSION_INPUT": "",
            "CREATE_GITHUB_RELEASE": "true",
            "PUBLISH_GALAXY": "true",
            "GITHUB_REPOSITORY": REPOSITORY,
            "REPOSITORY_ID": "1103407173",
            "GITHUB_RUN_ID": "42",
            "GITHUB_RUN_ATTEMPT": "1",
            "WORKFLOW_EVENT": "workflow_dispatch",
            "WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/release-prepare.yml@refs/heads/main",
            "WORKFLOW_ACTOR": "fixture",
            "GH_TOKEN": "must-never-enter-the-environment",
        }
        Path(env["RUNNER_TEMP"]).mkdir()
        git = ["/usr/bin/git", "-C", str(root)]
        for arguments in (("init", "-q"), ("add", "."), ("commit", "-qm", "Main tooling")):
            subprocess.run(git + list(arguments), env=env, check=True, capture_output=True)  # noqa: S603
        env["WORKFLOW_SOURCE_SHA"] = subprocess.check_output(git + ["rev-parse", "HEAD"], env=env, text=True).strip()  # noqa: S603
        (root / "changelogs/fragments/change.yml").write_text("bugfixes:\n  - Reviewed change.\n")
        (root / "yaml.py").write_text("raise RuntimeError('Develop shadow executed')\n")
        (root / "scripts/normal_release_environment.sh").write_text("touch candidate-helper-executed\nexit 91\n")
        for arguments in (("add", "."), ("commit", "-qm", "Develop product")):
            subprocess.run(git + list(arguments), env=env, check=True, capture_output=True)  # noqa: S603
        env["BASE_SHA"] = subprocess.check_output(git + ["rev-parse", "HEAD"], env=env, text=True).strip()  # noqa: S603
        script = step("release-prepare.yml", "prepare", "Prepare release branch")["run"]
        transport = script.split("# LI-360 normal EE transport:start\n", 1)[1].split(
            "# LI-360 normal EE transport:end", 1
        )[0]
        return root, env, script, transport

    def test_real_generation_and_build_use_main_tooling_and_no_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env, script, transport = self.fixture(directory)

            def operation(name):
                source = (
                    (ROOT / "scripts/normal_release_environment.sh").read_text() if name == "RELEASE_INPUTS" else script
                )
                return source.split(f"<<'{name}'\n", 1)[1].split(f"\n{name}\n", 1)[0]

            actual = transport + "\nrelease_data <<'CHECK'\n" + operation("RELEASE_INPUTS") + "\nCHECK\n"
            actual += "resolution=$(release_data <<'VERSION_OP'\n" + operation("RELEASE_VERSION") + "\nVERSION_OP\n)\n"
            actual += 'VERSION=$(jq -er .version <<<"$resolution")\nPREPARATION_MODE=normal\n'
            actual += "release_data <<'GENERATE_OP'\n" + operation("RELEASE_GENERATE") + "\nGENERATE_OP\n"
            actual += "release_data <<'BUILD_OP'\n" + operation("RELEASE_BUILD") + "\nBUILD_OP\n"
            actual += "release_data <<'BOUNDARY'\n"
            actual += 'test -z "${GH_TOKEN:-}"\ntest -z "${GITHUB_TOKEN:-}"\n'
            actual += 'test -f yaml.py\ntest ! -e "$workflow_source/yaml.py"\nBOUNDARY\n'
            result = shell(actual, root, env)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            self.assertIn("version: 1.0.1", (root / "galaxy.yml").read_text())
            self.assertFalse((root / "changelogs/fragments/change.yml").exists())
            self.assertTrue((root / "lit-supplementary-1.0.1.tar.gz").is_file())
            self.assertFalse((root / "candidate-helper-executed").exists())
            self.assertIn("Develop shadow executed", (root / "yaml.py").read_text())
            context = Path(env["RUNNER_TEMP"]) / "normal-release-ee/context.sh"
            self.assertNotIn(env["GH_TOKEN"], context.read_text())

    def test_failed_environment_in_command_substitution_cannot_return_output_or_copy_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env, _script, transport = self.fixture(directory)
            before = (root / "galaxy.yml").read_bytes()
            actual = transport + "\nresolution=$(release_data <<'FAIL'\n"
            actual += "printf 'version: 999.0.0\\n' >galaxy.yml\nexit 23\nFAIL\n)\n"
            actual += "touch forbidden-acceptance\n"
            result = shell(actual, root, env)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((root / "forbidden-acceptance").exists())
            self.assertEqual(before, (root / "galaxy.yml").read_bytes())

    def test_generation_commit_to_proof_uses_clean_prepared_data_view(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env, script, transport = self.fixture(directory)

            def operation(name):
                return script.split(f"<<'{name}'\n", 1)[1].split(f"\n{name}\n", 1)[0]

            actual = transport + "\nresolution=$(release_data <<'VERSION_OP'\n"
            actual += operation("RELEASE_VERSION") + "\nVERSION_OP\n)\n"
            actual += 'VERSION=$(jq -er .version <<<"$resolution")\nPREPARATION_MODE=normal\n'
            for name in ("RELEASE_GENERATE", "RELEASE_BUILD"):
                actual += "release_data <<'NEXT_OP'\n" + operation(name) + "\nNEXT_OP\n"
            actual += "git add galaxy.yml changelogs CHANGELOG.rst\n"
            actual += 'GIT_AUTHOR_NAME="lightning-it-release-automation[bot]" '
            actual += 'GIT_AUTHOR_EMAIL="307565056+lightning-it-release-automation[bot]@users.noreply.github.com" '
            actual += 'GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL" '
            actual += 'git commit -qm "chore(release): prepare v${VERSION}"\n'
            actual += 'pushed_sha=$(git rev-parse HEAD)\nprintf "preserve\\n" >host-untracked-work\n'
            start = script.index('git -C "$normal_ee_space/data" fetch')
            end = script.index("release_data <<'RELEASE_PREPARATION_PROOF'", start)
            actual += script[start:end]
            actual += "release_data <<'ACTUAL_PREPARATION_PROOF'\n"
            actual += operation("RELEASE_PREPARATION_PROOF") + "\nACTUAL_PREPARATION_PROOF\n"
            # Also assert the proof saw the committed clean data view and did
            # not modify host work or execute the candidate's helper/shadow.
            actual += "release_data <<'CHECK_PREPARED_PROOF_VIEW'\n"
            actual += 'test "$(git rev-parse HEAD)" = "$pushed_sha"\n'
            actual += 'test -z "$(git status --porcelain)"\n'
            actual += 'git show HEAD:changelogs/release-preparation.json >"$RUNNER_TEMP/committed-receipt.json"\n'
            actual += 'cmp changelogs/release-preparation.json "$RUNNER_TEMP/committed-receipt.json"\n'
            actual += 'test "$(jq -er .next_version changelogs/release-preparation.json)" = "$VERSION"\n'
            actual += 'test -z "${GH_TOKEN:-}" && test -z "${GITHUB_TOKEN:-}"\n'
            actual += "CHECK_PREPARED_PROOF_VIEW\n"
            result = shell(actual, root, env)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            self.assertEqual("preserve\n", (root / "host-untracked-work").read_text())
            self.assertFalse((root / "candidate-helper-executed").exists())
            self.assertIn("Develop shadow executed", (root / "yaml.py").read_text())

    def test_explicit_normal_version_must_still_equal_reviewed_fragment_impact(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env, script, transport = self.fixture(directory)
            operation = script.split("<<'RELEASE_VERSION'\n", 1)[1].split("\nRELEASE_VERSION\n", 1)[0]
            actual = transport + "\nresolution=$(release_data --requested-version 1.0.2 <<'VERSION_OP'\n"
            actual += operation + "\nVERSION_OP\n)\ntouch forbidden-acceptance\n"
            result = shell(actual, root, env)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((root / "forbidden-acceptance").exists())
            self.assertIn("version", result.stderr)
            self.assertNotIn("version: 1.0.2", (root / "galaxy.yml").read_text())
