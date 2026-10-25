"""Actual two-stage Git topology, native proof drift and workflow wiring tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("normal_release_proof", ROOT / "scripts/normal_release_proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)
REPOSITORY = "lightning-it/ansible-collection-supplementary"
REAL_VERIFY_COMPLETION = getattr(PROOF.archive, "verify_completion", None)


def install_ee_dispatcher(root, prefix=""):
    """Substitute the outer mount only; fixture commands already run inside EE.

    Native I/O seams are explicit fixture prefixes. This never qualifies an
    image, network access, production identity or protected check.
    """
    scripts = root / "scripts"
    scripts.mkdir(exist_ok=True)
    (scripts / "wunder-devtools-ee.sh").write_text(
        "#!/bin/bash\nset -euo pipefail\n" + prefix + "\n"
        "unset GH_TOKEN GITHUB_TOKEN\n"
        'if [ "${1:-}" = bash ] && [ "${2:-}" = -c ]; then\n'
        '  program="${3//\\/workspace/$PWD}"\nshift 3\n'
        '  exec bash -c "$program" "$@"\n'
        "fi\n"
        'arguments=()\nfor argument; do arguments+=("${argument//\\/workspace/$PWD}"); done\n'
        'exec "${arguments[@]}"\n'
    )


class NativeControlPolicyContractTests(unittest.TestCase):
    def test_actual_adopted_producer_is_accepted_by_real_pinned_source(self):
        # Qualification loads the immutable donor checkout, never a mocked policy
        # or an inferred Git ancestry list. Generic source-only clones may omit
        # the separately staged offline fixture; that is not qualification.
        directory = Path(os.environ.get("LIT_RELEASE_CONTROL_FIXTURE", ROOT / ".cache/release-control-source"))
        if not directory.is_dir():
            self.skipTest("immutable offline native-control fixture not staged; qualification not executed")
        previous = sys.modules.pop("workflow_control", None)
        try:
            core = PROOF.load_control(directory)
            self.assertEqual((directory / "scripts/workflow_control.py").resolve(), Path(core.__file__).resolve())
            producer = "bb1a5df9f54c5f98547048297e7e367cc382543e"
            unknown = "0" * 40
            protected = json.loads((ROOT / ".lit/workflow-control.json").read_text())
            lineage = json.loads((directory / ".lit/workflow-source-lineage.json").read_text())
            self.assertNotIn(producer, lineage["accepted_predecessors"])
            self.assertNotIn(unknown, lineage["accepted_predecessors"])
            api = Mock()
            api.file.return_value = json.dumps(protected).encode()
            config = core.policy(api, REPOSITORY, "a" * 40, PROOF.CONTROL_SOURCE)
            api.file.assert_called_once_with(REPOSITORY, ".lit/workflow-control.json", "a" * 40)
            self.assertIn(producer, config["accepted_sources"])
            self.assertNotIn(unknown, config["accepted_sources"])
            self.assertEqual({producer, *lineage["accepted_predecessors"]}, set(config["accepted_sources"]))
            old_reader = core.policy(api, REPOSITORY, "a" * 40, "f263bac1a19c7b7a0f727e744c35360666925820")
            self.assertNotIn(producer, old_reader["accepted_sources"])
            protected["accepted_sources"] = [unknown]
            api.file.return_value = json.dumps(protected).encode()
            with self.assertRaisesRegex(core.ControlError, "consumer-cannot-admit-central-source"):
                core.policy(api, REPOSITORY, "a" * 40, PROOF.CONTROL_SOURCE)
            # The existing publisher pins the exact same defining source.
            workflow = yaml.safe_load((ROOT / ".github/workflows/collection-publish.yml").read_text())
            checkout = next(
                step
                for step in workflow["jobs"]["publish"]["steps"]
                if step.get("name") == "Checkout immutable public native-control verifier"
            )
            self.assertEqual(producer, checkout["with"]["ref"])
        finally:
            sys.modules.pop("workflow_control", None)
            if previous is not None:
                sys.modules["workflow_control"] = previous


class NormalReleaseProofTests(unittest.TestCase):
    def git(self, *args):
        executable = shutil.which("git")
        assert executable
        return (
            subprocess.check_output(  # noqa: S603 -- local isolated Git fixture.
                [executable, *args],
                cwd=self.root,
                env=self.git_env,
            )
            .decode()
            .strip()
        )

    def commit(self, message, parents):
        args = ["commit-tree", self.git("write-tree"), "-m", message]
        for parent in parents:
            args += ["-p", parent]
        return self.git(*args)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git_env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": PROOF.APP[0],
            "GIT_AUTHOR_EMAIL": PROOF.git_contract.CONTRACT.RELEASE_APP_EMAIL,
            "GIT_COMMITTER_NAME": PROOF.APP[0],
            "GIT_COMMITTER_EMAIL": PROOF.git_contract.CONTRACT.RELEASE_APP_EMAIL,
        }
        for variable in ("GIT_COMMON_DIR", "GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"):
            self.git_env.pop(variable, None)
        self.git("init", "--quiet")
        (self.root / "galaxy.yml").write_text("---\nnamespace: lit\nname: supplementary\nversion: 1.0.0\n")
        (self.root / ".lit").mkdir()
        (self.root / ".lit/repository.yml").write_text(
            "publishing_targets: [github-release, ansible-galaxy]\ngalaxy_publish: true\n"
        )
        for name, content in getattr(self, "extra_baseline", {}).items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        for name in ("CHANGELOG.rst", "changelogs/changelog.yaml", "changelogs/.plugin-cache.yaml"):
            path = self.root / name
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("generated state\n")
        self.git("add", ".")
        self.main_base = self.commit("protected Main workflow source", [])
        self.git("checkout", "--quiet", "--detach", self.main_base)
        fragments = self.root / "changelogs/fragments"
        fragments.mkdir(parents=True)
        (fragments / "change.yml").write_text("---\nbugfixes:\n  - Reviewed change.\n")
        self.git("add", ".")
        self.content_base = self.commit("reviewed content ingress", [self.main_base])
        self.git("checkout", "--quiet", "--detach", self.content_base)
        version = PROOF.version_module()
        resolution = version.resolve_version(self.root / "galaxy.yml", fragments)
        self.receipt = version.build_preparation_receipt(
            resolution,
            repository=REPOSITORY,
            repository_id="1103407173",
            base_sha=self.content_base,
            workflow_run_id="10",
            workflow_attempt="1",
            workflow_ref=f"{REPOSITORY}/.github/workflows/release-prepare.yml@refs/heads/main",
            workflow_event="workflow_dispatch",
            workflow_actor="litroc",
            workflow_source_sha=self.main_base,
            root=self.root,
        )
        (self.root / PROOF.RECEIPT).write_bytes(PROOF.git_contract.CONTRACT.canonical_document_bytes(self.receipt))
        (self.root / "galaxy.yml").write_text("---\nnamespace: lit\nname: supplementary\nversion: 1.0.1\n")
        (fragments / "change.yml").unlink()
        self.git("add", "-A")
        self.prepared = self.commit("chore(release): prepare v1.0.1", [self.content_base])
        self.develop = self.commit("Merge preparation PR", [self.content_base, self.prepared])
        self.release = self.commit("Merge normal promotion PR", [self.main_base, self.develop])
        self.git("checkout", "--quiet", "--detach", self.release)
        self.prep = self.pull(1, self.develop, "develop", "release/v1.0.1", self.content_base, self.prepared)
        self.promotion = self.pull(2, self.release, "main", "develop", self.main_base, self.develop)
        self.ingress = {
            "run": 20,
            "attempt": 1,
            "job": 21,
            "head": self.prepared,
            "source_sha": PROOF.CONTROL_SOURCE,
            "route": "codex",
            "artifact": "control-proof-1",
            "proof_sha256": "a" * 64,
        }
        self.run = {
            "id": 30,
            "run_attempt": 1,
            "head_sha": self.develop,
            "status": "completed",
            "conclusion": "success",
            "workflow_id": 123,
            "workflow_url": "native-required",
            "path": "required",
        }
        self.proof = {
            "version": 1,
            "source_sha": PROOF.CONTROL_SOURCE,
            "route": "promotion",
            "binding": {"head": self.develop},
            "authorization": {"run": 30, "approval": {"user": "litroc"}},
            "evidence": {
                "base": self.main_base,
                "head": self.develop,
                "integration_tree": self.git("rev-parse", f"{self.release}^{{tree}}"),
                "ingress": [{"pull": 1, "merge": self.develop, "control": self.ingress}],
            },
        }
        self.api = Mock()
        self.api.pages.side_effect = self.pages
        self.api.call.side_effect = self.call
        self.core = Mock()
        self.core.policy.return_value = {"accepted_sources": [PROOF.CONTROL_SOURCE]}
        self.core.check_native_control.return_value = self.ingress
        self.core.ingress_candidates.return_value = [self.run]
        self.core.native_jobs.return_value = [{"name": "Current revision review", "conclusion": "success"}]
        self.core.artifact_record.return_value = self.proof
        self.core.binding.side_effect = lambda p: {"head": p["head"]["sha"]}
        self.core.operation_record.return_value = {"binding": {"head": self.develop}}
        self.core.same_immutable_tuple.side_effect = lambda a, b: a == b
        self.core.native_required.return_value = True
        self.core.native_approval.return_value = {"user": "litroc"}
        self.core.digest.side_effect = lambda p: hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest()

    def pull(self, number, merge, base_ref, head_ref, base, head):
        return {
            "number": number,
            "state": "closed",
            "draft": False,
            "merged": True,
            "merged_at": "2026-10-18T00:00:00Z",
            "merge_commit_sha": merge,
            "user": dict(zip(("login", "id", "type"), PROOF.APP, strict=True)),
            "base": {"ref": base_ref, "sha": base, "repo": {"full_name": REPOSITORY}},
            "head": {"ref": head_ref, "sha": head, "repo": {"full_name": REPOSITORY}},
        }

    def pages(self, path, key=None):
        if f"commits/{self.develop}/pulls" in path:
            return [self.prep]
        if f"commits/{self.release}/pulls" in path:
            return [self.promotion]
        if "actions/runs?" in path:
            return [self.run]
        if path.endswith("/artifacts"):
            return [
                {
                    "id": 31,
                    "name": "control-proof-1",
                    "expired": False,
                    "size_in_bytes": 100,
                    "digest": "sha256:" + "b" * 64,
                }
            ]
        raise AssertionError(path)

    def call(self, path):
        if path.endswith("pulls/1"):
            return self.prep
        if path.endswith("pulls/2"):
            return self.promotion
        if path.endswith("actions/runs/30"):
            return self.run
        if path.endswith("actions/runs/10"):
            return {
                "id": 10,
                "run_attempt": 1,
                "repository": {"full_name": REPOSITORY},
                "head_repository": {"full_name": REPOSITORY},
                "head_sha": self.main_base,
                "head_branch": "main",
                "path": ".github/workflows/release-prepare.yml",
                "event": "workflow_dispatch",
                "actor": {"login": "litroc"},
                "status": "completed",
                "conclusion": "success",
            }
        if path.endswith("git/ref/heads/main"):
            return {"object": {"sha": self.release}}
        raise AssertionError(path)

    def promotion_ready(self):
        previous = self.api.call.side_effect

        def current(path):
            if path == f"repos/{REPOSITORY}":
                return {"id": 1103407173, "full_name": REPOSITORY, "archived": False, "disabled": False}
            if path.endswith("git/ref/heads/main"):
                return {"object": {"sha": getattr(self, "live_main_tip", self.main_base)}}
            if path.endswith("git/ref/heads/develop"):
                return {"object": {"sha": getattr(self, "live_develop_tip", self.develop)}}
            result = previous(path)
            if path.endswith("actions/runs/10"):
                result.update(getattr(self, "preparation_run_override", {}))
            return result

        self.api.call.side_effect = current
        return PROOF.promotion_ready(
            self.root, self.api, self.core, REPOSITORY, "1103407173", self.main_base, self.develop
        )

    def test_pre_promotion_accepts_only_genuine_reviewed_preparation(self):
        result = self.promotion_ready()
        self.assertEqual(result["preparation_pr"], 1)
        self.assertEqual(result["prepared_head"], self.prepared)
        self.assertEqual(result["next_version"], "1.0.1")
        self.core.policy.assert_called_once_with(self.api, REPOSITORY, self.main_base, PROOF.CONTROL_SOURCE)
        self.core.check_native_control.assert_called_once_with(
            self.api, REPOSITORY, self.prep, self.core.policy.return_value
        )

    def test_pre_promotion_rejects_other_native_route(self):
        self.ingress["route"] = "ancestry"
        with self.assertRaisesRegex(ValueError, "genuine-app-ingress-review-required"):
            self.promotion_ready()

    def test_pre_promotion_rejects_unreviewed_or_foreign_app_ingress(self):
        self.prep["user"]["id"] = 1
        with self.assertRaisesRegex(ValueError, "release-app-pr-required"):
            self.promotion_ready()

    def test_pre_promotion_rejects_missing_native_ingress(self):
        self.core.check_native_control.side_effect = ValueError("native-control-missing")
        with self.assertRaisesRegex(ValueError, "native-control-missing"):
            self.promotion_ready()

    def test_pre_promotion_rejects_native_head_or_source_drift(self):
        for change in ({"head": "0" * 40}, {"source_sha": "0" * 40}):
            with self.subTest(change=change):
                original = self.ingress.copy()
                self.ingress.update(change)
                with self.assertRaisesRegex(ValueError, "preparation-native-control-drift"):
                    self.promotion_ready()
                self.ingress.clear()
                self.ingress.update(original)

    def test_pre_promotion_rejects_wrong_protected_preparer_generation(self):
        for change in (
            {"head_sha": "0" * 40},
            {"run_attempt": 2},
            {"conclusion": "failure"},
            {"head_repository": {"full_name": "elsewhere/fork"}},
        ):
            with self.subTest(change=change):
                self.preparation_run_override = change
                with self.assertRaisesRegex(ValueError, "protected-main-preparation-run-required"):
                    self.promotion_ready()

    def test_pre_promotion_rejects_nonidentical_merge_tree(self):
        self.git("checkout", "--quiet", "--detach", self.develop)
        (self.root / "unrelated-product.txt").write_text("extra merge delta\n")
        self.git("add", ".")
        self.develop = self.commit("drifting preparation merge", [self.content_base, self.prepared])
        with self.assertRaisesRegex(ValueError, "preparation-ingress-tree-drift"):
            self.promotion_ready()

    def test_pre_promotion_rechecks_both_current_protected_tips(self):
        for field, message in (
            ("live_main_tip", "protected-main-tip-drift"),
            ("live_develop_tip", "protected-develop-tip-drift"),
        ):
            with self.subTest(field=field):
                setattr(self, field, "0" * 40)
                with self.assertRaisesRegex(ValueError, message):
                    self.promotion_ready()
                delattr(self, field)

    def test_pre_promotion_rejects_extra_commit_after_preparation(self):
        self.git("checkout", "--quiet", "--detach", self.develop)
        self.develop = self.commit("unreviewed subsequent Develop delta", [self.develop])
        with self.assertRaisesRegex(ValueError, "exact-preparation-ingress-parents-required"):
            self.promotion_ready()

    def baseline_api(self, current_main):
        # These unit fixtures mock crypto separately from replay semantics.
        # Dedicated archive tests verify the exact gh verification boundary.
        checkout = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "--detach", self.release)

        def original_record(api, repository, run, _name, _filename):
            api.pages(f"repos/{repository}/actions/runs/{run['id']}/artifacts", "artifacts")
            return copy.deepcopy(self.proof)

        self.core.artifact_record.side_effect = original_record
        snapshot = self.root / "snapshot.json"
        PROOF.publish_snapshot(
            self.root,
            self.api,
            self.core,
            REPOSITORY,
            "1103407173",
            self.release,
            self.main_base,
            self.develop,
            snapshot,
        )
        self.snapshot_bytes = snapshot.read_bytes()
        snapshot.unlink()
        self.git("checkout", "--quiet", "--detach", checkout)

        def download(_published, _repository, directory):
            (directory / PROOF.archive.SNAPSHOT).write_bytes(self.snapshot_bytes)
            (directory / PROOF.archive.BUNDLE).write_text("unit-crypto-fixture")

        download_patch = patch.object(PROOF.archive, "download_pair", side_effect=download)
        verify_patch = patch.object(
            PROOF.archive,
            "verify_files",
            side_effect=lambda snapshot, *_args: PROOF.archive.decode(snapshot.read_bytes()),
        )
        download_patch.start()
        verify_patch.start()
        self.addCleanup(download_patch.stop)
        self.addCleanup(verify_patch.stop)
        self.api.reset_mock()
        self.core.artifact_record.reset_mock()
        previous = self.call
        self.git("tag", "-a", "-m", "published normal version", "v1.0.1", self.release)
        self.tag_ref = {
            "ref": "refs/tags/v1.0.1",
            "object": {"type": "tag", "sha": self.git("rev-parse", "refs/tags/v1.0.1")},
        }
        self.tag_object = {"tag": "v1.0.1", "object": {"type": "commit", "sha": self.release}}
        self.published_release = {
            "id": 40,
            "tag_name": "v1.0.1",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-10-18T00:00:00Z",
            "target_commitish": "develop",
        }

        def read(path):
            if path.endswith("git/ref/heads/main"):
                return {"object": {"sha": current_main}}
            if path.endswith("git/ref/tags/v1.0.1"):
                return self.tag_ref
            if f"git/tags/{self.tag_ref['object']['sha']}" in path:
                return self.tag_object
            if path.endswith("releases/tags/v1.0.1"):
                return self.published_release
            return previous(path)

        self.api.call.side_effect = read
        # These tests isolate historical replay; completion crypto/manifest has
        # its own actual reader tests. The interruption regression removes this seam.
        if REAL_VERIFY_COMPLETION is not None:
            completion_patch = patch.object(PROOF.archive, "verify_completion", return_value={"fixture": "completed"})
            completion_patch.start()
            self.addCleanup(completion_patch.stop)

    def test_interrupted_pair_upload_denies_baseline_but_preserves_original_recovery_pair(self):
        self.baseline_api(self.release)
        original_pages = self.api.pages.side_effect
        self.api.pages.side_effect = lambda path, key=None: (
            [self.published_release] if path.endswith("/releases") else original_pages(path, key)
        )
        # Exactly the failure boundary in the native finding: authentic pair,
        # but no mandatory publication assets or completion receipt.
        self.published_release["assets"] = [
            {"id": 70, "name": PROOF.archive.SNAPSHOT, "state": "uploaded", "size": 100},
            {"id": 71, "name": PROOF.archive.BUNDLE, "state": "uploaded", "size": 100},
        ]
        if REAL_VERIFY_COMPLETION is None:
            with self.assertRaises(ValueError):
                PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)
        else:
            with patch.object(PROOF.archive, "verify_completion", side_effect=REAL_VERIFY_COMPLETION):
                with self.assertRaisesRegex(ValueError, "completion-mandatory-assets"):
                    PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)
        self.core.artifact_record.side_effect = AssertionError("expired original artifact must not be downloaded")
        directory = self.root / "recovery-original-pair"
        result = PROOF.publication_archive(
            self.root,
            self.api,
            self.core,
            REPOSITORY,
            "1103407173",
            self.release,
            self.main_base,
            self.develop,
            directory,
        )
        self.assertTrue(result["archive_reused"])
        self.assertEqual(self.snapshot_bytes, (directory / PROOF.archive.SNAPSHOT).read_bytes())
        self.assertEqual("unit-crypto-fixture", (directory / PROOF.archive.BUNDLE).read_text())
        self.core.artifact_record.assert_not_called()

    def ordinary_main(self, previous_main, previous_develop, number):
        self.git("checkout", "--quiet", "--detach", previous_main)
        backmerge = self.commit("canonical unchanged-tree ancestry", [previous_develop, previous_main])
        (self.root / f"ordinary-{number}.txt").write_text("ordinary reviewed product work\n")
        self.git("add", ".")
        feature = self.commit("ordinary product change", [backmerge])
        develop = self.commit("ordinary product ingress", [backmerge, feature])
        main = self.commit("ordinary product promotion", [previous_main, develop])
        self.git("checkout", "--quiet", "--detach", main)
        return main, develop

    def test_publication_archive_reuses_complete_verified_pair_without_original_actions(self):
        self.baseline_api(self.release)
        original_pages = self.api.pages.side_effect
        self.api.pages.side_effect = lambda path, key=None: (
            [self.published_release] if path.endswith("/releases") else original_pages(path, key)
        )
        self.core.artifact_record.side_effect = AssertionError("expired original Actions must not execute")
        directory = self.root / "archived-pair"
        result = PROOF.publication_archive(
            self.root,
            self.api,
            self.core,
            REPOSITORY,
            "1103407173",
            self.release,
            self.main_base,
            self.develop,
            directory,
        )
        self.assertTrue(result["archive_reused"])
        self.assertEqual(self.snapshot_bytes, (directory / PROOF.archive.SNAPSHOT).read_bytes())
        self.assertEqual(b"unit-crypto-fixture", (directory / PROOF.archive.BUNDLE).read_bytes())
        self.core.artifact_record.assert_not_called()

    def test_existing_partial_pair_never_falls_back_to_new_live_snapshot(self):
        self.baseline_api(self.release)
        self.api.pages.return_value = [self.published_release]
        self.api.pages.side_effect = None
        with (
            patch.object(PROOF.archive, "download_pair", side_effect=ValueError("archive-pair-missing")),
            patch.object(PROOF, "publish_snapshot") as new,
            self.assertRaisesRegex(ValueError, "archive-pair-missing"),
        ):
            PROOF.publication_archive(
                self.root,
                self.api,
                self.core,
                REPOSITORY,
                "1103407173",
                self.release,
                self.main_base,
                self.develop,
                self.root / "partial-pair",
            )
        new.assert_not_called()

    def test_new_snapshot_is_written_only_after_complete_live_success(self):
        original_pages = self.api.pages.side_effect
        self.api.pages.side_effect = lambda path, key=None: (
            [] if path.endswith("/releases") else original_pages(path, key)
        )

        def original_record(api, repository, run, _name, _filename):
            api.pages(f"repos/{repository}/actions/runs/{run['id']}/artifacts", "artifacts")
            return copy.deepcopy(self.proof)

        self.core.artifact_record.side_effect = original_record
        directory = self.root / "new-pair"
        result = PROOF.publication_archive(
            self.root,
            self.api,
            self.core,
            REPOSITORY,
            "1103407173",
            self.release,
            self.main_base,
            self.develop,
            directory,
        )
        self.assertFalse(result["archive_reused"])
        self.assertTrue((directory / PROOF.archive.SNAPSHOT).is_file())
        self.assertFalse((directory / PROOF.archive.BUNDLE).exists())
        self.proof["authorization"]["approval"] = {"user": "wrong"}
        rejected = self.root / "rejected-pair"
        with self.assertRaisesRegex(ValueError, "native-human-approval-drift"):
            PROOF.publication_archive(
                self.root,
                self.api,
                self.core,
                REPOSITORY,
                "1103407173",
                self.release,
                self.main_base,
                self.develop,
                rejected,
            )
        self.assertFalse((rejected / PROOF.archive.SNAPSHOT).exists())

    def test_archive_assets_are_attested_before_checksums_and_verified_after_native_download(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-publish.yml").read_text())
        steps = workflow["jobs"]["publish"]["steps"]
        names = [step.get("name", "") for step in steps]
        mapping = {step.get("name"): step for step in steps}
        retain = "Retain authenticated normal publication observations"
        attest = "Attest normal publication observations"
        verify = "Verify and retain normal native evidence attestation"
        final = "Verify GitHub Release download, install, and smoke"
        self.assertLess(names.index(retain), names.index(attest))
        self.assertLess(names.index(attest), names.index(verify))
        checksum = next(
            index
            for index, step in enumerate(steps)
            if index > names.index(verify)
            and "sha256sum" in step.get("run", "")
            and "SHA256SUMS" in step.get("run", "")
        )
        self.assertLess(names.index(verify), checksum)
        self.assertLess(checksum, names.index(final))
        self.assertEqual("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6", mapping[attest]["uses"])
        self.assertIn("NORMAL_NATIVE_ARCHIVE_REUSED != 'true'", mapping[attest]["if"])
        self.assertEqual("dist/release/" + PROOF.archive.SNAPSHOT, mapping[attest]["with"]["subject-path"])
        self.assertIn("bundle-path", str(mapping[verify]["env"]))
        self.assertIn("normal_release_archive.py", mapping[final]["run"])
        self.assertIn('if [ "${NORMAL_TWO_STAGE:-false}" = true ]; then', mapping[final]["run"])
        self.assertIn('--release "$RELEASE_SHA"', mapping[final]["run"])

    def test_published_baseline_uses_archive_after_original_actions_artifacts_expire(self):
        current, _develop = self.ordinary_main(self.release, self.develop, 1)
        self.baseline_api(current)
        previous = self.api.call.side_effect

        def expired(path):
            if "/actions/" in path:
                raise AssertionError("historical Actions API must not be queried")
            return previous(path)

        self.api.call.side_effect = expired
        self.api.pages.side_effect = AssertionError("historical inventory must not be queried")
        self.core.artifact_record.side_effect = AssertionError("original artifact download must not execute")
        result = PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", current)
        self.assertEqual(self.release, result["main_merge"])
        self.core.artifact_record.assert_not_called()
        self.api.pages.assert_not_called()
        self.assertFalse(any("/actions/" in call.args[0] for call in self.api.call.call_args_list))

    def test_archived_proof_drift_still_fails_original_native_checks(self):
        self.baseline_api(self.release)
        original = self.snapshot_bytes
        for change in ("approval", "tree", "binding", "receipt", "source"):
            with self.subTest(change=change):
                value = PROOF.archive.decode(original)
                records = [read for read in value["reads"] if read["kind"] == "artifact"]
                proof = records[0]["value"]["record"]
                if change == "approval":
                    proof["authorization"]["approval"] = {"user": "different"}
                elif change == "tree":
                    proof["evidence"]["integration_tree"] = "0" * 40
                elif change == "binding":
                    proof["binding"] = {}
                elif change == "source":
                    proof["source_sha"] = "0" * 40
                else:
                    read = next(
                        read
                        for read in value["reads"]
                        if read["kind"] == "call" and read["args"][0].endswith("actions/runs/10")
                    )
                    read["value"]["head_sha"] = "0" * 40
                self.snapshot_bytes = PROOF.archive.canonical(value)
                with self.assertRaises(ValueError):
                    PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)
        self.snapshot_bytes = original

    def test_published_baseline_survives_two_later_ordinary_main_promotions(self):
        first, develop = self.ordinary_main(self.release, self.develop, 1)
        second, _unused_develop = self.ordinary_main(first, develop, 2)
        self.baseline_api(second)
        for current in (first, second):
            with self.subTest(current=current):
                self.git("checkout", "--quiet", "--detach", current)
                actual = self.api.call.side_effect
                self.api.call.side_effect = lambda path, current=current, actual=actual: (
                    {"object": {"sha": current}} if path.endswith("git/ref/heads/main") else actual(path)
                )
                result = PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", current)
                self.assertEqual(result["main_merge"], self.release)
                with self.assertRaisesRegex(ValueError, "exact-release-checkout-required"):
                    self.publish()

    def test_published_baseline_requires_existing_annotated_published_version(self):
        self.baseline_api(self.release)
        for field, value in (("draft", True), ("prerelease", True), ("id", 0), ("tag_name", "v9.0.0")):
            with self.subTest(field=field):
                original = self.published_release.copy()
                self.published_release[field] = value
                with self.assertRaisesRegex(ValueError, "published-baseline-release-required"):
                    PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)
                self.published_release = original
        self.tag_ref["object"]["type"] = "commit"
        with self.assertRaisesRegex(ValueError, "published-baseline-annotated-tag-required"):
            PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)

    def test_published_baseline_rejects_changed_inherited_receipt(self):
        changed = copy.deepcopy(self.receipt)
        changed["publication"]["galaxy"] = False
        (self.root / PROOF.RECEIPT).write_bytes(PROOF.git_contract.CONTRACT.canonical_document_bytes(changed))
        self.git("add", ".")
        current = self.commit("invalid inherited receipt change", [self.release])
        self.git("checkout", "--quiet", "--detach", current)
        self.baseline_api(current)
        with self.assertRaisesRegex(ValueError, "published-baseline-receipt-drift"):
            PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", current)

    def test_published_baseline_rejects_generated_state_drift_and_unrelated_tag(self):
        (self.root / "CHANGELOG.rst").write_text("unreviewed generated state\n")
        self.git("add", ".")
        current = self.commit("invalid generated state", [self.release])
        self.git("checkout", "--quiet", "--detach", current)
        self.baseline_api(current)
        with self.assertRaisesRegex(ValueError, "published-baseline-generated-state-drift"):
            PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", current)
        self.tag_object["object"]["sha"] = self.commit("unrelated tagged tree", [])
        with self.assertRaisesRegex(ValueError, "published-baseline-not-ancestor"):
            PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", current)

    def test_published_baseline_rechecks_actual_published_release(self):
        self.baseline_api(self.release)
        original = self.api.call.side_effect
        observations = []

        def read(path):
            value = original(path)
            if path.endswith("releases/tags/v1.0.1"):
                observations.append(path)
                if len(observations) > 1:
                    value = {**value, "draft": True}
            return value

        self.api.call.side_effect = read
        with self.assertRaisesRegex(ValueError, "published-baseline-release-drift"):
            PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)

    def test_published_baseline_allows_download_counter_changes_from_its_own_asset_reads(self):
        self.baseline_api(self.release)
        self.published_release["assets"] = [
            {
                "id": 70,
                "name": PROOF.archive.SNAPSHOT,
                "size": 100,
                "digest": "sha256:" + "a" * 64,
                "state": "uploaded",
                "download_count": 1,
            },
            {
                "id": 71,
                "name": PROOF.archive.BUNDLE,
                "size": 200,
                "digest": "sha256:" + "b" * 64,
                "state": "uploaded",
                "download_count": 1,
            },
        ]
        original_read = self.api.call.side_effect
        original_download = PROOF.archive.download_pair.side_effect

        def read(path):
            # Each REST response is a new JSON value, not the fixture's shared dict.
            return copy.deepcopy(original_read(path))

        def download(published, repository, directory):
            original_download(published, repository, directory)
            for asset in self.published_release["assets"]:
                asset["download_count"] += 1

        self.api.call.side_effect = read
        with patch.object(PROOF.archive, "download_pair", side_effect=download):
            result = PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)
        self.assertEqual(self.release, result["main_merge"])
        self.assertEqual([2, 2], [item["download_count"] for item in self.published_release["assets"]])

    def test_published_baseline_still_rejects_asset_identity_digest_size_name_or_state_drift(self):
        for field, changed in (
            ("id", 99),
            ("digest", "sha256:" + "c" * 64),
            ("size", 999),
            ("name", "foreign-evidence.json"),
            ("state", "new"),
        ):
            with self.subTest(field=field):
                self.baseline_api(self.release)
                self.published_release["assets"] = [
                    {
                        "id": 70,
                        "name": PROOF.archive.SNAPSHOT,
                        "size": 100,
                        "digest": "sha256:" + "a" * 64,
                        "state": "uploaded",
                        "download_count": 1,
                    }
                ]
                original_read = self.api.call.side_effect
                original_download = PROOF.archive.download_pair.side_effect

                def read(path, original=original_read):
                    return copy.deepcopy(original(path))

                def download(
                    published, repository, directory, selected=field, value=changed, original=original_download
                ):
                    original(published, repository, directory)
                    self.published_release["assets"][0][selected] = value

                self.api.call.side_effect = read
                with (
                    patch.object(PROOF.archive, "download_pair", side_effect=download),
                    self.assertRaisesRegex(ValueError, "published-baseline-release-drift"),
                ):
                    PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)
                self.git("tag", "-d", "v1.0.1")

    def test_published_baseline_rechecks_immutable_tag_after_proof(self):
        self.baseline_api(self.release)
        original = self.api.call.side_effect
        observations = []

        def read(path):
            value = original(path)
            if path.endswith("git/ref/tags/v1.0.1"):
                observations.append(path)
                if len(observations) > 1:
                    value = {**value, "object": {"type": "tag", "sha": "0" * 40}}
            return value

        self.api.call.side_effect = read
        with self.assertRaisesRegex(ValueError, "published-baseline-tag-drift"):
            PROOF.published_baseline(self.root, self.api, self.core, REPOSITORY, "1103407173", self.release)

    def publish(self):
        return PROOF.publish(
            self.root, self.api, self.core, REPOSITORY, "1103407173", self.release, self.main_base, self.develop
        )

    def test_actual_git_two_stage_and_native_coverage(self):
        result = self.publish()
        self.assertEqual(self.prepared, result["prepared_head"])
        self.assertEqual(self.content_base, result["content_base"])
        self.assertEqual(2, result["promotion_pr"])
        self.assertTrue(all(len(call.args) == 1 and not call.kwargs for call in self.api.call.call_args_list))
        self.core.check_native_control.assert_called_once()

    def test_proof_drift_and_missing_native_relations_fail_closed(self):
        original = copy.deepcopy(self.proof)
        for label, mutate in (
            ("route", lambda p: p.__setitem__("route", "codex")),
            ("source", lambda p: p.__setitem__("source_sha", "f" * 40)),
            ("approval", lambda p: p.__setitem__("authorization", None)),
            ("ingress", lambda p: p["evidence"].__setitem__("ingress", [])),
            ("tree", lambda p: p["evidence"].__setitem__("integration_tree", "a" * 40)),
        ):
            with self.subTest(label=label):
                self.proof = copy.deepcopy(original)
                mutate(self.proof)
                self.core.artifact_record.return_value = self.proof
                with self.assertRaises(ValueError):
                    self.publish()

    def test_wrong_app_fork_or_branch_rejected(self):
        original = copy.deepcopy(self.prep)
        for label, mutate in (
            ("author-id", lambda p: p["user"].__setitem__("id", 1)),
            ("fork", lambda p: p["head"]["repo"].__setitem__("full_name", "other/repo")),
            ("target", lambda p: p["base"].__setitem__("ref", "main")),
            ("prepared-head", lambda p: p["head"].__setitem__("sha", "a" * 40)),
        ):
            with self.subTest(label=label):
                self.prep = copy.deepcopy(original)
                mutate(self.prep)
                with self.assertRaises(ValueError):
                    self.publish()

    def test_pending_native_promotion_cannot_reuse_old_success(self):
        self.run["status"] = "in_progress"
        with unittest.mock.patch.dict(sys.modules, {"workflow_ingress": Mock()}):
            sys.modules["workflow_ingress"].merged_attempt.side_effect = ValueError("native-pending")
            with self.assertRaisesRegex(ValueError, "native-pending"):
                self.publish()

    def test_preparation_must_be_single_app_commit_and_generated_only(self):
        self.assertEqual(
            self.receipt,
            PROOF.preparation(self.root, self.content_base, self.prepared, self.main_base, REPOSITORY, "1103407173"),
        )
        (self.root / "executable.py").write_text("print('unreviewed')\n")
        self.git("add", ".")
        changed = self.commit("chore(release): prepare v1.0.1", [self.content_base])
        with self.assertRaisesRegex(ValueError, "non-generated"):
            PROOF.preparation(self.root, self.content_base, changed, self.main_base, REPOSITORY, "1103407173")
        with self.assertRaisesRegex(ValueError, "base SHA differs"):
            PROOF.preparation(self.root, self.main_base, self.prepared, self.main_base, REPOSITORY, "1103407173")

    def test_native_approval_is_rechecked(self):
        self.core.native_approval.return_value = {"user": "different"}
        with self.assertRaisesRegex(ValueError, "native-human-approval-drift"):
            self.publish()

    def test_changed_preparation_run_source_rejected(self):
        original = self.call

        def drift(path):
            result = original(path)
            if path.endswith("actions/runs/10"):
                result["head_sha"] = self.content_base
            return result

        self.api.call.side_effect = drift
        with self.assertRaisesRegex(ValueError, "protected-main-preparation-run"):
            self.publish()

    def test_squashed_or_later_develop_head_is_rejected(self):
        for head in (self.prepared, self.commit("later unbound Develop change", [self.develop])):
            with self.subTest(head=head):
                release = self.commit("promotion with wrong ingress shape", [self.main_base, head])
                self.git("checkout", "--quiet", "--detach", release)
                with self.assertRaisesRegex(ValueError, "exact-preparation-ingress-parents"):
                    PROOF.publish(
                        self.root, self.api, self.core, REPOSITORY, "1103407173", release, self.main_base, head
                    )

    def test_native_source_loading_requires_actual_pinned_clean_checkout(self):
        with self.assertRaisesRegex(ValueError, "pinned-control-source"):
            PROOF.load_control(self.root)

    def test_control_audit_observations_do_not_relabel_native_reference(self):
        recorded = copy.deepcopy(self.ingress)
        current = copy.deepcopy(self.ingress)
        current["post_merge_failed_attempts"] = [{"conclusion": "failure", "attempt": 2}]
        self.assertEqual(PROOF.control_reference(recorded), PROOF.control_reference(current))
        current["attempt"] = 2
        self.assertNotEqual(PROOF.control_reference(recorded), PROOF.control_reference(current))
        current["new_authority"] = True
        with self.assertRaisesRegex(ValueError, "reference-shape"):
            PROOF.control_reference(current)

    def test_newer_native_generation_is_rejected(self):
        newer = {**self.run, "run_attempt": 2}
        self.core.ingress_candidates.side_effect = [[self.run], [newer]]
        with self.assertRaisesRegex(ValueError, "newer-promotion-generation"):
            self.publish()

    def test_actual_readiness_steps_distinguish_consumed_unjoined_and_pending_tips(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/release-prepare.yml").read_text())["jobs"]
        steps = {step["id"]: step for step in jobs["normal-readiness"]["steps"] if "id" in step}
        self.git("remote", "add", "origin", str(self.root))
        (self.root / "scripts").mkdir()
        # This fixture already runs inside the pinned EE. Exercise the actual
        # workflow's dispatcher arguments without trying nested containers.
        (self.root / "scripts/wunder-devtools-ee.sh").write_text('#!/bin/bash\nset -euo pipefail\nexec "$@"\n')
        for name in ("release-version.py", "security_release_contract.py"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        content = self.root / "release-readiness-content"
        (content / "changelogs/fragments").mkdir(parents=True)
        (content / "galaxy.yml").write_text("---\nversion: 1.0.1\n")
        pending = self.root / "changelogs/fragments/next.yml"
        pending.parent.mkdir(parents=True, exist_ok=True)
        pending.write_text("---\nbugfixes:\n  - Reviewed next change.\n")
        self.git("add", "changelogs/fragments/next.yml")
        unjoined = self.commit("next Develop ingress", [self.develop])
        joined = self.commit("next ingress after Main ancestry", [self.release])
        executable = shutil.which("bash")
        assert executable
        native = r"""gh() {
          printf '%s\n' "$2" >>"$NATIVE_CALLS"
          case "$2" in
            */branches/main) printf '{"protected":true,"commit":{"sha":"%s"}}\n' "$GITHUB_SHA";;
            */branches/develop) printf '{"protected":true,"commit":{"sha":"%s"}}\n' "$CONTENT_SHA";;
            */git/ref/heads/main) echo "$GITHUB_SHA";;
            */git/ref/heads/develop) echo "$CONTENT_SHA";;
            *) return 1;;
          esac
        }
        """
        for label, head, has_fragments, expected_status in (
            ("consumed-unjoined", self.develop, False, 0),
            ("pending-unjoined", unjoined, True, 1),
            ("pending-joined", joined, True, 0),
        ):
            with self.subTest(case=label):
                fragment = content / "changelogs/fragments/next.yml"
                if has_fragments:
                    fragment.write_bytes(pending.read_bytes())
                else:
                    fragment.unlink(missing_ok=True)
                calls = self.root / f"{label}-native-calls"
                output = self.root / f"{label}-output"
                environment = {
                    **self.git_env,
                    "GITHUB_REPOSITORY": REPOSITORY,
                    "GITHUB_SHA": self.release,
                    "CONTENT_SHA": head,
                    "VERSION_INPUT": "",
                    "BASE_INPUT": "",
                    "TARGET_INPUT": "",
                    "NATIVE_CALLS": str(calls),
                    "GITHUB_OUTPUT": str(output),
                }
                bind = subprocess.run(  # noqa: S603 -- actual read-only steps with offline native fixture.
                    [executable, "-c", native + steps["tips"]["run"]],
                    cwd=self.root,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, bind.returncode, bind.stderr)
                self.assertEqual(f"content_sha={head}\n", output.read_text())
                output.unlink()
                need = subprocess.run(  # noqa: S603 -- actual Main parser and real Git topology.
                    [executable, "-c", native + steps["need"]["run"]],
                    cwd=self.root,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(expected_status, need.returncode, need.stderr)
                if label == "consumed-unjoined":
                    self.assertEqual("ready=false\n", output.read_text())
                    self.assertIn("no-op", need.stdout)
                elif label == "pending-unjoined":
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual("ready=true\n", output.read_text())
                native_reads = calls.read_text().splitlines()
                expected_reads = [f"repos/{REPOSITORY}/branches/main", f"repos/{REPOSITORY}/branches/develop"]
                if label == "pending-joined":
                    expected_reads += [
                        f"repos/{REPOSITORY}/git/ref/heads/main",
                        f"repos/{REPOSITORY}/git/ref/heads/develop",
                    ]
                self.assertEqual(expected_reads, native_reads)

    def test_standalone_preparation_cli_rejects_foreign_receipt_identity(self):
        for repository, repository_id, expected_error in (
            ("other/collection", "1103407173", "repository differs"),
            (REPOSITORY, "999999", "repository id differs"),
        ):
            with self.subTest(repository=repository, repository_id=repository_id):
                receipt = copy.deepcopy(self.receipt)
                receipt["repository"] = repository
                receipt["repository_id"] = repository_id
                receipt["workflow"]["ref"] = f"{repository}/.github/workflows/release-prepare.yml@refs/heads/main"
                (self.root / PROOF.RECEIPT).write_bytes(PROOF.git_contract.CONTRACT.canonical_document_bytes(receipt))
                self.git("add", PROOF.RECEIPT)
                foreign = self.commit("chore(release): prepare v1.0.1", [self.content_base])
                result = subprocess.run(  # noqa: S603 -- actual read-only CLI, fixed fixture arguments.
                    [
                        sys.executable,
                        str(ROOT / "scripts/normal_release_proof.py"),
                        "preparation",
                        "--root",
                        str(self.root),
                        "--base",
                        self.content_base,
                        "--head",
                        foreign,
                        "--workflow-source",
                        self.main_base,
                        "--repository",
                        REPOSITORY,
                        "--repository-id",
                        "1103407173",
                    ],
                    cwd=self.root,
                    env=self.git_env,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertIn(expected_error, result.stderr)

    def test_empty_fragment_guard_is_actual_noop(self):
        prepare = yaml.safe_load((ROOT / ".github/workflows/release-prepare.yml").read_text())["jobs"]
        step = next(step for step in prepare["normal-readiness"]["steps"] if step.get("id") == "need")
        (self.root / "release-readiness-content/changelogs/fragments").mkdir(parents=True)
        output = self.root / "readiness-output"
        executable = shutil.which("bash")
        assert executable
        result = subprocess.run(  # noqa: S603 -- actual protected read-only guard, offline Devtools.
            [executable, "-c", step["run"]],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
            env={**self.git_env, "GITHUB_OUTPUT": str(output)},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("ready=false\n", output.read_text())
        self.assertIn("no-op", result.stdout)

    def test_readiness_uses_main_parser_and_rejects_unpublished_version_baseline(self):
        prepare = yaml.safe_load((ROOT / ".github/workflows/release-prepare.yml").read_text())["jobs"]
        step = next(step for step in prepare["normal-readiness"]["steps"] if step.get("id") == "need")
        (self.root / "scripts").mkdir()
        (self.root / "scripts/wunder-devtools-ee.sh").write_text('#!/bin/bash\nset -euo pipefail\nexec "$@"\n')
        for name in ("release-version.py", "security_release_contract.py"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        content = self.root / "release-readiness-content"
        (content / "changelogs/fragments").mkdir(parents=True)
        (content / "galaxy.yml").write_text("---\nversion: 1.0.0\n")
        (content / "changelogs/fragments/change.yml").write_text("---\nbugfixes:\n  - Reviewed fix.\n")
        output = self.root / "readiness-output"
        executable = shutil.which("bash")
        assert executable
        native = (
            'gh() { case "$2" in */heads/main) echo "$GITHUB_SHA";; '
            '*/heads/develop) echo "$CONTENT_SHA";; *) return 1;; esac; }\n'
        )
        for main_version, expected_status in (("1.0.0", 0), ("0.9.9", 1)):
            with self.subTest(main_version=main_version):
                output.unlink(missing_ok=True)
                (self.root / "galaxy.yml").write_text(f"---\nversion: {main_version}\n")
                result = subprocess.run(  # noqa: S603 -- offline parser and fake read-only native refs.
                    [executable, "-c", native + step["run"]],
                    cwd=self.root,
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **self.git_env,
                        "GITHUB_OUTPUT": str(output),
                        "VERSION_INPUT": "",
                        "GITHUB_REPOSITORY": REPOSITORY,
                        "GITHUB_SHA": self.main_base,
                        "CONTENT_SHA": self.content_base,
                    },
                )
                self.assertEqual(expected_status, result.returncode, result.stderr)
                if expected_status == 0:
                    self.assertEqual("ready=true\n", output.read_text())
                else:
                    self.assertFalse(output.exists())
                    self.assertIn("baseline differs", result.stdout)

    def test_legacy_normal_profile_cannot_create_missing_publications(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-publish.yml").read_text())["jobs"]["publish"]
        steps = {step["name"]: step for step in workflow["steps"]}
        identity = steps["Verify protected-main and reviewed merge identity"]["run"]
        self.assertIn('git fetch --no-tags origin "refs/tags/${legacy_tag}"', identity)
        self.assertIn("releases/tags/${legacy_tag}", identity)
        self.assertIn(".draft == false and .prerelease == false", identity)
        for name, effect in (
            ("Create or verify immutable tag with dedicated App", "tag_object="),
            ("Create or verify GitHub Release and immutable assets", "gh release create"),
            ("Publish or verify validated artifact on Ansible Galaxy", "ansible-galaxy collection publish"),
        ):
            script = steps[name]["run"]
            self.assertLess(script.index("Legacy normal recheck cannot create"), script.index(effect))

    def test_workflow_executes_proof_and_gates_app_on_readiness(self):
        prepare = yaml.safe_load((ROOT / ".github/workflows/release-prepare.yml").read_text())["jobs"]
        self.assertNotIn("environment", prepare["normal-readiness"])
        self.assertIn("normal-readiness", prepare["prepare"]["needs"])
        self.assertIn("outputs.ready == 'true'", prepare["prepare"]["if"])
        script = "\n".join(step.get("run", "") for step in prepare["prepare"]["steps"])
        self.assertIn('"$workflow_source/scripts/normal_release_proof.py" preparation', script)
        self.assertIn('if [ "$REVIEW_ROUTE" = legacy ]; then\n  gh workflow', script)
        publish = yaml.safe_load((ROOT / ".github/workflows/collection-publish.yml").read_text())["jobs"]["publish"]
        steps = {step["name"]: step for step in publish["steps"]}
        proof = steps["Prove normal preparation ingress and exact approved promotion"]
        self.assertIn("normal_release_proof.py publish", proof["run"])
        self.assertEqual("env.NORMAL_TWO_STAGE == 'true'", proof["if"])


class RealNativeArchiveTests(unittest.TestCase):
    """Synthetic native transport, actual pinned reader and actual Git graph."""

    def association_fence(self, fixture, core, collected, fresh):
        """Actual bb1 selection and the final fence observe mapping-only drift."""
        index = json.loads((fresh / "index.json").read_text())
        pull = fixture.promotion
        for endpoint in (
            "actions/runs/30",
            "actions/runs/30/attempts/1",
            f"actions/runs?head_sha={pull['head']['sha']}&per_page=100&page=1",
        ):
            path = f"repos/{REPOSITORY}/{endpoint}"
            leaf = fresh / index["calls"][path]
            original = leaf.read_bytes()
            baseline = json.loads(original)
            self.assertEqual({"fresh": True}, PROOF.native_fence(core, collected, fresh, REPOSITORY, "1103407173"))
            for change in ("missing", "empty", "foreign", "base", "head", "ambiguous", "null", "malformed"):
                with self.subTest(endpoint=endpoint, association=change):
                    value = copy.deepcopy(baseline)
                    run = value["workflow_runs"][0] if "workflow_runs" in value else value
                    association = copy.deepcopy(run["pull_requests"][0])
                    if change == "missing":
                        del run["pull_requests"]
                    elif change == "empty":
                        run["pull_requests"] = []
                    elif change == "foreign":
                        association["number"] += 100
                        run["pull_requests"] = [association]
                    elif change in {"base", "head"}:
                        association[change]["sha"] = "0" * 40
                        run["pull_requests"] = [association]
                    elif change == "ambiguous":
                        run["pull_requests"] = [association, copy.deepcopy(association)]
                    else:
                        run["pull_requests"] = None if change == "null" else [None]

                    def candidates(observed_run):
                        # Missing/empty mappings on a merged PR may use its already
                        # authenticated operation binding. They do not equal the
                        # originally observed explicit association at this fence.
                        return core.ingress_candidates(
                            None,
                            REPOSITORY,
                            pull,
                            [PROOF.CONTROL_SOURCE],
                            [observed_run],
                            {(observed_run["id"], observed_run["run_attempt"]): True},
                            read_operations=False,
                        )

                    if change in {"missing", "empty"}:
                        self.assertEqual([run], candidates(run))
                    elif change == "ambiguous":
                        with self.assertRaisesRegex(core.ControlError, "ingress-association-ambiguous"):
                            candidates(run)
                    elif change in {"null", "malformed"}:
                        with self.assertRaises((TypeError, AttributeError)):
                            candidates(run)
                    else:
                        self.assertEqual([], candidates(run))
                    leaf.write_text(json.dumps(value))
                    try:
                        with self.assertRaisesRegex(ValueError, "normal-native-(freshness|generation)"):
                            PROOF.native_fence(core, collected, fresh, REPOSITORY, "1103407173")
                    finally:
                        leaf.write_bytes(original)
            self.assertEqual({"fresh": True}, PROOF.native_fence(core, collected, fresh, REPOSITORY, "1103407173"))
            # Preserve absence as well as the value; absent->null must not be
            # collapsed, because actual bb1 accepts only the former fallback.
            initial_index = json.loads((collected / "index.json").read_text())
            initial_leaf = collected / initial_index["calls"][path]
            initial_original = initial_leaf.read_bytes()
            absent = copy.deepcopy(baseline)
            absent_run = absent["workflow_runs"][0] if "workflow_runs" in absent else absent
            del absent_run["pull_requests"]
            try:
                initial_leaf.write_text(json.dumps(absent))
                leaf.write_text(json.dumps(absent))
                self.assertEqual({"fresh": True}, PROOF.native_fence(core, collected, fresh, REPOSITORY, "1103407173"))
                absent_run["pull_requests"] = None
                leaf.write_text(json.dumps(absent))
                with self.assertRaisesRegex(ValueError, "normal-native-(freshness|generation)"):
                    PROOF.native_fence(core, collected, fresh, REPOSITORY, "1103407173")
            finally:
                initial_leaf.write_bytes(initial_original)
                leaf.write_bytes(original)

    def raw_native(self, fixture, core, captured):
        """Actual collector, raw ZIPs and actual bb1 verifier; no native claim."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw"
            raw.mkdir()
            index = {"version": 1, "repository": REPOSITORY, "calls": {}, "logs": {}, "artifacts": {}, "assets": {}}
            responses, inventories = {}, {}
            for entry in captured["reads"]:
                kind, args, value = entry["kind"], entry["args"], entry["value"]
                if kind == "call":
                    responses[args[0]] = value
                elif kind == "pages":
                    path, key = args
                    separator = "&" if "?" in path else "?"
                    responses[f"{path}{separator}per_page=100&page=1"] = (
                        {key: value, "total_count": len(value)} if key else value
                    )
                elif kind == "file":
                    wire = base64.b64decode(value)
                    response = {
                        "type": "file",
                        "path": args[1],
                        "encoding": "base64",
                        "size": len(wire),
                        "sha": hashlib.sha1(
                            b"blob " + str(len(wire)).encode() + b"\0" + wire, usedforsecurity=False
                        ).hexdigest(),
                        "content": value,
                    }
                    for revision in (args[2], fixture.content_base):
                        responses[f"repos/{REPOSITORY}/contents/{args[1]}?ref={revision}"] = response
                elif kind == "artifact":
                    metadata = copy.deepcopy(value["metadata"])
                    payload = io.BytesIO()
                    with zipfile.ZipFile(payload, "w") as zipped:
                        zipped.writestr(args[5], json.dumps(value["record"]))
                    wire = payload.getvalue()
                    metadata.update(
                        size_in_bytes=len(wire),
                        digest="sha256:" + hashlib.sha256(wire).hexdigest(),
                        workflow_run={
                            "id": args[1],
                            "head_sha": args[3],
                            "repository_id": 1103407173,
                            "head_repository_id": 1103407173,
                        },
                    )
                    inventories.setdefault(args[1], {})[args[4]] = metadata
                    name = f"artifact-{metadata['id']}.zip"
                    (raw / name).write_bytes(wire)
                    index["artifacts"][str(metadata["id"])] = name
            for run, inventory in inventories.items():
                responses[f"repos/{REPOSITORY}/actions/runs/{run}/artifacts?per_page=100&page=1"] = {
                    "artifacts": list(inventory.values()),
                    "total_count": len(inventory),
                }
            for branch, revision in (("main", fixture.release), ("develop", fixture.develop)):
                responses[f"repos/{REPOSITORY}/branches/{branch}"] = {"protected": True, "commit": {"sha": revision}}
                responses[f"repos/{REPOSITORY}/git/ref/heads/{branch}"] = {"object": {"sha": revision}}
            responses[f"repos/{REPOSITORY}"] = {
                "id": 1103407173,
                "full_name": REPOSITORY,
                "archived": False,
                "disabled": False,
            }
            responses[f"repos/{REPOSITORY}/releases?per_page=100&page=1"] = []
            responses[f"repos/{REPOSITORY}/actions/runs/10/artifacts?per_page=100&page=1"] = {
                "artifacts": [],
                "total_count": 0,
            }
            for pull in (fixture.prep, fixture.promotion):
                responses[f"repos/{REPOSITORY}/issues/{pull['number']}/events?per_page=100&page=1"] = []
                inventory = responses[
                    f"repos/{REPOSITORY}/actions/runs?head_sha={pull['head']['sha']}&per_page=100&page=1"
                ]
                for run in inventory["workflow_runs"]:
                    responses[f"repos/{REPOSITORY}/actions/runs/{run['id']}"] = run
                    responses[f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/1"] = run
                    responses.setdefault(f"repos/{REPOSITORY}/actions/runs/{run['id']}/approvals", [])
            for number, (path, value) in enumerate(responses.items()):
                name = f"read-{number}.json"
                (raw / name).write_text(json.dumps(value))
                index["calls"][path] = name
            (raw / "index.json").write_text(json.dumps(index))
            wire_index = {path: str(raw / name) for path, name in index["calls"].items()}
            wire_index.update(
                {
                    f"repos/{REPOSITORY}/actions/artifacts/{identifier}/zip": str(raw / name)
                    for identifier, name in index["artifacts"].items()
                }
            )
            locator = root / "wire.json"
            locator.write_text(json.dumps(wire_index))
            binary = root / "bin"
            binary.mkdir()
            command = binary / "gh"
            command.write_text(
                "#!/bin/bash\nset -euo pipefail\n"
                'test "$1 $2 $3" = "api --method GET"\n'
                'test "$4" != "${FAIL_GH_PATH:-}"\n'
                'cat "$(jq -er --arg path "$4" \'.[$path]\' "$WIRE_INDEX")"\n'
            )
            command.chmod(0o755)
            env = fixture.git_env | {"PATH": f"{binary}:{os.environ['PATH']}", "WIRE_INDEX": str(locator)}
            helper = ROOT / "scripts/normal_release_observations.sh"
            collected, fresh = root / "collected", root / "fresh"
            for mode, output in (("publication", collected), ("fresh", fresh)):
                result = subprocess.run(  # noqa: S603 -- actual read-only collector with synthetic native I/O.
                    ["/bin/bash", str(helper), mode, str(output), REPOSITORY, fixture.release, str(collected)],
                    cwd=fixture.root,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
            with PROOF.native_reads(core, collected, REPOSITORY, "1103407173") as api:
                result = PROOF.publish(
                    fixture.root,
                    api,
                    core,
                    REPOSITORY,
                    "1103407173",
                    fixture.release,
                    fixture.main_base,
                    fixture.develop,
                )
            self.assertEqual(fixture.release, result["main_merge"])
            self.assertEqual({"fresh": True}, PROOF.native_fence(core, collected, fresh, REPOSITORY, "1103407173"))
            self.association_fence(fixture, core, collected, fresh)
            collected_index = json.loads((collected / "index.json").read_text())
            identifier = next(iter(collected_index["artifacts"]))
            artifact = collected / collected_index["artifacts"][identifier]
            original = artifact.read_bytes()
            artifact.write_bytes(original + b"changed")
            with PROOF.native_reads(core, collected, REPOSITORY, "1103407173") as api:
                with self.assertRaisesRegex(ValueError, "artifact-digest"):
                    PROOF.publish(
                        fixture.root,
                        api,
                        core,
                        REPOSITORY,
                        "1103407173",
                        fixture.release,
                        fixture.main_base,
                        fixture.develop,
                    )
            artifact.write_bytes(original)
            artifact.unlink()
            with self.assertRaisesRegex(ValueError, "observation-bound"):
                PROOF.native_snapshot(core, collected, REPOSITORY, "1103407173")
            artifact.write_bytes(original)
            for suffix in ("git/ref/heads/main", "pulls/2", "actions/runs/30", "actions/runs/30/approvals"):
                with self.subTest(fresh=suffix):
                    path = f"repos/{REPOSITORY}/{suffix}"
                    leaf = fresh / json.loads((fresh / "index.json").read_text())["calls"][path]
                    original = leaf.read_bytes()
                    value = json.loads(original)
                    if suffix.endswith("heads/main"):
                        value["object"]["sha"] = "0" * 40
                    elif suffix == "pulls/2":
                        value["draft"] = True
                    elif suffix == "actions/runs/30":
                        value["run_attempt"] = 2
                    else:
                        value.clear()
                    leaf.write_text(json.dumps(value))
                    with self.assertRaisesRegex(ValueError, "freshness-drift"):
                        PROOF.native_fence(core, collected, fresh, REPOSITORY, "1103407173")
                    leaf.write_bytes(original)
            failed = subprocess.run(  # noqa: S603 -- native transport error never creates a proof.
                ["/bin/bash", str(helper), "publication", str(root / "failed"), REPOSITORY, fixture.release],
                cwd=fixture.root,
                env=env | {"FAIL_GH_PATH": f"repos/{REPOSITORY}/branches/main"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, failed.returncode)

    def test_pinned_native_verifiers_replay_all_original_checks_without_actions_transport(self):
        directory = Path(os.environ.get("LIT_RELEASE_CONTROL_FIXTURE", ROOT / ".cache/release-control-source"))
        if not directory.is_dir():
            self.skipTest("immutable offline native-control fixture not staged; qualification not executed")
        fixture = NormalReleaseProofTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        previous = sys.modules.pop("workflow_control", None)

        def restore_module():
            sys.modules.pop("workflow_control", None)
            if previous is not None:
                sys.modules["workflow_control"] = previous

        self.addCleanup(restore_module)
        core = PROOF.load_control(directory)
        for pull in (fixture.prep, fixture.promotion):
            pull.update(title="Synthetic native-shaped reviewed change", body="Offline regression", labels=[])
        runs = {}
        for run_id, pull in ((20, fixture.prep), (30, fixture.promotion)):
            runs[run_id] = {
                "id": run_id,
                "run_attempt": 1,
                "head_sha": pull["head"]["sha"],
                "status": "completed",
                "conclusion": "success",
                "workflow_id": 123,
                "workflow_url": f"https://api.github.com/repos/{REPOSITORY}/actions/required_workflows/123",
                "path": core.WORKFLOW,
                "pull_requests": [copy.deepcopy(pull)],
            }
        prep_record = {
            "version": 1,
            "source_sha": PROOF.CONTROL_SOURCE,
            "route": "codex",
            "binding": core.binding(fixture.prep),
        }
        approval = {
            "state": "approved",
            "user": {"login": "fixture-reviewer", "id": 1234, "type": "User"},
            "environments": [{"name": "normal-release-promotion-approval"}],
        }
        promotion_record = copy.deepcopy(fixture.proof)
        promotion_record["binding"] = core.binding(fixture.promotion)
        promotion_record["authorization"] = {"run": 30, "approval": approval}
        promotion_record["evidence"]["ingress"][0]["control"]["proof_sha256"] = core.digest(prep_record)
        operation = {"version": 1, "source_sha": PROOF.CONTROL_SOURCE, "binding": core.binding(fixture.promotion)}
        records = {
            (20, "control-proof-1"): prep_record,
            (30, "control-proof-1"): promotion_record,
            (30, "control-operation-1"): operation,
        }
        api = Mock()
        api.file.return_value = (ROOT / ".lit/workflow-control.json").read_bytes()

        def call(path):
            if path.endswith("/approvals"):
                return [copy.deepcopy(approval)]
            if path.endswith("environments/normal-release-promotion-approval"):
                return {
                    "name": "normal-release-promotion-approval",
                    "can_admins_bypass": False,
                    "protection_rules": [
                        {"type": "required_reviewers", "prevent_self_review": False, "reviewers": [{"type": "User"}]}
                    ],
                }
            for run_id, run in runs.items():
                if path.endswith(f"actions/runs/{run_id}"):
                    return copy.deepcopy(run)
            return copy.deepcopy(fixture.call(path))

        def pages(path, key=None):
            for run_id, run in runs.items():
                if path.endswith(f"actions/runs?head_sha={run['head_sha']}"):
                    return [copy.deepcopy(run)]
                if path.endswith(f"actions/runs/{run_id}/attempts/1/jobs"):
                    return [
                        {"id": run_id + 1, "run_id": run_id, "name": "Current revision review", "conclusion": "success"}
                    ]
                if path.endswith(f"actions/runs/{run_id}/artifacts"):
                    return [
                        {
                            "id": run_id * 10 + index,
                            "name": name,
                            "expired": False,
                            "size_in_bytes": 1024,
                            "digest": "sha256:" + "a" * 64,
                        }
                        for index, (identity, name) in enumerate(records, 1)
                        if identity == run_id
                    ]
            return copy.deepcopy(fixture.pages(path, key))

        api.call.side_effect = call
        api.pages.side_effect = pages
        original_run = subprocess.run
        downloads = []

        def transport(args, **kwargs):
            if args[:3] == ["gh", "run", "download"]:
                run_id, name = int(args[3]), args[args.index("--name") + 1]
                target = Path(args[args.index("--dir") + 1])
                filename = "control-operation.json" if "operation" in name else "control-proof.json"
                (target / filename).write_text(json.dumps(records[(run_id, name)]))
                downloads.append((run_id, name))
                return subprocess.CompletedProcess(args, 0, b"", b"")
            return original_run(args, check=kwargs.pop("check", False), **kwargs)

        snapshot = fixture.root / "native-snapshot.json"
        with patch.object(subprocess, "run", side_effect=transport):
            result = PROOF.publish_snapshot(
                fixture.root,
                api,
                core,
                REPOSITORY,
                "1103407173",
                fixture.release,
                fixture.main_base,
                fixture.develop,
                snapshot,
            )
        self.assertEqual([(20, "control-proof-1"), (30, "control-proof-1"), (30, "control-operation-1")], downloads)
        value = PROOF.archive.decode(snapshot.read_bytes())
        snapshot.unlink()
        self.raw_native(fixture, core, value)
        current, _develop = fixture.ordinary_main(fixture.release, fixture.develop, 1)
        expected = PROOF.archive.binding(
            REPOSITORY, "1103407173", fixture.release, fixture.main_base, fixture.develop, PROOF.CONTROL_SOURCE
        )

        def expired_pages(path, key=None):
            if "/actions/" in path:
                raise ValueError("original native Actions evidence expired")
            return pages(path, key)

        api.pages.side_effect = expired_pages
        with self.assertRaisesRegex(ValueError, "original native Actions evidence expired"):
            PROOF._publish(
                fixture.root,
                api,
                core,
                REPOSITORY,
                "1103407173",
                fixture.release,
                fixture.main_base,
                fixture.develop,
                current,
            )
        api.reset_mock()
        api.call.side_effect = api.pages.side_effect = AssertionError("expired original Actions must not be read")
        api.file.side_effect = AssertionError("historical protected policy must come from signed observations")

        def expired_transport(args, **kwargs):
            if args[0] == "gh":
                raise AssertionError("original artifact download must not execute during replay")
            return original_run(args, check=kwargs.pop("check", False), **kwargs)

        def replay(observations):
            adapter = PROOF.archive.Replay(observations, expected, current)
            with (
                patch.object(subprocess, "run", side_effect=expired_transport),
                PROOF.archive.artifact_reader(core, adapter),
            ):
                observed = PROOF._publish(
                    fixture.root,
                    adapter,
                    core,
                    REPOSITORY,
                    "1103407173",
                    fixture.release,
                    fixture.main_base,
                    fixture.develop,
                    current,
                )
            adapter.finish(observed)
            return observed

        self.assertEqual(result, replay(value))
        api.call.assert_not_called()
        api.pages.assert_not_called()
        api.file.assert_not_called()
        for defect in ("approval", "tree", "preparation-binding", "operation-binding", "source", "run-origin"):
            changed = copy.deepcopy(value)
            artifacts = [entry for entry in changed["reads"] if entry["kind"] == "artifact"]
            if defect == "approval":
                artifacts[1]["value"]["record"]["authorization"]["approval"]["user"]["id"] = 4321
            elif defect == "tree":
                artifacts[1]["value"]["record"]["evidence"]["integration_tree"] = "0" * 40
            elif defect == "preparation-binding":
                artifacts[0]["value"]["record"]["binding"]["head"] = "0" * 40
            elif defect == "operation-binding":
                artifacts[2]["value"]["record"]["binding"]["head"] = "0" * 40
            elif defect == "source":
                artifacts[0]["value"]["record"]["source_sha"] = "0" * 40
            else:
                entry = next(
                    entry
                    for entry in changed["reads"]
                    if entry["kind"] == "pages"
                    and entry["args"][0].endswith(f"actions/runs?head_sha={fixture.prepared}")
                )
                entry["value"][0]["workflow_url"] = "https://example.invalid/foreign"
            with self.subTest(defect=defect), self.assertRaises((ValueError, core.ControlError)):
                replay(changed)


if __name__ == "__main__":
    unittest.main()
