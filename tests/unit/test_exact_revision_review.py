from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
MATERIALIZER_PATH = ROOT / "scripts" / "materialize-exact-revision-review.py"


def load_materializer() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("materialize_exact_revision_review", MATERIALIZER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load exact-revision materializer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExactRevisionMaterializerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_materializer()
        self.arguments = argparse.Namespace(
            repository="lightning-it/ansible-collection-supplementary",
            pull_request=748,
            base_ref="develop",
            expected_base="a" * 40,
            expected_head="b" * 40,
            trusted_workflow_sha="a" * 40,
            trigger="app_dispatch",
            dispatch_ref="refs/heads/develop",
        )

    def git_output(self, diff: bytes):
        def output(_git, _git_dir, arguments, **_kwargs):
            if arguments[:2] == ["rev-parse", "refs/review/base^{commit}"]:
                return f"{self.arguments.expected_base}\n"
            if arguments[:2] == ["rev-parse", "refs/review/head^{commit}"]:
                return f"{self.arguments.expected_head}\n"
            if arguments[:2] == ["merge-base", "--all"]:
                return f"{'c' * 40}\n"
            if arguments[:2] == ["merge-tree", "--write-tree"]:
                return f"{'d' * 40}\n"
            if arguments[:2] == ["cat-file", "-t"]:
                return "tree\n"
            if arguments and arguments[0] == "diff":
                return diff
            return ""

        return output

    def materialize(self, diff: bytes, output: Path):
        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "unit-test-token"}),
            mock.patch.object(self.module, "read_live_pull_request", return_value={}) as live,
            mock.patch.object(self.module, "executable", side_effect=lambda name: f"/usr/bin/{name}"),
            mock.patch.object(self.module, "run", return_value=subprocess.CompletedProcess([], 0, "", "")),
            mock.patch.object(self.module, "git_output", side_effect=self.git_output(diff)),
        ):
            metadata = self.module.materialize(self.arguments, output)
        self.assertEqual(2, live.call_count)
        return metadata

    def test_binary_diff_is_complete_and_bound_to_merge_result(self) -> None:
        binary_diff = (
            b"diff --git a/payload.bin b/payload.bin\n"
            b"new file mode 100644\n"
            b"index 0000000000000000000000000000000000000000..1111111111111111111111111111111111111111\n"
            b"GIT binary patch\nliteral 3\nKcmZQzU|?Vb3IG5A\n\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "review"
            metadata = self.materialize(binary_diff, output)
            self.assertEqual(binary_diff, (output / "change.patch").read_bytes())
            self.assertEqual("c" * 40, metadata["merge_base_sha"])
            self.assertEqual("d" * 40, metadata["integration_tree_sha"])
            self.assertEqual(64, len(metadata["diff_sha256"]))
            self.assertEqual(len(binary_diff), metadata["review_bytes"])
            self.assertEqual(5, metadata["schema_version"])

    def test_command_failure_with_one_argument_preserves_the_real_error(self) -> None:
        failed = subprocess.CompletedProcess(["gh"], 1, "", "denied")
        with (
            mock.patch.object(self.module.subprocess, "run", return_value=failed),
            self.assertRaisesRegex(
                self.module.MaterializationError,
                "Command failed closed: gh: denied",
            ),
        ):
            self.module.run(["gh"], environment={})

    def test_only_protected_base_refs_are_accepted(self) -> None:
        for base_ref in ("develop", "main"):
            with self.subTest(base_ref=base_ref):
                arguments = argparse.Namespace(
                    **{
                        **vars(self.arguments),
                        "base_ref": base_ref,
                        "dispatch_ref": f"refs/heads/{base_ref}",
                    }
                )
                self.module.validate_inputs(arguments)
        arguments = argparse.Namespace(
            **{
                **vars(self.arguments),
                "base_ref": "feature/untrusted",
            }
        )
        with self.assertRaisesRegex(
            self.module.MaterializationError,
            "Base ref must be develop or main",
        ):
            self.module.validate_inputs(arguments)

    def test_complete_input_binds_every_protected_asset_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            assets = {
                "copilot_workflow_sha256": root / "copilot-workflow.yml",
                "materializer_sha256": root / "materializer.py",
                "prompt_sha256": root / "prompt.md",
                "rerun_workflow_sha256": root / "rerun-workflow.yml",
                "schema_sha256": root / "schema.json",
                "workflow_sha256": root / "workflow.yml",
            }
            for index, path in enumerate(assets.values(), start=1):
                path.write_text(f"protected asset {index}\n", encoding="utf-8")
            metadata = {
                "schema_version": 5,
                "base_sha": "a" * 40,
                "head_sha": "b" * 40,
                "diff_sha256": "c" * 64,
            }
            first = self.module.bind_protected_assets(metadata, assets)
            second = self.module.bind_protected_assets(metadata, assets)
            self.assertEqual(first, second)
            self.assertEqual(64, len(first["input_sha256"]))
            for key in assets:
                self.assertEqual(64, len(first[key]))

            assets["prompt_sha256"].write_text("tampered prompt\n", encoding="utf-8")
            tampered = self.module.bind_protected_assets(metadata, assets)
            self.assertNotEqual(first["prompt_sha256"], tampered["prompt_sha256"])
            self.assertNotEqual(first["input_sha256"], tampered["input_sha256"])

    def test_protected_asset_reader_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            target.write_text("protected\n", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(self.module.MaterializationError, "unavailable|non-symlink"):
                self.module.protected_asset_bytes(link, "prompt")

    def test_protected_asset_reader_requires_no_follow_support(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            protected = Path(temporary).resolve() / "prompt.md"
            protected.write_text("protected\n", encoding="utf-8")
            with (
                mock.patch.object(self.module.os, "O_NOFOLLOW", None),
                self.assertRaisesRegex(
                    self.module.MaterializationError,
                    "requires O_NOFOLLOW support",
                ),
            ):
                self.module.protected_asset_bytes(protected, "prompt")

    def test_empty_and_oversized_diffs_fail_closed(self) -> None:
        for name, diff in (("empty", b""), ("oversized", b"x" * 200_000)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(
                    self.module.MaterializationError,
                    "must contain 1..199999 bytes",
                ):
                    self.materialize(diff, Path(temporary).resolve() / "review")

    def test_workspace_creation_failure_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "missing-parent" / "review"
            with self.assertRaisesRegex(
                self.module.MaterializationError,
                "Unable to create the exact-revision review workspace",
            ):
                self.module.write_materialized_workspace(
                    output,
                    b"bounded diff\n",
                    {},
                )

    def test_dispatch_must_run_from_exact_protected_base(self) -> None:
        self.arguments.dispatch_ref = "refs/heads/main"
        with self.assertRaisesRegex(self.module.MaterializationError, "protected pull-request base ref"):
            self.module.validate_inputs(self.arguments)
        self.arguments.dispatch_ref = "refs/heads/develop"
        self.arguments.trusted_workflow_sha = "e" * 40
        with self.assertRaisesRegex(self.module.MaterializationError, "workflow SHA"):
            self.module.validate_inputs(self.arguments)

    def test_verify_rejects_missing_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            review = root / "review"
            review.mkdir()
            (review / "change.patch").write_bytes(b"bounded diff\n")
            metadata = {key: None for key in self.module.IMMUTABLE_METADATA_KEYS}
            (review / "review-metadata.json").write_text(
                json.dumps(metadata) + "\n",
                encoding="utf-8",
            )
            with (
                mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root / "missing")}),
                self.assertRaisesRegex(
                    self.module.MaterializationError,
                    "RUNNER_TEMP must identify an existing directory",
                ),
            ):
                self.module.verify(self.arguments, review, {})

    def test_verify_rejects_oversized_stored_diff_before_regeneration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            review = Path(temporary).resolve() / "review"
            review.mkdir()
            (review / "change.patch").write_bytes(b"x" * self.module.MAX_REVIEW_BYTES)
            (review / "review-metadata.json").write_text("{}\n", encoding="utf-8")
            with (
                mock.patch.object(self.module, "materialize") as materialize,
                self.assertRaisesRegex(
                    self.module.MaterializationError,
                    "must be between 1 and 199999 bytes",
                ),
            ):
                self.module.verify(self.arguments, review, {})
            materialize.assert_not_called()

    def test_verify_requires_the_exact_protected_metadata_shape(self) -> None:
        for name, metadata, expected_error in (
            ("non-object", [], "must be a JSON object"),
            ("unexpected-key", {"attacker_controlled": True}, "unexpected=\\['attacker_controlled'\\]"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                review = Path(temporary).resolve() / "review"
                review.mkdir()
                (review / "change.patch").write_bytes(b"bounded diff\n")
                (review / "review-metadata.json").write_text(
                    json.dumps(metadata) + "\n",
                    encoding="utf-8",
                )
                with (
                    mock.patch.object(self.module, "materialize") as materialize,
                    self.assertRaisesRegex(self.module.MaterializationError, expected_error),
                ):
                    self.module.verify(self.arguments, review, {})
                materialize.assert_not_called()

    def test_live_binding_rejects_non_release_app_author(self) -> None:
        payload = {
            "state": "open",
            "draft": False,
            "user": {"login": "another-bot[bot]", "type": "Bot"},
            "base": {
                "ref": self.arguments.base_ref,
                "sha": self.arguments.expected_base,
                "repo": {"full_name": self.arguments.repository},
            },
            "head": {
                "sha": self.arguments.expected_head,
                "repo": {"full_name": self.arguments.repository},
            },
        }
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "unit-test-token"}),
            mock.patch.object(self.module, "executable", return_value="/usr/bin/gh"),
            mock.patch.object(self.module, "run", return_value=completed),
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(self.module.MaterializationError, "unauthorized"),
        ):
            self.module.read_live_pull_request(self.arguments, home=Path(temporary).resolve())


class ExactRevisionWorkflowContractTests(unittest.TestCase):
    def test_release_app_review_is_protected_and_final_revision_only(self) -> None:
        workflow = (ROOT / ".github/workflows/release-bot-exact-head-review.yml").read_text(encoding="utf-8")
        self.assertTrue(workflow.startswith("# Managed by lightning-it/shared-assets-lit."))
        self.assertIn("# Do not edit downstream copies directly.", workflow)
        trigger = workflow.split("on:", 1)[1].split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("pull_request_target:", trigger)
        self.assertNotIn("opened", trigger)
        self.assertNotIn("synchronize", trigger)
        self.assertIn("github.actor == 'lightning-it-release-automation[bot]'", workflow)
        self.assertIn("      actions: read\n      checks: write", workflow)
        self.assertIn("checks: write", workflow)
        self.assertNotIn("actions/checkout@", workflow)
        self.assertEqual(9, workflow.count("load_protected_asset"))
        for protected_path in (
            "scripts/materialize-exact-revision-review.py",
            ".github/codex/prompts/review-exact-head.md",
            ".github/codex/schemas/exact-head-review.schema.json",
            ".github/workflows/release-bot-exact-head-review.yml",
            ".github/workflows/current-revision-rerun.yml",
            ".github/workflows/copilot-review.yml",
        ):
            self.assertIn(protected_path, workflow)
        self.assertEqual(1, workflow.count("?ref=${TRUSTED_WORKFLOW_SHA}"))
        self.assertIn("permission-profile: :read-only", workflow)
        steps = yaml.safe_load(workflow)["jobs"]["exact-revision-codex-review"]["steps"]
        args = next(step["with"]["codex-args"] for step in steps if "openai/codex-action@" in step.get("uses", ""))
        alternatives = [json.loads(value) for value in re.findall(r"'(\[.*?\])'", args)]
        self.assertEqual(2, len(alternatives))
        self.assertTrue(all("--ephemeral" in values for values in alternatives))
        self.assertIn('web_search="disabled"', alternatives[0])
        self.assertIn("name: Current revision review", workflow)
        self.assertIn("mlx90-exact-revision:v5:${input_sha256}:", workflow)
        self.assertIn("mlx90-current-revision:v4:${producer_run_id}:${input_sha256}", workflow)
        self.assertNotIn("mlx90-legacy-exact-revision:", workflow)
        self.assertNotIn("Successful Copilot review", workflow)
        has_legacy_publisher = "publish_once() {" in workflow
        has_durable_publisher = "create_reservation_once() {" in workflow
        self.assertTrue(has_legacy_publisher or has_durable_publisher)
        if has_legacy_publisher:
            (
                _before_publisher,
                definition_marker,
                publisher_and_invocation,
            ) = workflow.partition("publish_once() {")
            self.assertEqual("publish_once() {", definition_marker)
            publisher, invocation_marker, _after_publisher = publisher_and_invocation.partition(
                "publish_once \\",
            )
            self.assertEqual("publish_once \\", invocation_marker)
            self.assertIn("select(.name == $name)", publisher)
            self.assertIn('jq -rn --arg value "${check_name}"', publisher)
            self.assertNotIn('jq -n --arg value "${check_name}"', publisher)
            self.assertIn(
                'select(.app.id == 15368 and .app.slug == "github-actions")',
                publisher,
            )
            self.assertNotIn(
                "select(.name == $name and .external_id == $external_id)",
                publisher,
            )
            self.assertNotIn("current_external_id", publisher)
            self.assertIn("strict status policy", publisher)
            self.assertIn('completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"', workflow)
            self.assertIn('-f "completed_at=${completed_at}"', workflow)
            self.assertIn("and .completed_at == $completed_at", workflow)
        if has_durable_publisher:
            self.assertIn("-f name='Protected Exact-Revision Codex result'", workflow)
            self.assertIn(
                "actions/workflows/release-bot-exact-head-review.yml/runs?",
                workflow,
            )
            self.assertIn(
                "The durable workflow ledger does not contain exactly one protected AI invocation",
                workflow,
            )
            self.assertIn("Reusing the protected PASS for identical input", workflow)
        self.assertTrue("'Current revision review'" in workflow or "-f name='Current revision review'" in workflow)
        self.assertIn('select(.app.id == 15368 and .app.slug == "github-actions")', workflow)
        self.assertIn("filter=all", workflow)
        self.assertIn("per_page=100", workflow)
        self.assertIn("automatic retry is forbidden", workflow)
        self.assertIn("input_sha256 == $bound.input_sha256", workflow)
        self.assertIn('and .path == ".github/workflows/release-bot-exact-head-review.yml"', workflow)
        self.assertIn("and .display_title == $title", workflow)
        self.assertIn("and .triggering_actor.login == $actor", workflow)
        self.assertEqual(1, workflow.count("and .run_attempt == 1"))
        self.assertEqual(1, workflow.count("uses: openai/codex-action@"))

    def test_ruleset_workflow_verifies_the_producer_instead_of_trusting_a_check_name(self) -> None:
        rerun = (ROOT / ".github/workflows/current-revision-rerun.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", rerun)
        workflow_call_inputs = rerun.split("  workflow_call:", 1)[1].split("  workflow_dispatch:", 1)[0]
        dispatch_inputs = rerun.split("  workflow_dispatch:", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(2, workflow_call_inputs.count("required: false"))
        self.assertEqual(3, workflow_call_inputs.count("required: true"))
        self.assertEqual(0, workflow_call_inputs.count('default: ""'))
        self.assertEqual(5, dispatch_inputs.count("required: true"))
        self.assertEqual(1, dispatch_inputs.count("required: false"))
        self.assertIn("producer_run_attempt:", dispatch_inputs)
        self.assertIn("default: 0", dispatch_inputs)
        self.assertEqual(0, dispatch_inputs.count('default: ""'))
        self.assertIn('test "${GITHUB_REF}" = "refs/heads/${EVENT_BASE_REF}"', rerun)
        self.assertIn('[[ "${EVENT_BASE_REF}" =~ ^(develop|main)$ ]]', rerun)
        self.assertIn(
            '.path == ".github/workflows/supplementary-current-revision-required.yml"',
            rerun,
        )
        self.assertIn("/actions/required_workflows/", rerun)
        self.assertIn('(.workflow_id | type == "number" and . > 0)', rerun)
        self.assertNotIn(
            '.name == "Protected Supplementary current-revision evidence verifier"',
            rerun,
        )
        self.assertIn("rep60-required-workflow:v2:", rerun)
        self.assertIn(".producer_run_id", rerun)
        self.assertIn(".output.summary | fromjson", rerun)
        self.assertIn(
            "${GITHUB_SERVER_URL}/${REPOSITORY}/runs/${neutral_check_id}",
            rerun,
        )
        self.assertIn(
            "${GITHUB_SERVER_URL}/${REPOSITORY}/runs/${reservation_id}",
            rerun,
        )
        self.assertNotIn(
            "producer_url=\"$(jq -r '.[0].details_url // empty'",
            rerun,
        )
        self.assertEqual(1, rerun.count(".triggering_actor.login == $actor"))
        retry = rerun.split(
            '          case "${verifier_conclusion}" in',
            1,
        )[1]
        self.assertIn('case "${verifier_conclusion}" in', rerun)
        self.assertIn("run_attempt=", retry)
        self.assertIn('if [ "${run_attempt}" -gt 2 ]', retry)
        self.assertIn('if [ "${run_attempt}" -eq 2 ]', retry)
        self.assertIn(
            "repos/${REPOSITORY}/actions/runs/${run_id}/attempts/1/jobs?filter=all&per_page=100",
            retry,
        )
        self.assertIn("synthetic_evidence_jobs=$(jq -c", retry)
        for variable, name in (
            ("synthetic_authorization_jobs", "Authorize exact Supplementary catch-up v5 successor"),
            ("synthetic_promotion_jobs", "Verify aggregated develop-to-main promotion evidence"),
        ):
            self.assertIn(f"{variable}=$(jq -c", retry)
            self.assertIn(f'.name == "{name}"', retry)
        self.assertIn('runner("Route protected current-revision verification"; "success")', retry)
        self.assertIn('runner("Legacy protected current-revision verifier"; "failure")', retry)
        self.assertIn('runner("Required current-revision workflow"; "failure")', retry)
        self.assertIn('skipped("Reserve protected S0 feature-to-main verification")', retry)
        self.assertIn('skipped("Verify protected S0 feature-to-main input")', retry)
        self.assertIn('skipped("Finalize the protected S0 feature-to-main result")', retry)
        self.assertIn("((map(.name) | unique | length) == length)", retry)
        self.assertIn("repos/${REPOSITORY}/actions/jobs/${required_job_id}/rerun", retry)
        self.assertNotIn(
            "repos/${REPOSITORY}/actions/runs/${run_id}/rerun",
            retry,
        )
        self.assertEqual(1, retry.count('/rerun" >/dev/null'))
        self.assertIn('if [ "${observed_attempt}" -ne 2 ]', retry)
        self.assertIn(".external_id == $external_id", retry)
        self.assertIn(".id == $check_id", retry)
        self.assertIn('test "$(jq \'length\' <<<"${post_neutral}")" -eq 1', retry)
        required_run = rerun.split(
            'run="$(gh api "repos/${REPOSITORY}/actions/runs/${run_id}")"',
            1,
        )[1].split('if [ "$(jq -r .conclusion <<<"${run}")" = success ]', 1)[0]
        self.assertIn(
            "head_repository=\"$(jq -er '.head.repo.full_name",
            rerun,
        )
        self.assertIn('--arg base_ref "${base_ref}"', required_run)
        self.assertIn('--arg head_ref "${head_ref}"', required_run)
        self.assertIn('--arg head_repository "${head_repository}"', required_run)
        self.assertIn('--arg head_sha "${EXPECTED_HEAD}"', required_run)
        self.assertIn(".head_branch == $head_ref", required_run)
        self.assertIn(".head_sha == $head_sha", required_run)
        self.assertIn(".pull_requests[0].base.ref == $base_ref", required_run)
        self.assertIn(
            '.pull_requests[0].head.repo.url == ($api_url + "/repos/" + $head_repository)',
            required_run,
        )
        self.assertNotIn(".head_branch == $base_ref", required_run)
        self.assertNotIn(".head_sha == $base_sha", required_run)
        self.assertNotIn(
            "and .head.repo.full_name == $repository",
            required_run,
        )

    def test_review_producers_request_only_the_protected_verifier_rerun(self) -> None:
        for name in ("copilot-review.yml", "release-bot-exact-head-review.yml"):
            with self.subTest(workflow=name):
                workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                rerun_job_marker = "  request-protected-verifier-reevaluation:"
                if name == "copilot-review.yml":
                    rerun_job_marker = "  request-protected-verifier-reevaluation-develop:"
                rerun_job = workflow.split(rerun_job_marker, 1)[1]
                self.assertIn("actions: write", rerun_job)
                if name == "copilot-review.yml":
                    develop_job, main_jobs = rerun_job.split("  validate-protected-main-helper-pin:", 1)
                    main_guard, main_job = main_jobs.split(
                        "  request-protected-verifier-reevaluation-main:",
                        1,
                    )
                    self.assertIn("uses: ./.github/workflows/current-revision-rerun.yml", develop_job)
                    self.assertIn(
                        "uses: lightning-it/ansible-collection-supplementary/.github/workflows/"
                        "current-revision-rerun.yml@64451b42ec9d03c47ba8156f0952c139c0744648",
                        main_job,
                    )
                    self.assertIn(
                        "github.event.pull_request.base.sha == '64451b42ec9d03c47ba8156f0952c139c0744648'",
                        main_job,
                    )
                    self.assertIn(
                        "PINNED_MAIN_HELPER: 64451b42ec9d03c47ba8156f0952c139c0744648",
                        main_guard,
                    )
                    self.assertIn('if [ "${EVENT_BASE}" != "${PINNED_MAIN_HELPER}" ]; then', main_guard)
                    self.assertIn('live_main="$(gh api "repos/${REPOSITORY}/branches/main")"', main_guard)
                    self.assertIn("and .protected == true", main_guard)
                    self.assertIn("and .commit.sha == $event_base", main_guard)
                    self.assertIn(
                        "needs.validate-protected-main-helper-pin.result == 'success'",
                        main_job,
                    )
                    legacy_rerun = rerun_job.split("  dispatch-event-verifier-reevaluation:", 1)[0]
                    self.assertNotIn("current-revision-rerun.yml/dispatches", legacy_rerun)
                    self.assertNotIn('-f "ref=${BASE_REF}"', legacy_rerun)
                    for required_input in (
                        "base_ref: ${{ github.event.pull_request.base.ref }}",
                        "pr_number: ${{ github.event.pull_request.number }}",
                        "expected_base: ${{ github.event.pull_request.base.sha }}",
                        "expected_head: ${{ github.event.pull_request.head.sha }}",
                        "producer_run_id: ${{ github.run_id }}",
                    ):
                        self.assertIn(required_input, develop_job)
                        self.assertIn(required_input, main_job)
                    self.assertNotIn("openai/codex-action@", rerun_job)
                    continue
                self.assertIn("current-revision-rerun.yml/dispatches", rerun_job)
                self.assertIn('-f "ref=${BASE_REF}"', rerun_job)
                self.assertIn('-f "inputs[base_ref]=${BASE_REF}"', rerun_job)
                self.assertIn('-f "inputs[pr_number]=${PR_NUMBER}"', rerun_job)
                self.assertIn('-f "inputs[expected_base]=${EXPECTED_BASE}"', rerun_job)
                self.assertIn('-f "inputs[expected_head]=${EXPECTED_HEAD}"', rerun_job)
                self.assertIn('-f "inputs[producer_run_id]=${PRODUCER_RUN_ID}"', rerun_job)
                legacy_binding = 'test "${GITHUB_WORKFLOW_SHA}" = "${EXPECTED_BASE}"'
                explicit_binding = 'test "${EXECUTED_WORKFLOW_SHA}" = "${EXPECTED_BASE}"'
                self.assertEqual(
                    1,
                    rerun_job.count(legacy_binding) + rerun_job.count(explicit_binding),
                    "the protected release workflow SHA must have exactly one base binding",
                )
                if explicit_binding in rerun_job:
                    self.assertIn(
                        "EXECUTED_WORKFLOW_SHA: ${{ github.workflow_sha }}",
                        rerun_job,
                    )
                self.assertIn('test "${GITHUB_REF}" = "refs/heads/${BASE_REF}"', rerun_job)
                self.assertIn('test "${GITHUB_REF_PROTECTED}" = true', rerun_job)
                self.assertIn('test "${live_base}" = "${EXPECTED_BASE}"', rerun_job)
                self.assertNotIn('-F "inputs[pr_number]=${PR_NUMBER}"', rerun_job)
                self.assertNotIn("openai/codex-action@", rerun_job)
                self.assertIn("BASE_REF: ${{ inputs.base_ref }}", rerun_job)

    def test_human_current_revision_path_protects_main_and_develop(self) -> None:
        workflow = (ROOT / ".github/workflows/copilot-review.yml").read_text(encoding="utf-8")
        binding = 'base_ref="$(jq -er \'.base.ref | select(. == "develop" or . == "main")\''
        self.assertEqual(workflow.count(binding), 2)
        self.assertIn(
            "mlx90-current-revision:${external_kind}:v6:${PR_NUMBER}:${GITHUB_RUN_ID}:${EVENT_BASE}:${EVENT_HEAD}",
            workflow,
        )
        self.assertIn(
            "'{schema:4,base_sha:$base,head_sha:$head,head_repository:$head_repository,",
            workflow,
        )
        self.assertIn("controller_sha:$controller", workflow)
        producer_step_marker = "      - name: Publish bound neutral result"
        _before_producer, found_producer_step, producer_and_following = workflow.partition(producer_step_marker)
        self.assertEqual(producer_step_marker, found_producer_step)
        publisher_marker = "          publish_once() {"
        producer, found_publisher, _following = producer_and_following.partition(publisher_marker)
        self.assertEqual(publisher_marker, found_publisher)
        for field in (
            "head_repository:$head_repository",
            "controller_ref:$controller_ref",
            "pull_request_labels_sha256:$labels_sha256",
        ):
            self.assertIn(field, producer)
        self.assertIn("pull_request_number:$pr_number", workflow)
        self.assertIn("producer_run_id:$run_id", workflow)
        self.assertIn("read_named_checks() {", workflow)
        self.assertIn(
            "select(.name == $name)",
            workflow,
        )
        self.assertIn('select(.app.id == 15368 and .app.slug == "github-actions")', workflow)
        self.assertIn('if [ "${count}" -gt 1 ]; then', workflow)
        self.assertIn("Multiple protected ${check_name} results exist", workflow)
        self.assertIn("read_metadata_revision() {", workflow)
        self.assertIn("pull_request_last_edited_at", workflow)
        self.assertIn(
            "mlx90-current-revision:metadata-${reservation_kind}:v1:${PR_NUMBER}:${GITHUB_RUN_ID}:${EVENT_BASE}:${EVENT_HEAD}",
            workflow,
        )
        self.assertIn("read_labels_sha256() {", workflow)
        self.assertIn("pull-request metadata, labels, or review state changed during result publication", workflow)
        self.assertIn(".external_id == $external and .output.summary == $evidence", workflow)
        self.assertIn("${GITHUB_SERVER_URL}/${REPOSITORY}/runs/${check_id}", workflow)
        self.assertIn('-f "details_url=${check_url}"', workflow)
        self.assertIn('publication_details "${check_id}" "${external_id}" "${check_url}" || return 1', workflow)
        self.assertIn('publication_read "${check_id}" "${external_id}" any "${url}" || return 1', workflow)
        self.assertIn("A prior native publisher consumed every uncertain mutation", workflow)

    def test_release_app_is_excluded_except_bound_ancestry_backmerge(self) -> None:
        workflow = (ROOT / ".github/workflows/copilot-review.yml").read_text(encoding="utf-8")
        request_job = workflow.split("  request-current-revision-review:", 1)[1].split(
            "  verify-current-revision-policy:", 1
        )[0]
        review_job = workflow.split("  verify-current-revision-policy:", 1)[1].split(
            "  request-protected-verifier-reevaluation-develop:",
            1,
        )[0]
        self.assertIn("github.event.pull_request.user.login == 'litroc'", request_job)
        self.assertIn('test "$(jq -r .user.login <<<"${pr}")" = litroc', request_job)
        self.assertNotIn("Contributor-funded review required", request_job)
        self.assertIn('if [ "${EXPECTED_BASE_REF}" = develop ]; then', request_job)
        self.assertIn('test "${TRUSTED_WORKFLOW_SHA}" = "${EXPECTED_BASE}"', request_job)
        self.assertIn('test "${EXPECTED_BASE_REF}" = main', request_job)
        self.assertIn(
            "${REPOSITORY}/.github/workflows/copilot-review.yml@refs/heads/${DEFAULT_BRANCH}",
            request_job,
        )
        self.assertNotIn("compare/${TRUSTED_WORKFLOW_SHA}...${default_head}", request_job)
        self.assertIn('test "${TRUSTED_WORKFLOW_SHA}" = "${default_head}"', request_job)
        self.assertIn('[[ "${default_head}" =~ ^[0-9a-f]{40}$ ]]', request_job)
        self.assertIn("and .protected == true", request_job)
        self.assertIn("pull_request_target:", workflow)
        self.assertNotIn("pull_request_review:", workflow)
        self.assertNotIn("\n  workflow_dispatch:", workflow)
        condition = review_job.split("    if: >-", 1)[1].split("    permissions:", 1)[0]
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", condition)
        self.assertIn("github.event.pull_request.user.login != 'lightning-it-release-automation[bot]'", condition)
        self.assertNotIn("github.event.pull_request.user.login == 'lightning-it-release-automation[bot]'", condition)
        self.assertIn("github.event.pull_request.base.ref == 'develop'", condition)
        self.assertIn("startsWith(github.event.pull_request.head.ref, 'backmerge/')", condition)
        self.assertIn(
            "'chore(governance): record main ancestry before '",
            condition,
        )
        self.assertNotIn("endsWith(github.event.pull_request.head.ref, '-main')", condition)
        self.assertIn(
            "expected_backmerge_author='lightning-it-release-automation[bot]'",
            review_job,
        )
        self.assertIn('test "${author}" = "${expected_backmerge_author}"', review_job)
        self.assertIn(
            "test \"${author}\" != 'lightning-it-release-automation[bot]'",
            review_job,
        )
        self.assertIn("name: Verify current revision policy", review_job)
        self.assertNotIn("\n    name: Current revision review\n", workflow)
        self.assertNotIn("\n    name: Successful Copilot review\n", workflow)
        self.assertNotIn("mlx90-legacy-copilot:", workflow)
        self.assertNotIn("'Successful Copilot review'", review_job)
        self.assertIn('-f name="${check_name}"', review_job)
        self.assertIn('if [ "${EVENT_BASE_REF}" = develop ]; then', review_job)
        self.assertIn('test "${TRUSTED_WORKFLOW_SHA}" = "${EVENT_BASE}"', review_job)
        self.assertIn('test "${EVENT_BASE_REF}" = main', review_job)
        self.assertIn(
            "${REPOSITORY}/.github/workflows/copilot-review.yml@refs/heads/${DEFAULT_BRANCH}",
            review_job,
        )
        self.assertNotIn("compare/${TRUSTED_WORKFLOW_SHA}...${default_head}", review_job)
        self.assertIn('test "${TRUSTED_WORKFLOW_SHA}" = "${default_head}"', review_job)
        self.assertIn('[[ "${default_head}" =~ ^[0-9a-f]{40}$ ]]', review_job)
        self.assertEqual(1, review_job.count("and .protected == true"))
        self.assertIn('--arg controller_ref "${DEFAULT_BRANCH}"', review_job)
        self.assertEqual(1, request_job.count("EXPECTED_HEAD_REF: ${{ github.event.pull_request.head.ref }}"))
        self.assertIn('--arg branch "${EXPECTED_HEAD_REF}"', request_job)
        self.assertIn('--arg sha "${EXPECTED_HEAD}"', request_job)
        self.assertIn("EVENT_HEAD_REF: ${{ github.event.pull_request.head.ref }}", review_job)
        self.assertIn("EVENT_HEAD_REPOSITORY: ${{ github.event.pull_request.head.repo.full_name }}", review_job)
        self.assertIn('--arg branch "${EVENT_HEAD_REF}"', review_job)
        self.assertIn('--arg head_repository "${EVENT_HEAD_REPOSITORY}"', review_job)
        self.assertIn('--arg sha "${EVENT_HEAD}"', review_job)
        self.assertIn(".head_branch == $branch", review_job)
        self.assertIn(".head_sha == $sha", review_job)
        self.assertIn("The one exact-head Copilot request was already consumed", request_job)
        self.assertIn("Copilot review request accepted", request_job)
        self.assertNotIn("review_is_visible_for_head()", request_job)
        self.assertNotIn("--method DELETE", request_job)

        rerun_job = workflow.split("  request-protected-verifier-reevaluation-develop:", 1)[1]
        self.assertIn("pr_number: ${{ github.event.pull_request.number }}", rerun_job)
        self.assertNotIn('-F "inputs[pr_number]=${PR_NUMBER}"', rerun_job)

    def test_human_producer_verifier_separates_event_head_from_controller_sha(self) -> None:
        rerun = (ROOT / ".github/workflows/current-revision-rerun.yml").read_text(encoding="utf-8")
        author_paths = rerun.split(
            '            elif [ "${external_kind}" = managed-sync ]; then',
            1,
        )[1]
        human_path = author_paths.split("            else\n", 1)[1].split(
            "\n          fi\n\n          reservations=''", 1
        )[0]
        self.assertIn(".controller_sha", human_path)
        self.assertIn('test "${default_branch}" = develop', rerun)
        self.assertIn("compare/${controller_sha}...${default_head}", human_path)
        self.assertIn('--arg head_ref "${head_ref}"', human_path)
        self.assertIn('--arg head_sha "${EXPECTED_HEAD}"', human_path)
        self.assertIn(".head_branch == $head_ref", human_path)
        self.assertIn(".head_sha == $head_sha", human_path)
        self.assertNotIn(".head_branch == $default_branch", human_path)
        self.assertNotIn(".head_sha == $controller_sha", human_path)

    def test_release_app_pr_creators_finalize_draft_once(self) -> None:
        # Release metadata still needs Exact-Revision review. A develop-to-main
        # promotion instead opens with v2 native-ingress aggregation evidence.
        for name in (
            "release-prepare.yml",
            "release-back-sync.yml",
        ):
            with self.subTest(workflow=name):
                workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                self.assertIn("--draft", workflow)
                self.assertIn("gh pr ready", workflow)
                self.assertIn("lightning-it-release-automation[bot]", workflow)
                self.assertIn("gh workflow run release-bot-exact-head-review.yml", workflow)
                self.assertIn("permission-actions: write", workflow)
                self.assertIn("expected_base=", workflow)
                self.assertIn("expected_head=", workflow)
                self.assertLess(
                    workflow.index("gh pr ready"),
                    workflow.index("gh workflow run release-bot-exact-head-review.yml"),
                )
        ancestry = (ROOT / ".github/workflows/sync-main-to-develop.yml").read_text(encoding="utf-8")
        self.assertNotIn("--draft", ancestry)
        self.assertNotIn("gh pr ready", ancestry)
        self.assertNotIn("id: review-dispatch-app", ancestry)
        self.assertNotIn("permission-actions: write", ancestry)
        self.assertNotIn("release-bot-exact-head-review.yml", ancestry)
        self.assertNotIn("Dispatch protected Exact-Revision review", ancestry)
        self.assertNotIn("gh workflow run", ancestry)
        self.assertIn(".isDraft == false", ancestry)
        self.assertIn("and .headRefOid == $expected_head", ancestry)
        self.assertIn("mergeMethod:MERGE", ancestry)
        self.assertIn("Enable protected ancestry auto-merge", ancestry)
        self.assertNotIn("openai/codex-action", ancestry)
        self.assertNotIn("copilot", ancestry.lower())
        release_prepare = (ROOT / ".github/workflows/release-prepare.yml").read_text(encoding="utf-8")
        self.assertIn('gh pr ready "$existing" --repo "$GITHUB_REPOSITORY"', release_prepare)
        release_edit = release_prepare.split('gh pr edit "$existing"', 1)[1].split("--title", 1)[0]
        self.assertIn('--repo "$GITHUB_REPOSITORY"', release_edit)
        release_dispatch = release_prepare.split("gh workflow run release-bot-exact-head-review.yml", 1)[1].split(
            "expected_head", 1
        )[0]
        self.assertIn('--repo "$GITHUB_REPOSITORY"', release_dispatch)

    def test_exact_revision_result_is_validated_as_one_object(self) -> None:
        workflow = (ROOT / ".github/workflows/release-bot-exact-head-review.yml").read_text(encoding="utf-8")
        self.assertIn(". as $result | $metadata[0] as $bound |", workflow)
        self.assertNotIn(".[0] as $result | $metadata[0] as $bound |", workflow)

    def test_main_backmerge_has_deterministic_reviewable_evidence(self) -> None:
        workflow = (ROOT / ".github/workflows/sync-main-to-develop.yml").read_text(encoding="utf-8")
        changelog_policy = (ROOT / "scripts/devtools-changelog-check.sh").read_text(encoding="utf-8")
        self.assertIn("Create reviewable ancestry backmerge", workflow)
        self.assertIn("git merge --no-ff --no-commit --strategy=ours origin/main", workflow)
        self.assertIn("evidence_path='.lit/main-ancestry.json'", workflow)
        self.assertIn('test "$(git diff --name-only origin/develop HEAD --)"', workflow)
        self.assertNotIn("Create file-identical ancestry backmerge", workflow)
        self.assertNotIn("git diff --quiet origin/develop HEAD", workflow)
        self.assertIn('non_user_visible_re+="\\\\.lit/main-ancestry\\\\.json$|"', changelog_policy)

        evidence = json.loads((ROOT / ".lit/main-ancestry.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["schema_version"], 1)
        self.assertEqual(evidence["repository"], "lightning-it/ansible-collection-supplementary")
        self.assertRegex(evidence["main_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(evidence["develop_parent_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(evidence["purpose"], "Bind the reviewed main ancestry backmerge.")

    def test_external_contributors_are_never_auto_funded(self) -> None:
        workflow = (ROOT / ".github/workflows/copilot-review.yml").read_text(encoding="utf-8")
        request_job = workflow.split("  request-current-revision-review:", 1)[1].split(
            "  verify-current-revision-policy:", 1
        )[0]
        self.assertIn("github.event.pull_request.user.login == 'litroc'", request_job)
        self.assertIn('test "$(jq -r .user.login <<<"${pr}")" = litroc', request_job)
        self.assertNotIn("Contributor-funded review required", request_job)
        policy = (ROOT / "docs/mlx90-exact-revision-codex-review.md").read_text(encoding="utf-8")
        self.assertIn("exact account\n`litroc`", policy)
        self.assertIn("under their own", policy)
        self.assertIn("never requests or funds", policy)


if __name__ == "__main__":
    unittest.main()
