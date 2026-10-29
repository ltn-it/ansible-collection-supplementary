"""Regression tests for the collection's GitHub Actions trust boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / ".github" / "actions" / "run-quality-profile" / "action.yml"
SCORECARD_ACTION = ROOT / ".github" / "actions" / "run-scorecard" / "action.yml"
PINNED_USE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
PINNED_DOCKER_USE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{path} is not a YAML mapping")
    return payload


def uses_values(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "uses" and isinstance(nested, str):
                found.append(nested)
            found.extend(uses_values(nested))
    elif isinstance(value, list):
        for nested in value:
            found.extend(uses_values(nested))
    return found


def docker_action_image(path: Path) -> str | None:
    payload = load_yaml(path)
    runs = payload.get("runs")
    if not isinstance(runs, dict) or runs.get("using") != "docker":
        return None
    image = runs.get("image")
    return image if isinstance(image, str) else None


class WorkflowSecurityTests(unittest.TestCase):
    def test_rep60_bootstrap_controllers_are_absent_after_cutover(self) -> None:
        for name in (
            "rep60-bootstrap-app-rearm.yml",
            "rep60-bootstrap-protected-review-alias.yml",
            "rep60-develop-bootstrap-review-alias.yml",
        ):
            with self.subTest(workflow=name):
                self.assertFalse((WORKFLOWS / name).exists())

    def test_copilot_instructions_bind_the_exact_agent_contract(self) -> None:
        agents_digest = hashlib.sha256((ROOT / "AGENTS.md").read_bytes()).hexdigest()
        instructions = (ROOT / ".github" / "copilot-instructions.md").read_text(encoding="utf-8").splitlines()
        while instructions and not instructions[-1].strip():
            instructions.pop()
        self.assertEqual(
            [
                "<!-- Managed contract: Codex and Copilot must apply AGENTS.md. -->",
                f"<!-- AGENTS_SHA256: {agents_digest} -->",
            ],
            instructions[-2:],
        )

    def test_quality_cells_install_only_the_prebuilt_exact_candidate(self) -> None:
        action = ACTION.read_text(encoding="utf-8")
        install = re.search(
            r"ansible-galaxy collection install \\\n(?P<body>(?:\s+.*\n){1,8})",
            action,
        )
        self.assertIsNotNone(install)
        command = install.group(0) if install is not None else ""
        self.assertIn('"${candidates[0]}"', command)
        self.assertIn("--force", command)
        self.assertIn("--no-deps", command)
        self.assertIn("runtime-collections.tar.gz", action)
        self.assertIn('path.parts[0] != "ansible_collections"', action)
        self.assertIn("member.issym()", action)
        self.assertIn("member.islnk()", action)
        self.assertIn("absolute runtime collection link", action)
        self.assertIn("escaping runtime collection link", action)
        self.assertIn("duplicate runtime collection member", action)
        self.assertIn('"members": members', action)
        self.assertIn('extract_arguments["filter"] = "data"', action)
        self.assertIn("C.COLLECTIONS_PATHS", action)
        self.assertIn("missing declared runtime collections", action)
        self.assertIn(
            "ANSIBLE_COLLECTIONS_PATH=$QUALITY_INSTALL_ROOT:$default_collection_paths",
            action,
        )
        workflow = (WORKFLOWS / "collection-ci.yml").read_text(encoding="utf-8")
        self.assertIn("-czf dist/candidate/runtime-collections.tar.gz", workflow)
        self.assertIn("--exclude=ansible_collections/lit/supplementary", workflow)
        self.assertIn("for path, _ in members", workflow)
        self.assertIn("runtime collection bundle contains the candidate collection", workflow)
        self.assertIn("runtime-collections.tar.gz \\", workflow)

    def test_release_evidence_selects_only_the_collection_candidate_and_exact_head(self) -> None:
        workflow = (WORKFLOWS / "collection-ci.yml").read_text(encoding="utf-8")
        self.assertIn("-name 'lit-supplementary-*.tar.gz'", workflow)
        self.assertIn('.glob("lit-supplementary-*.tar.gz")', workflow)
        self.assertNotIn('.glob("*.tar.gz")', workflow)
        self.assertNotIn(
            "find artifacts/candidate -maxdepth 1 -type f -name '*.tar.gz'",
            workflow,
        )

        publish_workflow = (WORKFLOWS / "collection-publish.yml").read_text(encoding="utf-8")
        self.assertIn("-name 'lit-supplementary-*.tar.gz'", publish_workflow)
        self.assertNotIn("-name '*.tar.gz'", publish_workflow)
        self.assertIn(
            "'$2 == candidate { print }'",
            publish_workflow,
        )
        self.assertNotIn(
            "cp incoming/candidate/candidate-SHA256SUMS",
            publish_workflow,
        )

        payload = load_yaml(WORKFLOWS / "collection-ci.yml")
        self.assertNotIn("QUALITY_SOURCE_SHA", payload["env"])
        self.assertEqual(
            payload["env"]["SOURCE_SHA"],
            payload["jobs"]["runtime-evidence"]["env"]["QUALITY_SOURCE_SHA"],
        )

    def test_keycloak_cells_reserve_memory_for_the_full_runtime_stack(self) -> None:
        collection = load_yaml(WORKFLOWS / "collection-ci.yml")
        tiny_action = next(
            step
            for step in collection["jobs"]["tiny-cells"]["steps"]
            if step.get("uses") == "./.github/actions/run-quality-profile"
        )
        self.assertEqual("12GiB", tiny_action["with"]["memory-limit"])
        for job_name, required_output in (
            ("heavy-cells", "heavy_required"),
            ("acceptance-cells", "acceptance_required"),
        ):
            guard = collection["jobs"][job_name]["if"]
            self.assertIn("github.event_name == 'push'", guard)
            self.assertIn("github.ref == 'refs/heads/main'", guard)
            self.assertIn(f"quality-matrix.outputs.{required_output} == 'true'", guard)
            self.assertNotIn("pull_request", guard)
            self.assertNotIn("workflow_dispatch", guard)
        self.assertFalse((WORKFLOWS / "candidate-platform-validation.yml").exists())

    def test_copilot_and_renovate_gates_preserve_safe_update_boundaries(self) -> None:
        copilot = (WORKFLOWS / "copilot-review.yml").read_text(encoding="utf-8")
        renovate = (WORKFLOWS / "renovate-guarded-automerge.yml").read_text(encoding="utf-8")
        changelog = (WORKFLOWS / "changelog.yml").read_text(encoding="utf-8")
        collection_ci = load_yaml(WORKFLOWS / "collection-ci.yml")

        self.assertIn('([.labels[].name] | index("safe-automerge") != null)', copilot)
        self.assertIn('([.labels[].name] | index("breaking-update") == null)', copilot)
        self.assertIn('$events[.].event == "labeled"', copilot)
        self.assertIn("$events[$last_safe_index].actor == $author", copilot)
        self.assertIn(
            ".label == $safe_label\n                          and .actor != $author",
            copilot,
        )
        self.assertIn("(.head.sha == $head_sha)", copilot)
        self.assertIn("review_observations=40", copilot)
        self.assertIn('for attempt in $(seq 1 "${review_observations}")', copilot)
        self.assertIn(".isResolved == false", copilot)
        self.assertIn("expected_safe_event=$'labeled\\tsafe-automerge\\trenovate[bot]'", renovate)
        self.assertIn('[ "$safe_event" = "$expected_safe_event" ]', renovate)
        self.assertIn('grep -Fq "$breaking_event_pattern"', renovate)
        self.assertIn("Enable auto-merge for trusted Renovate PR", renovate)
        self.assertIn("Enable auto-merge after live-state verification", renovate)
        self.assertIn('--match-head-commit "${PR_HEAD_SHA}"', renovate)
        self.assertNotIn("gh pr review", renovate)
        self.assertIn("prohibits Actions from submitting", renovate)
        self.assertIn('[ "$PR_AUTHOR" = "renovate[bot]" ]', changelog)
        self.assertIn('[ "$PR_BASE" = "develop" ]', changelog)
        self.assertIn('[[ "$PR_HEAD" = renovate/* ]]', changelog)
        self.assertIn('index("renovate") != null', changelog)
        self.assertIn('index("dependencies") != null', changelog)
        self.assertIn('index("safe-automerge") != null', changelog)
        self.assertIn('index("breaking-update") == null', changelog)
        self.assertIn('[ "$PR_AUTHOR" = "lightning-it-release-automation[bot]" ]', changelog)
        self.assertIn('[ "$PR_BASE" = "main" ]', changelog)
        self.assertIn('[[ "$PR_HEAD" = security-release/MLX90-* ]]', changelog)
        self.assertIn("python scripts/classify-security-release.py", changelog)
        self.assertIn('if grep -Fxq "security_recovery_receipt=true"', changelog)
        self.assertNotIn("skip-changelog", changelog)
        static_steps = [
            step
            for step in collection_ci["jobs"]["lint-sanity"]["steps"]
            if step.get("name") == "Run repository static pre-commit gates"
        ]
        self.assertEqual(1, len(static_steps))
        self.assertEqual("security-classification", collection_ci["jobs"]["lint-sanity"]["needs"])
        self.assertEqual(
            "${{ steps.classify.outputs.security_recovery_receipt }}",
            collection_ci["jobs"]["security-classification"]["outputs"]["security-recovery-receipt"],
        )
        static_env = static_steps[0]["env"]
        self.assertEqual("${{ env.COMPARE_BASE_SHA }}", static_env["BASE_SHA"])
        self.assertEqual("${{ env.SOURCE_SHA }}", static_env["HEAD_SHA"])
        self.assertEqual(
            "${{ github.event_name == 'pull_request' && toJson(github.event.pull_request.labels.*.name) || '[]' }}",
            static_env["LABELS_JSON"],
        )
        require_fragment = static_env["REQUIRE_FRAGMENT"]
        self.assertIn(
            "needs.security-classification.outputs.security-recovery-receipt != 'true'",
            require_fragment,
        )
        self.assertIn("github.event.pull_request.base.ref == 'develop'", require_fragment)
        self.assertIn("startsWith(github.event.pull_request.head.ref, 'renovate/')", require_fragment)
        self.assertIn("github.event.pull_request.user.login == 'renovate[bot]'", require_fragment)
        self.assertIn("contains(github.event.pull_request.labels.*.name, 'renovate')", require_fragment)
        self.assertIn("contains(github.event.pull_request.labels.*.name, 'dependencies')", require_fragment)
        self.assertIn("contains(github.event.pull_request.labels.*.name, 'safe-automerge')", require_fragment)
        self.assertIn("!contains(github.event.pull_request.labels.*.name, 'breaking-update')", require_fragment)

    def test_changelog_recovery_classification_preserves_normal_security_prs(self) -> None:
        workflow = load_yaml(WORKFLOWS / "changelog.yml")
        validate = next(
            step
            for step in workflow["jobs"]["changelog"]["steps"]
            if step.get("name") == "Validate changelog policy via devtools"
        )
        script = validate["run"]
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            bin_root = temporary_root / "bin"
            bin_root.mkdir()
            python = bin_root / "python"
            python.write_text(
                """#!/bin/sh
set -eu
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--github-output" ]; then
    shift
    output="$1"
  fi
  shift
done
test -n "$output"
printf 'security_recovery_receipt=%s\\n' "$TEST_RECOVERY_RECEIPT" >>"$output"
""",
                encoding="utf-8",
            )
            bash = bin_root / "bash"
            bash.write_text(
                """#!/bin/sh
set -eu
printf '%s\\n' "$REQUIRE_FRAGMENT" >"$TEST_CAPTURE"
""",
                encoding="utf-8",
            )
            python.chmod(0o700)
            bash.chmod(0o700)
            for classified, expected in (("false", "true"), ("true", "false")):
                with self.subTest(classified=classified):
                    capture = temporary_root / f"capture-{classified}"
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "BASE_SHA": "1" * 40,
                            "HEAD_SHA": "2" * 40,
                            "LABELS_JSON": "[]",
                            "PATH": f"{bin_root}:{environment['PATH']}",
                            "PR_AUTHOR": "lightning-it-release-automation[bot]",
                            "PR_BASE": "main",
                            "PR_HEAD": "security-release/MLX90-EXACT-RECOVERY",
                            "TEST_CAPTURE": str(capture),
                            "TEST_RECOVERY_RECEIPT": classified,
                        }
                    )
                    result = subprocess.run(  # noqa: S603
                        ["/bin/bash", "-c", script],
                        cwd=ROOT,
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                        timeout=30,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(expected, capture.read_text(encoding="utf-8").strip())

    def test_copilot_review_is_requested_only_for_one_finalized_exact_head(self) -> None:
        copilot = (WORKFLOWS / "copilot-review.yml").read_text(encoding="utf-8")
        request_job = copilot.split("  request-current-revision-review:", 1)[1].split(
            "  verify-current-revision-policy:", 1
        )[0]
        self.assertIn("github.event.action == 'ready_for_review'", request_job)
        self.assertIn("github.event.action == 'opened'", request_job)
        self.assertIn("github.event_name == 'pull_request_target'", request_job)
        self.assertIn("github.event.pull_request.user.login == 'litroc'", request_job)
        self.assertNotIn("workflow_dispatch", request_job.split("    permissions:", 1)[0])
        self.assertIn("vars.LI219_EVENT_MODE == 'enabled'", request_job)
        self.assertIn('test "$(jq -r .head.sha <<<"${pr}")" = "${EXPECTED_HEAD}"', request_job)
        self.assertIn('test "$(jq -r .user.login <<<"${pr}")" = litroc', request_job)
        self.assertNotIn('if [ "${author}" != litroc ]', request_job)
        self.assertNotIn("Contributor-funded review required", request_job)
        self.assertIn("Copilot already reviewed the exact finalized head", request_job)
        self.assertIn('reviews="$(gh api --paginate --slurp', request_job)
        self.assertIn('--arg reviewer "${reviewer}"', request_job)
        self.assertIn(
            ".user.login == $reviewer",
            request_job,
        )
        self.assertIn("review_status=$?", request_job)
        self.assertIn('if [ "${review_status}" -ne 1 ]; then', request_job)
        self.assertIn("mlx90-copilot-request head=${EXPECTED_HEAD}", request_job)
        self.assertIn(
            "The one exact-head Copilot request was already consumed; automatic retry is forbidden.",
            request_job,
        )
        self.assertIn("A review is pending; awaiting head-bound evidence without another request.", request_job)
        self.assertNotIn("Copilot review is already pending for the exact finalized head", request_job)
        self.assertIn("Copilot review request accepted for finalized head", request_job)
        self.assertNotIn('gh api --method DELETE "${requested_reviewers_url}"', request_job)
        self.assertNotIn("review_is_visible_for_head()", request_job)
        self.assertNotIn("Copilot reviewer request did not become visible", request_job)
        self.assertIn("concurrency:", request_job)
        self.assertIn("group: copilot-review-request-${{ github.event.pull_request.number }}", request_job)
        self.assertIn("cancel-in-progress: false", request_job)
        verify_job = copilot.split("  verify-current-revision-policy:", 1)[1]
        self.assertIn(
            "group: copilot-review-verify-${{ github.event.pull_request.number }}",
            verify_job,
        )
        self.assertIn(
            "group: copilot-review-${{ github.event.pull_request.number }}-${{ github.event.action }}",
            copilot,
        )
        self.assertEqual(3, copilot.count("cancel-in-progress: false"))
        self.assertIn("pull_request_target:", copilot)
        for action in (
            "opened",
            "synchronize",
            "reopened",
            "ready_for_review",
            "edited",
            "labeled",
            "unlabeled",
        ):
            self.assertIn(f"        {action},", copilot)
        self.assertIn("github.event.action == 'edited'", verify_job)
        self.assertIn(
            "Invalidate prior result after pull-request metadata change",
            verify_job,
        )
        self.assertIn("github.event.action == 'labeled'", verify_job)
        self.assertIn("github.event.action == 'unlabeled'", verify_job)
        self.assertIn("pull_request_labels_sha256", verify_job)
        self.assertIn("head_repository:$head_repository", verify_job)
        self.assertIn("controller_ref:$controller_ref", verify_job)
        self.assertIn("conclusion=failure", verify_job)
        self.assertNotIn("pull_request_review:", copilot)

    def test_bound_copilot_review_converges_across_graphql_and_rest(self) -> None:
        copilot = (WORKFLOWS / "copilot-review.yml").read_text(encoding="utf-8")
        verifier = copilot.split("      - name: Verify current Copilot review and resolved findings", 1)[1].split(
            "      - name: Publish bound neutral result", 1
        )[0]
        publisher = copilot.split("      - name: Publish bound neutral result", 1)[1].split(
            "  request-protected-verifier-reevaluation-develop:", 1
        )[0]

        self.assertIn("id: copilot-review", verifier)
        self.assertIn('echo "review_id=${review_id}" >>"${GITHUB_OUTPUT}"', verifier)
        self.assertIn("BOUND_REVIEW_ID: ${{ steps.copilot-review.outputs.review_id }}", publisher)
        self.assertIn("validate_bound_review() {", publisher)
        self.assertIn("for attempt in $(seq 1 10); do", publisher)
        self.assertIn("sleep 3", publisher)
        self.assertIn("select(.node_id == $review_id)", publisher)
        self.assertIn("$reviews[0].commit_id == $head", publisher)
        self.assertEqual(2, copilot.count("=~ ^[A-Za-z0-9_+/=-]+$"))
        self.assertNotIn("=~ ^[A-Za-z0-9_=-]+$", copilot)
        self.assertGreater(
            publisher.index('default_head="$(gh api "repos/${REPOSITORY}/branches/${DEFAULT_BRANCH}"'),
            publisher.index('elif [ "${TRUSTED_KIND}" = ancestry-backmerge ]; then'),
        )
        self.assertIn('test -z "${BOUND_REVIEW_ID}"', publisher)
        self.assertIn('review_id:(if $review_id == "" then null else $review_id end)', publisher)
        self.assertEqual(4, publisher.count("validate_bound_review"))

    def test_main_review_controller_is_exact_and_calls_same_revision_helper(self) -> None:
        copilot = (WORKFLOWS / "copilot-review.yml").read_text(encoding="utf-8")
        self.assertNotIn("controller_ancestry", copilot)
        self.assertEqual(2, copilot.count('test "${TRUSTED_WORKFLOW_SHA}" = "${default_head}"'))
        self.assertEqual(5, copilot.count("and .protected == true"))

        handoff = copilot.split("  request-protected-verifier-reevaluation-develop:", 1)[1]
        develop_handoff, main_jobs = handoff.split("  validate-protected-main-helper-pin:", 1)
        main_guard, main_handoff = main_jobs.split(
            "  request-protected-verifier-reevaluation-main:",
            1,
        )
        helper_name_line = next(line.strip() for line in main_guard.splitlines() if line.strip().startswith("name: "))
        self.assertEqual("name: Validate protected main helper pin", helper_name_line)
        self.assertNotIn("${{", helper_name_line)
        self.assertNotIn("Inactive legacy main pin", main_guard)
        self.assertIn("uses: ./.github/workflows/current-revision-rerun.yml", develop_handoff)
        self.assertIn(
            "uses: lightning-it/ansible-collection-supplementary/.github/workflows/"
            "current-revision-rerun.yml@64451b42ec9d03c47ba8156f0952c139c0744648",
            main_handoff,
        )
        self.assertIn(
            "github.event.pull_request.base.sha == '64451b42ec9d03c47ba8156f0952c139c0744648'",
            main_handoff,
        )
        self.assertIn(
            "PINNED_MAIN_HELPER: 64451b42ec9d03c47ba8156f0952c139c0744648",
            main_guard,
        )
        self.assertIn('live_main="$(gh api "repos/${REPOSITORY}/branches/main")"', main_guard)
        self.assertIn("and .protected == true", main_guard)
        self.assertIn("and .commit.sha == $event_base", main_guard)
        self.assertIn("needs.validate-protected-main-helper-pin.result == 'success'", main_handoff)
        self.assertIn("Advance the protected main helper pin through a normal PR to develop", main_guard)
        legacy_handoff = handoff.split("  dispatch-event-verifier-reevaluation:", 1)[0]
        self.assertNotIn("current-revision-rerun.yml/dispatches", legacy_handoff)
        self.assertNotIn("ref=${BASE_REF}", legacy_handoff)
        for required_input in (
            "base_ref",
            "pr_number",
            "expected_base",
            "expected_head",
            "producer_run_id",
        ):
            self.assertIn(required_input, develop_handoff)
            self.assertIn(required_input, main_handoff)

    def test_current_revision_rerun_discovers_required_workflow_by_exact_head(self) -> None:
        helper = (WORKFLOWS / "current-revision-rerun.yml").read_text(encoding="utf-8")

        self.assertIn(
            "actions/runs?head_sha=${EXPECTED_HEAD}&per_page=100",
            helper,
        )
        self.assertNotIn("actions/runs?event=pull_request_target", helper)
        self.assertIn('select(.event == "pull_request_target")', helper)

    def test_release_app_ancestry_backmerge_uses_deterministic_controller(
        self,
    ) -> None:
        workflow = (WORKFLOWS / "copilot-review.yml").read_text(encoding="utf-8")
        ancestry = (WORKFLOWS / "sync-main-to-develop.yml").read_text(encoding="utf-8")
        self.assertIn("Release-App review belongs only", workflow)
        self.assertNotIn("Release-App AI review belongs only", workflow)
        request_condition = workflow.split(
            "\n  request-current-revision-review:",
            1,
        )[1].split("    permissions:", 1)[0]
        self.assertIn(
            "github.event.pull_request.user.login == 'litroc'",
            request_condition,
        )
        self.assertNotIn("lightning-it-release-automation[bot]", request_condition)
        self.assertIn("vars.LI219_EVENT_MODE == 'enabled'", request_condition)

        trusted_automation = workflow.split(
            "      - name: Classify trusted automation pull request",
            1,
        )[1].split("      - name: Accept trusted automation exemption", 1)[0]
        for exact_binding in (
            "expected_backmerge_author='lightning-it-release-automation[bot]'",
            'if [ "${REPOSITORY}" = "lightning-it/.github" ]; then',
            "expected_backmerge_author='lightning-it-shared-assets-sync[bot]'",
            'elif [ "${PR_AUTHOR}" = "${expected_backmerge_author}" ]',
            '[ "${PR_HEAD_REPO}" = "${REPOSITORY}" ]',
            '[[ "${PR_HEAD}" == backmerge/*-main ]]',
            '[ "${PR_BASE}" = "develop" ]',
            '[[ "${PR_TITLE}" == "chore(governance): record main ancestry before "* ]]',
            "trusted_kind=ancestry-backmerge",
        ):
            with self.subTest(exact_binding=exact_binding):
                self.assertIn(exact_binding, trusted_automation)

        for evidence_binding in (
            "Verify evidence-bound ancestry backmerge",
            "trusted_kind=ancestry-backmerge",
            '"repos/${REPOSITORY}/git/commits/${HEAD_SHA}"',
            '"repos/${REPOSITORY}/branches/develop"',
            '"repos/${REPOSITORY}/branches/main"',
            ".parents[0].sha == $develop",
            ".parents[1].sha == $main",
            '.files[0].filename == ".lit/main-ancestry.json"',
            "contents/.lit/main-ancestry.json?ref=${HEAD_SHA}",
            'review_path="deterministic evidence-bound ancestry exemption"',
            'external_kind="ancestry-backmerge"',
            "mlx90-current-revision:${external_kind}:v6:${PR_NUMBER}",
            '[ "${TRUSTED_KIND}" = ancestry-backmerge ]',
            "expected_backmerge_author='lightning-it-release-automation[bot]'",
            'test "${author}" = "${expected_backmerge_author}"',
            'test "${default_head}" = "${EVENT_BASE}"',
            'test "${BASE_SHA}" = "${current_develop}"',
            '(keys | sort) == ["develop_parent_sha", "main_sha", "purpose", "repository", "schema_version"]',
            'test -z "${BOUND_REVIEW_ID}"',
        ):
            with self.subTest(evidence_binding=evidence_binding):
                self.assertIn(evidence_binding, workflow)

        self.assertNotIn("id: review-dispatch-app", ancestry)
        self.assertNotIn("permission-actions: write", ancestry)
        self.assertNotIn("release-bot-exact-head-review.yml", ancestry)
        self.assertNotIn("Dispatch protected Exact-Revision review", ancestry)
        self.assertNotIn("gh workflow run", ancestry)
        self.assertIn(
            'push --porcelain origin "${desired_head}:refs/heads/${upload_branch}"',
            ancestry,
        )
        self.assertNotIn(
            'push --porcelain origin "HEAD:refs/heads/${upload_branch}"',
            ancestry,
        )
        self.assertIn("Enable protected ancestry auto-merge", ancestry)
        self.assertNotIn("openai/codex-action", ancestry)
        self.assertNotIn("copilot", ancestry.lower())
        self.assertNotIn("gh auth setup-git", workflow)
        self.assertNotIn("git fetch", workflow)

        remediation = (WORKFLOWS / "codex-copilot-remediation.yml").read_text(encoding="utf-8")
        self.assertIn("reviewThreads(first:100,after:$after)", remediation)
        self.assertIn('if [ "${round}" -gt 1 ]', remediation)
        self.assertIn("identical Copilot finding set repeated", remediation)
        self.assertIn("the single automatic repair round was already consumed", remediation)
        self.assertEqual(1, remediation.count('git commit -m "fix: remediate Copilot findings'))
        self.assertEqual(1, remediation.count("gh workflow run codex-copilot-remediation.yml"))
        self.assertNotIn("maximum three automatic repair rounds", remediation)
        prompt = (ROOT / ".github" / "codex" / "prompts" / "remediate-copilot.md").read_text(encoding="utf-8")
        self.assertIn("complete thread set", prompt)
        self.assertIn("one bounded correction package", prompt)
        self.assertIn("Do not manufacture a no-op", prompt)
        self.assertIn("only one final Current-Head", prompt)

    def test_synchronize_request_requires_enabled_pilot_and_same_head_cas(self) -> None:
        workflow = (WORKFLOWS / "copilot-review.yml").read_text(encoding="utf-8")
        request_job = workflow.split("  request-current-revision-review:", 1)[1].split(
            "  verify-current-revision-policy:", 1
        )[0]
        condition = request_job.split("    if: >-", 1)[1].split("    permissions:", 1)[0]
        self.assertIn("github.event.action == 'ready_for_review'", condition)
        self.assertIn("github.event.action == 'synchronize'", condition)
        self.assertIn("vars.LI219_EVENT_MODE == 'enabled'", condition)
        self.assertIn("contains(fromJSON", condition)
        self.assertEqual(1, request_job.count('gh api --method POST "${requested_reviewers_url}"'))
        events = [{"action": "synchronize", "commit": index} for index in range(10)]
        self.assertFalse(any(event["action"] == "ready_for_review" for event in events))

    def test_style_only_remediation_cannot_create_a_noop_commit(self) -> None:
        workflow = (WORKFLOWS / "codex-copilot-remediation.yml").read_text(encoding="utf-8")
        push_step = workflow.split("      - name: Verify, commit, and push without force", 1)[1].split(
            "      - name: Explicitly continue after GITHUB_TOKEN push", 1
        )[0]
        no_op = "if git diff --quiet && git diff --cached --quiet; then"
        self.assertLess(push_step.index(no_op), push_step.index("git add -A"))
        self.assertLess(push_step.index('echo "changed=false"'), push_step.index("git commit -m"))
        self.assertIn('echo "changed=false" >>"${GITHUB_OUTPUT}"\n            exit 0', push_step)
        continuation = workflow.split("      - name: Explicitly continue after GITHUB_TOKEN push", 1)[1].split(
            "  enable-develop-automerge:", 1
        )[0]
        self.assertIn("if: steps.push.outputs.changed == 'true'", continuation)
        self.assertNotIn("enable-develop-automerge-after-evidence-only-remediation", workflow)
        evidence_free_automerge = workflow.split("  enable-develop-automerge:", 1)[1]
        self.assertIn("needs.inspect.outputs.actionable == 'false'", evidence_free_automerge)
        prompt = (ROOT / ".github" / "codex" / "prompts" / "remediate-copilot.md").read_text(encoding="utf-8")
        self.assertIn("Formatter-, linter-, or type-only style suggestions require no source edit", prompt)
        self.assertIn("Do not manufacture a no-op", prompt)

    def test_material_remediation_invalidates_old_evidence_and_binds_one_rereview(self) -> None:
        workflow = (WORKFLOWS / "codex-copilot-remediation.yml").read_text(encoding="utf-8")
        push_step = workflow.split("      - name: Verify, commit, and push without force", 1)[1].split(
            "      - name: Explicitly continue after GITHUB_TOKEN push", 1
        )[0]
        continuation = workflow.split("      - name: Explicitly continue after GITHUB_TOKEN push", 1)[1].split(
            "  enable-develop-automerge:", 1
        )[0]
        dispatch = workflow.split("  continue-after-push:", 1)[1].split("  inspect:", 1)[0]

        self.assertIn('new_head="$(git rev-parse HEAD)"', push_step)
        self.assertIn(
            'test "$(gh api "repos/${REPOSITORY}/pulls/${PR_NUMBER}" --jq .head.sha)" = "${new_head}"',
            push_step,
        )
        self.assertIn('echo "new_head=${new_head}"', push_step)
        self.assertIn("NEW_HEAD: ${{ steps.push.outputs.new_head }}", continuation)
        self.assertEqual(1, continuation.count("gh workflow run codex-copilot-remediation.yml"))
        self.assertIn('-f expected_head="${NEW_HEAD}"', continuation)
        self.assertIn('test "${current_head}" = "${EXPECTED_HEAD}"', dispatch)
        self.assertEqual(1, dispatch.count('"repos/${REPOSITORY}/pulls/${PR_NUMBER}/requested_reviewers"'))
        self.assertEqual(2, dispatch.count("state=consumed"))
        self.assertEqual(1, dispatch.count('"repos/${REPOSITORY}/issues/${PR_NUMBER}/comments"'))
        self.assertLess(dispatch.index("state=consumed"), dispatch.index("requested_reviewers"))
        self.assertIn("the consumed marker forbids an automatic retry", dispatch)

    def test_review_automation_has_no_privileged_bypass_path(self) -> None:
        workflows = "\n".join(
            (WORKFLOWS / name).read_text(encoding="utf-8")
            for name in ("copilot-review.yml", "codex-copilot-remediation.yml")
        )
        for forbidden in (
            "git push --force",
            "--force-with-lease",
            "gh pr merge --admin",
            "/rulesets",
            "/protection",
            "environment:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflows)

    def test_shared_assets_guard_streams_large_check_evidence_via_stdin(self) -> None:
        workflow = (WORKFLOWS / "shared-assets-guarded-automerge.yml").read_text(encoding="utf-8")
        self.assertNotIn('--argjson check_pages "$check_runs"', workflow)
        self.assertNotIn('--argjson status_pages "$status_pages"', workflow)

        start_marker = (
            '            evidence="$(\n'
            '              printf \'%s\\n%s\\n\' "$check_runs" "$status_pages" |\n'
            "                jq -s '\n"
        )
        end_marker = "\n              '\n            )\"\n            pending=false"
        start = workflow.index(start_marker) + len(start_marker)
        jq_program = workflow[start : workflow.index(end_marker, start)]

        check_pages = [
            {
                "check_runs": [
                    {
                        "id": 1,
                        "name": "required / large evidence",
                        "app": {"id": 15368},
                        "status": "completed",
                        "conclusion": "success",
                        "ignored_payload": "x" * (3 * 1024 * 1024),
                    }
                ]
            }
        ]
        jq = shutil.which("jq")
        if jq is None:
            self.fail("jq is required for the workflow evidence regression test")
        result = subprocess.run(  # noqa: S603
            [jq, "-s", jq_program],
            input=f"{json.dumps(check_pages)}\n{json.dumps([[]])}\n",
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            [
                {
                    "context": "required / large evidence",
                    "app_id": 15368,
                    "state": "success",
                }
            ],
            json.loads(result.stdout),
        )

    def test_collection_ci_concurrency_isolated_by_pr_and_exact_head(self) -> None:
        workflow = load_yaml(WORKFLOWS / "collection-ci.yml")
        top_group = workflow["concurrency"]["group"]
        self.assertIn("github.repository", top_group)
        self.assertIn("github.workflow", top_group)
        self.assertIn("github.event.pull_request.number || github.ref", top_group)
        self.assertNotIn("head.sha", top_group)
        self.assertEqual(
            "${{ github.event_name == 'pull_request' }}",
            workflow["concurrency"]["cancel-in-progress"],
        )

        jobs = workflow["jobs"]
        tiny_group = jobs["tiny-cells"]["concurrency"]["group"]
        self.assertIn("github.repository", tiny_group)
        self.assertIn("github.workflow", tiny_group)
        self.assertIn("github.event.pull_request.number || github.ref", tiny_group)
        self.assertIn("github.event.pull_request.head.sha || github.sha", tiny_group)

        for name, profile in (
            ("heavy-cells", "heavy"),
            ("acceptance-cells", "application_acceptance"),
        ):
            delegated = jobs[name]
            self.assertRegex(
                delegated["uses"],
                r"^ltn-it/modulix-validation/\.github/workflows/"
                r"collection-quality-profile\.yml@[0-9a-f]{40}$",
            )
            self.assertEqual(profile, delegated["with"]["profile"])
            self.assertIn("quality-matrix.outputs", delegated["with"]["matrix-json"])
            self.assertIn(
                "github.event.pull_request.head.sha || github.sha",
                delegated["with"]["source-sha"],
            )

        self.assertIn(
            "heavy",
            jobs["acceptance-cells"]["needs"],
            "delegated Incus profiles must run serially to avoid concurrency cancellation",
        )

    def test_all_trust_roots_require_security_and_compliance_ownership(self) -> None:
        codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        rules = {
            line.split("#", maxsplit=1)[0].strip()
            for line in codeowners.splitlines()
            if line.split("#", maxsplit=1)[0].strip()
        }
        owner = "@lightning-it/lightning-it-security-and-compliance-maintainers"
        self.assertIn(
            f"/.github/workflows/** {owner}",
            rules,
        )
        self.assertIn(
            f"/.github/actions/** {owner}",
            rules,
        )
        for path in (
            "/meta/quality-impact.yml",
            "/scripts/quality_cell_identity.py",
            "/scripts/select-quality-impact.py",
            "/scripts/source_dependencies.py",
            "/scripts/validate-role-coverage.py",
        ):
            self.assertIn(f"{path} {owner}", rules)

    def test_every_external_action_is_commit_pinned(self) -> None:
        paths = sorted(WORKFLOWS.glob("*.yml")) + sorted((ROOT / ".github" / "actions").rglob("*.yml"))
        uses = [item for path in paths for item in uses_values(load_yaml(path))]
        external = [item for item in uses if not item.startswith(("./", "docker://"))]
        docker = [item for item in uses if item.startswith("docker://")]
        docker.extend(image for path in paths if (image := docker_action_image(path)) is not None)
        self.assertTrue(external)
        self.assertEqual([], [item for item in external if PINNED_USE.fullmatch(item) is None])
        self.assertTrue(docker)
        self.assertEqual(
            [],
            [item for item in docker if PINNED_DOCKER_USE.fullmatch(item) is None],
        )

    def test_release_credentials_are_outside_pull_request_jobs(self) -> None:
        jobs = load_yaml(WORKFLOWS / "collection-ci.yml")["jobs"]
        release_security = jobs["release-security"]
        release_guard = release_security["if"]
        self.assertIn("github.event_name == 'push'", release_guard)
        self.assertIn("github.ref == 'refs/heads/main'", release_guard)
        self.assertNotIn("pull_request", release_guard)
        self.assertNotIn("workflow_dispatch", release_guard)
        release_environment = release_security["environment"]["name"]
        self.assertIn("mlx90-security-release-evidence", release_environment)
        self.assertIn("ansible-collection-release-evidence", release_environment)
        self.assertIn("lightning-it-release-automation[bot]", release_environment)
        self.assertIn("runtime-evidence", release_security["needs"])
        self.assertEqual("Collection / Release Evidence", jobs["evidence"]["name"])
        self.assertNotIn("environment", jobs["evidence"])
        self.assertEqual({"contents": "read"}, jobs["evidence"]["permissions"])
        self.assertFalse(any(step.get("id") == "validation-app" for step in jobs["evidence"]["steps"]))
        evidence_step = next(
            step
            for step in jobs["evidence"]["steps"]
            if step["name"] == "Enforce exact-SHA local release prerequisites"
        )
        self.assertNotIn("GH_TOKEN", evidence_step["env"])
        self.assertNotIn("modulix-validation", evidence_step["run"])

    def test_self_hosted_pr_cells_require_exact_head_and_protected_environment(self) -> None:
        jobs = load_yaml(WORKFLOWS / "collection-ci.yml")["jobs"]
        guard = jobs["tiny-cells"]["if"]
        tiny_aggregate = jobs["tiny"]
        tiny_expectation = tiny_aggregate["steps"][0]["env"]["TINY_EXECUTION_EXPECTED"]
        self.assertIn("needs.quality-matrix.outputs.tiny_required == 'true'", guard)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", guard)
        self.assertIn(
            "release/rep60-supplementary-protected-checkpoint-1-v5-successor-",
            guard,
        )
        self.assertEqual(
            ["quality-matrix", "tiny-cells", "security-classification"],
            tiny_aggregate["needs"],
        )
        normalized_tiny_expectation = tiny_expectation.strip().removeprefix("${{").removesuffix("}}")
        self.assertEqual(" ".join(guard.split()), " ".join(normalized_tiny_expectation.split()))
        self.assertEqual(
            "${{ needs.security-classification.result }}",
            tiny_aggregate["steps"][0]["env"]["CLASSIFICATION_RESULT"],
        )
        self.assertIn('test "$CLASSIFICATION_RESULT" = success', tiny_aggregate["steps"][0]["run"])
        self.assertIn('if [ "$TINY_EXECUTION_EXPECTED" = true ]; then', tiny_aggregate["steps"][0]["run"])
        self.assertNotIn("github.event_name == 'schedule'", guard)
        for job_name in ("heavy-cells", "acceptance-cells", "runtime-evidence"):
            protected_main_guard = jobs[job_name]["if"]
            self.assertIn("github.event_name == 'push'", protected_main_guard)
            self.assertIn("github.ref == 'refs/heads/main'", protected_main_guard)
            self.assertNotIn("pull_request", protected_main_guard)
            self.assertNotIn("workflow_dispatch", protected_main_guard)
        for job_name in ("heavy-cells", "acceptance-cells"):
            delegated = jobs[job_name]
            self.assertEqual(
                "ltn-it/modulix-validation/.github/workflows/"
                "collection-quality-profile.yml@"
                "154c99eb0d907b01edc10e9b39c94ef4912fd9dd",
                delegated["uses"],
            )
            self.assertEqual(
                "ansible-collection-runtime-protected",
                delegated["with"]["environment-name"],
            )
            self.assertNotIn("secrets", delegated)
        self.assertEqual("Collection / Release Evidence", jobs["evidence"]["name"])
        self.assertEqual(
            ["lint-sanity", "build-install", "role-coverage", "quality-matrix", "tiny"],
            jobs["fast"]["needs"],
        )

    def test_protected_main_evidence_adapter_is_exact_and_fail_closed(self) -> None:
        jobs = load_yaml(WORKFLOWS / "collection-ci.yml")["jobs"]

        self.assertEqual("Collection / Heavy", jobs["heavy"]["name"])
        self.assertEqual("Collection / Application Acceptance", jobs["acceptance"]["name"])
        self.assertEqual("Runtime evidence / exact tested SHA", jobs["runtime-evidence"]["name"])
        self.assertEqual("Collection / Release Security", jobs["release-security"]["name"])
        self.assertEqual("Collection / Release Validation", jobs["release-validation"]["name"])

        for job_name in (
            "heavy",
            "acceptance",
            "runtime-evidence",
            "release-security",
            "release-validation",
        ):
            guard = jobs[job_name]["if"]
            self.assertIn("github.event_name == 'push'", guard)
            self.assertIn("github.ref == 'refs/heads/main'", guard)
            self.assertNotIn("pull_request", guard)
            self.assertNotIn("workflow_dispatch", guard)

        self.assertIn("runtime-evidence", jobs["release-security"]["needs"])
        self.assertIn("runtime-evidence", jobs["release-validation"]["needs"])
        release_security = json.dumps(jobs["release-security"])
        release_validation = json.dumps(jobs["release-validation"])
        self.assertIn("needs.runtime-evidence.result", release_security)
        self.assertIn("needs.runtime-evidence.result", release_validation)
        release_security_aggregate = next(
            step
            for step in jobs["release-security"]["steps"]
            if step.get("name") == "Enforce trusted release-security result after upload"
        )
        self.assertEqual(
            "${{ needs.runtime-evidence.result }}",
            release_security_aggregate["env"]["RUNTIME_EVIDENCE_RESULT"],
        )
        self.assertIn(
            'test "$RUNTIME_EVIDENCE_RESULT" = success',
            release_security_aggregate["run"],
        )
        release_security_finalize = next(
            step
            for step in jobs["release-security"]["steps"]
            if step.get("name") == "Finalize protected-main publication eligibility"
        )
        self.assertEqual(
            "${{ needs.runtime-evidence.result }}",
            release_security_finalize["env"]["RUNTIME_EVIDENCE_RESULT"],
        )
        self.assertIn(
            '"runtime_evidence": os.environ["RUNTIME_EVIDENCE_RESULT"] == "success"',
            release_security_finalize["run"],
        )
        self.assertIn("collection-evidence-${{ env.SOURCE_SHA }}", release_security)
        self.assertIn("collection-release-evidence-${{ env.SOURCE_SHA }}", release_security)
        self.assertIn("collection-release-evidence-${{ env.SOURCE_SHA }}", release_validation)
        final_aggregate = next(
            step
            for step in jobs["release-validation"]["steps"]
            if step.get("name") == "Enforce every mandatory aggregate"
        )
        self.assertEqual(
            "${{ needs.runtime-evidence.result }}",
            final_aggregate["env"]["RUNTIME_EVIDENCE_RESULT"],
        )
        self.assertIn(
            'test "$RUNTIME_EVIDENCE_RESULT" = success',
            final_aggregate["run"],
        )

    def test_candidate_platforms_run_only_as_non_release_promotion_input(self) -> None:
        self.assertFalse((WORKFLOWS / "candidate-platform-validation.yml").exists())
        self.assertFalse((WORKFLOWS / "nightly-develop.yml").exists())

    def test_composite_shell_never_interpolates_untrusted_inputs_directly(self) -> None:
        action = load_yaml(ACTION)
        run_scripts = [
            step["run"]
            for step in action["runs"]["steps"]
            if isinstance(step, dict) and isinstance(step.get("run"), str)
        ]
        self.assertTrue(run_scripts)
        self.assertFalse(any("${{ inputs." in script for script in run_scripts))

    def test_publish_mutation_is_protected_and_scorecard_is_immutable(self) -> None:
        publish = load_yaml(WORKFLOWS / "collection-publish.yml")["jobs"]["publish"]
        publish_environment = publish["environment"]["name"]
        self.assertIn("mlx90-security-publish", publish_environment)
        self.assertIn("ansible-collections", publish_environment)
        self.assertIn("lightning-it-release-automation[bot]", publish_environment)
        self.assertIn("github.ref == 'refs/heads/main'", publish["if"])
        self.assertEqual("write", publish["permissions"]["contents"])
        self.assertEqual("write", publish["permissions"]["id-token"])
        self.assertEqual("write", publish["permissions"]["actions"])
        serialized_publish = json.dumps(publish)
        self.assertNotIn("LITRELEASEBOT_TOKEN", serialized_publish)
        self.assertNotIn("steps.token.outputs.value", serialized_publish)
        self.assertIn("github.token", serialized_publish)
        first_step = publish["steps"][0]
        self.assertEqual(
            "Enforce dedicated release-tag principal configuration",
            first_step["name"],
        )
        self.assertIn("RELEASE_TAG_APP_ID", json.dumps(first_step))
        self.assertIn("RELEASE_TAG_APP_CLIENT_ID", json.dumps(first_step))
        self.assertIn("RELEASE_TAG_APP_INSTALLATION_ID", json.dumps(first_step))
        self.assertIn("RELEASE_TAG_APP_PRIVATE_KEY", json.dumps(first_step))

        token_step = next(
            step
            for step in publish["steps"]
            if step.get("name") == "Mint exact repository-scoped release-tag App token"
        )
        self.assertEqual(
            "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
            token_step["uses"],
        )
        self.assertEqual("write", token_step["with"]["permission-contents"])
        self.assertIn("github.event.repository.name", token_step["with"]["repositories"])

        validate_step = next(
            step for step in publish["steps"] if step.get("name") == "Validate exact release-tag App installation"
        )
        self.assertIn("/apps/${ACTION_APP_SLUG}", validate_step["run"])
        self.assertNotIn("gh api /installation", validate_step["run"])
        self.assertIn("EXPECTED_APP_CLIENT_ID", json.dumps(validate_step))
        self.assertIn("/installation/repositories?per_page=100", validate_step["run"])
        self.assertIn(".total_count == 1", validate_step["run"])
        tag_step = next(
            step for step in publish["steps"] if step.get("name") == "Create or verify immutable tag with dedicated App"
        )
        self.assertEqual(
            "${{ steps.release-tag-token.outputs.token }}",
            tag_step["env"]["GH_TOKEN"],
        )
        self.assertIn("/git/refs", tag_step["run"])
        self.assertNotIn("gh release", tag_step["run"])
        release_step = next(
            step
            for step in publish["steps"]
            if step.get("name") == "Create or verify GitHub Release and immutable assets"
        )
        self.assertEqual("${{ github.token }}", release_step["env"]["GH_TOKEN"])
        self.assertIn("gh release", release_step["run"])
        self.assertNotIn("steps.release-tag-token.outputs.token", release_step["run"])

        scorecard = load_yaml(WORKFLOWS / "openssf-scorecard.yml")
        scorecard_job = scorecard["jobs"]["scorecard"]
        self.assertNotIn("id-token", scorecard_job["permissions"])
        scorecard_step_name = "Run commit-pinned OpenSSF Scorecard analysis"
        run_step = next(step for step in scorecard_job["steps"] if step.get("name") == scorecard_step_name)
        self.assertEqual(
            "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc",
            run_step["uses"],
        )
        self.assertIs(run_step["with"]["publish_results"], False)
        scorecard_action = load_yaml(SCORECARD_ACTION)
        self.assertRegex(scorecard_action["runs"]["image"], PINNED_DOCKER_USE)
        self.assertEqual(
            "${{ github.token }}",
            scorecard_action["inputs"]["repo_token"]["default"],
        )
        self.assertEqual(
            "false",
            scorecard_action["inputs"]["publish_results"]["default"],
        )

    def test_release_automation_uses_the_organization_app(self) -> None:
        for name in (
            "promote-develop-to-main.yml",
            "release-back-sync.yml",
            "release-prepare.yml",
        ):
            with self.subTest(workflow=name):
                text = (WORKFLOWS / name).read_text(encoding="utf-8")
                self.assertIn(
                    "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
                    text,
                )
                self.assertIn("RELEASE_AUTOMATION_APP_CLIENT_ID", text)
                self.assertIn("RELEASE_AUTOMATION_APP_PRIVATE_KEY", text)
                self.assertIn("repositories: ${{ github.event.repository.name }}", text)
                self.assertIn("permission-pull-requests: write", text)
                self.assertIn("ansible-collection-release-prepare", text)
                self.assertNotIn("LITRELEASEBOT_TOKEN", text)
                self.assertNotIn("litreleasebot", text)

        promotion = (WORKFLOWS / "promote-develop-to-main.yml").read_text(encoding="utf-8")
        self.assertNotIn("mlx90-security-", promotion)
        self.assertIn("environment: ansible-collection-release-prepare", promotion)

        for name in ("release-back-sync.yml", "release-prepare.yml"):
            with self.subTest(security_workflow=name):
                text = (WORKFLOWS / name).read_text(encoding="utf-8")
                self.assertIn("mlx90-security-release-prepare", text)
                self.assertIn("lightning-it-release-automation[bot]", text)

        for name in ("release-back-sync.yml", "release-prepare.yml"):
            with self.subTest(identity_workflow=name):
                text = (WORKFLOWS / name).read_text(encoding="utf-8")
                self.assertIn("steps.release-bot.outputs.login", text)
                self.assertIn("steps.release-bot.outputs.email", text)

        back_sync = (WORKFLOWS / "release-back-sync.yml").read_text(encoding="utf-8")
        self.assertNotIn("--force-with-lease", back_sync)
        self.assertNotIn("authenticated_push --force origin", back_sync)
        self.assertIn('"$back_sync_policy/scripts/verify_release_back_sync.py"', back_sync)
        self.assertIn('authenticated_push origin "HEAD:${branch_ref}"', back_sync)
        self.assertNotIn("permission-issues:", back_sync)
        self.assertNotIn("gh label ", back_sync)
        self.assertNotIn("--label skip-changelog", back_sync)
        self.assertNotIn("--add-label skip-changelog", back_sync)
        release_prepare = (WORKFLOWS / "release-prepare.yml").read_text(encoding="utf-8")
        self.assertNotIn("--force-with-lease", release_prepare)
        self.assertIn('"$promotion_base/scripts/security_main_promotion.py"', release_prepare)
        self.assertIn('authenticated_push origin "HEAD:${release_ref}"', release_prepare)
        for workflow in (back_sync, release_prepare, (WORKFLOWS / "collection-ci.yml").read_text()):
            self.assertIn("git cat-file -e", workflow)
            self.assertIn("git merge-base --is-ancestor", workflow)

    def test_zero_touch_is_security_only_and_normal_promotion_stays_manual(self) -> None:
        ci = load_yaml(WORKFLOWS / "collection-ci.yml")["jobs"]
        prepare = load_yaml(WORKFLOWS / "release-prepare.yml")["jobs"]
        publish = load_yaml(WORKFLOWS / "collection-publish.yml")["jobs"]
        back_sync = load_yaml(WORKFLOWS / "release-back-sync.yml")["jobs"]
        promotion = load_yaml(WORKFLOWS / "promote-develop-to-main.yml")["jobs"]

        for jobs, mutation_name in (
            (prepare, "prepare"),
            (publish, "publish"),
            (back_sync, "back-sync"),
        ):
            with self.subTest(mutation=mutation_name):
                self.assertIn("security-classification", jobs)
                mutation = jobs[mutation_name]
                self.assertIn("security-classification", mutation["needs"])
                normalized_condition = " ".join(mutation["if"].split())
                self.assertIn(
                    "needs.security-classification.outputs.security-release == 'false'",
                    normalized_condition,
                )
                self.assertIn(
                    "security-release == 'false' || "
                    "(needs.security-classification.outputs.security-release == "
                    "'true' &&",
                    normalized_condition,
                )
                self.assertNotIn("security-release != 'true'", normalized_condition)
                self.assertIn(
                    "lightning-it-release-automation[bot]",
                    normalized_condition,
                )

        for name in ("tiny-cells", "release-security"):
            with self.subTest(ci_job=name):
                self.assertIn("security-classification", ci[name]["needs"])
                normalized_condition = " ".join(ci[name]["if"].split())
                self.assertIn(
                    "needs.security-classification.outputs.security-release == 'false'",
                    normalized_condition,
                )
                self.assertIn(
                    "security-release == 'false' || "
                    "(needs.security-classification.outputs.security-release == "
                    "'true' &&",
                    normalized_condition,
                )
                self.assertNotIn("security-release != 'true'", normalized_condition)
                self.assertIn(
                    "lightning-it-release-automation[bot]",
                    normalized_condition,
                )

        self.assertEqual(
            "ansible-collection-release-prepare",
            promotion["promote"]["environment"],
        )

    def test_release_prepare_bounds_exact_owned_pr_propagation_retries(self) -> None:
        workflow = load_yaml(WORKFLOWS / "release-prepare.yml")
        prepare_step = next(
            step for step in workflow["jobs"]["prepare"]["steps"] if step.get("name") == "Prepare release branch"
        )
        run = prepare_step["run"]
        retry_start = 'pushed_sha="$(git rev-parse HEAD)"'
        retry_end = "existing=\"$(jq -r '.[0].number'"
        self.assertIn(retry_start, run)
        after_retry_start = run.partition(retry_start)[2]
        self.assertIn(retry_end, after_retry_start)
        retry_block = after_retry_start.partition(retry_end)[0]

        self.assertIn("max_pr_lookup_attempts=6", retry_block)
        self.assertIn("successful_pr_lookup_count=0", retry_block)
        self.assertIn(
            "for (( attempt=1; attempt<=max_pr_lookup_attempts; attempt++ )); do",
            retry_block,
        )
        self.assertIn("lookup_outcome=api-failure", retry_block)
        self.assertIn("lookup_outcome=non-converged", retry_block)
        self.assertGreaterEqual(retry_block.count("owned_pulls='[]'"), 2)
        self.assertIn(
            "successful_pr_lookup_count=$((successful_pr_lookup_count + 1))",
            retry_block,
        )
        self.assertIn(
            'if [ "$successful_pr_lookup_count" -eq 0 ]; then',
            retry_block,
        )
        self.assertIn(
            "failed on the final API attempt after",
            retry_block,
        )
        self.assertIn(
            "${successful_pr_lookup_count} successful but non-converged response(s)",
            retry_block,
        )
        self.assertIn("retry_delay=$((1 << (attempt - 1)))", retry_block)
        self.assertIn('sleep "$retry_delay"', retry_block)
        self.assertIn(
            "Release PR API request failed; retrying in ${retry_delay}s",
            retry_block,
        )
        self.assertIn(
            "Release PR lookup has not converged to the exact expected state",
            retry_block,
        )
        self.assertIn("retrying in ${retry_delay}s", retry_block)
        self.assertIn("Unexpected Release PR lookup outcome", retry_block)
        self.assertIn('if [ "$owned_count" -gt 1 ]; then', retry_block)
        self.assertIn(
            'owned_numbers="$(jq -c \'map(.number)\' <<< "$owned_pulls")"',
            retry_block,
        )
        self.assertIn(
            "Multiple same-repository release PRs exist: ${owned_numbers}",
            retry_block,
        )
        for exact_binding in (
            ".[0].head.repo.full_name == $repo",
            ".[0].head.ref == $branch",
            ".[0].head.sha == $sha",
            ".[0].base.ref == $base",
        ):
            self.assertIn(exact_binding, retry_block)
        self.assertIn(
            "Release PR did not converge to the exact same-repository ref/base/head",
            retry_block,
        )
        self.assertIn("after ${max_pr_lookup_attempts} API attempts. Expected", retry_block)
        self.assertIn("${GITHUB_REPOSITORY}:${RELEASE_BRANCH}@${pushed_sha}", retry_block)

    def test_release_evidence_and_publication_are_attempt_and_identity_bound(self) -> None:
        ci = (WORKFLOWS / "collection-ci.yml").read_text(encoding="utf-8")
        self.assertIn("/${GITHUB_RUN_ID}/attempt-${GITHUB_RUN_ATTEMPT}", ci)
        self.assertIn("detect-secrets scan --all-files", ci)
        self.assertIn('detect-secrets scan --all-files "$candidate_extract"', ci)
        self.assertNotIn("detect-secrets scan --all-files \\\n            artifacts/aggregate-input", ci)
        self.assertIn("secret-scan-inventory.json", ci)
        self.assertIn("scripts/enrich-cyclonedx-sbom.py", ci)
        self.assertIn('scripts/source_dependencies.py --candidate "$candidate"', ci)
        self.assertIn('git show "$SOURCE_SHA:meta/source-dependencies.yml"', ci)
        self.assertIn("artifacts/evidence/security/source-dependencies.yml", ci)
        self.assertIn("cmp --silent", ci)
        self.assertNotRegex(ci, r"(?im)^\s*(?:vex|ignore|allowlist)\s*:")
        self.assertNotIn("openvex", ci.casefold())
        self.assertNotIn("vulnerability-exploitability", ci.casefold())
        self.assertEqual([], list((ROOT / "security" / "vex").glob("*")))
        trivy_marker = "- name: Independently scan the candidate-bound SBOM with Trivy"
        before_trivy, marker, after_trivy = ci.partition(trivy_marker)
        self.assertTrue(before_trivy)
        self.assertEqual(trivy_marker, marker)
        trivy_step, next_marker, remaining_steps = after_trivy.partition("- name:")
        self.assertEqual("- name:", next_marker)
        self.assertTrue(remaining_steps)
        for exact_contract in (
            "docker run --rm",
            "--read-only",
            'cache_dir="$RUNNER_TEMP/trivy-cache-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
            'test ! -e "$cache_dir"',
            'mkdir -m 0700 "$cache_dir"',
            '--user "$(id -u):$(id -g)"',
            "--cap-drop ALL",
            "--security-opt no-new-privileges=true",
            "--pids-limit 128",
            "--network bridge",
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
            '-v "$PWD:/workspace:ro"',
            '-v "$cache_dir:/trivy-cache:rw"',
            "docker.io/aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e",
            "--cache-dir /trivy-cache",
            "--config /dev/null",
            "--quiet",
            "--timeout 15m",
            "sbom",
            "--no-progress",
            "--disable-telemetry",
            "--scanners vuln",
            "--pkg-types os,library",
            "--severity HIGH,CRITICAL",
            "--ignore-unfixed=false",
            "--skip-vex-repo-update",
            "--ignorefile /dev/null",
            "--exit-code 1",
            "--format json",
            "artifacts/evidence/security/sbom.cdx.json",
            "> artifacts/evidence/security/trivy-vulnerability-report.json",
            "test -s artifacts/evidence/security/trivy-vulnerability-report.json",
        ):
            self.assertIn(exact_contract, trivy_step)
        self.assertNotIn("aquasecurity/trivy-action", ci)
        self.assertIn("test ! -e .trivyignore", trivy_step)
        self.assertIn("test ! -e trivy.yaml", trivy_step)
        self.assertNotIn("--ignore-policy", trivy_step)
        self.assertNotIn("--vex", trivy_step)
        self.assertIn(
            "artifacts/release-assets/trivy-vulnerability-report.json",
            ci,
        )

        publish = (WORKFLOWS / "collection-publish.yml").read_text(encoding="utf-8")
        self.assertIn(
            "incoming/evidence/evidence/security/trivy-vulnerability-report.json",
            publish,
        )
        self.assertIn("dist/release/trivy-vulnerability-report.json", publish)
        self.assertIn("dist/release/SHA256SUMS.sigstore.json", publish)
        self.assertIn("existing-release-checksum-pair", publish)
        self.assertIn('test "$checksum_asset_count" -eq "$bundle_asset_count"', publish)
        self.assertIn('cmp --silent "$existing_pair/SHA256SUMS"', publish)
        self.assertIn("collection-publish.yml@refs/heads/main", publish)
        self.assertIn('--certificate-github-workflow-sha "$RELEASE_SHA"', publish)
        self.assertIn("cosign verify-blob", publish)

        self.assertIn('--certificate-github-workflow-sha "$SOURCE_SHA"', ci)

        back_sync = (WORKFLOWS / "release-back-sync.yml").read_text(encoding="utf-8")
        self.assertIn("git cat-file -t FETCH_HEAD", back_sync)
        self.assertIn("git cat-file tag FETCH_HEAD", back_sync)
        self.assertIn(
            'git merge-base --is-ancestor "$release_sha" origin/main',
            back_sync,
        )
        self.assertIn(
            'message.rstrip("\\n") != f"Release {os.environ[\'RELEASE_TAG\']}"',
            back_sync,
        )
        self.assertNotIn("/apps/${tagger_app_slug}", back_sync)
        self.assertNotIn("release-back-sync-tagger-app.json", back_sync)
        self.assertIn("/users/${tagger_app_slug}[bot]", back_sync)
        self.assertIn(
            '.id == $bot_id and .login == $login and .type == "Bot"',
            back_sync,
        )
        self.assertIn("EXPECTED_TAG_APP_ID", back_sync)
        self.assertIn("EXPECTED_TAG_APP_CLIENT_ID", back_sync)
        self.assertIn("[A-Za-z0-9._-]{0,127}", back_sync)
        self.assertIn(
            'test "$EXPECTED_TAG_APP_SLUG" = "lightning-it-release-tag-creator"',
            back_sync,
        )
        self.assertIn('test "$EXPECTED_TAG_APP_ID" = "4344269"', back_sync)
        self.assertIn(
            'test "$EXPECTED_TAG_APP_CLIENT_ID" = "Iv23liJnnvOQwajan2Mf"',
            back_sync,
        )
        self.assertIn('test "$tagger_app_slug" = "$EXPECTED_TAG_APP_SLUG"', back_sync)
        self.assertNotIn("RELEASE_TAG_APP_PRIVATE_KEY", back_sync)
        self.assertEqual(2, back_sync.count("actions/create-github-app-token@"))
        self.assertNotIn("tagger litreleasebot", back_sync)
        self.assertIn('git merge --no-ff -X ours "$release_sha"', back_sync)
        self.assertIn("release_is_ancestor=false", back_sync)
        self.assertIn('if [ "$release_is_ancestor" = true ]; then', back_sync)
        self.assertIn(
            "develop already contains the exact tagged release state; back-sync not needed.",
            back_sync,
        )
        self.assertNotIn(
            "develop already contains the tagged release; release back-sync not needed.",
            back_sync,
        )
        self.assertIn('test "$tag" = "v${tagged_version}"', back_sync)
        self.assertNotIn("git merge --no-ff -X ours origin/main", back_sync)

        recovery = load_yaml(WORKFLOWS / "release-back-sync.yml")["jobs"]["failed-pre-tag-recovery"]
        dispatch_inputs = load_yaml(WORKFLOWS / "release-back-sync.yml")[True]["workflow_dispatch"]["inputs"]
        self.assertLessEqual(len(dispatch_inputs), 10)
        for published_tag_input in (
            "release_tag_app_slug",
            "release_tag_app_id",
            "release_tag_app_client_id",
        ):
            self.assertFalse(dispatch_inputs[published_tag_input]["required"])
            self.assertEqual("", dispatch_inputs[published_tag_input]["default"])
        published_tag_classification = back_sync.split("  security-classification:", 1)[1].split("  back-sync:", 1)[0]
        self.assertIn(
            "EXPECTED_TAG_APP_SLUG: ${{ inputs.release_tag_app_slug || '' }}",
            published_tag_classification,
        )
        self.assertIn(
            'test "$EXPECTED_TAG_APP_SLUG" = "lightning-it-release-tag-creator"',
            published_tag_classification,
        )
        self.assertIn(
            'test "$EXPECTED_TAG_APP_ID" = "4344269"',
            published_tag_classification,
        )
        self.assertIn(
            'test "$EXPECTED_TAG_APP_CLIENT_ID" = "Iv23liJnnvOQwajan2Mf"',
            published_tag_classification,
        )
        normalized_condition = " ".join(recovery["if"].split())
        self.assertIn("github.ref == 'refs/heads/develop'", normalized_condition)
        self.assertIn("github.ref_protected == true", normalized_condition)
        self.assertIn("inputs.mode == 'failed-pre-tag-recovery'", normalized_condition)
        self.assertIn("github.actor == 'litroc'", normalized_condition)
        self.assertIn("github.triggering_actor == 'litroc'", normalized_condition)
        self.assertEqual("normal-release-promotion-approval", recovery["environment"])
        self.assertEqual({"contents": "read", "pull-requests": "read"}, recovery["permissions"])
        recovery_text = back_sync.split("  failed-pre-tag-recovery:", 1)[1]
        self.assertIn('test "$protected_develop" = "$GITHUB_SHA"', recovery_text)
        self.assertIn('test "$protected_main" = "$EXPECTED_MAIN"', recovery_text)
        self.assertIn('echo "main=$EXPECTED_MAIN"', recovery_text)
        self.assertIn(
            "EXPECTED_MAIN: ${{ steps.recovery-source.outputs.main }}",
            recovery_text,
        )
        self.assertEqual(
            2,
            recovery_text.count('protected_main="$(gh api "repos/${REPOSITORY}/git/ref/heads/main" --jq .object.sha)"'),
        )
        self.assertEqual(2, recovery_text.count('test "$protected_main" = "$EXPECTED_MAIN"'))
        self.assertIn('select((keys | sort) == ["diff_sha256", "main_sha", "paths_sha256"])', recovery_text)
        self.assertIn('.state == "closed"', recovery_text)
        self.assertIn(".merged == false", recovery_text)
        self.assertIn('.user.login == "litroc"', recovery_text)
        self.assertIn("and .head.sha == $head", recovery_text)
        self.assertIn('test "$(git merge-base "$GITHUB_SHA" "$EXPECTED_HEAD")" = "$EXPECTED_BASE"', recovery_text)
        self.assertIn(
            'integration_tree="$(git merge-tree --write-tree "$GITHUB_SHA" "$EXPECTED_HEAD")"',
            recovery_text,
        )
        self.assertIn('test "$(git cat-file -t "$integration_tree")" = tree', recovery_text)
        self.assertIn(
            "git diff --binary --full-index --no-color --no-ext-diff --no-textconv",
            recovery_text,
        )
        self.assertIn('"${GITHUB_SHA}^{tree}" "$integration_tree" --', recovery_text)
        self.assertNotIn('"$EXPECTED_BASE" "$EXPECTED_HEAD" -- >"$diff_file"', recovery_text)
        self.assertIn('test "$(sha256sum "$manifest"', recovery_text)
        self.assertIn('test "$(sha256sum "$diff_file"', recovery_text)
        self.assertIn(
            "changelogs/fragments/*.yml|changelogs/fragments/*.yaml)",
            recovery_text,
        )
        self.assertIn("changelogs/fragments/*/*)", recovery_text)
        self.assertIn("Nested release fragment is unauthorized", recovery_text)
        self.assertIn(
            'test "$fragment" = "${fragment##*/}"',
            recovery_text,
        )
        self.assertIn(
            'test("^[A-Za-z0-9][A-Za-z0-9._-]*\\\\.ya?ml$")',
            recovery_text,
        )
        self.assertIn('test "$status" = D', recovery_text)
        self.assertIn(
            'git cat-file -e "${EXPECTED_BASE}:${fragment_path}"',
            recovery_text,
        )
        self.assertIn(
            'test "$(sha256sum "$fragment_file"',
            recovery_text,
        )
        self.assertIn(
            'cmp --silent "$receipt_fragments" "$deleted_fragments"',
            recovery_text,
        )
        self.assertIn("plugins/modules/atomic_path.py|plugins/modules/atomic_unlink.py", recovery_text)
        self.assertIn("tests/unit/test_li139_release_metadata.py", recovery_text)
        self.assertIn('cmp --silent "$receipt_from_main" "$receipt_from_head"', recovery_text)
        self.assertIn("permission-contents: read", recovery_text)
        self.assertNotIn("permission-contents: write", recovery_text)
        self.assertIn("gh pr create \\", recovery_text)
        self.assertIn("--draft \\", recovery_text)
        self.assertIn('.user.login == "lightning-it-release-automation[bot]"', recovery_text)
        self.assertIn('gh pr ready "$recovery_pr"', recovery_text)
        self.assertNotIn("gh workflow run release-bot-exact-head-review.yml", recovery_text)
        self.assertIn("Native common control evaluates", recovery_text)
        self.assertNotIn("git push", recovery_text)
        self.assertNotIn("--force", recovery_text)

        refresh_path = WORKFLOWS / "release-recovery-review-refresh.yml"
        refresh = refresh_path.read_text(encoding="utf-8")
        refresh_yaml = load_yaml(refresh_path)
        refresh_inputs = refresh_yaml[True]["workflow_dispatch"]["inputs"]
        refresh_job = refresh_yaml["jobs"]["refresh"]
        self.assertEqual(
            {
                "recovery_pr",
                "source_pr",
                "tag",
                "expected_base",
                "expected_head",
                "main_sha",
                "paths_sha256",
                "diff_sha256",
            },
            set(refresh_inputs),
        )
        normalized_refresh_condition = " ".join(refresh_job["if"].split())
        self.assertIn("github.ref == 'refs/heads/develop'", normalized_refresh_condition)
        self.assertIn("github.ref_protected == true", normalized_refresh_condition)
        self.assertIn("github.actor == 'litroc'", normalized_refresh_condition)
        self.assertIn("github.triggering_actor == 'litroc'", normalized_refresh_condition)
        self.assertEqual("normal-release-promotion-approval", refresh_job["environment"])
        self.assertEqual({"contents": "read", "pull-requests": "read"}, refresh_job["permissions"])
        self.assertIn('test "$protected_develop" = "$GITHUB_SHA"', refresh)
        self.assertIn('test "$protected_develop" = "$EXPECTED_BASE"', refresh)
        self.assertIn('test "$protected_main" = "$MAIN_SHA"', refresh)
        self.assertIn('.user.login == "lightning-it-release-automation[bot]"', refresh)
        self.assertIn('.user.login == "litroc"', refresh)
        self.assertIn("and .body == $body", refresh)
        self.assertIn('test "$hop_count" -le 20', refresh)
        self.assertIn('synchronized_tree="$(git merge-tree --write-tree', refresh)
        self.assertIn(
            'git merge-base --is-ancestor "$synchronized_base" "$EXPECTED_BASE"',
            refresh,
        )
        self.assertIn('recovery_pr_base="$(jq -er .base.sha <<<"$recovery_pr")"', refresh)
        self.assertIn('current_recovery_base="$synchronized_base"', refresh)
        self.assertIn('recovery_base="$recovery_pr_base"', refresh)
        self.assertIn('test "$recovery_pr_base" = "$current_recovery_base"', refresh)
        self.assertIn(
            'git merge-base --is-ancestor "$current_recovery_base" "$EXPECTED_BASE"',
            refresh,
        )
        self.assertIn('echo "recovery_pr_base=$recovery_pr_base"', refresh)
        pre_token_proof = refresh.split(
            "      - name: Prove immutable recovery, ancestry, and next tree before token access",
            1,
        )[1].split("      - name: Mint repository-scoped release automation App token", 1)[0]
        self.assertNotIn('--arg base "$EXPECTED_BASE"', pre_token_proof)
        self.assertIn('and (.base.sha | test("^[0-9a-f]{40}$"))', pre_token_proof)
        self.assertIn(
            'GH_TOKEN="$GH_TOKEN" git -c credential.helper= \\',
            refresh,
        )
        self.assertIn(
            "-c 'credential.helper=!gh auth git-credential' fetch \"$@\"",
            refresh,
        )
        self.assertIn("authenticated_fetch --no-tags origin \\", refresh)
        self.assertNotIn("\n          git fetch --no-tags origin \\", refresh)
        self.assertIn('test "$(sha256sum "$original_manifest"', refresh)
        self.assertIn('test "$(sha256sum "$original_diff"', refresh)
        self.assertIn('test "$(sha256sum "$final_manifest"', refresh)
        self.assertIn('test "$(sha256sum "$final_diff"', refresh)
        self.assertIn('cmp --silent "$receipt_from_main" "$receipt_from_source"', refresh)
        self.assertIn(".repository_id == $repository_id", refresh)
        self.assertIn('git merge-base --is-ancestor "$receipt_base" "$source_base"', refresh)
        self.assertIn("plugins/modules/atomic_path.py|plugins/modules/atomic_unlink.py", refresh)
        self.assertIn('cmp --silent "$receipt_fragments" "$deleted_fragments"', refresh)
        self.assertLess(
            refresh.index('receipt_from_main="$RUNNER_TEMP/'),
            refresh.index("      - name: Mint repository-scoped release automation App token"),
        )
        self.assertIn("permission-actions: write", refresh)
        self.assertIn("permission-contents: write", refresh)
        self.assertNotIn("permission-contents: read", refresh)
        self.assertIn("GitHub requires App callers of update-branch", refresh)
        self.assertIn("permission-pull-requests: write", refresh)
        final_step = refresh.split(
            "      - name: Re-prove, update normally, and dispatch exact-head review as Release App",
            1,
        )[1]
        self.assertIn("MAIN_SHA: ${{ inputs.main_sha }}", final_step)
        self.assertIn("SOURCE_HEAD: ${{ steps.recovery.outputs.source_head }}", final_step)
        self.assertIn("SOURCE_PR_NUMBER: ${{ inputs.source_pr }}", final_step)
        self.assertIn(
            "RECOVERY_PR_BASE: ${{ steps.recovery.outputs.recovery_pr_base }}",
            final_step,
        )
        self.assertIn(
            'protected_main="$(gh api "repos/${REPOSITORY}/git/ref/heads/main" --jq .object.sha)"',
            final_step,
        )
        self.assertIn('test "$protected_main" = "$MAIN_SHA"', final_step)
        self.assertIn('source_pr="$(gh api "repos/${REPOSITORY}/pulls/${SOURCE_PR_NUMBER}")"', final_step)
        self.assertIn('.state == "closed"', final_step)
        self.assertIn("and .merged == false", final_step)
        self.assertIn('and .user.login == "litroc"', final_step)
        self.assertIn("and .head.sha == $head", final_step)
        self.assertIn('expected_body="Release-App recovery of the closed source PR', final_step)
        self.assertIn("and .body == $body", final_step)
        self.assertEqual(2, final_step.count('test "$protected_main" = "$MAIN_SHA"'))
        self.assertEqual(2, final_step.count("and .body == $body"))
        self.assertLess(
            final_step.index('--arg base "$RECOVERY_PR_BASE"'),
            final_step.index('"repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}/update-branch"'),
        )
        self.assertGreater(
            final_step.rindex('--arg base "$EXPECTED_BASE"'),
            final_step.index('"repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}/update-branch"'),
        )
        self.assertEqual(
            3,
            final_step.count('live_pr="$(gh api "repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}")"'),
        )
        dispatch_offset = final_step.index("gh workflow run release-bot-exact-head-review.yml")
        self.assertLess(final_step.rindex('test "$protected_main" = "$MAIN_SHA"'), dispatch_offset)
        self.assertLess(final_step.rindex("and .body == $body"), dispatch_offset)
        self.assertGreater(
            final_step.rindex('live_pr="$(gh api "repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}")"'),
            final_step.rindex('source_pr="$(gh api "repos/${REPOSITORY}/pulls/${SOURCE_PR_NUMBER}")"'),
        )
        self.assertLess(
            final_step.rindex('live_pr="$(gh api "repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}")"'),
            final_step.rindex("and .body == $body"),
        )
        self.assertLess(
            final_step.index("and .body == $body"),
            final_step.index('"repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}/update-branch"'),
        )
        self.assertIn('"repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}/update-branch"', refresh)
        self.assertIn('-f "expected_head_sha=${EXPECTED_HEAD}"', refresh)
        self.assertIn("and .parents[0].sha == $previous", refresh)
        self.assertIn("and .parents[1].sha == $base", refresh)
        self.assertIn("and .tree.sha == $tree", refresh)
        self.assertIn("gh workflow run release-bot-exact-head-review.yml", refresh)
        self.assertLess(
            refresh.index('"repos/${REPOSITORY}/pulls/${RECOVERY_PR_NUMBER}/update-branch"'),
            refresh.index("gh workflow run release-bot-exact-head-review.yml"),
        )
        self.assertNotIn("git push", refresh)
        self.assertNotIn("--force", refresh)
        self.assertNotIn("gh pr merge", refresh)
        self.assertNotIn("--admin", refresh)
        self.assertNotIn("--auto", refresh)

        self.assertIn(
            '-f release_tag_app_slug="$RELEASE_TAG_APP_SLUG"',
            publish,
        )
        self.assertIn('-f release_tag_app_id="$RELEASE_TAG_APP_ID"', publish)
        self.assertIn(
            '-f release_tag_app_client_id="$RELEASE_TAG_APP_CLIENT_ID"',
            publish,
        )

        for name in (
            "promote-develop-to-main.yml",
            "release-back-sync.yml",
            "release-prepare.yml",
        ):
            with self.subTest(workflow=name):
                workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
                if name == "promote-develop-to-main.yml":
                    self.assertIn("REPOSITORY_OWNER: ${{ github.repository_owner }}", workflow)
                else:
                    self.assertIn("GITHUB_REPOSITORY_OWNER", workflow)
                self.assertIn(".head.repo.full_name", workflow)
                self.assertNotIn("gh pr list", workflow)

    def test_release_version_and_merge_policy_fail_closed(self) -> None:
        prepare = (WORKFLOWS / "release-prepare.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/release-version.py", prepare)
        self.assertIn("--write-preparation-receipt changelogs/release-preparation.json", prepare)
        self.assertIn('--security-target-version "$SECURITY_VERSION"', prepare)
        self.assertIn("unselected-release-fragments-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}", prepare)
        self.assertIn('test ! -e "changelogs/fragments/$selected_fragment"', prepare)
        self.assertIn('mv -- "$fragment" "changelogs/fragments/${fragment##*/}"', prepare)
        self.assertIn('--base-sha "$BASE_SHA"', prepare)
        self.assertNotIn("AUTO_RELEASE_BUMP", prepare)
        self.assertIn("Required merge method: \\`merge commit\\`", prepare)

    def test_main_recovery_is_relayed_to_the_immutable_main_controller(self) -> None:
        dispatch = (WORKFLOWS / "security-release-dispatch.yml").read_text(encoding="utf-8")
        self.assertIn("Relay successful protected-main run to immutable main controller", dispatch)
        self.assertIn('-f "recovery_source_run_id=$SOURCE_RUN_ID"', dispatch)
        self.assertIn("${{ inputs.recovery_source_run_id }}", dispatch)
        classify = dispatch.split("classify-recovery:", 1)[1].split("dispatch-recovery:", 1)[0]
        self.assertNotIn("github.event_name == 'workflow_run'", classify)
        prepare = (WORKFLOWS / "release-prepare.yml").read_text(encoding="utf-8")
        self.assertIn("Immutable tag v${VERSION} already exists", prepare)
        publish = (WORKFLOWS / "collection-publish.yml").read_text(encoding="utf-8")
        exact_revision = (WORKFLOWS / "release-bot-exact-head-review.yml").read_text(encoding="utf-8")
        self.assertIn("Re-prove fragment-derived version and authorized preparation", publish)
        self.assertIn('release_mode="$(jq -er \'.release_mode\' "$receipt")"', publish)
        self.assertIn('--security-target-version "$expected_version"', publish)
        self.assertIn('--root "$base_tree"', publish)
        self.assertIn('version_args=(--requested-version "$expected_version")', publish)
        self.assertIn('"${version_args[@]}"', publish)
        self.assertIn('test "${#preparation_parents[@]}" -eq 1', publish)
        self.assertIn(
            'git diff --quiet "$REVIEWED_HEAD_SHA" "$RELEASE_SHA" -- .',
            publish,
        )
        self.assertIn("--verify-preparation-receipt", publish)
        self.assertIn('git worktree add --detach --quiet "$base_tree" "$REVIEWED_BASE_SHA"', publish)
        self.assertIn('--root "$base_tree"', publish)
        self.assertEqual(
            2,
            publish.count('python "$workflow_tree/scripts/release-version.py"'),
        )
        self.assertIn('workflow_tree="$base_tree"', publish)
        self.assertIn('git worktree add --detach --quiet "$workflow_tree" "$workflow_source"', publish)
        self.assertIn('--galaxy "$base_tree/galaxy.yml"', publish)
        self.assertIn('--fragments "$base_tree/changelogs/fragments"', publish)
        self.assertNotIn("pull_request_target:", exact_revision)
        self.assertIn("workflow_dispatch:", exact_revision)
        self.assertIn("github.actor == 'lightning-it-release-automation[bot]'", exact_revision)
        self.assertIn("load_protected_asset() {", exact_revision)
        self.assertIn("scripts/materialize-exact-revision-review.py", exact_revision)
        self.assertEqual(1, exact_revision.count("?ref=${TRUSTED_WORKFLOW_SHA}"))
        self.assertIn("name: Current revision review", exact_revision)
        self.assertTrue("publish_once() {" in exact_revision or "create_reservation_once() {" in exact_revision)
        self.assertTrue(
            "'Current revision review'" in exact_revision or "-f name='Current revision review'" in exact_revision
        )
        self.assertNotIn("Successful Copilot review", exact_revision)
        self.assertIn("actions/runs/${preparation_run_id}", publish)
        self.assertIn('.conclusion == "success"', publish)
        action = ACTION.read_text(encoding="utf-8")
        collection_ci = (WORKFLOWS / "collection-ci.yml").read_text(encoding="utf-8")
        self.assertIn("QUALITY_SOURCE_SHA:", collection_ci)
        expected_quality_source = (
            "QUALITY_SOURCE_SHA: ${{ github.event_name == 'pull_request' && "
            "github.event.pull_request.head.sha || github.sha }}"
        )
        self.assertIn(
            expected_quality_source,
            collection_ci,
        )
        collection_payload = load_yaml(WORKFLOWS / "collection-ci.yml")
        self.assertNotIn("QUALITY_SOURCE_SHA", collection_payload["env"])
        self.assertNotIn("actions/setup-python@", action)
        self.assertIn('tool_root="$(mktemp -d ', action)
        self.assertIn('echo "QUALITY_TOOL_ROOT=$tool_root" >> "$GITHUB_ENV"', action)
        self.assertIn('python3 -m venv "$tool_root"', action)
        self.assertNotIn("--system-site-packages", action)
        self.assertIn('case "$QUALITY_TOOL_ROOT" in', action)
        self.assertIn('"$RUNNER_TEMP"/supplementary-quality-tools/*)', action)
        self.assertIn('rm -rf -- "$QUALITY_TOOL_ROOT"', action)
        self.assertIn("ansible-core==2.18.18", action)
        self.assertIn("molecule==25.12.0", action)
        self.assertIn("molecule-plugins==25.8.12", action)
        self.assertNotIn("QUALITY_DEFAULT_COLLECTION_PATHS", action)
        self.assertIn('export PATH="$tool_root/bin:$PATH"', action)
        self.assertIn("command -v python3", action)
        self.assertNotRegex(action, r"(?m)(?<![A-Za-z0-9_-])python(?!3)(?:\s|$)")
        self.assertIn(
            "MOLECULE_EPHEMERAL_DIRECTORY=$molecule_ephemeral_root",
            action,
        )
        self.assertIn('molecule_ephemeral_root="${temp_root}/molecule-ephemeral"', action)
        self.assertIn('os.environ["QUALITY_PROFILE"].replace("_", "-")', action)
        self.assertIn('["git", "show", f"{source_sha}:{path.as_posix()}"]', action)
        self.assertIn('registry = Path("meta/role-coverage.yml")', action)
        self.assertIn('"schema_version": 2', action)
        self.assertIn('"test_application_policy": policy', action)
        self.assertIn("scenario-owned test-application descriptors are forbidden", action)

    def test_local_container_launchers_fail_closed_and_guard_ssh_credentials(self) -> None:
        for name in ("wunder-container-run.sh", "wunder-devtools-ee.sh"):
            with self.subTest(wrapper=name):
                wrapper = (ROOT / "scripts" / name).read_text(encoding="utf-8")
                self.assertIn("fail_closed", wrapper)
                self.assertNotIn("fail_or_skip", wrapper)
                self.assertNotIn("skipping local hook", wrapper)

        devtools = (ROOT / "scripts" / "wunder-devtools-ee.sh").read_text(encoding="utf-8")
        self.assertIn(
            'VAGRANT_SSH_POLICY="${WUNDER_DEVTOOLS_FORWARD_VAGRANT_SSH:-disabled}"',
            devtools,
        )
        self.assertNotIn("${VAGRANT_SSH_KEY:+-e VAGRANT_SSH_KEY}", devtools)
        self.assertIn('if [ "$VAGRANT_SSH_POLICY" = enabled ]', devtools)
        self.assertIn(
            'HOME_TMPFS_MOUNT="${CONTAINER_HOME}:rw,exec,nosuid,nodev,size=1g,mode=1777"',
            devtools,
        )
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("explicitly mounted `exec`", contributing)
        self.assertIn("No persistent whole-home cache is mounted", contributing)

        molecule = (ROOT / "scripts" / "devtools-molecule.sh").read_text(encoding="utf-8")
        self.assertIn("A Docker-compatible socket must not enter", molecule)
        self.assertNotIn("Skipping Molecule tests because Docker", molecule)
        self.assertIn("WUNDER_DEVTOOLS_DOCKER_SOCKET=disabled", molecule)
        self.assertIn("WUNDER_DEVTOOLS_NETWORK=none", molecule)
        self.assertIn("WUNDER_DEVTOOLS_ROOTFS_MODE=ro", molecule)
        self.assertIn("WUNDER_DEVTOOLS_WORKSPACE_MODE=ro", molecule)
        self.assertIn("WUNDER_DEVTOOLS_RUN_AS_HOST_UID=1", molecule)
        self.assertIn("WUNDER_DEVTOOLS_RUN_AS_ROOT=0", molecule)
        self.assertIn("WUNDER_DEVTOOLS_MOUNT_SOURCE_ROOT=disabled", molecule)
        self.assertIn("WUNDER_DEVTOOLS_FORWARD_VAGRANT_SSH=disabled", molecule)
        self.assertIn("WUNDER_DEVTOOLS_OFFLINE_LOCAL_ONLY=1", molecule)
        self.assertIn("REQUIRE_DECLARED_DEPENDENCIES=0", molecule)
        self.assertIn("REQUIRE_DECLARED_DEPENDENCIES=1", molecule)
        self.assertIn(
            'WUNDER_DEVTOOLS_REQUIRE_DECLARED_DEPENDENCIES="${REQUIRE_DECLARED_DEPENDENCIES}"',
            molecule,
        )
        self.assertIn('SCENARIO_FILTER="${1:-artifacts-basic}"', molecule)
        self.assertIn('driver.get("name") != "default"', molecule)
        self.assertIn("except yaml.YAMLError:", molecule)
        self.assertIn("if not isinstance(payload, dict):", molecule)
        self.assertIn("if not isinstance(driver, dict):", molecule)
        self.assertIn(
            "if not isinstance(platforms, list) or not platforms:",
            molecule,
        )
        self.assertIn(
            "if any(not isinstance(platform, dict) for platform in platforms):",
            molecule,
        )
        self.assertIn('platform.get("managed") is not False', molecule)
        self.assertIn('[[ ! "${scen}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]', molecule)
        self.assertIn('printf "%s\\n" "prerun: false"', molecule)
        self.assertIn('molecule_ephemeral_root="${HOME}/molecule-ephemeral"', molecule)
        self.assertIn('MOLECULE_EPHEMERAL_DIRECTORY="${molecule_ephemeral_directory}"', molecule)
        self.assertIn('molecule -c "${offline_base}" test', molecule)
        self.assertNotIn("docker info", molecule)
        self.assertNotIn("WUNDER_DEVTOOLS_CAP_ADD=CHOWN", molecule)

        prepare = (ROOT / "scripts" / "devtools-collection-prepare.sh").read_text(encoding="utf-8")
        self.assertIn('offline_local_only="${WUNDER_DEVTOOLS_OFFLINE_LOCAL_ONLY:-0}"', prepare)
        self.assertIn("Offline local-only mode: external collection dependency installation is forbidden.", prepare)
        self.assertIn("local dependency source roots are intentionally not mounted", prepare)
        self.assertIn("WUNDER_DEVTOOLS_REQUIRE_DECLARED_DEPENDENCIES=0 or 1", prepare)
        self.assertIn("/usr/share/ansible/collections/ansible_collections/", prepare)
        self.assertIn("/MANIFEST.json", prepare)
        self.assertIn("declared galaxy.yml dependencies missing", prepare)
        self.assertIn("This offline gate requires every declared dependency", prepare)
        for helper_name in (
            "devtools-ansible-lint.sh",
            "devtools-collection-smoke.sh",
            "devtools-galaxy-verify.sh",
            "devtools-molecule.sh",
        ):
            with self.subTest(offline_helper=helper_name):
                helper = (ROOT / "scripts" / helper_name).read_text(encoding="utf-8")
                self.assertIn("WUNDER_DEVTOOLS_NETWORK=none", helper)
                self.assertIn("WUNDER_DEVTOOLS_OFFLINE_LOCAL_ONLY=1", helper)
                self.assertIn("WUNDER_DEVTOOLS_REQUIRE_DECLARED_DEPENDENCIES=", helper)
                self.assertNotIn("WUNDER_DEVTOOLS_NETWORK=bridge", helper)

        ansible_lint = (ROOT / "scripts" / "devtools-ansible-lint.sh").read_text(encoding="utf-8")
        self.assertIn("export ANSIBLE_LINT_NODEPS=1", ansible_lint)
        self.assertIn('ansible-lint --offline "${ansible_lint_args[@]}"', ansible_lint)
        self.assertIn('"--exclude" "playbooks/rhel_prepare.yml"', ansible_lint)
        self.assertIn('"--exclude" "playbooks/rhel_teardown.yml"', ansible_lint)

    def test_devtools_capability_policy_expands_to_individual_docker_arguments(self) -> None:
        wrapper = ROOT / "scripts" / "wunder-devtools-ee.sh"
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                '#!/usr/bin/env bash\nset -euo pipefail\nprintf "%s\\n" "$@" >"${WUNDER_DEVTOOLS_ARGV:?}"\n',
                encoding="utf-8",
            )
            fake_docker.chmod(0o700)
            captured_arguments = temporary / "docker-arguments"
            container_home = temporary / "container-home"
            environment = os.environ.copy()
            environment.update(
                {
                    "CONTAINER_HOME": str(container_home),
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "WUNDER_CONTAINER_ENGINE": "docker",
                    "WUNDER_DEVTOOLS_ARGV": str(captured_arguments),
                    "WUNDER_DEVTOOLS_CAP_ADD": "CHOWN,FOWNER",
                    "WUNDER_DEVTOOLS_DOCKER_SOCKET": "disabled",
                }
            )

            bash = shutil.which("bash")
            self.assertIsNotNone(bash, "bash is required for the wrapper contract test")
            subprocess.run(  # noqa: S603 -- execute the repository-owned wrapper under test.
                [bash, str(wrapper), "true"],
                cwd=temporary,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )

            arguments = captured_arguments.read_text(encoding="utf-8").splitlines()
            capability_indices = [index for index, argument in enumerate(arguments) if argument == "--cap-add"]
            self.assertEqual(["CHOWN", "FOWNER"], [arguments[index + 1] for index in capability_indices])
            self.assertNotIn("CHOWN,FOWNER", arguments)
            capability_drop_index = arguments.index("--cap-drop")
            self.assertEqual("ALL", arguments[capability_drop_index + 1])
            self.assertNotIn("--privileged", arguments)
            self.assertIn(
                f"{container_home}:rw,exec,nosuid,nodev,size=1g,mode=1777",
                arguments,
            )

    def test_security_publish_requires_nexus_and_signed_validation_before_galaxy(self) -> None:
        workflow = (WORKFLOWS / "collection-publish.yml").read_text(encoding="utf-8")
        jobs = yaml.safe_load(workflow)["jobs"]
        stage_names = [step.get("name") for step in jobs["publish"]["steps"]]
        finalize_names = [step.get("name") for step in jobs["publish-security-finalize"]["steps"]]
        self.assertLess(
            stage_names.index("Stage exact Security candidate in native Nexus Galaxy v3"),
            stage_names.index("Dispatch exact ModuLix validation request once"),
        )
        self.assertLess(
            finalize_names.index("Reverify the same signed ModuLix receipt"),
            finalize_names.index("Publish or verify validated artifact on Ansible Galaxy"),
        )
        self.assertIn("modulix-validation-window-6", jobs["publish-security-finalize"]["needs"])
        self.assertIn(
            "needs.modulix-validation-window-6.outputs.complete == 'true'", jobs["publish-security-finalize"]["if"]
        )
        self.assertIn("RELEASE_AUTOMATION_APP_CLIENT_ID", workflow)
        self.assertIn("RELEASE_AUTOMATION_APP_PRIVATE_KEY", workflow)
        self.assertIn("permission-actions: write", workflow)
        self.assertIn("steps.modulix-validation-app.outputs.token", workflow)
        self.assertIn("scripts/nexus-galaxy-v3-stage.py", workflow)
        self.assertIn("scripts/modulix-validation-receipt.py", workflow)
        self.assertNotIn("scripts/dispatch-transition-validation.py", workflow)
        self.assertNotIn("transition-noop", workflow)

    def test_security_finalizer_publication_guards_allow_validated_release(self) -> None:
        jobs = load_yaml(WORKFLOWS / "collection-publish.yml")["jobs"]
        finalizer = jobs["publish-security-finalize"]
        environment = finalizer["env"]
        self.assertEqual("true", environment["SECURITY_RELEASE"])
        self.assertEqual("true", environment["GALAXY_REQUIRED"])
        steps = {step.get("name"): step for step in finalizer["steps"]}
        for name in (
            "Create or verify immutable tag with dedicated App",
            "Create or verify GitHub Release and immutable assets",
            "Publish or verify validated artifact on Ansible Galaxy",
        ):
            with self.subTest(step=name):
                condition = steps[name].get("if", "'true' == 'true'")
                # These publication guards use only string comparisons. Execute
                # that boolean expression with the actual finalizer environment.
                condition = re.sub(
                    r"env\.([A-Z_]+)",
                    lambda match: "'" + environment[match[1]] + "'",
                    condition,
                )
                self.assertRegex(condition, r"^[a-z' =!&|()\s]+$")
                executable = shutil.which("bash")
                assert executable
                result = subprocess.run(  # noqa: S603 -- repository-owned boolean guard, constrained above.
                    [executable, "-c", "[[ " + condition + " ]]"],
                    check=False,
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(0, result.returncode, result.stderr.decode())

    def test_publish_security_release_is_metadata_bound_and_dispatches_after_acceptance(self) -> None:
        workflow_path = WORKFLOWS / "collection-publish.yml"
        workflow_text = workflow_path.read_text(encoding="utf-8")
        jobs = load_yaml(workflow_path)["jobs"]
        publish = jobs["publish"]
        finalizer = jobs["publish-security-finalize"]
        self.assertEqual("write", publish["permissions"]["attestations"])
        self.assertEqual(90, publish["timeout-minutes"])
        self.assertEqual(90, finalizer["timeout-minutes"])
        step_names = [step.get("name") for step in publish["steps"]]
        classify_index = step_names.index("Classify exact-SHA Security release metadata")
        prepare_index = step_names.index("Prepare deterministic signed Security release evidence")
        attest_index = step_names.index("Attest Security release evidence")
        stage_dispatch_index = step_names.index("Dispatch exact ModuLix validation request once")
        final_names = [step.get("name") for step in finalizer["steps"]]
        receipt_index = final_names.index("Reverify the same signed ModuLix receipt")
        finalize_index = final_names.index("Finalize immutable release attachments and notes")
        release_index = final_names.index("Create or verify GitHub Release and immutable assets")
        verify_index = final_names.index("Verify GitHub Release download, install, and smoke")
        post_receipt_index = final_names.index("Attach signed post-publication verification receipt")
        dispatch_index = final_names.index("Dispatch immutable Security evidence after Producer acceptance")
        self.assertLess(classify_index, prepare_index)
        self.assertLess(prepare_index, attest_index)
        self.assertLess(attest_index, stage_dispatch_index)
        self.assertLess(receipt_index, finalize_index)
        self.assertLess(finalize_index, release_index)
        self.assertLess(release_index, verify_index)
        self.assertLess(verify_index, post_receipt_index)
        self.assertLess(post_receipt_index, dispatch_index)

        steps = {step.get("name"): step for step in publish["steps"]}
        self.assertEqual(
            "env.SECURITY_RELEASE == 'true'",
            steps["Prepare deterministic signed Security release evidence"]["if"],
        )
        self.assertEqual(
            "env.SECURITY_RELEASE == 'true'",
            steps["Attest Security release evidence"]["if"],
        )
        self.assertNotIn("attest_needed", workflow_text)
        self.assertIn('test -n "$ATTESTATION_ID"', workflow_text)
        self.assertIn('test -s "$ATTESTATION_BUNDLE"', workflow_text)
        final_steps = {step.get("name"): step for step in finalizer["steps"]}
        self.assertEqual(
            "env.SECURITY_RELEASE == 'true'",
            final_steps["Dispatch immutable Security evidence after Producer acceptance"]["if"],
        )
        self.assertEqual(
            "env.SECURITY_RELEASE == 'true' && env.GALAXY_REQUIRED == 'true'",
            steps["Dispatch exact ModuLix validation request once"]["if"],
        )
        self.assertIn(
            "env.SECURITY_RELEASE != 'true'", steps["Publish or verify validated artifact on Ansible Galaxy"]["if"]
        )
        self.assertNotIn('test "$GALAXY_REQUIRED" = true', workflow_text)
        self.assertIn("No exact-version Security metadata", workflow_text)
        self.assertIn(".lit/security-releases/${RELEASE_VERSION}.json", workflow_text)
        self.assertIn('--metadata "$SECURITY_METADATA"', workflow_text)
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6", workflow_text)
        self.assertIn('test "$APP_INSTALLATION_ID" = 148019054', workflow_text)
        self.assertIn("installation/repositories?per_page=100", workflow_text)
        self.assertIn(
            "jq -sc '[.[].repositories[].full_name] | sort | unique'",
            workflow_text,
        )
        self.assertNotIn("gh api --paginate --slurp", workflow_text)
        self.assertIn('test "$revocation_count" -eq 0', workflow_text)
        self.assertGreaterEqual(workflow_text.count("generate-security-release-evidence.py verify"), 2)
        self.assertIn("permission-actions: write", workflow_text)
        self.assertNotIn("--clobber", workflow_text)

        generator = (ROOT / "scripts/generate-security-release-evidence.py").read_text(encoding="utf-8")
        for free_claim in (
            'add_argument("--id"',
            'add_argument("--security-id"',
            'add_argument("--consumer"',
            'add_argument("--acceptance-profile"',
            'add_argument("--created-at"',
            'add_argument("--not-before"',
            'add_argument("--expires-at"',
        ):
            self.assertNotIn(free_claim, generator)
        dispatcher = (ROOT / "scripts/dispatch-security-release.py").read_text(encoding="utf-8")
        self.assertIn("security-release-update.yml/dispatches", dispatcher)
        self.assertIn("inputs[evidence_url]", dispatcher)
        self.assertIn("inputs[evidence_sha256]", dispatcher)
        self.assertNotIn("inputs[evidence_id]", dispatcher)
        self.assertNotIn('add_argument("--ref"', dispatcher)

        profiles = json.loads((ROOT / ".lit" / "security-release-profiles.json").read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "lit.supplementary/forgejo-manifest-secret-permissions-v1": {
                    "description": (
                        "Verify the packaged Forgejo Pod manifest writer is root:root mode 0600 with no_log enabled."
                    ),
                    "releaseEligible": True,
                },
                "lit.supplementary/keycloak-26.7.1-security-v1": {
                    "description": (
                        "Verify the packaged Keycloak runtime is pinned to official "
                        "26.7.1 OCI index digest in role defaults, identity manifest, "
                        "and source inventory."
                    ),
                    "releaseEligible": True,
                },
                "lit.supplementary/mlx90-fixture": {
                    "description": "Historical v3.1.2/#488 dry-run fixture; never release eligible.",
                    "releaseEligible": False,
                },
            },
            profiles["profiles"],
        )


if __name__ == "__main__":
    unittest.main()
