"""Canonical port invariants outside the central .github Required authority."""

import json
import os
import shutil
import subprocess
import unittest

import yaml

from unit.review_event_contract_helpers import ROOT, shell_function


class EventPortTests(unittest.TestCase):
    def test_enabled_refresh_accepts_same_repo_v5_without_field_and_keeps_v6_binding(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/copilot-review-refresh.yml").read_text())
        job = workflow["jobs"]["refresh-canonical-gate"]
        self.assertIn("vars.LI219_EVENT_MODE == 'enabled'", job["if"])
        body = job["steps"][1]["run"]
        start = body.index('if [ "${neutral_count}" -eq 1 ]; then\n  refresh_expected_snapshot=')
        decision = body[start : body.index('\nincomplete="$(jq', start)]
        repository = "lightning-it/ansible-collection-supplementary"
        base, head = "a" * 40, "b" * 40
        for version, head_repository, summary_repository, accepted in (
            (5, repository, None, True),
            (5, "contributor/fork", None, False),
            (5, repository, "contributor/fork", False),
            (6, repository, repository, True),
            (6, repository, "contributor/fork", False),
            (6, repository, None, False),
        ):
            with self.subTest(version=version, head=head_repository, summary=summary_repository):
                summary = {"schema": 4, "base_sha": base, "head_sha": head, "producer_run_id": 77}
                if summary_repository is not None:
                    summary["head_repository"] = summary_repository
                if version == 6:
                    summary["pull_request_number"] = 23
                external = f"mlx90-current-revision:copilot:v{version}:"
                external += ("23:" if version == 6 else "") + f"77:{base}:{head}"
                check = {
                    "id": 101,
                    "status": "completed",
                    "conclusion": "success",
                    "details_url": f"https://github.com/{repository}/runs/101",
                    "external_id": external,
                    "output": {"title": "Current revision review passed", "summary": json.dumps(summary)},
                }
                # Exercise the enabled writer's actual post-authentication
                # decision block; owner/native-read and effect helpers are inert.
                script = (
                    'set -euo pipefail\ntest "$LI219_EVENT_MODE" = enabled\n'
                    "va() { return 0; }\nvh() { return 1; }\n"
                    "gh() { return 97; }\ninvalidate_refresh_check() { invalidations=$((invalidations + 1)); }\n"
                    "neutral_count=1\ninvalidations=0\n"
                    + decision
                    + '\nprintf "%s:%s" "$neutral_count" "$invalidations"\n'
                )
                result = subprocess.run(  # noqa: S603 -- actual local workflow block with inert effect helpers.
                    [shutil.which("bash") or "/bin/bash", "-c", script],
                    env={
                        **os.environ,
                        "LI219_EVENT_MODE": "enabled",
                        "neutral": json.dumps([check]),
                        "REPOSITORY": repository,
                        "HEAD_REPOSITORY": head_repository,
                        "BASE_SHA": base,
                        "HEAD_SHA": head,
                        "PR_NUMBER": "23",
                        "PR_AUTHOR": "litroc",
                        "current_external_kind": "copilot",
                        "owner_run_id": "77",
                        "evidence_owner_run_id": "77",
                        "owner_pr_number": "23",
                        "GITHUB_SERVER_URL": "https://github.com",
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(result.stdout.endswith("1:0" if accepted else "0:1"), result.stdout)

    def test_event_producer_attempt_and_complete_terminal_inventory(self):
        function = shell_function(ROOT / ".github/workflows/current-revision-rerun.yml", "validate_event_producer")
        # Bind the count before boolean checks: jq 1.8 changes the ambiguous
        # `predicate and generator as $count` evaluation used by older jq.
        self.assertIn('([.[].jobs[]] | length) as $count\n    | type == "array"', function)
        for attempt in (1, 2):
            for conclusion in ("success", "failure"):
                producer = {
                    "id": 42,
                    "run_attempt": attempt,
                    "status": "completed",
                    "conclusion": conclusion,
                    "actor": {"login": "maintainer"},
                    "triggering_actor": {"login": "maintainer" if attempt == 1 else "github-actions[bot]"},
                    "event": "pull_request_target",
                    "path": ".github/workflows/copilot-review.yml",
                    "head_sha": "b" * 40,
                    "head_branch": "feature",
                    "created_at": "2026-10-07T00:00:00Z",
                    "display_title": "Contributor feature",
                }
                jobs = [
                    {
                        "total_count": 3,
                        "jobs": [
                            {
                                "id": 100 + index,
                                "name": name,
                                "run_id": 42,
                                "run_attempt": attempt,
                                "head_sha": "b" * 40,
                                "status": "completed",
                                "conclusion": result,
                            }
                            for index, (name, result) in enumerate(
                                (
                                    ("Verify current revision policy", "success"),
                                    ("Request protected verifier re-evaluation", conclusion),
                                    ("Inactive legacy handoff", "skipped"),
                                )
                            )
                        ],
                    }
                ]
                origin = {**producer, "run_attempt": 1, "triggering_actor": producer["actor"]}
                cases = [("valid maintainer differs from author", producer, jobs, origin, True)]
                for name, target, key, value in (
                    ("stale attempt", "producer", "run_attempt", 3 - attempt),
                    ("in progress", "producer", "status", "in_progress"),
                    ("hidden job", "page", "total_count", 4),
                    ("fractional id", "job", "id", 100.5),
                    ("wrong head", "job", "head_sha", "c" * 40),
                    ("extra failure", "job", "conclusion", "failure"),
                    ("foreign sender", "producer", "actor", {"login": "foreign"}),
                    ("foreign rerunner", "producer", "triggering_actor", {"login": "foreign"}),
                ):
                    p, j = (json.loads(json.dumps(producer)), json.loads(json.dumps(jobs)))
                    {"producer": p, "page": j[0], "job": j[0]["jobs"][0]}[target][key] = value
                    cases.append((name, p, j, origin, False))
                for key, value in (
                    ("actor", {"login": "foreign"}),
                    ("triggering_actor", {"login": "foreign"}),
                    ("id", 99),
                    ("run_attempt", 2),
                    ("status", "in_progress"),
                    ("head_sha", "c" * 40),
                    ("display_title", "another event"),
                ):
                    cases.append(("wrong original " + key, producer, jobs, {**origin, key: value}, False))
                for name, p, j, original, valid in cases:
                    with self.subTest(attempt=attempt, conclusion=conclusion, case=name):
                        result = subprocess.run(  # noqa: S603 -- fixed local workflow fixture and stub transport.
                            [
                                shutil.which("bash") or "/bin/bash",
                                "-c",
                                function + '\nvalidate_event_producer "$PAYLOAD" "$JOBS"',
                            ],
                            env={
                                **os.environ,
                                "PAYLOAD": json.dumps(p),
                                "JOBS": json.dumps(j),
                                "EVENT_PRODUCER_RUN_ATTEMPT": str(attempt),
                                "producer_id": "42",
                                "author": "litroc",
                                "event_producer_origin": json.dumps(original),
                                "EXPECTED_HEAD": "b" * 40,
                            },
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.assertEqual(valid, result.returncode == 0, result.stderr)

    def test_terminal_markers_never_claim_or_post_and_later_valid_review_can_resume(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("markers", ROOT / "scripts/review_content_markers.py")
        markers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(markers)
        workflow = ROOT / ".github/workflows/copilot-review-refresh.yml"
        for marker in (
            *markers.FAILURE_MARKERS,
            "I can't review this pull request.",
            "I can\u2019t review this pull request.",
            "I can't review any files.",
            "I can\u2019t review any files.",
        ):
            for inline in (False, True):
                with self.subTest(marker=marker, inline=inline):
                    script = (
                        r"""set -euo pipefail
revalidate_refresh_state() { :; }
validate_refresh_owner_run() { :; }
assert_refresh_rerun_budget() { :; }
read_refresh_review_state() { printf '%s' '{"event_current":true,"incomplete":0,"unresolved":0}'; }
claim_review_operation() { printf C; }
gh() {
  if [[ "$*" == *'--method POST'* ]]; then printf P;
  else printf '%s' '{"status":"completed","run_attempt":1}'; fi
}
oa() {
  if [[ "$*" == *'/comments?'* ]]; then printf '%s' "$COMMENTS";
  elif [[ "$*" == *'/reviews?'* ]]; then printf '[[%s]]' "$REVIEW";
  else printf '%s' "$REVIEW"; fi
}
"""
                        + shell_function(workflow, "usable_current_review")
                        + "\n"
                        + shell_function(workflow, "rerun_owner_if_review_current")
                        + r"""
first="$(rerun_owner_if_review_current)"
test -z "$first"
REVIEW="$VALID_REVIEW"
COMMENTS='[[]]'
rerun_owner_if_review_current
"""
                    )
                    valid = {
                        "id": 17,
                        "commit_id": "b" * 40,
                        "body": "Review complete",
                        "user": {"login": "copilot-pull-request-reviewer[bot]"},
                        "state": "COMMENTED",
                    }
                    result = subprocess.run(  # noqa: S603 -- fixed local workflow fixture and stub transport.
                        [shutil.which("bash") or "/bin/bash", "-c", script],
                        capture_output=True,
                        text=True,
                        check=False,
                        env={
                            **os.environ,
                            "REVIEW": json.dumps(valid if inline else valid | {"body": marker}),
                            "VALID_REVIEW": json.dumps(valid),
                            "COMMENTS": json.dumps([[{"body": marker}]] if inline else [[]]),
                            "current_external_kind": "copilot",
                            "REPOSITORY": "lightning-it/shared-assets-lit",
                            "PR_NUMBER": "23",
                            "HEAD_SHA": "b" * 40,
                            "BASE_SHA": "a" * 40,
                            "owner_run_id": "77",
                            "refresh_expected_count": "0",
                            "refresh_expected_snapshot": "fixture",
                        },
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertTrue(result.stdout.startswith("CPRerun requested"), result.stdout)
