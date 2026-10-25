"""Canonical port invariants outside the central .github Required authority."""

import json
import os
import shutil
import subprocess
import unittest

from unit.review_event_contract_helpers import ROOT, shell_function


class EventPortTests(unittest.TestCase):
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
