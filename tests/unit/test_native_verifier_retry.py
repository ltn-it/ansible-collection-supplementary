"""Real LI-259 caller/receiver and Git-CAS protocol against native API fixtures."""

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("native_retry", ROOT / "scripts/native_verifier_retry.py")
RETRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETRY)


class NativeRetryTests(unittest.TestCase):
    REPOSITORY = "lightning-it/.github"

    def setUp(self):
        self.repo, self.repo_id = self.REPOSITORY, "123"
        self.head, self.source, self.receiver_source = "b" * 40, "c" * 40, "d" * 40
        self.start = dt.datetime(2026, 10, 7, tzinfo=dt.UTC)
        self.now = self.start
        self.pr = {
            "id": 23,
            "number": 23,
            "draft": False,
            "state": "open",
            "title": "Fix",
            "body": "Review this",
            "labels": [],
            "user": {"id": 76040632, "login": "litroc", "type": "User"},
            "head": {"sha": self.head, "ref": "fix/test", "repo": {"full_name": self.repo}},
            "base": {"sha": self.source, "ref": "develop", "repo": {"full_name": self.repo}},
        }
        recorded = {
            "number": 23,
            "url": f"https://api.github.com/repos/{self.repo}/pulls/23",
            **{
                side: {
                    "sha": self.pr[side]["sha"],
                    "ref": self.pr[side]["ref"],
                    "repo": {"url": f"https://api.github.com/repos/{self.repo}"},
                }
                for side in ("head", "base")
            },
        }
        self.run = {
            "id": 99,
            "workflow_id": 5,
            "workflow_url": f"https://api.github.com/repos/{self.repo}/actions/workflows/5",
            "path": RETRY.RECEIVER,
            "event": "pull_request_target",
            "repository": {"full_name": self.repo},
            "head_repository": {"full_name": self.repo},
            "head_sha": self.head,
            "head_branch": "fix/test",
            "actor": {"login": "litroc"},
            "triggering_actor": {"login": "litroc"},
            "pull_requests": [recorded],
            "display_title": f"Protected current revision PR #23 opened {self.head}",
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "failure",
            "run_started_at": self.at(-10),
        }
        if self.repo != "lightning-it/.github":
            self.run["workflow_url"] = f"https://api.github.com/repos/{self.repo}/actions/required_workflows/5"
        self.original = {
            "id": 100,
            "name": RETRY.JOB,
            "run_id": 99,
            "run_attempt": 1,
            "head_sha": self.head,
            "status": "completed",
            "conclusion": "failure",
            "steps": [
                {
                    "name": (
                        f"{RETRY.SOURCE_MARKER}lightning-it/.github/{RETRY.RECEIVER}@refs/heads/main "
                        f"{self.receiver_source} PR 23 base {self.source} head {self.head}"
                    ),
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        }
        self.jobs = {1: [self.original]}
        self.history = {1: copy.deepcopy(self.run)}
        self.producer = {
            **self.run,
            "id": 77,
            "path": RETRY.proof.PRODUCER,
            "status": "completed",
            "conclusion": "success",
        }
        self.producer_jobs = [
            {
                "id": 78,
                "name": "Verify current revision policy",
                "run_id": 77,
                "run_attempt": 1,
                "head_sha": self.head,
                "status": "completed",
                "conclusion": "success",
                "runner_id": 1,
                "steps": [{"name": "Verify current Copilot review and resolved findings", "conclusion": "success"}],
            }
        ]
        self.neutral = {
            "id": 79,
            "name": "Current revision review",
            "head_sha": self.head,
            "app": {"id": 15368, "slug": "github-actions"},
            "status": "completed",
            "conclusion": "success",
            "completed_at": self.at(-1),
            "external_id": f"mlx90-current-revision:copilot:v6:23:77:{self.source}:{self.head}",
            "output": {
                "summary": json.dumps(
                    {
                        "schema": 4,
                        "producer_run_id": 77,
                        "pull_request_number": 23,
                        "base_sha": self.source,
                        "head_sha": self.head,
                        "controller_sha": self.source,
                        "pull_request_last_edited_at": None,
                    }
                )
            },
        }
        self.review = {
            "id": 17,
            "commit_id": self.head,
            "user": {"login": RETRY.proof.BOT, "type": "Bot"},
            "state": "APPROVED",
            "body": "Review complete.",
            "submitted_at": self.at(-2),
        }
        self.last_edited_at = None
        self.comments, self.thread_rows = [], []
        self.annotation_rows = [
            {
                "annotation_level": "failure",
                "message": RETRY.ACQUISITION,
                "path": ".github",
                "start_line": 1,
                "end_line": 1,
            },
            {"annotation_level": "notice", "message": "Runner image migration notice"},
        ]
        self.effects, self.writes = [], []
        self.oid = "1" * 40
        self.snapshots = {self.oid: {}}
        self.cas_hook = None
        self.cas_unknown = False
        self.cas_before_visible = False
        self.cas_attempts = 0
        self.pending_cas = None
        self.effect_unknown = None
        self.scheduler_runs = []
        self.extra_run, self.extra_jobs = None, {}
        self.branches = {"develop": self.source, "main": self.receiver_source}
        self.env = {
            "LI219_EVENT_MODE": "enabled",
            "LI259_INFRA_RETRY": "enabled",
            "GITHUB_REPOSITORY": self.repo,
            "GITHUB_REPOSITORY_ID": self.repo_id,
            "GITHUB_RUN_ID": "55",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_SHA": self.source,
            "GITHUB_REF_PROTECTED": "true",
            "WORKFLOW_SHA": self.receiver_source,
            "WORKFLOW_REF": f"lightning-it/.github/{RETRY.RECEIVER}@refs/heads/main",
            "EVENT_BASE": self.source,
            "EVENT_HEAD": self.head,
            "PR_NUMBER": "23",
        }
        self.stack = [
            patch.dict(os.environ, self.env),
            patch.object(RETRY.proof, "api", side_effect=self.api),
            patch.object(RETRY, "utc_now", side_effect=lambda: self.now),
            patch("builtins.print"),
        ]
        for patcher in self.stack:
            patcher.start()
            self.addCleanup(patcher.stop)

    def at(self, seconds):
        return RETRY.stamp(self.start + dt.timedelta(seconds=seconds))

    def native_writer(self, run_id):
        known = next((run for run in self.scheduler_runs if run["id"] == run_id), None)
        if known is not None:
            return copy.deepcopy(known)
        return {
            "id": run_id,
            "run_attempt": 1,
            "path": RETRY.HELPER if run_id in (55, 155) else RETRY.WORKFLOW,
            "event": "workflow_dispatch" if run_id in (55, 155) else "schedule",
            "head_sha": self.source,
            "workflow_id": 6,
            "run_number": 1,
            "created_at": self.at(2102),
            "head_branch": "develop",
            "status": "in_progress",
            "repository": {"full_name": self.repo},
            "head_repository": {"full_name": self.repo},
            "actor": {"login": "github-actions[bot]"},
            "triggering_actor": {"login": "github-actions[bot]"},
        }

    @staticmethod
    def blob(record):
        if record is None:
            return None
        text = json.dumps(record)
        return {"__typename": "Blob", "isTruncated": False, "byteSize": len(text.encode()), "text": text}

    def api(self, route, payload=None, fields=()):
        if route == "graphql" and payload is not None:
            import base64

            self.cas_attempts += 1
            request = payload["variables"]["input"]
            prior = request["expectedHeadOid"]
            if self.cas_hook is not None:
                hook, self.cas_hook = self.cas_hook, None
                hook()
            if self.cas_before_visible:
                self.pending_cas = copy.deepcopy(payload)
                raise subprocess.TimeoutExpired("gh", 30)
            if prior != self.oid:
                return {
                    "data": {"createCommitOnBranch": None},
                    "errors": [
                        {
                            "type": "STALE_DATA",
                            "path": ["createCommitOnBranch"],
                            "message": f'Expected branch to point to "{prior}" but it did not. Pull and try again.',
                        }
                    ],
                }
            changes = request["fileChanges"]["additions"]
            record = json.loads(base64.b64decode(changes[0]["contents"]))
            self.writes.append((changes[0]["path"], record))
            self.oid = f"{len(self.writes) + 1:040x}"
            self.snapshots[self.oid] = {**self.snapshots[prior], changes[0]["path"]: record}
            if self.cas_unknown:
                raise subprocess.TimeoutExpired("gh", 30)
            return {
                "data": {"createCommitOnBranch": {"commit": {"oid": self.oid, "parents": {"nodes": [{"oid": prior}]}}}}
            }
        if payload is not None:
            self.effects.append((route, payload))
            if route.endswith("/jobs/202/rerun"):
                self.extra_run.update(run_attempt=3, status="in_progress", conclusion=None)
                return None
            if self.effect_unknown != "not-delivered":
                self.run = {
                    **self.run,
                    "run_attempt": self.run["run_attempt"] + 1,
                    "status": "in_progress",
                    "conclusion": None,
                    "run_started_at": RETRY.stamp(self.now + dt.timedelta(seconds=1)),
                }
            if self.effect_unknown:
                raise subprocess.TimeoutExpired("gh", 30)
            return None
        if route == "graphql":
            values = dict(field.split("=", 1) for field in fields if "=" in field)
            if "lastEditedAt" in values["query"]:
                return {
                    "data": {
                        "repository": {
                            "nameWithOwner": self.repo,
                            "pullRequest": {
                                "number": 23,
                                "headRefOid": self.pr["head"]["sha"],
                                "baseRefOid": self.pr["base"]["sha"],
                                "title": self.pr["title"],
                                "body": self.pr["body"] or "",
                                "lastEditedAt": self.last_edited_at,
                            },
                        }
                    }
                }
            if "reviewThreads" in values["query"]:
                return {
                    "data": {
                        "repository": {
                            "pullRequest": {
                                "reviewThreads": {
                                    "nodes": copy.deepcopy(self.thread_rows),
                                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                                }
                            }
                        }
                    }
                }
            oid = values["oid"]
            path = values["record"].split(":", 1)[1]
            return {
                "data": {
                    "repository": {
                        "nameWithOwner": self.repo,
                        "source": {"__typename": "Commit", "oid": oid},
                        "manifest": self.blob(
                            {
                                "schema": 1,
                                "repository": self.repo,
                                "repository_id": self.repo_id,
                                "ref": "refs/heads/lit-review-operations",
                            }
                        ),
                        "record": self.blob(
                            {
                                "schema": 1,
                                "repository": self.repo,
                                "repository_id": self.repo_id,
                                "ref": "refs/heads/lit-review-operations",
                            }
                            if path == "manifest.json"
                            else self.snapshots[oid].get(path)
                        ),
                    }
                }
            }
        prefix = f"repos/{self.repo}"
        if route == "repos/lightning-it/.github/branches/main":
            return {"name": "main", "protected": True, "commit": {"sha": self.branches["main"]}}
        if route == prefix:
            return {"full_name": self.repo, "id": 123, "default_branch": "develop"}
        if route.startswith(prefix + "/branches/"):
            branch = route.rsplit("/", 1)[1]
            return {"name": branch, "protected": True, "commit": {"sha": self.branches[branch]}}
        if "/compare/" in route:
            return {"status": "identical"}
        if route == prefix + "/git/ref/heads/lit-review-operations":
            return {"ref": "refs/heads/lit-review-operations", "object": {"type": "commit", "sha": self.oid}}
        if route.startswith(prefix + "/git/commits/"):
            oid = route.rsplit("/", 1)[1]
            return {"sha": oid, "tree": {"sha": oid}}
        if route.startswith(prefix + "/git/trees/"):
            oid = route.rsplit("/", 1)[1].split("?")[0]
            return {
                "sha": oid,
                "truncated": False,
                "tree": [
                    {"path": path, "type": "blob", "mode": "100644", "sha": "a" * 40} for path in self.snapshots[oid]
                ],
            }
        if route == prefix + "/pulls/23":
            return copy.deepcopy(self.pr)
        if route == prefix + "/actions/runs/99":
            return copy.deepcopy(self.run)
        if route == prefix + "/actions/runs/199":
            return copy.deepcopy(self.extra_run)
        if route == prefix + "/actions/runs/77":
            return copy.deepcopy(self.producer)
        if route in [
            prefix + f"/actions/runs/{ident}" for ident in (55, 66, 155, *[run["id"] for run in self.scheduler_runs])
        ]:
            return self.native_writer(int(route.rsplit("/", 1)[1]))
        if route == prefix + "/actions/workflows/review-infrastructure-retry.yml":
            return {"id": 6, "path": RETRY.WORKFLOW}
        if route == prefix + "/actions/workflows/6/runs?per_page=1":
            return {"total_count": len(self.scheduler_runs), "workflow_runs": copy.deepcopy(self.scheduler_runs[-1:])}
        if route.startswith(prefix + "/actions/runs/99/attempts/") and "jobs" not in route:
            return copy.deepcopy(self.history[int(route.rsplit("/", 1)[1])])
        parsed, query = urlsplit(route), parse_qs(urlsplit(route).query)
        bare = parsed.path[len(prefix) :]
        if bare == "/pulls":
            return [copy.deepcopy(self.pr)] if self.pr["state"] == "open" else []
        if bare == "/actions/runs":
            rows, key = [self.run] + ([] if self.extra_run is None else [self.extra_run]), "workflow_runs"
            rows = [run for run in rows if not query.get("head_sha") or run["head_sha"] == query["head_sha"][0]]
        elif bare == "/actions/workflows/6/runs":
            rows, key = self.scheduler_runs, "workflow_runs"
            if "created" in query:
                start, end = query["created"][0].split("..")
                rows = [
                    run
                    for run in rows
                    if RETRY.proof.epoch(start) <= RETRY.proof.epoch(run["created_at"]) <= RETRY.proof.epoch(end)
                ]
        elif bare.startswith("/actions/runs/199/attempts/") and bare.endswith("/jobs"):
            rows, key = self.extra_jobs[int(bare.split("/")[-2])], "jobs"
        elif bare.startswith("/actions/runs/99/attempts/") and bare.endswith("/jobs"):
            rows, key = self.jobs[int(bare.split("/")[-2])], "jobs"
        elif bare == "/actions/runs/77/attempts/1/jobs":
            rows, key = self.producer_jobs, "jobs"
        elif bare == f"/commits/{self.head}/check-runs":
            rows, key = [self.neutral], "check_runs"
        elif bare == "/pulls/23/reviews":
            rows, key = [self.review], None
        elif bare == "/pulls/23/reviews/17/comments":
            rows, key = self.comments, None
        elif bare.startswith("/check-runs/"):
            if bare.endswith("/annotations"):
                return copy.deepcopy(self.annotation_rows)
            check_id = int(bare.rsplit("/", 1)[1])
            return {
                "id": check_id,
                "name": RETRY.JOB,
                "head_sha": self.head,
                "status": "completed",
                "conclusion": "cancelled",
                "app": {"id": 15368, "slug": "github-actions"},
                "output": {"annotations_count": len(self.annotation_rows)},
            }
        else:
            raise AssertionError((route, fields))
        page = int(query["page"][0])
        batch = copy.deepcopy(rows[(page - 1) * 100 : page * 100])
        return {"total_count": len(rows), key: batch} if key else batch

    def fail_attempt(self, attempt, started, completed):
        self.run.update(
            run_attempt=attempt,
            status="completed",
            conclusion="cancelled",
            triggering_actor={"login": "github-actions[bot]"},
            run_started_at=self.at(started),
        )
        self.history[attempt] = copy.deepcopy(self.run)
        self.jobs[attempt] = [
            {
                "id": 100 + attempt,
                "run_id": 99,
                "run_attempt": attempt,
                "head_sha": self.head,
                "name": RETRY.JOB,
                "status": "completed",
                "conclusion": "cancelled",
                "runner_id": 0,
                "runner_name": "",
                "steps": [],
                "labels": ["ubuntu-latest"],
                "created_at": self.at(started),
                "started_at": self.at(started),
                "completed_at": self.at(completed),
                "check_run_url": f"https://api.github.com/repos/{self.repo}/check-runs/{100 + attempt}",
            }
        ]

    def prime(self):
        RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        key = f"li219-verifier-operation:v1:23:{self.source}:{self.head}:99"
        RETRY.proof.Journal(self.repo, self.repo_id).create(
            RETRY.proof.record_path(key),
            {
                "schema": 1,
                "action": "rerun",
                "operation": key,
                "repository": self.repo,
                "repository_id": self.repo_id,
                "claim_run": "55",
                "claim_attempt": "1",
                "source_sha": self.source,
            },
        )
        self.fail_attempt(2, 1, 902)
        self.now = self.start + dt.timedelta(seconds=2102)
        self.scheduler_runs.append(self.native_writer(66))
        os.environ.update(GITHUB_RUN_ID="66", GITHUB_EVENT_NAME="schedule")

    def recover(self):
        return RETRY.recover(self.repo, self.repo_id, 99, self.source, self.now)

    def second_candidate(self):
        self.extra_run = {**self.history[1], "id": 199}
        self.extra_jobs[1] = [{**copy.deepcopy(self.original), "id": 200, "run_id": 199}]
        with (
            patch.dict(os.environ, GITHUB_RUN_ID="155", GITHUB_EVENT_NAME="workflow_dispatch"),
            patch.object(self, "scheduler_runs", []),
        ):
            RETRY.seal(self.repo, self.repo_id, 23, 199, self.source, self.start)
        key = f"li219-verifier-operation:v1:23:{self.source}:{self.head}:199"
        RETRY.proof.Journal(self.repo, self.repo_id).create(
            RETRY.proof.record_path(key),
            {
                "schema": 1,
                "action": "rerun",
                "operation": key,
                "repository": self.repo,
                "repository_id": self.repo_id,
                "claim_run": "155",
                "claim_attempt": "1",
                "source_sha": self.source,
            },
        )
        self.extra_run = {**copy.deepcopy(self.run), "id": 199}
        self.extra_jobs[2] = [
            {
                **copy.deepcopy(self.jobs[2][0]),
                "id": 202,
                "run_id": 199,
                "check_run_url": f"https://api.github.com/repos/{self.repo}/check-runs/202",
            }
        ]

    def reconcile(self):
        with patch.object(sys, "argv", ["native_verifier_retry.py", "reconcile"]):
            RETRY.main()

    def edit_and_revert(self):
        original = copy.deepcopy(self.pr)
        self.pr.update(title="Edited title", body="Edited body")
        self.last_edited_at = self.at(100)
        self.pr.update(original)

    def test_reconcile_observed_pr_drift_never_revives_after_restore(self):
        for drift in ("head", "draft", "closed"):
            with self.subTest(drift=drift):
                self.setUp()
                self.prime()
                original = copy.deepcopy(self.pr)
                if drift == "head":
                    self.pr["head"]["sha"] = "e" * 40
                elif drift == "draft":
                    self.pr["draft"] = True
                else:
                    self.pr["state"] = "closed"
                self.reconcile()
                self.assertEqual("contract-drift", self.snapshots[self.oid]["li259/99/terminal.json"]["state"])
                writes = len(self.writes)
                self.pr = original
                self.reconcile()
                self.assertEqual(writes, len(self.writes))
                self.assertEqual([], self.effects)

    def test_seed_inventory_rejects_incomplete_duplicate_or_unbound_trees_before_effects(self):
        for corruption in ("truncated", "duplicate", "sha", "mode"):
            with self.subTest(corruption=corruption):
                self.setUp()
                self.prime()
                original = self.api

                def malformed(route, payload=None, fields=(), original=original, corruption=corruption):
                    result = original(route, payload, fields)
                    if "/git/trees/" in route:
                        if corruption == "truncated":
                            result["truncated"] = True
                        elif corruption == "duplicate":
                            result["tree"] *= 2
                        elif corruption == "sha":
                            result["sha"] = "f" * 40
                        else:
                            result["tree"][0]["mode"] = "120000"
                    return result

                writes = len(self.writes)
                with patch.object(RETRY.proof, "api", side_effect=malformed):
                    with self.assertRaises(RETRY.GlobalReadFailure):
                        self.reconcile()
                self.assertEqual(writes, len(self.writes))
                self.assertEqual([], self.effects)

    def test_original_handoff_gaps_are_pending_without_writes_and_can_converge(self):
        for phase in ("before-claim", "before-post", "attempt-two-not-visible", "claim-not-visible"):
            with self.subTest(phase=phase):
                self.setUp()
                self.prime()
                record_path = RETRY.proof.record_path(f"li219-verifier-operation:v1:23:{self.source}:{self.head}:99")
                record = self.snapshots[self.oid][record_path]
                if phase in ("before-claim", "claim-not-visible"):
                    del self.snapshots[self.oid][record_path]
                actual = copy.deepcopy(self.run)
                if phase != "claim-not-visible":
                    self.run = copy.deepcopy(self.history[1])
                writes = len(self.writes)
                self.assertEqual("handoff-pending-readback-only", self.recover())
                self.assertEqual(writes, len(self.writes))
                self.assertEqual([], self.effects)
                self.snapshots[self.oid][record_path] = record
                self.run = actual
                self.assertEqual("dispatched", self.recover())
                self.assertEqual([(f"repos/{self.repo}/actions/jobs/102/rerun", {})], self.effects)

    def test_unconfirmed_original_handoff_expires_read_only_and_real_drift_is_terminal(self):
        self.prime()
        self.run = copy.deepcopy(self.history[1])
        writes = len(self.writes)
        self.now = self.start + dt.timedelta(seconds=RETRY.POLICY["total_seconds"] + 1)
        self.assertEqual("handoff-expired-readback-only", self.recover())
        self.assertEqual(writes, len(self.writes))
        self.assertEqual([], self.effects)
        self.pr["draft"] = True
        self.assertEqual("terminal", self.recover())
        self.assertEqual([], self.effects)

    def test_edit_revert_before_seal_rejects_old_neutral_without_write(self):
        self.edit_and_revert()
        with self.assertRaisesRegex(RETRY.CandidateClosed, "neutral metadata revision"):
            RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        self.assertEqual([], self.writes)
        self.assertEqual([], self.effects)

    def test_edit_revert_after_seal_is_terminal_even_when_input_bytes_return(self):
        self.prime()
        before = copy.deepcopy(self.pr)
        self.edit_and_revert()
        self.assertEqual(before, self.pr)
        self.assertEqual("terminal", self.recover())
        self.assertEqual("inactive", self.recover())
        self.assertEqual("contract-drift", self.snapshots[self.oid]["li259/99/terminal.json"]["state"])
        self.assertEqual([], self.effects)

    def test_edit_revert_during_cas_consumes_slot_without_post(self):
        self.prime()
        self.cas_hook = self.edit_and_revert
        self.assertEqual("consumed-readback-only", self.recover())
        writes = len(self.writes)
        self.assertEqual("consumed-readback-only", self.recover())
        self.assertEqual(writes, len(self.writes))
        self.assertEqual([], self.effects)

    def test_receiver_rejects_edit_revert_after_dispatch(self):
        self.prime()
        self.assertEqual("dispatched", self.recover())
        self.edit_and_revert()
        with self.assertRaisesRegex(RETRY.CandidateClosed, "neutral metadata revision"):
            self.receive()
        self.assertEqual(1, len(self.effects))

    def test_metadata_revision_null_and_timestamp_are_sealed_and_received(self):
        for value in (None, self.at(-60)):
            with self.subTest(revision=value):
                self.setUp()
                self.last_edited_at = value
                summary = json.loads(self.neutral["output"]["summary"])
                summary["pull_request_last_edited_at"] = value
                self.neutral["output"]["summary"] = json.dumps(summary)
                self.prime()
                contract = self.snapshots[self.oid]["li259/99/seed.json"]["contract"]
                self.assertIn("pull_request_last_edited_at", contract)
                self.assertEqual(value, contract["pull_request_last_edited_at"])
                self.assertEqual("dispatched", self.recover())
                self.receive()

    def test_neutral_requires_explicit_metadata_revision(self):
        summary = json.loads(self.neutral["output"]["summary"])
        del summary["pull_request_last_edited_at"]
        self.neutral["output"]["summary"] = json.dumps(summary)
        with self.assertRaises(RETRY.CandidateClosed):
            RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        self.assertEqual([], self.writes)

    def test_partial_or_invalid_metadata_read_aborts_without_write(self):
        original = self.api
        cases = ("errors", "missing", "malformed", "wrong-type")
        for corruption in cases:

            def malformed(route, payload=None, fields=(), corruption=corruption, original=original):
                result = original(route, payload, fields)
                if route == "graphql" and payload is None and any("lastEditedAt" in item for item in fields):
                    pr = result["data"]["repository"]["pullRequest"]
                    if corruption == "errors":
                        result["errors"] = [{"message": "partial response"}]
                    elif corruption == "missing":
                        del pr["lastEditedAt"]
                    else:
                        pr["lastEditedAt"] = "not-a-timestamp" if corruption == "malformed" else 0
                return result

            with self.subTest(corruption=corruption), patch.object(RETRY.proof, "api", side_effect=malformed):
                with self.assertRaises(RETRY.GlobalReadFailure):
                    RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        self.assertEqual([], self.writes)
        self.assertEqual([], self.effects)

    def test_metadata_errors_envelope_requires_an_explicit_empty_array(self):
        original = self.api
        for errors in (None, {}, "", False, 0, {"unexpected": "error"}, ["error"], []):

            def envelope(route, payload=None, fields=(), errors=errors):
                result = original(route, payload, fields)
                if route == "graphql" and payload is None and any("lastEditedAt" in item for item in fields):
                    result["errors"] = errors
                return result

            with self.subTest(errors=errors), patch.object(RETRY.proof, "api", side_effect=envelope):
                if isinstance(errors, list) and not errors:
                    self.assertIsNone(RETRY.metadata_revision(self.repo, self.pr))
                else:
                    with self.assertRaises(RETRY.GlobalReadFailure):
                        RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        self.assertEqual([], self.writes)
        self.assertEqual([], self.effects)

    def test_metadata_read_must_match_rest_snapshot_identity_and_input(self):
        original = self.api
        for field, value in (
            ("number", 24),
            ("headRefOid", "e" * 40),
            ("baseRefOid", "e" * 40),
            ("title", "changed"),
            ("body", "changed"),
        ):

            def changed(route, payload=None, fields=(), field=field, value=value):
                result = original(route, payload, fields)
                if route == "graphql" and payload is None and any("lastEditedAt" in item for item in fields):
                    result["data"]["repository"]["pullRequest"][field] = value
                return result

            with self.subTest(field=field), patch.object(RETRY.proof, "api", side_effect=changed):
                with self.assertRaises(RETRY.CandidateClosed):
                    RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        self.assertEqual([], self.writes)

    def test_first_candidate_original_helper_rerun_is_terminal_and_second_dispatches(self):
        self.prime()
        self.second_candidate()
        native_writer = self.native_writer
        with patch.object(
            self, "native_writer", side_effect=lambda run: {**native_writer(run), "run_attempt": 2 if run == 55 else 1}
        ):
            self.reconcile()
            self.assertEqual("inactive", self.recover())
        self.assertEqual("contract-drift", self.snapshots[self.oid]["li259/99/terminal.json"]["state"])
        self.assertEqual([(f"repos/{self.repo}/actions/jobs/202/rerun", {})], self.effects)

    def test_first_candidate_contract_drift_is_terminal_and_second_dispatches(self):
        self.prime()
        self.second_candidate()
        self.original["steps"] = []
        self.reconcile()
        self.assertEqual("inactive", self.recover())
        self.assertEqual([(f"repos/{self.repo}/actions/jobs/202/rerun", {})], self.effects)

    def test_post_cas_drift_closes_claim_get_only_and_sweep_continues(self):
        self.prime()
        self.second_candidate()
        self.cas_hook = lambda: self.original.update(steps=[])
        self.reconcile()
        writes = len(self.writes)
        self.assertEqual("consumed-readback-only", self.recover())
        self.reconcile()
        self.assertEqual(writes, len(self.writes))
        self.assertNotIn("li259/99/terminal.json", self.snapshots[self.oid])
        self.assertIn("li259/99/attempt-3.json", self.snapshots[self.oid])
        self.assertEqual([(f"repos/{self.repo}/actions/jobs/202/rerun", {})], self.effects)

    def test_original_helper_rerun_after_cas_closes_claim_without_post(self):
        self.prime()
        native_writer = self.native_writer

        def rerun_helper():
            self.native_writer = lambda run: {**native_writer(run), "run_attempt": 2 if run == 55 else 1}

        self.cas_hook = rerun_helper
        self.assertEqual("consumed-readback-only", self.recover())
        writes = len(self.writes)
        self.assertEqual("consumed-readback-only", self.recover())
        self.assertEqual(writes, len(self.writes))
        self.assertEqual([], self.effects)

    def test_unconfirmed_terminal_record_stops_sweep_instead_of_claiming_closure(self):
        self.prime()
        self.second_candidate()
        self.original["steps"] = []
        with patch.object(RETRY.proof.Journal, "create", side_effect=subprocess.TimeoutExpired("gh", 30)):
            with self.assertRaisesRegex(RETRY.GlobalReadFailure, "terminal record not confirmed"):
                self.reconcile()
        self.assertNotIn("li259/99/terminal.json", self.snapshots[self.oid])
        self.assertEqual([], self.effects)

    def test_global_read_and_inventory_failures_stop_sweep_before_second_candidate(self):
        for corruption in ("timeout", "duplicate", "incomplete", "duplicate-thread", "incomplete-annotations"):
            with self.subTest(corruption=corruption):
                self.setUp()
                self.prime()
                self.second_candidate()
                original = self.api

                def malformed(route, payload=None, fields=(), corruption=corruption, original=original):
                    if corruption == "timeout" and route.endswith("/actions/runs/55"):
                        raise subprocess.TimeoutExpired("gh", 30)
                    result = original(route, payload, fields)
                    if "/runs/99/attempts/2/jobs?" in route and corruption in ("duplicate", "incomplete"):
                        result["total_count"] = 2
                        if corruption == "duplicate":
                            result["jobs"] *= 2
                    if "/check-runs/102/annotations?" in route and corruption == "incomplete-annotations":
                        return []
                    return result

                if corruption == "duplicate-thread":
                    self.thread_rows = [{"id": "T1", "isResolved": True}] * 2
                writes = len(self.writes)
                with patch.object(RETRY.proof, "api", side_effect=malformed):
                    with self.assertRaises((RETRY.GlobalReadFailure, ValueError)):
                        self.reconcile()
                self.assertEqual(writes, len(self.writes))
                self.assertEqual([], self.effects)

    def receive(self):
        os.environ.update(GITHUB_RUN_ID="99", GITHUB_RUN_ATTEMPT=str(self.run["run_attempt"]))
        RETRY.receiver(self.repo, self.repo_id, 99, self.run["run_attempt"], self.now)

    def test_native_acquisition_reaches_same_bound_receiver_and_one_job_post(self):
        self.prime()
        self.assertEqual("dispatched", self.recover())
        self.receive()
        self.assertEqual([(f"repos/{self.repo}/actions/jobs/102/rerun", {})], self.effects)
        self.assertFalse(
            any("requested_reviewers" in route or "/dispatches" in route for route, _payload in self.effects)
        )
        self.assertEqual(self.head, self.pr["head"]["sha"])

    def test_actual_schedule_main_calls_recovery_and_duplicate_delivery_is_inert(self):
        self.prime()
        self.effect_unknown = "not-delivered"
        with patch.object(sys, "argv", ["native_verifier_retry.py", "reconcile"]):
            RETRY.main()
            RETRY.main()
        self.assertEqual(1, len(self.effects))
        self.assertEqual("consumed-readback-only", self.recover())

    def test_native_empty_pr_projection_requires_exact_successful_source_step(self):
        self.run["pull_requests"] = []
        self.prime()
        self.assertEqual("dispatched", self.recover())
        self.receive()

    def test_mismatched_receiver_source_step_never_seals_empty_projection(self):
        self.run["pull_requests"] = []
        self.original["steps"][0]["name"] = self.original["steps"][0]["name"].replace("PR 23", "PR 24")
        with self.assertRaisesRegex(ValueError, "unwired receiver source"):
            RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        self.assertEqual([], self.writes)

    def test_cas_race_loser_never_posts_even_when_winner_record_is_visible(self):
        self.prime()
        self.cas_hook = self.recover
        self.assertEqual("unconfirmed-claim-readback-only", self.recover())
        self.assertEqual(1, len(self.effects))

    def test_lost_claim_response_never_posts_and_remains_consumed(self):
        self.prime()
        self.cas_unknown = True
        self.assertEqual("unconfirmed-claim-readback-only", self.recover())
        self.cas_unknown = False
        self.assertEqual("consumed-readback-only", self.recover())
        self.assertEqual([], self.effects)

    def next_scheduler(self, run_id, seconds):
        run = self.native_writer(run_id)
        run.update(run_number=len(self.scheduler_runs) + 1, created_at=self.at(seconds))
        self.scheduler_runs.append(run)
        self.now = self.start + dt.timedelta(seconds=seconds)
        os.environ.update(GITHUB_RUN_ID=str(run_id), GITHUB_RUN_ATTEMPT="1", GITHUB_EVENT_NAME="schedule")

    def test_unknown_cas_before_observable_commit_never_retries_from_later_scheduler(self):
        self.prime()
        writes = len(self.writes)
        attempts = self.cas_attempts
        self.cas_before_visible = True
        self.assertEqual("unconfirmed-claim-readback-only", self.recover())
        self.cas_before_visible = False
        self.assertEqual(attempts + 1, self.cas_attempts)
        self.assertNotIn("li259/99/attempt-3.json", self.snapshots[self.oid])
        self.next_scheduler(67, 2702)
        self.assertEqual("native-owner-readback-only", self.recover())
        self.next_scheduler(68, 3302)
        self.assertEqual("native-owner-readback-only", self.recover())
        self.assertEqual(writes, len(self.writes))
        self.assertEqual(attempts + 1, self.cas_attempts)
        self.assertEqual([], self.effects)
        self.api("graphql", self.pending_cas)
        self.assertEqual("consumed-readback-only", self.recover())
        self.assertEqual([], self.effects)

    def test_unknown_unseen_cas_remains_read_only_after_drift_and_budget_expiry(self):
        self.prime()
        self.cas_before_visible = True
        self.assertEqual("unconfirmed-claim-readback-only", self.recover())
        self.cas_before_visible = False
        attempts = self.cas_attempts
        self.review["body"] = "Drift"
        self.next_scheduler(67, 10801)
        self.assertEqual("native-owner-readback-only", self.recover())
        self.assertEqual(attempts, self.cas_attempts)
        self.assertEqual([], self.effects)

    def test_missing_original_claim_with_impossible_budget_stays_read_only_and_sweep_continues(self):
        for seconds, result in ((10001, "handoff-pending-readback-only"), (12601, "handoff-expired-readback-only")):
            with self.subTest(seconds=seconds):
                self.setUp()
                self.prime()
                self.scheduler_runs.clear()
                self.fail_attempt(2, 1, 10000)
                self.next_scheduler(66, seconds)
                self.second_candidate()
                seed = self.snapshots[self.oid]["li259/199/seed.json"]
                seed["created_at"] = self.at(seconds - 2102)
                self.extra_jobs[2][0].update(
                    created_at=self.at(seconds - 2101),
                    started_at=self.at(seconds - 2101),
                    completed_at=self.at(seconds - 1200),
                )
                record_path = RETRY.proof.record_path(f"li219-verifier-operation:v1:23:{self.source}:{self.head}:99")
                del self.snapshots[self.oid][record_path]
                writes = len(self.writes)
                self.assertEqual(result, self.recover())
                self.assertEqual(writes, len(self.writes))
                self.assertEqual([], self.effects)
                self.reconcile()
                self.assertNotIn("li259/99/terminal.json", self.snapshots[self.oid])
                self.assertEqual([(f"repos/{self.repo}/actions/jobs/202/rerun", {})], self.effects)

    def test_impossible_late_cooldown_closes_seed_before_election_and_sweep_continues(self):
        self.prime()
        self.scheduler_runs.clear()
        self.fail_attempt(2, 1, 10000)
        self.next_scheduler(66, 12601)
        self.second_candidate()
        seed = self.snapshots[self.oid]["li259/199/seed.json"]
        seed["created_at"] = self.at(10500)
        self.extra_jobs[2][0].update(created_at=self.at(10501), started_at=self.at(10501), completed_at=self.at(11401))
        self.reconcile()
        self.assertEqual("budget-exhausted", self.snapshots[self.oid]["li259/99/terminal.json"]["state"])
        self.assertEqual([(f"repos/{self.repo}/actions/jobs/202/rerun", {})], self.effects)

    def test_expired_unseen_claim_has_frozen_history_and_does_not_block_fresh_seed(self):
        self.prime()
        self.cas_before_visible = True
        self.assertEqual("unconfirmed-claim-readback-only", self.recover())
        self.cas_before_visible = False
        # More than the native inventory cap accumulates after the old deadline.
        for offset in range(1, 1101):
            self.next_scheduler(1000 + offset, 10801 + offset * 600)
        self.second_candidate()
        seed = self.snapshots[self.oid]["li259/199/seed.json"]
        seed["created_at"] = self.at(10801 + 1096 * 600)
        seed["scheduler_frontier"]["run_number"] = 1097
        self.extra_jobs[2][0].update(
            created_at=self.at(10801 + 1096 * 600 + 1),
            started_at=self.at(10801 + 1096 * 600 + 1),
            completed_at=self.at(10801 + 1098 * 600),
        )
        writes = len(self.writes)
        self.assertEqual("native-owner-readback-only", self.recover())
        self.assertEqual(writes, len(self.writes))
        self.reconcile()
        self.assertEqual([(f"repos/{self.repo}/actions/jobs/202/rerun", {})], self.effects)
        self.assertNotIn("li259/99/attempt-3.json", self.snapshots[self.oid])

    def test_same_run_discovered_for_two_prs_never_repeats_unseen_cas_in_one_sweep(self):
        self.prime()
        self.cas_before_visible = True
        attempts = self.cas_attempts
        original = self.api

        def shared_head(route, payload=None, fields=()):
            result = original(route, payload, fields)
            if "/pulls?state=open" in route:
                return [result[0], {**result[0], "id": 24, "number": 24}]
            return result

        with patch.object(RETRY.proof, "api", side_effect=shared_head):
            self.reconcile()
        self.assertEqual(attempts + 1, self.cas_attempts)
        self.assertEqual([], self.effects)

    def test_unseen_first_native_owner_cannot_be_skipped_by_later_scheduler(self):
        self.prime()
        self.next_scheduler(67, 2702)
        self.scheduler_runs.pop(0)
        writes = len(self.writes)
        with self.assertRaisesRegex(ValueError, "incomplete scheduler sequence"):
            self.recover()
        self.assertEqual(writes, len(self.writes))
        self.assertEqual([], self.effects)

    def test_distinct_scheduler_race_only_native_owner_can_attempt_cas(self):
        self.prime()
        outcomes = []

        def later_scheduler():
            with patch.dict(os.environ):
                self.next_scheduler(67, 2702)
                outcomes.append(self.recover())

        attempts = self.cas_attempts
        self.cas_hook = later_scheduler
        self.assertEqual("dispatched", self.recover())
        self.assertEqual(["native-owner-readback-only"], outcomes)
        self.assertEqual(attempts + 1, self.cas_attempts)
        self.assertEqual(1, len(self.effects))

    def test_receiver_rejects_claim_bound_to_later_native_scheduler(self):
        self.prime()
        self.assertEqual("dispatched", self.recover())
        self.next_scheduler(67, 2702)
        self.snapshots[self.oid]["li259/99/attempt-3.json"]["claim_run"] = 67
        with self.assertRaisesRegex(ValueError, "receiver native owner"):
            self.receive()

    def test_native_owner_drift_after_cas_never_posts_and_stays_consumed(self):
        for changes in (
            {"run_attempt": 2},
            {"triggering_actor": {"login": "litroc"}},
            {"head_sha": "e" * 40},
            {"head_branch": "feature"},
            {"status": "completed"},
        ):
            with self.subTest(changes=changes):
                self.setUp()
                self.prime()
                self.cas_hook = lambda changes=changes: self.scheduler_runs[0].update(changes)
                self.assertEqual("consumed-readback-only", self.recover())
                self.next_scheduler(67, 2702)
                self.assertEqual("consumed-readback-only", self.recover())
                self.assertEqual([], self.effects)

    def test_receiver_rechecks_exact_native_claimant_authority(self):
        self.prime()
        self.assertEqual("dispatched", self.recover())
        self.scheduler_runs[0]["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "native scheduler claimant"):
            self.receive()

    def test_cancelled_or_rerun_native_owner_never_elects_successor(self):
        for changes in ({"status": "completed", "conclusion": "cancelled"}, {"run_attempt": 2}):
            with self.subTest(changes=changes):
                self.setUp()
                self.prime()
                self.scheduler_runs[0].update(changes)
                self.next_scheduler(67, 2702)
                writes = len(self.writes)
                self.assertEqual("native-owner-readback-only", self.recover())
                self.assertEqual(writes, len(self.writes))
                self.assertEqual([], self.effects)

    def test_source_marker_legacy_fallback_rechecks_live_head_after_jobs_get(self):
        self.original["steps"] = []
        original = self.api

        def drift(route, payload=None, fields=()):
            value = original(route, payload, fields)
            if "/runs/99/attempts/1/jobs?" in route:
                self.pr["head"]["sha"] = "e" * 40
            return value

        with patch.object(RETRY.proof, "api", side_effect=drift):
            with self.assertRaisesRegex(ValueError, "legacy fallback live binding drift"):
                RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)
        self.assertEqual([], self.writes)
        self.assertEqual([], self.effects)

    def test_lost_post_response_is_readback_only_whether_delivered_or_not(self):
        for outcome in ("delivered", "not-delivered"):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.prime()
                self.effect_unknown = outcome
                self.assertEqual("unknown-post-readback-only", self.recover())
                self.assertIn(self.recover(), ("active", "consumed-readback-only"))
                self.assertEqual(1, len(self.effects))

    def test_unknown_post_stays_get_only_after_drift_and_expiry(self):
        self.prime()
        self.effect_unknown = "not-delivered"
        self.recover()
        count = len(self.writes)
        self.review["body"] = "Edited"
        self.now += dt.timedelta(days=1)
        self.assertEqual("consumed-readback-only", self.recover())
        self.assertEqual(count, len(self.writes))
        self.assertEqual(1, len(self.effects))

    def test_cooldown_has_no_sleep_claim_or_effect_before_exact_boundary(self):
        self.prime()
        count = len(self.writes)
        self.now -= dt.timedelta(seconds=1)
        self.assertEqual("cooldown", self.recover())
        self.assertEqual(count, len(self.writes))
        self.assertEqual([], self.effects)
        self.now += dt.timedelta(seconds=1)
        self.assertEqual("dispatched", self.recover())

    def test_attempt_four_uses_longer_cooldown_and_exhaustion_is_absorbing(self):
        self.prime()
        self.recover()
        self.fail_attempt(3, 2103, 3004)
        self.now = self.start + dt.timedelta(seconds=5403)
        self.assertEqual("cooldown", self.recover())
        self.now += dt.timedelta(seconds=1)
        self.next_scheduler(67, 5404)
        self.assertEqual("dispatched", self.recover())
        self.receive()
        os.environ.update(GITHUB_RUN_ID="66", GITHUB_RUN_ATTEMPT="1")
        self.fail_attempt(4, 5405, 6306)
        self.now = self.start + dt.timedelta(seconds=6306)
        self.assertEqual("terminal", self.recover())
        self.assertEqual("inactive", self.recover())
        self.assertEqual(2, len(self.effects))

    def test_runtime_reserve_deadline_boundary_and_receiver_total_deadline(self):
        self.prime()
        self.now = self.start + dt.timedelta(seconds=7200)
        self.assertEqual("dispatched", self.recover())
        self.now = self.start + dt.timedelta(seconds=10800)
        self.receive()
        self.now += dt.timedelta(seconds=1)
        with self.assertRaisesRegex(ValueError, "receiver deadline"):
            self.receive()

    def test_no_start_with_less_than_complete_runtime_reserve(self):
        self.prime()
        self.now = self.start + dt.timedelta(seconds=7201)
        self.assertEqual("terminal", self.recover())
        self.assertEqual([], self.effects)

    def test_receiver_rechecks_wall_clock_after_all_remote_reads(self):
        self.prime()
        self.recover()
        with patch.object(RETRY, "utc_now", return_value=self.start + dt.timedelta(seconds=10801)):
            with self.assertRaisesRegex(ValueError, "final receiver deadline"):
                self.receive()

    def test_clock_crossing_deadline_after_claim_consumes_without_post(self):
        self.prime()
        with patch.object(RETRY, "utc_now", return_value=self.start + dt.timedelta(seconds=7201)):
            self.assertEqual("consumed-readback-only", self.recover())
        self.assertEqual([], self.effects)
        self.assertEqual("consumed-readback-only", self.recover())

    def test_no_retroactive_seed_or_unclaimed_native_attempt(self):
        os.environ.update(GITHUB_RUN_ID="66", GITHUB_EVENT_NAME="schedule")
        self.assertEqual("inactive", self.recover())
        with self.assertRaises((ValueError, TypeError)):
            RETRY.receiver(self.repo, self.repo_id, 99, 3, self.now)

    def test_completion_during_sweep_uses_observation_clock_without_extending_seed(self):
        self.prime()
        stale = self.start + dt.timedelta(seconds=901)
        self.assertEqual("cooldown", RETRY.recover(self.repo, self.repo_id, 99, self.source, stale))
        seed = self.snapshots[self.oid]["li259/99/seed.json"]
        self.assertEqual(self.at(0), seed["created_at"])
        self.assertEqual("dispatched", self.recover())
        self.receive()

    def test_optional_seal_preserves_non_li259_author_entitlement(self):
        for author in ({"login": "other-human", "type": "User"}, {"login": "renovate[bot]", "type": "Bot"}):
            with self.subTest(author=author):
                self.pr["user"] = author
                self.assertFalse(RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start))
                with self.assertRaises(ValueError):
                    RETRY.snapshot(self.repo, self.repo_id, 23, 99, self.source)
        self.assertEqual([], self.writes)
        self.assertEqual([], self.effects)

    def test_pre_rollout_single_required_verifier_has_no_retry_grant(self):
        self.original.update(name=RETRY.AGGREGATE, steps=[])
        self.assertFalse(RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start))
        self.assertEqual([], self.writes)
        with self.assertRaisesRegex(ValueError, "ambiguous native verifier"):
            RETRY.jobs_for(self.repo, 99, 1, self.head)
        self.original["name"] = "Unknown verifier"
        with self.assertRaisesRegex(ValueError, "ambiguous native verifier"):
            RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start)

    def test_pre_rollout_receiver_keeps_baseline_route_without_new_authority(self):
        self.original["steps"] = []
        self.assertFalse(RETRY.seal(self.repo, self.repo_id, 23, 99, self.source, self.start))
        self.assertEqual([], self.writes)
        self.fail_attempt(2, 1, 902)
        os.environ.update(GITHUB_RUN_ID="66", GITHUB_EVENT_NAME="schedule")
        self.assertEqual("inactive", self.recover())

    def test_receiver_rejects_changed_review_and_unclaimed_attempt(self):
        self.prime()
        self.recover()
        self.review["body"] = "Changed review"
        with self.assertRaisesRegex(ValueError, "receiver contract drift"):
            self.receive()
        self.review["body"] = "Review complete."
        self.run["run_attempt"] = 4
        with self.assertRaises(ValueError):
            self.receive()

    def test_policy_head_base_controller_review_and_thread_drift_are_terminal(self):
        cases = (
            lambda: self.pr["head"].update(sha="e" * 40),
            lambda: self.pr["base"].update(sha="e" * 40),
            lambda: self.branches.update(main="e" * 40),
            lambda: self.review.update(body="Edited"),
            lambda: self.thread_rows.append({"id": "T1", "isResolved": False}),
            lambda: self.neutral["output"].update(summary="{}"),
        )
        for index, change in enumerate(cases):
            with self.subTest(case=index):
                self.setUp()
                self.prime()
                change()
                self.assertEqual("terminal", self.recover())
                self.assertEqual("inactive", self.recover())
                self.assertEqual([], self.effects)

    def test_runnerless_dto_and_all_unclassified_failures_remain_terminal(self):
        for field, value in (
            ("runner_id", None),
            ("runner_id", 7),
            ("steps", [{"name": "Verify", "conclusion": "failure"}]),
            ("conclusion", "failure"),
            ("labels", ["self-hosted"]),
            ("name", "Published check"),
        ):
            with self.subTest(field=field, value=value):
                self.setUp()
                self.prime()
                self.jobs[2][0][field] = value
                self.assertEqual("terminal", self.recover())
                self.assertEqual([], self.effects)
        for message in ("Permission denied", "Quota exhausted", "Service unavailable", "permanent-producer-binding"):
            with self.subTest(message=message):
                self.setUp()
                self.prime()
                self.annotation_rows[0]["message"] = message
                self.assertEqual("terminal", self.recover())
                self.assertEqual([], self.effects)

    def test_duplicate_or_incomplete_native_inventories_never_authorize(self):
        self.prime()
        original = self.api
        for corruption in ("duplicate", "incomplete"):

            def malformed(route, payload=None, fields=(), corruption=corruption, original=original):
                result = original(route, payload, fields)
                if "/attempts/2/jobs?" in route:
                    result["total_count"] = 2
                    if corruption == "duplicate":
                        result["jobs"] *= 2
                return result

            with self.subTest(corruption=corruption), patch.object(RETRY.proof, "api", side_effect=malformed):
                with self.assertRaises(RETRY.GlobalReadFailure):
                    RETRY.infrastructure_cause(self.repo, self.run, self.head, self.now)
        self.assertEqual([], self.effects)

    def test_only_the_expected_dependent_gate_failure_can_accompany_acquisition(self):
        self.prime()
        aggregate = {
            **self.jobs[2][0],
            "id": 103,
            "name": RETRY.AGGREGATE,
            "runner_id": 8,
            "conclusion": "failure",
            "steps": [
                {
                    "name": "Enforce exactly one terminal verification route",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ],
        }
        self.jobs[2].append(aggregate)
        self.assertEqual(
            RETRY.POLICY["cause"], RETRY.infrastructure_cause(self.repo, self.run, self.head, self.now)["code"]
        )
        aggregate["steps"][0]["name"] = "Set up job"
        with self.assertRaisesRegex(ValueError, "independent failed job"):
            RETRY.infrastructure_cause(self.repo, self.run, self.head, self.now)

    def test_disabled_mode_performs_zero_reads_and_writes(self):
        with patch.dict(os.environ, LI259_INFRA_RETRY="disabled"), patch.object(RETRY.proof, "api") as api:
            with patch.object(sys, "argv", ["native_verifier_retry.py", "reconcile"]):
                RETRY.main()
            api.assert_not_called()


class SourceNativeRetryTests(NativeRetryTests):
    REPOSITORY = "lightning-it/shared-assets-lit"


class PortNativeRetryTests(NativeRetryTests):
    REPOSITORY = "lightning-it/ansible-collection-supplementary"


class WorkflowCouplingTests(unittest.TestCase):
    def test_port_binds_exact_candidate_bytes_and_keeps_activation_pending(self):
        manifest = json.loads((ROOT / ".lit/li259-supplementary-port.json").read_text())
        self.assertEqual("5128b10bef931478541985d314293d879ea317be", manifest["source_candidate"])
        self.assertEqual("aa45941e2d24194f29f480306bff39d27d7b4824", manifest["core_candidate"])
        self.assertEqual("5b70bdaa4eaa9b0121545cb842eca8b3256e9cc3", manifest["protected_source_commit"])
        self.assertEqual("disabled-until-native-acceptance", manifest["activation"])
        dormant = {row["path"]: row for row in manifest["dormant_retirement"]["retired_assets"]}
        retirement = json.loads((ROOT / ".lit/li319-central-verifier-retirement.json").read_text())
        policies = {row["path"]: row for row in retirement["policy_updates"]}
        for row in manifest["assets"]:
            if row["path"] in dormant:
                self.assertFalse((ROOT / row["path"]).exists())
                self.assertEqual(row["sha256"], dormant[row["path"]]["sha256"])
                continue
            content = (ROOT / row["path"]).read_bytes()
            expected = row["sha256"]
            if row["path"] in policies:
                update = policies[row["path"]]
                self.assertEqual(expected, update["previous_sha256"])
                expected = update["sha256"]
            self.assertEqual(expected, hashlib.sha256(content).hexdigest(), row["path"])
            if row["mode"] == "byte-identical":
                self.assertEqual(
                    row["source_blob"],
                    hashlib.sha1(
                        b"blob " + str(len(content)).encode() + b"\0" + content, usedforsecurity=False
                    ).hexdigest(),
                )
        retirement = json.loads((ROOT / ".lit/li319-central-verifier-retirement.json").read_text())
        policies = {row["path"]: row for row in retirement["policy_updates"]}
        retired = {row["path"]: row for row in retirement["retired_assets"]}
        for row in manifest["local_policy_assets"]:
            self.assertEqual(row["sha256"], policies[row["path"]]["previous_sha256"])
            self.assertEqual(
                policies[row["path"]]["sha256"], hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest()
            )
        instructions = (ROOT / ".github/copilot-instructions.md").read_text()
        self.assertIn("AGENTS_SHA256: " + hashlib.sha256((ROOT / "AGENTS.md").read_bytes()).hexdigest(), instructions)
        policy = (ROOT / "AGENTS.md").read_text()
        self.assertIn("LI259_INFRA_RETRY=enabled", policy)
        self.assertIn("attempts 3 and 4", policy)
        self.assertNotIn("no third verifier attempt or LI-259 route is added", policy)
        inventory = json.loads((ROOT / ".lit/li219-managed-assets.json").read_text())
        local_assets = {asset["path"]: asset for asset in inventory["assets"]}
        for row in manifest["preserved_local_assets"]:
            if row["path"] in dormant:
                self.assertFalse((ROOT / row["path"]).exists())
                self.assertNotIn(row["path"], local_assets)
                continue
            if row["path"] in retired:
                self.assertFalse((ROOT / row["path"]).exists())
                self.assertNotIn(row["path"], local_assets)
                self.assertEqual(row["sha256"], retired[row["path"]]["historical_preserved_sha256"])
                continue
            self.assertEqual(row["sha256"], hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest(), row["path"])
        for step in yaml.safe_load((ROOT / ".github/workflows/current-revision-rerun.yml").read_text())[
            "jobs"
        ].values():
            for item in step.get("steps", []):
                if "run" in item:
                    self.assertLessEqual(len(item["run"].encode()), 64500)

    def test_execute_real_handoff_caller_orders_seal_claim_rebind_and_post(self):
        text = (ROOT / ".github/workflows/current-revision-rerun.yml").read_text()
        function = (
            "seal_native_retry_contract() {"
            + text.split("          seal_native_retry_contract() {", 1)[1].split("\n          }\n", 1)[0]
            + "\n}"
        )
        # Execute the shipped event branch through the actual job POST. The
        # surrounding native inventory/readiness guards have their own suites.
        start = text.index("            seal_native_retry_contract\n")
        end = text.index("            # GitHub can accept the verifier-job rerun", start)
        caller = textwrap.dedent(text[start:end]) + "  exit 1\nfi\n"
        shell = (
            r"""set -euo pipefail
revalidate_pr_metadata() { printf 'authorize\n'; }
validate_event_producer() { :; }
claim_review_operation() { printf 'claim\n'; }
gh() {
  shift
  if [ "$1" = --method ]; then printf 'POST\n' >>"${RUNNER_TEMP}/effects";
  elif [[ "$1" == */actions/runs/* ]]; then printf '{}';
  else printf 'dHJ1ZQo='; fi
}
bash() {
  printf 'seal\n'
  if [ "$FAIL_REBIND" = yes ] && [ -f "${RUNNER_TEMP}/sealed" ]; then return 1; fi
  touch "${RUNNER_TEMP}/sealed"
}
"""
            + textwrap.dedent(function)
            + '\nif [ "${LI219_EVENT_MODE}" = enabled ]; then\n'
            + caller
        )
        for fail, code, posts in (("no", 0, "POST\n"), ("yes", 1, "")):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as tmp:
                result = subprocess.run(  # noqa: S603 - execute the shipped caller with isolated native API stubs
                    [shutil.which("bash"), "-c", shell],
                    text=True,
                    capture_output=True,
                    check=False,
                    env={
                        **os.environ,
                        "RUNNER_TEMP": tmp,
                        "LI259_INFRA_RETRY": "enabled",
                        "REPOSITORY": "lightning-it/shared-assets-lit",
                        "WORKFLOW_SHA": "a" * 40,
                        "LI219_EVENT_MODE": "enabled",
                        "producer_id": "77",
                        "event_jobs_latest": "[]",
                        "required_job_id": "102",
                        "PR_NUMBER": "23",
                        "run_id": "99",
                        "EXPECTED_HEAD": "b" * 40,
                        "EXPECTED_BASE": "a" * 40,
                        "FAIL_REBIND": fail,
                    },
                )
                self.assertEqual(code, result.returncode, result.stderr)
                self.assertEqual(["seal", "claim", "authorize", "seal"], result.stdout.splitlines())
                effects = Path(tmp) / "effects"
                self.assertEqual(posts, effects.read_text() if effects.exists() else "")

    def test_existing_handoff_seals_before_claim_and_rebinds_before_post(self):
        text = (ROOT / ".github/workflows/current-revision-rerun.yml").read_text()
        function = text.split('            source "${RUNNER_TEMP}/helper-operation.sh"', 1)[1]
        self.assertLess(function.index("seal_native_retry_contract"), function.index("claim_review_operation"))
        self.assertLess(function.rindex("seal_native_retry_contract"), function.index("--method POST"))

    def test_retired_cross_receiver_and_ai_first_attempt_only(self):
        self.assertFalse((ROOT / "scripts/verify-dot-github-current-revision.py").exists())
        producer = (ROOT / ".github/workflows/copilot-review.yml").read_text()
        request = producer.split("  request-current-revision-review:", 1)[1].split("    permissions:", 1)[0]
        self.assertIn("github.run_attempt == 1", request)
        self.assertNotIn("LI259", producer)


if __name__ == "__main__":
    unittest.main()
