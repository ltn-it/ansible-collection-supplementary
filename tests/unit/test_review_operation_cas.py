"""Exercise the real workflow writer with a stateful GitHub CAS transport."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from unit import review_event_contract_helpers as contracts

ROOT = Path(__file__).resolve().parents[2]
BASE, HEAD, SOURCE = "a" * 40, "b" * 40, "c" * 40
INITIAL, COMMITTED = "0" * 40, "1" * 40

MOCK = r"""
import datetime as dt
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
file = Path(os.environ["STATE"])
s = json.loads(file.read_text())
worker = os.environ["GITHUB_RUN_ID"]
mode = s["mode"]
fields = dict(a.split("=", 1) for a in args if "=" in a)
route = next((a for a in args if a.startswith("repos/") or a == "graphql"), "")
post = "--method" in args and args[args.index("--method") + 1] == "POST"
call = {"worker": worker, "route": route, "post": post}
s["calls"].append(call)
rc, result = 0, None
if route == "graphql" and "--input" in args:
    request = json.load(sys.stdin)["variables"]["input"]
    call.update(cas=True, input=request)
    assert request["branch"] == {
        "repositoryNameWithOwner": "lightning-it/ansible-collection-supplementary",
        "branchName": "lit-review-operations",
    }
    assert len(request["fileChanges"]["additions"]) == 1
    assert "deletions" not in request["fileChanges"]
    old = request["expectedHeadOid"]
    if old != s["oid"]:
        result, rc = {"errors": [{"message": "expectedHeadOid mismatch"}]}, 1
    elif mode == "not-applied":
        rc = 42
    else:
        import base64

        entry = request["fileChanges"]["additions"][0]
        record = base64.b64decode(entry["contents"]).decode()
        s["oid"] = "1" * 40 if old == "0" * 40 else format(int(old, 16) + 1, "040x")
        s["versions"][s["oid"]] = {**s["versions"][old], entry["path"]: json.loads(record)}
        result = {"data": {"createCommitOnBranch": {"commit": {"oid": s["oid"], "parents": {"nodes": [{"oid": old}]}}}}}
        if mode == "lost-cas":
            result, rc = None, 42
        if mode == "partial-cas":
            result["errors"] = []
        if mode == "wrong-parent":
            result["data"]["createCommitOnBranch"]["commit"]["parents"]["nodes"] = []
elif route == "graphql":
    oid = fields["oid"]
    assert fields["manifest"] == oid + ":manifest.json"
    assert fields["record"].startswith(oid + ":operations/")
    record = s["versions"][oid].get(fields["record"].split(":", 1)[1])
    manifest = {
        "schema": 1,
        "repository": "lightning-it/ansible-collection-supplementary",
        "repository_id": "1103407173",
        "ref": "refs/heads/lit-review-operations",
    }
    if mode == "foreign-manifest":
        manifest["repository"] = "mallory/foreign"

    def blob(value):
        text = json.dumps(value)
        return {"__typename": "Blob", "isTruncated": False, "byteSize": len(text), "text": text}

    result = {
        "data": {
            "repository": {
                "nameWithOwner": "lightning-it/ansible-collection-supplementary",
                "source": {"__typename": "Commit", "oid": "f" * 40 if mode == "mixed-source" else oid},
                "manifest": blob(manifest),
                "record": None if record is None else blob(record),
            }
        }
    }
    if mode == "missing-record-field":
        del result["data"]["repository"]["record"]
    if mode == "partial-read":
        result["errors"] = []
    if mode == "truncated":
        result["data"]["repository"]["manifest"]["isTruncated"] = True
elif "/git/ref/" in route:
    if mode == "missing-bootstrap":
        rc = 1
    else:
        # Every later worker sees a stale but coherent immutable snapshot.
        # Authoritative CAS still checks the actual current server ref.
        oid = "0" * 40 if worker == "501" and mode in ("stale-ref", "lost-cas-stale") else s["oid"]
        result = {"ref": "refs/heads/lit-review-operations", "object": {"type": "commit", "sha": oid}}
elif post and route.endswith("/check-runs"):
    call["marker"] = True
    marker = {
        "id": 99,
        "name": fields["name"],
        "head_sha": fields["head_sha"],
        "external_id": fields["external_id"],
        "status": fields["status"],
        "conclusion": fields["conclusion"],
        "app": {"id": 15368, "slug": "github-actions"},
        "output": {"title": fields["output[title]"], "summary": fields["output[summary]"]},
    }
    s["markers"].append(marker)
    result = marker
    if mode == "lost-marker":
        rc = 42
elif route.endswith("/requested_reviewers"):
    if post:
        call["request"] = True
        if mode == "rejected-old-pending":
            call["accepted"] = False
            s["requested"] = True
            s["pending_head"] = "a" * 40
            rc = 42
        elif mode in (
            "request-success",
            "lost-request-response",
            "lost-request-response-cleared",
            "legacy-terminal-cleared",
        ):
            s["requested"] = True
            call["accepted"] = True
            if mode != "request-success":
                rc = 42
        else:
            rc = 42
    else:
        if mode in ("lost-request-response-cleared", "legacy-terminal-cleared") and worker != "500":
            s["requested"] = False
        result = {
            "users": [{"login": "copilot-pull-request-reviewer[bot]"}]
            if mode == "pending-review" or s.get("requested")
            else []
        }
elif "/comments" in route:
    if post:
        call["comment"] = True
        s.setdefault("comments", []).append({"user": {"login": "github-actions[bot]"}, "body": fields["body"]})
        rc = 0 if mode == "request-success" else 42
    else:
        result = [[] if worker == "501" and mode != "legacy-terminal-cleared" else s.get("comments", [])]
elif "/reviews?" in route:
    if mode == "legacy-terminal-cleared" and worker != "500":
        result = [
            [
                {
                    "commit_id": os.environ["EXPECTED_HEAD"],
                    "state": "COMMENTED",
                    "body": "Copilot was not able to review any files.",
                    "user": {"login": "copilot-pull-request-reviewer[bot]"},
                }
            ]
        ]
    else:
        result = [
            [
                {
                    "commit_id": os.environ["EXPECTED_HEAD"],
                    "state": "COMMENTED",
                    "body": "Review complete.",
                    "user": {"login": "copilot-pull-request-reviewer[bot]"},
                }
            ]
            if mode == "existing-review"
            else []
        ]
elif route.endswith("/pulls/23"):
    result = {
        "number": 23,
        "state": "open",
        "draft": False,
        "user": {"login": "litroc"},
        "head": {
            "sha": os.environ["EXPECTED_HEAD"],
            "repo": {"full_name": "lightning-it/ansible-collection-supplementary"},
        },
        "base": {
            "sha": os.environ["EXPECTED_BASE"],
            "repo": {"full_name": "lightning-it/ansible-collection-supplementary"},
        },
    }
elif post and route.endswith("/rerun"):
    call["rerun"] = True
    rc = 42
elif "/check-runs?" in route:
    # Exact reported regression: old marker invisible through confirmation of
    # any new marker; no consistency assumption is made about this inventory.
    visible = [] if worker == "501" or mode == "invisible-marker" else s["markers"]
    result = [{"total_count": len(visible), "check_runs": visible}]
elif "/actions/runs/" in route:
    created = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {
        "id": int(route.rsplit("/", 1)[1]),
        "run_attempt": 1,
        "status": "completed",
        "created_at": "2000-01-01T00:00:00Z" if mode == "expired" else created,
    }
else:
    raise AssertionError(args)
file.write_text(json.dumps(s))
if result is not None:
    print(json.dumps(result))
sys.exit(rc)
"""


class ReviewRequestCASTests(unittest.TestCase):
    def test_request_reservations_serialize_across_event_actions(self):
        import yaml

        paths = [ROOT / ".github/workflows/copilot-review.yml"]
        mirror = ROOT / "default/.github/workflows/copilot-review.yml"
        if mirror.exists():
            paths.append(mirror)
        for path in paths:
            request = yaml.safe_load(path.read_text())["jobs"]["request-current-revision-review"]
            self.assertEqual(
                {
                    "group": "copilot-review-request-${{ github.event.pull_request.number }}",
                    "cancel-in-progress": False,
                },
                request["concurrency"],
            )

    def probe(
        self,
        mode,
        new_head=False,
        *,
        event_mode="enabled",
        source_prefix="",
        interrupt=None,
        repository="lightning-it/ansible-collection-supplementary",
        repository_id="1103407173",
    ):
        import textwrap

        source = (ROOT / source_prefix / ".github/workflows/copilot-review.yml").read_text()
        raw = source.split("<<'CLAIM'\n", 1)[1].split("\n          CLAIM", 1)[0]
        claim = textwrap.dedent(raw)
        self.assertEqual(
            claim.strip(),
            contracts.RetainedReviewContracts._rerun_shell_function("claim_review_operation").strip(),
        )
        raw = source.split("          review_exists_for_head() {\n", 1)[1].split(
            "\n  verify-current-revision-policy:", 1
        )[0]
        caller = textwrap.dedent("          review_exists_for_head() {\n" + raw)
        shell = (
            r"""set -euo pipefail
sleep() { :; }
gh() {
  if [[ "$*" == *"--method POST"* && "$*" == *"/requested_reviewers"* ]]; then
    [ "${PROBE_INTERRUPT:-}" != before-request ] || exit 73
    python3 "${MOCK_GH}" "$@"
    status=$?
    [ "${PROBE_INTERRUPT:-}" != after-request ] || exit 73
    return "${status}"
  fi
  python3 "${MOCK_GH}" "$@"
}
timeout() { while [ "$1" != gh ]; do shift; done; "$@"; }
assert_bound_head_current() { :; }
reviewer_login="${reviewer%\[bot\]}"
marker="<!-- mlx90-copilot-request head=${EXPECTED_HEAD} -->"
"""
            + caller
        )
        with tempfile.TemporaryDirectory() as tmp:
            state, mock = Path(tmp) / "state", Path(tmp) / "mock.py"
            state.write_text(
                json.dumps(
                    {
                        "mode": mode,
                        "oid": INITIAL,
                        "versions": {INITIAL: {}},
                        "markers": [],
                        "calls": [],
                    }
                )
            )
            mock.write_text(MOCK)
            (Path(tmp) / "request-operation.sh").write_text(claim)
            # Missing original native authorization must fail closed in the new
            # deferred path. Full successful intent/consumer transport is covered
            # by the retained seal-helper tests, not fabricated in this CAS probe.
            (Path(tmp) / "review_request_continuation.py").write_text(
                (ROOT / "scripts/review_request_continuation.py").read_text()
            )
            workers = [("500", BASE, HEAD), ("501", "d" * 40, HEAD)]
            if new_head:
                workers.append(("502", "d" * 40, "e" * 40))
            observations = []
            outcomes = []
            for worker, base, head in workers:
                env = {
                    **os.environ,
                    "STATE": str(state),
                    "MOCK_GH": str(mock),
                    "RUNNER_TEMP": tmp,
                    "GITHUB_RUN_ID": worker,
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_EVENT_NAME": "pull_request_target",
                    "GITHUB_REF_PROTECTED": "true",
                    "GITHUB_REF": "refs/heads/develop",
                    "WORKFLOW_SHA": SOURCE,
                    "GITHUB_REPOSITORY_ID": repository_id,
                    "LI219_EVENT_MODE": event_mode or "",
                    "PROBE_INTERRUPT": (interrupt or "") if worker == "500" else "",
                    "REPOSITORY": repository,
                    "PR_NUMBER": "23",
                    "EXPECTED_HEAD": head,
                    "EXPECTED_BASE": base,
                    "reviewer": "copilot-pull-request-reviewer[bot]",
                    "requested_reviewers_url": f"repos/{repository}/pulls/23/requested_reviewers",
                    "UNABLE_REVIEW_MARKER": "unable to review this pull request",
                    "NO_FILES_REVIEW_MARKER": "was not able to review any files",
                    "QUOTA_EXHAUSTED_MARKER": "quota exhausted",
                    "QUOTA_EXCEEDED_MARKER": "quota exceeded",
                    "SUPPRESSED_COMMENTS_MARKER": "suppressed comments",
                    "PREMIUM_REQUEST_QUOTA_MARKER": "premium request quota",
                    "PREMIUM_REQUESTS_QUOTA_MARKER": "premium requests quota",
                    "ERROR_REVIEW_MARKER": "encountered an error",
                }
                if event_mode is None:
                    env.pop("LI219_EVENT_MODE", None)
                result = subprocess.run(  # noqa: S603 -- Fixed repository workflow with fixture transport.
                    ["/bin/bash", "-c", shell],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                # The preserved manual-request path may propagate a lost
                # comment response while still sending no additional AI request.
                allowed = (0, 1, 42) if mode == "pending-review" else (0, 1)
                if interrupt and worker == "500":
                    allowed = (73,)
                self.assertIn(result.returncode, allowed, result.stderr)
                outcomes.append(result.returncode)
                observations.append(json.loads(state.read_text()))
            final = json.loads(state.read_text())
            final["observations"] = observations
            final["outcomes"] = outcomes
            return final

    def test_legacy_interruption_before_post_leaves_only_uncertain_consumption(self):
        for prefix in ("",):
            for flag, repo in (
                (None, "lightning-it/shared-assets-lit"),
                ("disabled", "lightning-it/ansible-collection-supplementary"),
                ("Enabled", "lightning-it/ansible-role-docker"),
            ):
                with self.subTest(source=prefix, flag=flag, repository=repo):
                    state = self.probe(
                        "request-success",
                        event_mode=flag,
                        source_prefix=prefix,
                        interrupt="before-request",
                        repository=repo,
                    )
                    self.assertFalse(any(c.get("cas") or c.get("request") for c in state["calls"]))
                    self.assertTrue(state["observations"][0]["comments"])
                    self.assertTrue(all("UNCERTAIN:" in item["body"] for item in state["comments"]))

    def test_actual_request_order_and_interruption_after_post(self):
        for prefix in ("",):
            for flag in ("disabled", "enabled"):
                for interrupt in (None, "after-request"):
                    with self.subTest(source=prefix, flag=flag, interrupt=interrupt):
                        state = self.probe(
                            "request-success",
                            event_mode=flag,
                            source_prefix=prefix,
                            interrupt=interrupt,
                        )
                        effects = [c for c in state["calls"] if c.get("cas") or c.get("request") or c.get("comment")]
                        kinds = [
                            "cas" if c.get("cas") else "request" if c.get("request") else "comment" for c in effects
                        ]
                        self.assertEqual(
                            ((["cas"] if flag == "enabled" else ["comment"]) + ["request"]),
                            kinds[: kinds.index("request") + 1],
                        )
                        self.assertEqual(1, kinds.count("request"))
                        if interrupt:
                            # A later PR-scoped pending reviewer cannot prove
                            # which head the interrupted POST requested.
                            self.assertTrue(all("UNCERTAIN:" in item["body"] for item in state.get("comments", [])))
                        else:
                            self.assertEqual("comment", kinds[-1])
                        if interrupt:
                            self.assertFalse(
                                any(
                                    "request accepted" in item["body"]
                                    for item in state["observations"][0].get("comments", [])
                                )
                            )

    def test_enabled_interruption_after_claim_does_not_repeat_effect(self):
        for prefix in ("",):
            with self.subTest(source=prefix):
                state = self.probe("request-success", source_prefix=prefix, interrupt="before-request")
                self.assertEqual(1, sum(bool(c.get("cas")) for c in state["calls"]))
                self.assertFalse(any(c.get("request") or c.get("comment") for c in state["calls"]))

    def test_invisible_comment_stale_ref_new_run_and_base_cannot_repeat_request(self):
        for mode in ("consistent", "stale-ref"):
            with self.subTest(mode=mode):
                state = self.probe(mode, new_head=True)
                requests = [c for c in state["calls"] if c.get("request")]
                self.assertEqual(["500", "502"], [c["worker"] for c in requests])
                records = list(state["versions"][state["oid"]].values())
                self.assertEqual(2, len(records))
                self.assertEqual(
                    {
                        f"li219-review-request:v1:1103407173:23:{HEAD}",
                        "li219-review-request:v1:1103407173:23:" + "e" * 40,
                    },
                    {record["operation"] for record in records},
                )
                self.assertTrue(all(record["action"] == "request" for record in records))

    def test_lost_cas_or_existing_review_or_pending_request_never_calls_ai(self):
        for mode in (
            "lost-cas",
            "partial-cas",
            "existing-review",
            "pending-review",
            "missing-bootstrap",
        ):
            with self.subTest(mode=mode):
                state = self.probe(mode)
                self.assertFalse(any(c.get("request") for c in state["calls"]))
                if mode in ("existing-review", "pending-review"):
                    self.assertFalse(any(c.get("cas") for c in state["calls"]))

    def test_pending_old_head_never_marks_or_consumes_new_head_in_either_mirror(self):
        for prefix in ("",):
            for flag in ("enabled", "disabled"):
                with self.subTest(source=prefix, flag=flag):
                    state = self.probe("pending-review", new_head=True, event_mode=flag, source_prefix=prefix)
                    self.assertEqual(INITIAL, state["oid"])
                    self.assertFalse(
                        any(call.get("cas") or call.get("request") or call.get("comment") for call in state["calls"])
                    )

    def test_actual_job_predicate_allows_only_enabled_pilot_new_head_synchronize(self):
        from types import SimpleNamespace as NS

        import yaml

        for prefix in ("",):
            workflow = yaml.safe_load((ROOT / prefix / ".github/workflows/copilot-review.yml").read_text())
            condition = workflow["jobs"]["request-current-revision-review"]["if"]
            expression = condition.replace("needs.classify-main-trust-root-handoff", "handoff")
            expression = expression.replace("&&", " and ").replace("||", " or ")
            expression = " ".join(expression.split())

            def allowed(
                repo="lightning-it/shared-assets-lit",
                flag="enabled",
                action="synchronize",
                expression=expression,
                **changes,
            ):
                values = {
                    "author": "litroc",
                    "actor": "litroc",
                    "trigger": "litroc",
                    "attempt": 1,
                    "draft": False,
                    "same_repo": True,
                    "event": "pull_request_target",
                    **changes,
                }
                github = NS(
                    repository=repo,
                    event_name=values["event"],
                    run_attempt=values["attempt"],
                    actor=values["actor"],
                    triggering_actor=values["trigger"],
                    event=NS(
                        action=action,
                        pull_request=NS(
                            draft=values["draft"],
                            user=NS(login=values["author"]),
                            head=NS(repo=NS(full_name=repo if values["same_repo"] else "other/fork")),
                        ),
                    ),
                )
                return eval(  # noqa: S307 -- Fixed GitHub expression, no builtins, fixture globals only.
                    expression,
                    {"__builtins__": {}},
                    {
                        "github": github,
                        "vars": NS(LI219_EVENT_MODE=flag),
                        "false": False,
                        "true": True,
                        "handoff": NS(result="skipped", outputs=NS(repository_producers_authorized="false")),
                        "always": lambda: True,
                        "contains": lambda sequence, value: value in sequence,
                        "fromJSON": json.loads,
                    },
                )

            for repo in (
                "lightning-it/ansible-collection-supplementary",
                "lightning-it/shared-assets-lit",
                "lightning-it/ansible-collection-supplementary",
            ):
                self.assertTrue(allowed(repo=repo))
            for flag in ("", "disabled", "Enabled"):
                self.assertFalse(allowed(flag=flag))
                self.assertTrue(allowed(flag=flag, action="opened"))
                self.assertTrue(allowed(flag=flag, action="ready_for_review"))
            self.assertFalse(allowed(repo="lightning-it/ansible-role-docker"))
            for changes in (
                {"author": "other"},
                {"actor": "github-actions[bot]"},
                {"trigger": "other"},
                {"attempt": 2},
                {"draft": True},
                {"same_repo": False},
                {"event": "workflow_dispatch"},
            ):
                self.assertFalse(allowed(**changes))
            for action in ("edited", "labeled", "reopened"):
                self.assertFalse(allowed(action=action))

    def test_lost_original_post_response_never_publishes_accepted_marker(self):
        for prefix in ("",):
            for flag in (None, "disabled", "enabled"):
                for new_head in (False, True):
                    with self.subTest(source=prefix, flag=flag, new_head=new_head):
                        state = self.probe(
                            "lost-request-response", new_head=new_head, event_mode=flag, source_prefix=prefix
                        )
                        self.assertTrue(state["requested"])
                        self.assertEqual(1, state["outcomes"][0])
                        self.assertEqual(1, sum(bool(c.get("request")) for c in state["calls"]))
                        self.assertEqual(int(flag == "enabled"), sum(bool(c.get("cas")) for c in state["calls"]))
                        self.assertTrue(all("UNCERTAIN:" in item["body"] for item in state.get("comments", [])))

    def test_lost_original_post_keeps_claim_consumed_after_pending_clears(self):
        for prefix in ("",):
            for new_head in (False, True):
                with self.subTest(source=prefix, new_head=new_head):
                    state = self.probe("lost-request-response-cleared", new_head=new_head, source_prefix=prefix)
                    expected = ["500", "502"] if new_head else ["500"]
                    self.assertEqual(expected, [c["worker"] for c in state["calls"] if c.get("request")])
                    self.assertEqual(len(expected), sum(bool(c.get("cas")) for c in state["calls"]))
                    self.assertTrue(all("UNCERTAIN:" in item["body"] for item in state.get("comments", [])))

    def test_legacy_lost_response_terminal_review_and_cleared_pending_never_repeat(self):
        for prefix in ("",):
            for flag in (None, "disabled"):
                with self.subTest(source=prefix, flag=flag):
                    state = self.probe("legacy-terminal-cleared", event_mode=flag, source_prefix=prefix)
                    self.assertEqual(["500"], [c["worker"] for c in state["calls"] if c.get("request")])
                    self.assertFalse(any(c.get("cas") for c in state["calls"]))
                    self.assertEqual(1, len(state["comments"]))
                    self.assertIn("UNCERTAIN:", state["comments"][0]["body"])
                    self.assertNotIn("request accepted", state["comments"][0]["body"])
                    first = [c for c in state["calls"] if c["worker"] == "500" and c.get("post")]
                    self.assertTrue(first[0].get("comment"))
                    self.assertTrue(first[1].get("request"))

    def test_rejected_original_post_then_old_pending_never_accepts_new_head(self):
        for prefix in ("",):
            for flag in (None, "disabled", "enabled"):
                for new_head in (False, True):
                    with self.subTest(source=prefix, flag=flag, new_head=new_head):
                        state = self.probe(
                            "rejected-old-pending", new_head=new_head, event_mode=flag, source_prefix=prefix
                        )
                        attempts = [c for c in state["calls"] if c.get("request")]
                        self.assertEqual(1, len(attempts))
                        self.assertIs(False, attempts[0]["accepted"])
                        self.assertEqual(BASE, state["pending_head"])
                        self.assertEqual(1, state["outcomes"][0])
                        self.assertEqual(int(flag == "enabled"), sum(bool(c.get("cas")) for c in state["calls"]))
                        self.assertTrue(all("UNCERTAIN:" in item["body"] for item in state.get("comments", [])))
