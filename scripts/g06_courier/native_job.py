"""Hosted same-run courier. Only its own job GITHUB_TOKEN enters the envelope."""

import http.client
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from codec import ACTORS, TRANSITION_BEFORE, decode, need, public_digest, public_key, seal

REPO = "ltn-it/ansible-collection-supplementary"
V = "ltn-it/modulix-validation"
JOB_NAME = "G06 / Root acquisition courier"


def api(path, token, expected=200):
    need(path.startswith("/repos/") and ".." not in path, "fixed-github-route")
    connection = http.client.HTTPSConnection("api.github.com", timeout=10)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "lit-g06-courier/1",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        need(response.status == expected, "courier-api-status")
        raw = response.read(8 * 1024**2 + 1)
        need(len(raw) <= 8 * 1024**2, "courier-api-bound")
        if expected == 302:
            location = urlsplit(response.getheader("Location", ""))
            need(
                location.scheme == "https"
                and not location.username
                and not location.password
                and location.port is None
                and not location.fragment
                and (
                    location.hostname == "codeload.github.com"
                    or location.hostname == "results-receiver.actions.githubusercontent.com"
                    or re.fullmatch("[a-z0-9]{3,24}\\.blob\\.core\\.windows\\.net", location.hostname or "")
                ),
                "courier-download-origin",
            )
            return None
        return json.loads(raw)
    finally:
        connection.close()


def config(path):
    value = decode(path.read_bytes())
    need(
        type(value) is dict
        and set(value)
        == {"schema", "operation", "public_key_pem", "public_key_sha256", "controller_commit_sha", "hold_seconds"}
        and value["schema"] == 1
        and type(value["schema"]) is int
        and value["hold_seconds"] == 900
        and type(value["hold_seconds"]) is int
        and re.fullmatch("[a-f0-9]{32}", value["operation"])
        and re.fullmatch("[a-f0-9]{40}", value["controller_commit_sha"]),
        "courier-public-config",
    )
    need(
        public_digest(public_key(value["public_key_pem"].encode())) == value["public_key_sha256"],
        "courier-public-config-digest",
    )
    return value


def prepare():
    public = config(Path(".lit/g06-courier.json"))
    token = os.environ["GITHUB_TOKEN"]
    run_id = int(os.environ["GITHUB_RUN_ID"])
    sha = os.environ["GITHUB_SHA"]
    need(
        os.environ.get("GITHUB_REPOSITORY") == REPO
        and os.environ.get("GITHUB_EVENT_NAME") == "push"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        and os.environ.get("G06_EVENT_BEFORE") == TRANSITION_BEFORE
        and os.environ.get("GITHUB_JOB") == "g06-root-courier",
        "courier-hosted-context",
    )
    source = api("/repos/" + REPO, token)
    validation = api("/repos/" + V, token)
    for repo, name, expected in ((source, REPO, 1103407173), (validation, V, 1269461997)):
        need(
            repo.get("id") == expected and repo.get("full_name") == name and repo.get("private") is False,
            "courier-public-repository-identity",
        )
    branch = api("/repos/" + REPO + "/branches/main", token)
    need(
        branch.get("protected") is True and branch.get("commit", {}).get("sha") == sha, "courier-current-protected-main"
    )
    run = api("/repos/" + REPO + "/actions/runs/" + str(run_id), token)
    attempt = api("/repos/" + REPO + "/actions/runs/" + str(run_id) + "/attempts/1", token)
    actor_id = None
    for current in (run, attempt):
        need(
            current.get("id") == run_id
            and current.get("run_attempt") == 1
            and current.get("workflow_id") == 214182490
            and current.get("path") == ".github/workflows/collection-ci.yml"
            and current.get("event") == "push"
            and current.get("head_sha") == sha
            and current.get("head_branch") == "main"
            and current.get("status") == "in_progress"
            and current.get("conclusion") is None
            and current.get("repository", {}).get("id") == 1103407173,
            "courier-live-producer",
        )
        for field in ("actor", "triggering_actor"):
            actor = current.get(field, {})
            need(
                type(actor.get("id")) is int
                and actor["id"] in ACTORS
                and actor.get("type") == "User"
                and actor.get("login") == ACTORS[actor["id"]],
                "courier-human-actor",
            )
            if actor_id is None:
                actor_id = actor["id"]
            need(actor["id"] == actor_id, "courier-actor-drift")
    # Prove this exact S job token can read the public controller API routes
    # required by accepted U; no assumed cross-repository installation grant.
    commit = api("/repos/" + V + "/git/commits/" + public["controller_commit_sha"], token)
    need(commit.get("sha") == public["controller_commit_sha"], "courier-controller-commit")
    tree = commit.get("tree", {}).get("sha", "")
    need(re.fullmatch("[a-f0-9]{40}", tree), "courier-controller-tree")
    api("/repos/" + V + "/git/trees/" + tree + "?recursive=1", token)
    api("/repos/" + V + "/tarball/" + public["controller_commit_sha"], token, 302)
    artifacts = api("/repos/" + REPO + "/actions/runs/" + str(run_id) + "/artifacts?per_page=100", token)
    need(
        type(artifacts.get("total_count")) is int
        and artifacts["total_count"] <= 100
        and len(artifacts.get("artifacts", [])) == artifacts["total_count"],
        "courier-artifact-inventory",
    )
    found = [item for item in artifacts["artifacts"] if item.get("name") == "collection-candidate-" + sha]
    need(len(found) == 1, "courier-single-candidate")
    candidate = api("/repos/" + REPO + "/actions/artifacts/" + str(found[0]["id"]), token)
    need(
        candidate.get("id") == found[0]["id"]
        and candidate.get("expired") is False
        and candidate.get("name") == "collection-candidate-" + sha
        and candidate.get("workflow_run", {}).get("id") == run_id
        and candidate.get("workflow_run", {}).get("head_sha") == sha
        and re.fullmatch("sha256:[a-f0-9]{64}", candidate.get("digest", ""))
        and type(candidate.get("size_in_bytes")) is int
        and candidate["size_in_bytes"] > 0,
        "courier-candidate-binding",
    )
    api("/repos/" + REPO + "/actions/artifacts/" + str(candidate["id"]) + "/zip", token, 302)
    jobs = []
    for page in range(1, 12):
        frame = api(
            "/repos/" + REPO + "/actions/runs/" + str(run_id) + "/attempts/1/jobs?per_page=100&page=" + str(page), token
        )
        need(
            type(frame.get("total_count")) is int and frame["total_count"] <= 1000 and type(frame.get("jobs")) is list,
            "courier-job-inventory",
        )
        jobs.extend(frame["jobs"])
        if len(frame["jobs"]) < 100:
            break
    need(len(jobs) == frame["total_count"] and len({job["id"] for job in jobs}) == len(jobs), "courier-complete-jobs")
    selected = [
        job
        for job in jobs
        if job.get("name") == JOB_NAME
        and job.get("run_id") == run_id
        and job.get("head_sha") == sha
        and job.get("status") == "in_progress"
        and job.get("conclusion") is None
    ]
    need(len(selected) == 1, "courier-exact-live-job")
    issued = int(time.time())
    binding = {
        "transition_before": TRANSITION_BEFORE,
        "operation": public["operation"],
        "key_sha256": public["public_key_sha256"],
        "repository": REPO,
        "repository_id": 1103407173,
        "main_sha": sha,
        "workflow_id": 214182490,
        "run_id": run_id,
        "run_attempt": 1,
        "courier_job_id": selected[0]["id"],
        "actor_id": actor_id,
        "actor": ACTORS[actor_id],
        "candidate_artifact_id": candidate["id"],
        "candidate_digest": candidate["digest"][7:],
        "candidate_size": candidate["size_in_bytes"],
        "controller_sha": public["controller_commit_sha"],
        "issued_at": issued,
        "cutoff_at": issued + 900,
    }
    encrypted = seal(token, binding, public["public_key_pem"].encode(), issued)
    directory = Path(os.environ["RUNNER_TEMP"]) / "g06-root-courier"
    directory.mkdir(mode=0o700)
    fd = os.open(directory / "handoff.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encrypted)
        stream.flush()
        os.fsync(stream.fileno())
    print(
        json.dumps(
            {
                "state": "COURIER_CIPHERTEXT_READY",
                "operation": public["operation"],
                "run_id": run_id,
                "courier_job_id": selected[0]["id"],
                "cutoff_at": issued + 900,
            }
        )
    )


def hold():
    path = Path(os.environ["RUNNER_TEMP"]) / "g06-root-courier/handoff.json"
    binding = decode(path.read_bytes())["binding"]
    remaining = binding["cutoff_at"] - int(time.time())
    need(0 <= remaining <= 900, "courier-held-window")
    # The job token expires with job completion. Provider token expiry is not
    # exposed here. Root uses the earlier fixed cutoff and terminal readback.
    end = time.monotonic() + remaining
    while time.monotonic() < end:
        time.sleep(max(0, min(15, end - time.monotonic())))
    print(
        json.dumps(
            {
                "state": "COURIER_FIXED_WINDOW_ENDED",
                "run_id": binding["run_id"],
                "courier_job_id": binding["courier_job_id"],
            }
        )
    )


if __name__ == "__main__":
    try:
        need(sys.argv[1:] in (["prepare"], ["hold"]), "courier-arguments")
        prepare() if sys.argv[1] == "prepare" else hold()
    except Exception as error:
        print(
            json.dumps(
                {"state": "COURIER_HELD", "category": str(error) if type(error) is ValueError else type(error).__name__}
            )
        )
        raise SystemExit(2) from None
