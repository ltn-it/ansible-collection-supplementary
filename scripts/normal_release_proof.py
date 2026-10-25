"""Authenticate normal App preparation ingress and its approved Main promotion.

Read-only consumer of the pinned public Required Workflow. No review request,
workflow dispatch, approval, credential mutation or publication is implemented.
"""

# Exact JSON key/type contracts reject bool-as-int and unknown wire shapes.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import io
import json
import re
import shutil
import sys
import tempfile
import zipfile
from contextlib import contextmanager, nullcontext
from pathlib import Path

import normal_release_archive as archive
import security_main_promotion as git_contract

CONTROL_SOURCE = "bb1a5df9f54c5f98547048297e7e367cc382543e"
APP = ("lightning-it-release-automation[bot]", 307565056, "Bot")
RECEIPT = "changelogs/release-preparation.json"


def require(value, message):
    if not value:
        raise ValueError(message)


def version_module():
    path = Path(__file__).with_name("release-version.py")
    spec = importlib.util.spec_from_file_location("normal_release_version", path)
    require(spec is not None and spec.loader is not None, "release-version-module-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def text(root, *args):
    return git_contract.git_text(root, *args)


def document(root, revision):
    raw = git_contract.git_bytes(root, "show", f"{revision}:{RECEIPT}")
    value = git_contract.CONTRACT.load_json_bytes(raw, "normal release receipt")
    require(raw == git_contract.CONTRACT.canonical_document_bytes(value), "noncanonical-release-receipt")
    require(
        value.get("schema_version") == 3 and value.get("release_mode") == "normal", "normal-two-stage-schema-required"
    )
    return value


def preparation(root, base, head, workflow_source, repository, repository_id):
    for revision in (base, head, workflow_source):
        require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision), "invalid-revision")
    receipt = document(root, head)
    version = receipt["next_version"]
    require(receipt["workflow"]["source_sha"] == workflow_source, "preparation-workflow-source-drift")
    version_module().verify_preparation_receipt(
        receipt,
        expected_repository=repository,
        expected_repository_id=repository_id,
        expected_base_sha=base,
        expected_version=version,
        root=root,
    )
    git_contract.require_app_commit(root, base, head, f"chore(release): prepare v{version}")
    require(git_contract.is_ancestor(root, workflow_source, base), "workflow-source-not-in-content-ancestry")
    changes = dict((path, status) for status, path in git_contract.changed_paths(root, base, head))
    fragments = {f"changelogs/fragments/{item['path']}" for item in receipt["fragments"]}
    require({RECEIPT, "galaxy.yml"} <= changes.keys(), "release-generated-state-missing")
    require(set(changes) <= git_contract.RELEASE_GENERATED_PATHS | fragments, "non-generated-release-path")
    require(all(changes.get(path) == "D" for path in fragments), "reviewed-fragment-not-consumed")
    require(all(status in {"A", "M", "D"} for status in changes.values()), "release-path-type-change")
    for item in receipt["fragments"]:
        raw = git_contract.git_bytes(root, "show", f"{base}:changelogs/fragments/{item['path']}")
        require(git_contract.CONTRACT.sha256_bytes(raw) == f"sha256:{item['sha256']}", "fragment-digest-drift")
    for revision, expected in (
        (base, receipt["current_version"]),
        (workflow_source, receipt["current_version"]),
        (head, version),
    ):
        raw = git_contract.git_bytes(root, "show", f"{revision}:galaxy.yml").decode()
        observed = re.findall(r"(?m)^version:\s*[\"']?([^\s\"']+)[\"']?\s*$", raw)
        require(observed == [expected], "release-version-drift")
    return receipt


def preparation_changelog(root, base, head, workflow_source, repository, repository_id, head_ref, check_worktree):
    receipt = preparation(root, base, head, workflow_source, repository, repository_id)
    require(head_ref == f"release/v{receipt['next_version']}", "preparation-release-ref-drift")
    if check_worktree:
        paths = sorted(git_contract.RELEASE_GENERATED_PATHS | {"changelogs/fragments"})
        require(not text(root, "diff", "--name-only", head, "--", "."), "preparation-worktree-drift")
        require(
            not text(root, "ls-files", "--others", "--exclude-standard", "--", *paths), "preparation-untracked-state"
        )
    return receipt


def merged_pull(api, repository, merge, base_ref, head_ref, base, head):
    matches = [
        p
        for p in api.pages(f"repos/{repository}/commits/{merge}/pulls")
        if p.get("merged_at") and p.get("merge_commit_sha") == merge and p.get("base", {}).get("ref") == base_ref
    ]
    require(len(matches) == 1, "unique-merged-release-pr-required")
    pull = api.call(f"repos/{repository}/pulls/{matches[0]['number']}")
    require(
        pull.get("merged") is True
        and pull.get("state") == "closed"
        and pull.get("draft") is False
        and pull.get("merged_at")
        and pull.get("merge_commit_sha") == merge,
        "merged-release-pr-drift",
    )
    require(tuple(pull.get("user", {}).get(k) for k in ("login", "id", "type")) == APP, "release-app-pr-required")
    require(
        pull.get("base", {}).get("repo", {}).get("full_name") == repository
        and pull.get("head", {}).get("repo", {}).get("full_name") == repository,
        "same-repository-release-pr-required",
    )
    require(
        pull["base"]["ref"] == base_ref
        and pull["head"]["ref"] == head_ref
        and pull["base"]["sha"] == base
        and pull["head"]["sha"] == head,
        "exact-release-pr-relationship-required",
    )
    return pull


def load_control(directory):
    require(text(directory, "rev-parse", "HEAD") == CONTROL_SOURCE, "pinned-control-source-required")
    require(not text(directory, "status", "--porcelain"), "clean-control-source-required")
    sys.path.insert(0, str(directory / "scripts"))
    return importlib.import_module("workflow_control")


def promotion_control(api, core, repository, pull, config):
    runs = api.pages(f"repos/{repository}/actions/runs?head_sha={pull['head']['sha']}", "workflow_runs")
    cache = {}
    candidates = core.ingress_candidates(api, repository, pull, config["accepted_sources"], runs, cache)
    require(candidates, "native-promotion-run-required")
    observed = max(candidates, key=lambda run: (run["id"], run["run_attempt"]))
    selected = observed
    excluded = []
    if observed["status"] != "completed" or observed["conclusion"] != "success":
        # Reuse the source's exact historical closure-only proof. Semantic
        # failures, drift, pending and failed reviews never gain an exception.
        from workflow_ingress import merged_attempt

        selected, excluded = merged_attempt(api, repository, pull, observed)
    gates = [j for j in core.native_jobs(api, repository, selected) if j.get("name") == "Current revision review"]
    require(len(gates) == 1 and gates[0].get("conclusion") == "success", "native-promotion-gate-required")
    proof = core.artifact_record(
        api, repository, selected, f"control-proof-{selected['run_attempt']}", "control-proof.json"
    )
    require(
        proof.get("version") == 1
        and proof.get("source_sha") in config["accepted_sources"]
        and proof.get("binding") == core.binding(pull)
        and proof.get("route") == "promotion",
        "native-promotion-proof-binding",
    )
    authorization = proof.get("authorization")
    require(
        type(authorization) is dict and type(authorization.get("run")) is int and authorization["run"] > 0,
        "native-promotion-approval-required",
    )
    approval_run = api.call(f"repos/{repository}/actions/runs/{authorization['run']}")
    require(
        core.native_required(approval_run, repository) and approval_run.get("head_sha") == pull["head"]["sha"],
        "native-approval-run-origin",
    )
    operation = core.operation_record(api, repository, approval_run, proof["source_sha"])
    require(
        core.same_immutable_tuple(operation.get("binding", {}), core.binding(pull)), "native-approval-operation-drift"
    )
    core.normal_environment(api, repository)
    require(
        core.native_approval(api, repository, authorization["run"]) == authorization.get("approval"),
        "native-human-approval-drift",
    )
    current = api.call(f"repos/{repository}/actions/runs/{observed['id']}")
    require(
        all(
            current.get(k) == observed.get(k)
            for k in ("id", "run_attempt", "head_sha", "status", "conclusion", "workflow_id", "workflow_url", "path")
        ),
        "native-promotion-generation-drift",
    )
    latest = api.pages(f"repos/{repository}/actions/runs?head_sha={pull['head']['sha']}", "workflow_runs")
    candidates = core.ingress_candidates(api, repository, pull, config["accepted_sources"], latest, cache)
    require(
        candidates
        and max((r["id"], r["run_attempt"]) for r in candidates) == (observed["id"], observed["run_attempt"]),
        "newer-promotion-generation",
    )
    return proof, excluded


def promotion_ready(root, api, core, repository, repository_id, base, head):
    """Prove the reviewed preparation before permitting generated-state advancement."""
    live = api.call(f"repos/{repository}")
    require(
        live.get("full_name") == repository
        and str(live.get("id")) == repository_id
        and live.get("archived") is False
        and live.get("disabled") is False,
        "promotion-repository-identity-drift",
    )
    receipt = document(root, head)
    content_base = receipt["content_base"]["sha"]
    parents = text(root, "show", "-s", "--format=%P", head).split()
    require(len(parents) == 2 and parents[0] == content_base, "exact-preparation-ingress-parents-required")
    prepared = parents[1]
    require(
        text(root, "rev-parse", f"{head}^{{tree}}") == text(root, "rev-parse", f"{prepared}^{{tree}}"),
        "preparation-ingress-tree-drift",
    )
    source = receipt["workflow"]["source_sha"]
    require(
        git_contract.is_ancestor(root, source, base) and git_contract.is_ancestor(root, base, content_base),
        "protected-main-ancestry-required",
    )
    require(
        preparation(root, content_base, prepared, source, repository, repository_id) == receipt,
        "preparation-receipt-drift",
    )
    raw = git_contract.git_bytes(root, "show", f"{base}:galaxy.yml").decode()
    require(
        re.findall(r"(?m)^version:\s*[\"']?([^\s\"']+)[\"']?\s*$", raw) == [receipt["current_version"]],
        "promotion-main-version-drift",
    )
    for revision in (base, head):
        for directory in (".lit/security-releases", ".lit/security-release-intakes"):
            require(
                not text(root, "ls-tree", revision, "--", f"{directory}/{receipt['next_version']}.json"),
                "normal-promotion-security-marker",
            )
    pull = merged_pull(api, repository, head, "develop", f"release/v{receipt['next_version']}", content_base, prepared)
    config = core.policy(api, repository, base, CONTROL_SOURCE)
    ingress = core.check_native_control(api, repository, pull, config)
    require(ingress.get("route") == "codex", "genuine-app-ingress-review-required")
    require(
        ingress.get("head") == prepared and ingress.get("source_sha") in config["accepted_sources"],
        "preparation-native-control-drift",
    )
    workflow = receipt["workflow"]
    run = api.call(f"repos/{repository}/actions/runs/{workflow['run_id']}")
    require(
        str(run.get("id")) == workflow["run_id"]
        and str(run.get("run_attempt")) == workflow["run_attempt"]
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
        and run.get("head_sha") == source
        and run.get("head_branch") == "main"
        and run.get("path") == workflow["path"]
        and run.get("event") == workflow["event"]
        and run.get("actor", {}).get("login") == workflow["actor"]
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "protected-main-preparation-run-required",
    )
    current = api.call(f"repos/{repository}/pulls/{pull['number']}")
    require(
        core.binding(current) == core.binding(pull)
        and all(current.get(key) == pull.get(key) for key in ("state", "merged", "merged_at", "merge_commit_sha")),
        "release-pull-changed",
    )
    require(api.call(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == base, "protected-main-tip-drift")
    require(
        api.call(f"repos/{repository}/git/ref/heads/develop")["object"]["sha"] == head, "protected-develop-tip-drift"
    )
    return {
        "preparation_pr": pull["number"],
        "prepared_head": prepared,
        "develop_merge": head,
        "next_version": receipt["next_version"],
        "native_ingress": ingress,
    }


def control_reference(value):
    keys = {"run", "attempt", "job", "head", "source_sha", "route", "artifact", "proof_sha256"}
    require(
        type(value) is dict and keys <= value.keys() and set(value) <= keys | {"post_merge_failed_attempts"},
        "native-control-reference-shape",
    )
    return {key: value[key] for key in keys}


def _publish(root, api, core, repository, repository_id, release, base, head, current_main):
    require(text(root, "rev-parse", "HEAD") == current_main, "exact-release-checkout-required")
    receipt = document(root, release)
    require(
        receipt["repository"] == repository and receipt["repository_id"] == repository_id,
        "release-repository-identity-drift",
    )
    require(
        text(root, "show", "-s", "--format=%P", release).split() == [base, head],
        "exact-promotion-merge-parents-required",
    )
    require(
        text(root, "rev-parse", f"{release}^{{tree}}") == text(root, "rev-parse", f"{head}^{{tree}}"),
        "promotion-tree-drift",
    )
    content_base = receipt["content_base"]["sha"]
    ingress_parents = text(root, "show", "-s", "--format=%P", head).split()
    require(
        len(ingress_parents) == 2 and ingress_parents[0] == content_base, "exact-preparation-ingress-parents-required"
    )
    prepared = ingress_parents[1]
    require(
        text(root, "rev-parse", f"{head}^{{tree}}") == text(root, "rev-parse", f"{prepared}^{{tree}}"),
        "preparation-ingress-tree-drift",
    )
    workflow_source = receipt["workflow"]["source_sha"]
    require(
        git_contract.is_ancestor(root, workflow_source, base) and git_contract.is_ancestor(root, base, content_base),
        "protected-main-ancestry-required",
    )
    require(
        preparation(root, content_base, prepared, workflow_source, repository, repository_id) == receipt,
        "preparation-receipt-drift",
    )
    prep = merged_pull(api, repository, head, "develop", f"release/v{receipt['next_version']}", content_base, prepared)
    promotion = merged_pull(api, repository, release, "main", "develop", base, head)
    config = core.policy(api, repository, base, CONTROL_SOURCE)
    ingress = core.check_native_control(api, repository, prep, config)
    require(ingress["route"] == "codex", "genuine-app-ingress-review-required")
    proof, excluded = promotion_control(api, core, repository, promotion, config)
    evidence = proof.get("evidence", {})
    require(
        evidence.get("base") == base
        and evidence.get("head") == head
        and evidence.get("integration_tree") == text(root, "rev-parse", f"{release}^{{tree}}"),
        "native-promotion-integration-tree-drift",
    )
    references = [
        item for item in evidence.get("ingress", []) if item.get("pull") == prep["number"] and item.get("merge") == head
    ]
    require(
        len(references) == 1 and control_reference(references[0].get("control")) == control_reference(ingress),
        "preparation-not-in-native-promotion-coverage",
    )
    workflow = receipt["workflow"]
    run = api.call(f"repos/{repository}/actions/runs/{workflow['run_id']}")
    require(
        str(run.get("id")) == workflow["run_id"]
        and str(run.get("run_attempt")) == workflow["run_attempt"]
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
        and run.get("head_sha") == workflow_source
        and run.get("head_branch") == "main"
        and run.get("path") == workflow["path"]
        and run.get("event") == workflow["event"]
        and run.get("actor", {}).get("login") == workflow["actor"]
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "protected-main-preparation-run-required",
    )
    require(
        api.call(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == current_main, "protected-main-tip-drift"
    )
    for pull in (prep, promotion):
        current = api.call(f"repos/{repository}/pulls/{pull['number']}")
        require(
            core.binding(current) == core.binding(pull)
            and all(current.get(key) == pull.get(key) for key in ("state", "merged", "merged_at", "merge_commit_sha")),
            "release-pull-changed",
        )
    return {
        "content_base": content_base,
        "prepared_head": prepared,
        "develop_merge": head,
        "main_merge": release,
        "preparation_pr": prep["number"],
        "promotion_pr": promotion["number"],
        "promotion_proof_sha256": core.digest(proof),
        "post_merge_failed_attempts": excluded,
    }


def publish(root, api, core, repository, repository_id, release, base, head):
    """Default publication always requires the exact current Main checkout."""
    return _publish(root, api, core, repository, repository_id, release, base, head, release)


def publish_snapshot(root, api, core, repository, repository_id, release, base, head, output):
    """Persist native observations only after the complete live verifier succeeds."""
    expected = archive.binding(repository, repository_id, release, base, head, CONTROL_SOURCE)
    recorder = archive.Record(api, expected)
    with archive.artifact_reader(core, recorder):
        result = publish(root, recorder, core, repository, repository_id, release, base, head)
    output.write_bytes(recorder.finish(result))
    return result


def _archived_publication(root, api, core, repository, repository_id, current_main, *, export_directory=None):
    """Authenticate inherited schema3 state against an already-published ancestor.

    Only this existing annotated-tag/release boundary can enter historical proof;
    there is no caller-controlled historical mode on publication itself.
    """
    require(text(root, "rev-parse", "HEAD") == current_main, "exact-baseline-checkout-required")
    receipt = document(root, current_main)
    version = receipt["next_version"]
    require(
        re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version),
        "published-baseline-stable-version-required",
    )
    tag = f"v{version}"
    ref = api.call(f"repos/{repository}/git/ref/tags/{tag}")
    require(
        ref.get("ref") == f"refs/tags/{tag}"
        and ref.get("object", {}).get("type") == "tag"
        and re.fullmatch(r"[0-9a-f]{40}", ref.get("object", {}).get("sha", "")),
        "published-baseline-annotated-tag-required",
    )
    tag_object = api.call(f"repos/{repository}/git/tags/{ref['object']['sha']}")
    require(
        tag_object.get("tag") == tag
        and tag_object.get("object", {}).get("type") == "commit"
        and re.fullmatch(r"[0-9a-f]{40}", tag_object.get("object", {}).get("sha", "")),
        "published-baseline-tag-target-required",
    )
    release = tag_object["object"]["sha"]
    published = api.call(f"repos/{repository}/releases/tags/{tag}")
    require(
        type(published.get("id")) is int
        and published["id"] > 0
        and published.get("tag_name") == tag
        and published.get("draft") is False
        and published.get("prerelease") is False
        and published.get("published_at"),
        "published-baseline-release-required",
    )
    require(git_contract.is_ancestor(root, release, current_main), "published-baseline-not-ancestor")
    require(
        text(root, "rev-parse", f"{release}:{RECEIPT}") == text(root, "rev-parse", f"{current_main}:{RECEIPT}"),
        "published-baseline-receipt-drift",
    )
    for path in git_contract.RELEASE_GENERATED_PATHS - {"galaxy.yml", RECEIPT}:
        require(
            text(root, "rev-parse", f"{release}:{path}") == text(root, "rev-parse", f"{current_main}:{path}"),
            "published-baseline-generated-state-drift",
        )
    parents = text(root, "show", "-s", "--format=%P", release).split()
    require(len(parents) == 2, "exact-promotion-merge-parents-required")
    # Current Main remains a live observation; historical Actions are never
    # queried here. The signed snapshot preserves their original observations.
    require(
        api.call(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == current_main,
        "protected-main-tip-drift",
    )
    expected = archive.binding(repository, repository_id, release, parents[0], parents[1], CONTROL_SOURCE)
    with tempfile.TemporaryDirectory(prefix="normal-release-baseline-") as temporary:
        directory = Path(temporary)
        archive.download_pair(published, repository, directory)
        value = archive.verify_files(
            directory / archive.SNAPSHOT, directory / archive.BUNDLE, repository, repository_id, release
        )
        replay = archive.Replay(value, expected, current_main)
        with archive.artifact_reader(core, replay):
            result = _publish(
                root, replay, core, repository, repository_id, release, parents[0], parents[1], current_main
            )
        replay.finish(result)
        if export_directory is not None:
            for name in (archive.SNAPSHOT, archive.BUNDLE):
                shutil.copyfile(directory / name, export_directory / name)
    require(
        api.call(f"repos/{repository}/git/ref/tags/{tag}") == ref
        and api.call(f"repos/{repository}/git/tags/{ref['object']['sha']}") == tag_object,
        "published-baseline-tag-drift",
    )
    require(
        archive.release_state(api.call(f"repos/{repository}/releases/tags/{tag}")) == archive.release_state(published),
        "published-baseline-release-drift",
    )
    require(
        api.call(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == current_main, "protected-main-tip-drift"
    )
    return result, published, ref, tag_object


def published_baseline(root, api, core, repository, repository_id, current_main):
    """Baseline advancement requires completed publication, never just pre-publication observations."""
    result, published, ref, tag_object = _archived_publication(root, api, core, repository, repository_id, current_main)
    release = result["main_merge"]
    version = document(root, release)["next_version"]
    parser = version_module()
    policy = parser.yaml.load(  # noqa: S506 -- existing duplicate-key-rejecting SafeLoader.
        git_contract.git_bytes(root, "show", f"{release}:.lit/repository.yml"), Loader=parser.UniqueKeyLoader
    )
    require(
        type(policy) is dict
        and type(policy.get("publishing_targets")) is list
        and "github-release" in policy["publishing_targets"]
        and type(policy.get("galaxy_publish")) is bool,
        "completion-protected-publication-policy",
    )
    galaxy = policy["galaxy_publish"] and "ansible-galaxy" in policy["publishing_targets"]
    context = archive.completion_context(repository, repository_id, release, version, galaxy)
    with tempfile.TemporaryDirectory(prefix="normal-completion-") as temporary:
        archive.verify_completion(published, context, Path(temporary))
    require(
        api.call(f"repos/{repository}/git/ref/tags/{context['tag']}") == ref
        and api.call(f"repos/{repository}/git/tags/{ref['object']['sha']}") == tag_object,
        "published-baseline-tag-drift",
    )
    require(
        archive.release_state(api.call(f"repos/{repository}/releases/tags/{context['tag']}"))
        == archive.release_state(published),
        "published-baseline-release-drift",
    )
    require(
        api.call(f"repos/{repository}/git/ref/heads/main")["object"]["sha"] == current_main, "protected-main-tip-drift"
    )
    return result


def publication_archive(root, api, core, repository, repository_id, release, base, head, directory):
    """Create one new evidence snapshot, or retain the complete published pair."""
    require(text(root, "rev-parse", "HEAD") == release, "exact-release-checkout-required")
    require(
        text(root, "show", "-s", "--format=%P", release).split() == [base, head],
        "exact-promotion-merge-parents-required",
    )
    directory.mkdir(parents=True, exist_ok=False)
    tag = "v" + document(root, release)["next_version"]
    releases = api.pages(f"repos/{repository}/releases")
    matches = [item for item in releases if item.get("tag_name") == tag]
    require(len(matches) <= 1, "published-baseline-release-ambiguous")
    if matches:
        # No repair or replacement of a partial/foreign existing pair. Its
        # original signature is retained byte for byte, even after Actions expire.
        result, _published, _ref, _tag = _archived_publication(
            root, api, core, repository, repository_id, release, export_directory=directory
        )
        require(result["main_merge"] == release, "publication-existing-release-drift")
        return result | {"archive_reused": True}
    result = publish_snapshot(
        root, api, core, repository, repository_id, release, base, head, directory / archive.SNAPSHOT
    )
    return result | {"archive_reused": False}


def native_snapshot(core, directory, repository, repository_id):
    """Consume raw native observations offline; no API or downloader fallback."""
    require(
        repository == "lightning-it/ansible-collection-supplementary" and repository_id == "1103407173",
        "normal-observation-repository",
    )
    from workflow_proofs import read_native_json

    index = read_native_json(directory / "index.json", 1024 * 1024)
    require(
        type(index) is dict
        and set(index) == {"version", "repository", "calls", "logs", "artifacts", "assets"}
        and type(index["version"]) is int
        and index["version"] == 1
        and index["repository"] == repository,
        "normal-observation-binding",
    )
    names = set()
    endpoint = (
        r"(?:branches/(?:main|develop)|pulls/[1-9][0-9]*|issues/[1-9][0-9]*/events|"
        r"commits/[0-9a-f]{40}/pulls|contents/\.lit/workflow-control\.json\?ref=[0-9a-f]{40}|"
        r"actions/runs(?:\?head_sha=[0-9a-f]{40}|/[1-9][0-9]*(?:/(?:approvals|artifacts|"
        r"attempts/[1-9][0-9]*(?:/jobs)?))?)?|environments/normal-release-promotion-approval|"
        r"releases(?:/tags/v[0-9][A-Za-z0-9.+-]*)?|git/ref/(?:heads/(?:main|develop)|tags/v[0-9][A-Za-z0-9.+-]*)|"
        r"git/tags/[0-9a-f]{40})(?:[?&]per_page=100&page=[1-9][0-9]*)?"
    )
    for kind, pattern in (
        ("calls", r"read-[0-9]+\.json"),
        ("logs", r"log-[0-9]+\.txt"),
        ("artifacts", r"artifact-[0-9]+\.zip"),
        ("assets", r"asset-[0-9]+\.bin"),
    ):
        require(type(index[kind]) is dict, "normal-observation-index")
        for key, name in index[kind].items():
            require(
                type(name) is str and re.fullmatch(pattern, name) and name not in names,
                "normal-observation-file",
            )
            require(
                (
                    key == f"repos/{repository}"
                    or key.startswith(f"repos/{repository}/")
                    and re.fullmatch(endpoint, key.removeprefix(f"repos/{repository}/"))
                )
                if kind == "calls"
                else re.fullmatch(r"[1-9][0-9]*", key),
                "normal-observation-scope",
            )
            names.add(name)
    require(
        0 < len(names) <= 4096
        and {p.name for p in directory.iterdir()} == names | {"index.json"}
        and all((directory / name).is_file() and not (directory / name).is_symlink() for name in names)
        and sum((directory / name).stat().st_size for name in names if not name.startswith("asset-"))
        <= 128 * 1024 * 1024
        and sum((directory / name).stat().st_size for name in names if name.startswith("asset-")) <= 16_000_000_000
        and all((directory / name).stat().st_size <= 2_000_000_000 for name in names if name.startswith("asset-")),
        "normal-observation-bound",
    )

    class Observations(core.API):
        def call(self, path, *, method="GET", data=None):
            require(
                method == "GET" and data is None and path in index["calls"],
                "normal-missing-native-observation",
            )
            return read_native_json(directory / index["calls"][path], core.MAX_PROOF_BYTES)

        def native_job_log(self, repo, job):
            require(
                repo == repository and str(job) in index["logs"],
                "normal-missing-native-log",
            )
            return archive.bounded_file(directory / index["logs"][str(job)], core.MAX_OPERATION_BYTES).decode()

        def artifact(self, _original, _api, repo, run, name, filename):
            require(repo == repository, "normal-artifact-repository")
            archive.artifact_identity(repo, run, name, filename)
            reads = archive.ArtifactReads(self, repo, run)
            inventory = reads.pages(reads.path, "artifacts")
            matches = [a for a in inventory if a.get("name") == name and a.get("expired") is False]
            require(len(matches) == 1, "normal-native-artifact-unique")
            selected = matches[0]
            archive.artifact_metadata(selected, name)
            origin = selected.get("workflow_run", {})
            require(
                type(origin.get("id")) is int
                and origin.get("id") == run["id"]
                and origin.get("head_sha") == run["head_sha"]
                and str(origin.get("repository_id")) == repository_id
                and str(origin.get("head_repository_id")) == repository_id
                and str(selected["id"]) in index["artifacts"],
                "normal-native-artifact-origin",
            )
            maximum = core.MAX_OPERATION_BYTES if filename == "control-operation.json" else core.MAX_PROOF_BYTES
            raw = archive.bounded_file(
                directory / index["artifacts"][str(selected["id"])],
                core.MAX_PROOF_BYTES + 4096,
            )
            require(
                len(raw) == selected["size_in_bytes"]
                and selected.get("digest") == "sha256:" + hashlib.sha256(raw).hexdigest(),
                "normal-native-artifact-digest",
            )
            with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
                files = zipped.infolist()
                require(
                    len(files) == 1
                    and files[0].filename == filename
                    and not files[0].is_dir()
                    and files[0].external_attr >> 16 & 0o170000 in {0, 0o100000}
                    and 0 < files[0].file_size <= maximum,
                    "normal-native-artifact-zip",
                )
                with tempfile.TemporaryDirectory(prefix="normal-native-json-") as temporary:
                    leaf = Path(temporary) / filename
                    leaf.write_bytes(zipped.read(files[0]))
                    from workflow_proofs import read_native_json

                    return read_native_json(leaf, maximum)

    return Observations(), index


def native_fence(core, before, after, repository, repository_id):
    """Fresh native facts, using exactly the original proof's decision fields."""
    first, initial = native_snapshot(core, before, repository, repository_id)
    fresh, latest = native_snapshot(core, after, repository, repository_id)
    paths = [
        directory / name
        for directory, index in ((before, initial), (after, latest))
        for kind in ("calls", "logs", "artifacts")
        for name in index[kind].values()
    ]
    require(
        len(paths) <= 4096 and sum(path.stat().st_size for path in paths) <= 128 * 1024 * 1024,
        "normal-fresh-observation-bound",
    )
    require(
        initial["calls"].keys() == latest["calls"].keys(),
        "normal-fresh-observation-inventory",
    )

    def select(value, fields):
        return {key: value.get(key) for key in fields.split()}

    def project(path, value):
        if re.search(r"/pulls/[0-9]+$", path):
            return {
                "binding": core.binding(value),
                **select(value, "state merged merged_at merge_commit_sha"),
                "repositories": [value[side].get("repo", {}).get("id") for side in ("base", "head")],
            }
        if "/branches/" in path:
            return [value.get("protected"), value.get("commit", {}).get("sha")]
        if "/contents/" in path:
            return select(value, "type path encoding sha size content")
        if "/actions/runs" in path and not path.endswith("/approvals"):
            return {
                **select(
                    value,
                    "id head_sha head_branch event run_attempt workflow_id workflow_url path "
                    "status conclusion created_at run_started_at updated_at",
                ),
                "repositories": [
                    select(value.get(key) or {}, "id full_name") for key in ("repository", "head_repository")
                ],
                "actors": [select(value.get(key) or {}, "id login type") for key in ("actor", "triggering_actor")],
                # bb1 selects and fences generations using this association.
                # Keep presence and wire shape: absent/empty can use an already
                # authenticated merged operation; null/malformed cannot.
                "pull_requests": {"present": "pull_requests" in value, "value": value.get("pull_requests")},
            }
        if "/environments/" in path:
            return {
                **select(value, "name can_admins_bypass"),
                "rules": [
                    {
                        **select(rule, "type prevent_self_review"),
                        "reviewers": [
                            [r.get("type"), r.get("reviewer", {}).get("id")] for r in rule.get("reviewers", [])
                        ],
                    }
                    for rule in value.get("protection_rules", [])
                ],
            }
        if "/releases/tags/" in path:
            return archive.release_state(value)
        if path == f"repos/{repository}":
            return select(value, "id full_name archived disabled")
        # Approval objects and immutable tag objects retain full equality.
        return value

    collections = {}
    for path in initial["calls"]:
        match = re.fullmatch(r"(.+)[?&]per_page=100&page=([1-9][0-9]*)", path)
        if not match:
            require(
                project(path, first.call(path)) == project(path, fresh.call(path)),
                "normal-native-freshness-drift",
            )
            continue
        base = match[1]
        collections[base] = (
            "workflow_runs"
            if "/actions/runs?" in base
            else "jobs"
            if base.endswith("/jobs")
            else "artifacts"
            if base.endswith("/artifacts")
            else None
        )
    for path, key in collections.items():
        observed, current = first.pages(path, key), fresh.pages(path, key)
        if key == "workflow_runs":
            observed = [project(path, run) for run in observed if core.native_required(run, repository)]
            current = [project(path, run) for run in current if core.native_required(run, repository)]
        elif key == "jobs":
            fields = "id run_id head_sha run_attempt name status conclusion started_at completed_at steps"
            observed = [select(job, fields) for job in observed]
            current = [select(job, fields) for job in current]
        elif path.endswith("/releases"):
            observed = [archive.release_state(item) for item in observed]
            current = [archive.release_state(item) for item in current]
        elif "/issues/" in path:
            fields = "id event created_at commit_id"
            observed = [select(event, fields) for event in observed]
            current = [select(event, fields) for event in current]
        elif "/commits/" in path:
            observed = [project(f"repos/{repository}/pulls/{pull['number']}", pull) for pull in observed]
            current = [project(f"repos/{repository}/pulls/{pull['number']}", pull) for pull in current]
        require(observed == current, "normal-native-generation-or-collection-drift")
    return {"fresh": True}


@contextmanager
def native_reads(core, directory, repository, repository_id):
    """Raw native bytes enter the unchanged protected proof only inside EE."""
    api, _unused = native_snapshot(core, directory, repository, repository_id)
    with archive.observation_reads(directory, repository), archive.artifact_reader(core, api):
        yield api


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preparation", "promotion", "baseline", "publish", "freshness"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head")
    parser.add_argument("--workflow-source")
    parser.add_argument("--head-ref")
    parser.add_argument("--check-worktree", action="store_true")
    parser.add_argument("--release")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--control-root", type=Path)
    parser.add_argument("--archive-directory", type=Path)
    parser.add_argument("--observation-directory", type=Path)
    parser.add_argument("--fresh-observation-directory", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "preparation":
            if args.head_ref is not None or args.check_worktree:
                result = preparation_changelog(
                    args.root,
                    args.base,
                    args.head,
                    args.workflow_source,
                    args.repository,
                    args.repository_id,
                    args.head_ref,
                    args.check_worktree,
                )
            else:
                result = preparation(
                    args.root, args.base, args.head, args.workflow_source, args.repository, args.repository_id
                )
        else:
            core = load_control(args.control_root)
            if args.operation == "freshness":
                require(
                    args.observation_directory is not None and args.fresh_observation_directory is not None,
                    "normal-fresh-observations-required",
                )
                result = native_fence(
                    core,
                    args.observation_directory,
                    args.fresh_observation_directory,
                    args.repository,
                    args.repository_id,
                )
            else:
                context = (
                    native_reads(core, args.observation_directory, args.repository, args.repository_id)
                    if args.observation_directory is not None
                    else nullcontext(core.API())
                )
                with context as api:
                    if args.operation == "baseline":
                        result = published_baseline(
                            args.root, api, core, args.repository, args.repository_id, args.base
                        )
                    elif args.operation == "promotion":
                        result = promotion_ready(
                            args.root, api, core, args.repository, args.repository_id, args.base, args.head
                        )
                    elif args.archive_directory is not None:
                        result = publication_archive(
                            args.root,
                            api,
                            core,
                            args.repository,
                            args.repository_id,
                            args.release,
                            args.base,
                            args.head,
                            args.archive_directory,
                        )
                    else:
                        result = publish(
                            args.root,
                            api,
                            core,
                            args.repository,
                            args.repository_id,
                            args.release,
                            args.base,
                            args.head,
                        )
    except (ValueError, git_contract.PromotionError, git_contract.CONTRACT.ContractError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
