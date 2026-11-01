"""Authenticate normal App preparation ingress and its approved Main promotion.

Read-only consumer of the pinned public Required Workflow. No review request,
workflow dispatch, approval, credential mutation or publication is implemented.
"""

# Exact JSON key/type contracts reject bool-as-int and unknown wire shapes.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

import normal_release_archive as archive
import security_main_promotion as git_contract
import security_premerge_proof as policy_contract

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


def control_policy(api, core, repository, repository_id, base):
    """Adapt only the installed schema to bb1's unchanged lineage validator.

    Archive readers still receive the actual native bytes once. The projection
    is private parser input, never a native policy observation or proof. bb1
    cannot authenticate producer-only Security ingress, so that selector remains
    closed here instead of being silently ignored by its older policy reader.
    """
    require(repository_id == policy_contract.C.PRODUCER_REPOSITORY_ID, "protected-policy-repository-id")
    raw = api.file(repository, ".lit/workflow-control.json", base)
    installed = git_contract.CONTRACT.load_json_bytes(raw, "protected workflow-control policy")
    require(policy_contract.policy_schema(installed, repository) == "legacy", "normal-policy-security-profile")
    projected = installed | {"version": 1, "repository": repository}

    class PolicyRead:
        """Only the exact already-observed file may reach this parser input."""

        def file(self, repo, path, revision):
            require(
                (repo, path, revision) == (repository, ".lit/workflow-control.json", base),
                "protected-policy-read-scope",
            )
            return json.dumps(projected).encode()

    config = core.policy(PolicyRead(), repository, base, CONTROL_SOURCE)
    # Retain the real schema and repository label in the policy result; only
    # central source lineage is expanded by the immutable authority above.
    return config | {"version": installed["version"], "repository": installed["repository"]}


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
    config = control_policy(api, core, repository, repository_id, base)
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
    config = control_policy(api, core, repository, repository_id, base)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preparation", "promotion", "baseline", "publish"))
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
            if args.operation == "baseline":
                result = published_baseline(args.root, core.API(), core, args.repository, args.repository_id, args.base)
            elif args.operation == "promotion":
                result = promotion_ready(
                    args.root, core.API(), core, args.repository, args.repository_id, args.base, args.head
                )
            elif args.archive_directory is not None:
                result = publication_archive(
                    args.root,
                    core.API(),
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
                    args.root, core.API(), core, args.repository, args.repository_id, args.release, args.base, args.head
                )
    except (ValueError, git_contract.PromotionError, git_contract.CONTRACT.ContractError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
