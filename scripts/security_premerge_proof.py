"""Emit bounded data for a separately admitted native Security producer.

No admission, review request, API write or approval is implemented here. Source
independently authenticates completed native production and its own registry.
"""

# Exact JSON field types deliberately distinguish booleans from integers.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import security_main_promotion as GIT

C = GIT.CONTRACT
PROFILE = "release-app-security/v1"
MAX_PACKET = 262144
MAX_CONTEXT = 8 * 1024 * 1024
MAX_MATERIAL = 1024 * 1024
PRODUCERS = {
    "intake": (
        "supplementary-security-intake-v1",
        ".github/workflows/security-release-intake.yml",
        "Materialize isolated Security PR and request native auto-merge",
    ),
    "preparation": (
        "supplementary-security-preparation-v1",
        ".github/workflows/release-prepare.yml",
        "Prepare release PR",
    ),
}
APP = [C.RELEASE_APP_LOGIN, int(C.RELEASE_APP_ACCOUNT_ID), "Bot"]
SHA = re.compile(r"[0-9a-f]{40}")


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def parse(raw, label, limit=MAX_MATERIAL):
    require(0 < len(raw) <= limit, f"{label}-size")
    value = json.loads(
        raw, object_pairs_hook=C.reject_duplicate_keys, parse_constant=lambda _unused: C.fail("nonfinite-json")
    )
    require(type(value) is dict, f"{label}-shape")
    return value


def context_file(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_CONTEXT, "native-context-file")
    return parse(path.read_bytes(), "native-context", MAX_CONTEXT)


def blob(root, revision, path):
    require(type(revision) is str and SHA.fullmatch(revision), "material-revision")
    require(
        type(path) is str
        and len(path) <= 512
        and re.fullmatch(r"[A-Za-z0-9_.][A-Za-z0-9_./-]*", path)
        and all(part not in {"", ".", ".."} for part in path.split("/")),
        "unsafe-material-path",
    )
    entries = GIT.git_bytes(root, "ls-tree", "-z", revision, "--", path).split(b"\0")
    require(len(entries) == 2 and entries[-1] == b"", "material-not-unique")
    header, separator, observed = entries[0].partition(b"\t")
    fields = header.split()
    require(
        separator and len(fields) == 3 and fields[:2] == [b"100644", b"blob"] and observed.decode() == path,
        "material-mode-or-path",
    )
    oid = fields[2].decode()
    size = int(GIT.git_text(root, "cat-file", "-s", oid))
    require(0 < size <= MAX_MATERIAL, "material-size")
    raw = GIT.git_bytes(root, "cat-file", "blob", oid)
    require(len(raw) == size, "material-size-drift")
    return raw


def json_blob(root, revision, path, *, document=False):
    raw = blob(root, revision, path)
    value = parse(raw, "material-json")
    if document:
        require(raw == C.canonical_document_bytes(value), "noncanonical-product-receipt")
    return value, raw


def policy_schema(policy, repository):
    """Read the fixed target's installed schema without granting admission."""
    require(
        repository in {C.PRODUCER_REPOSITORY, "ltn-it/ansible-collection-supplementary"}
        and policy.get("repository") in {C.PRODUCER_REPOSITORY, "ltn-it/ansible-collection-supplementary"}
        and type(policy.get("version")) is int
        and policy["version"] in {1, 2},
        "protected-policy-identity",
    )
    if "supplementary_funding_contract" in policy:
        contract = policy["supplementary_funding_contract"]
        require(
            policy["version"] == 2
            and type(contract) is dict
            and type(contract.get("version")) is int
            and contract
            == {
                "version": 2,
                "candidate_scope": "repository-head",
                "legacy_claims": "consumed",
                "unknown_outcomes": "consumed_uncertain",
            },
            "supplementary-funding-contract-shape",
        )
    if "security_profile" not in policy:
        return "legacy"
    require(
        type(policy["security_profile"]) is str and policy["security_profile"] == PROFILE,
        "unknown-security-profile-selector",
    )
    # This selector only removes legacy funding. It grants no Common admission;
    # the independent Source registry may still reject this producer entirely.
    return "producer-only"


def route(root, source):
    policy, _unused = json_blob(root, source, ".lit/workflow-control.json")
    return policy_schema(policy, C.PRODUCER_REPOSITORY)


def locator(kind, run, attempt):
    require(
        kind in PRODUCERS and type(run) is int and run > 0 and type(attempt) is int and attempt > 0,
        "producer-locator-shape",
    )
    return (
        "<!-- lit-security-premerge/v1 "
        + canonical({"producer": PRODUCERS[kind][0], "run": run, "attempt": attempt}).decode()
        + " -->"
    )


def native_context(kind, source, run, jobs, env):
    producer, workflow, name = PRODUCERS[kind]
    require(
        env.get("GITHUB_REPOSITORY") == C.PRODUCER_REPOSITORY
        and env.get("GITHUB_REPOSITORY_ID") == C.PRODUCER_REPOSITORY_ID
        and env.get("GITHUB_SHA") == source
        and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("GITHUB_WORKFLOW_REF") == f"{C.PRODUCER_REPOSITORY}/{workflow}@refs/heads/main"
        and env.get("GITHUB_ACTOR") == C.RELEASE_APP_LOGIN
        and env.get("GITHUB_TRIGGERING_ACTOR") == C.RELEASE_APP_LOGIN
        and env.get("GITHUB_JOB") == {"intake": "materialize", "preparation": "prepare"}[kind],
        "bad-producer-context",
    )
    event = "workflow_dispatch" if kind == "intake" else "push"
    require(env.get("GITHUB_EVENT_NAME") == event, "bad-producer-event")
    identifier, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    require(
        re.fullmatch(r"[1-9][0-9]*", identifier) and re.fullmatch(r"[1-9][0-9]*", attempt), "bad-producer-run-context"
    )
    require(
        type(run.get("workflow_id")) is int
        and run["workflow_id"] > 0
        and type(run.get("id")) is int
        and run["id"] == int(identifier)
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] == int(attempt)
        and run.get("repository", {}).get("full_name") == C.PRODUCER_REPOSITORY
        and run.get("repository", {}).get("id") == int(C.PRODUCER_REPOSITORY_ID)
        and run.get("head_repository", {}).get("full_name") == C.PRODUCER_REPOSITORY
        and run.get("head_repository", {}).get("id") == int(C.PRODUCER_REPOSITORY_ID)
        and run.get("head_sha") == source
        and run.get("head_branch") == "main"
        and run.get("path") == workflow
        and run.get("event") == event
        and [run.get("actor", {}).get(k) for k in ("login", "id", "type")] == APP
        and [run.get("triggering_actor", {}).get(k) for k in ("login", "id", "type")] == APP
        and run.get("status") == "in_progress"
        and run.get("conclusion") is None,
        "native-producer-run-drift",
    )
    items = jobs.get("jobs")
    require(
        type(items) is list
        and type(jobs.get("total_count")) is int
        and jobs["total_count"] == len(items)
        and 0 < len(items) <= 100,
        "native-jobs-incomplete",
    )
    ids = [item.get("id") for item in items]
    require(
        all(type(value) is int and value > 0 for value in ids) and len(ids) == len(set(ids)), "duplicate-native-job"
    )
    selected = [item for item in items if item.get("name") == name]
    require(len(selected) == 1, "native-producer-job-not-unique")
    job = selected[0]
    require(
        type(job.get("run_id")) is int
        and type(job.get("run_attempt")) is int
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == run["run_attempt"]
        and job.get("status") == "in_progress"
        and job.get("conclusion") is None,
        "native-producer-job-drift",
    )
    return {"id": producer, "run": run["id"], "attempt": run["run_attempt"], "job": job["id"], "source_sha": source}


def emit(root, kind, source, pull, run, jobs, env, *, checked_at=None):
    require(kind in PRODUCERS and SHA.fullmatch(source), "producer-kind-or-source")
    producer = native_context(kind, source, run, jobs, env)
    require(
        pull.get("state") == "open"
        and pull.get("draft") is True
        and "auto_merge" in pull
        and pull["auto_merge"] is None
        and type(pull.get("number")) is int
        and pull["number"] > 0,
        "fresh-draft-producer-pull-required",
    )
    base, head = pull.get("base", {}), pull.get("head", {})
    require(
        base.get("ref") == "main"
        and base.get("sha") == source
        and base.get("repo", {}).get("full_name") == C.PRODUCER_REPOSITORY
        and head.get("repo", {}).get("full_name") == C.PRODUCER_REPOSITORY
        and SHA.fullmatch(head.get("sha", ""))
        and [pull.get("user", {}).get(k) for k in ("login", "id", "type")] == APP,
        "security-pull-binding",
    )
    expected_locator = locator(kind, producer["run"], producer["attempt"])
    body = pull.get("body")
    require(
        type(body) is str and body.count("lit-security-premerge/v1") == 1 and body.count(expected_locator) == 1,
        "security-locator-not-unique",
    )
    head_sha = head["sha"]
    require(GIT.git_text(root, "show", "-s", "--format=%P", head_sha).split() == [source], "security-head-parent")
    merge_tree = GIT.git_text(root, "merge-tree", "--write-tree", source, head_sha)
    require(
        SHA.fullmatch(merge_tree) and merge_tree == GIT.git_text(root, "rev-parse", f"{head_sha}^{{tree}}"),
        "integration-tree-drift",
    )
    full_diff = GIT.git_bytes(
        root,
        "diff",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        f"{source}^{{tree}}",
        merge_tree,
    )
    require(full_diff, "empty-security-diff")
    now = checked_at or datetime.now(UTC)
    if kind == "intake":
        require(
            re.fullmatch(r"security-release/MLX90-[A-Z0-9][A-Z0-9._-]{2,127}", head.get("ref", "")), "intake-head-ref"
        )
        receipt_paths = [
            path
            for status, path in GIT.changed_paths(root, source, head_sha)
            if re.fullmatch(r"\.lit/security-release-intakes/[0-9]+\.[0-9]+\.[0-9]+\.json", path) and status == "A"
        ]
        require(len(receipt_paths) == 1, "intake-receipt-count")
        receipt_path = receipt_paths[0]
        intake, _unused = json_blob(root, head_sha, receipt_path, document=True)
        preparation = None
    else:
        receipt_path = "changelogs/release-preparation.json"
        preparation, _unused = json_blob(root, head_sha, receipt_path, document=True)
        require(
            preparation.get("schema_version") == 2
            and preparation.get("release_mode") == "security"
            and preparation.get("base_sha") == source,
            "security-preparation-receipt",
        )
        intake_path = f".lit/security-release-intakes/{preparation.get('next_version')}.json"
        intake, _unused = json_blob(root, source, intake_path, document=True)
    C.verify_intake_receipt(intake, checked_at=now)
    request, verified = intake["request"], intake["verified"]
    require(not C.is_recovery_request(request), "historical-recovery-not-admitted")
    version = request["fixedVersion"]
    if kind == "intake":
        controller = intake["controller"]
        require(
            controller["runId"] == str(producer["run"])
            and controller["runAttempt"] == str(producer["attempt"])
            and controller["sourceSha"] == source,
            "intake-native-controller-drift",
        )
    else:
        workflow = preparation.get("workflow", {})
        require(
            workflow.get("run_id") == str(producer["run"])
            and workflow.get("run_attempt") == str(producer["attempt"])
            and workflow.get("source_sha") == source,
            "preparation-native-controller-drift",
        )
    GIT.require_app_commit(
        root,
        source,
        head_sha,
        f"fix(security): {request['evidenceId']}" if kind == "intake" else f"chore(release): prepare v{version}",
    )
    require(
        head["ref"] == (f"security-release/{request['evidenceId']}" if kind == "intake" else f"release/v{version}"),
        "security-target-ref",
    )
    metadata_path = f".lit/security-releases/{version}.json"
    metadata, metadata_raw = json_blob(root, head_sha, metadata_path)
    C.validate_metadata_payload(
        metadata,
        expected_evidence_id=request["evidenceId"],
        expected_version=version,
        expected_profile=request["acceptanceProfile"],
        checked_at=now,
    )
    C.validate_request_metadata_binding(request, metadata)
    require(
        C.sha256_bytes(metadata_raw) == request["metadataSha256"] == verified["metadataSha256"], "metadata-digest-drift"
    )
    profiles, _unused = json_blob(root, source, ".lit/security-release-profiles.json")
    C.validate_profile_registry(profiles, request["acceptanceProfile"])
    materials = []
    seen = set()

    def material(role, at, path):
        require(path not in seen, "duplicate-material-path")
        seen.add(path)
        raw = blob(root, source if at == "base" else head_sha, path)
        materials.append({"role": role, "at": at, "path": path, "sha256": hashlib.sha256(raw).hexdigest()})
        return raw

    material("receipt", "head", receipt_path)
    material("metadata", "head", metadata_path)
    if kind == "intake":
        require(request["baseSha"] == source and intake["controller"]["sourceSha"] == source, "intake-source-drift")
        diff = GIT.candidate_diff_without_receipt(root, source, head_sha, receipt_path)
        require(C.sha256_bytes(diff) == request["candidateDiffSha256"], "intake-candidate-digest-drift")
        require(
            sorted(path for _unused, path in GIT.changed_paths(root, source, head_sha) if path != receipt_path)
            == verified["changedPaths"],
            "intake-material-paths-drift",
        )
        fragment = material("fragment", "head", verified["changelogFragmentPath"])
        require(C.sha256_bytes(fragment) == verified["changelogFragmentSha256"], "fragment-digest-drift")
        C.validate_security_fragment(fragment, "producer fragment")
    else:
        require(blob(root, source, metadata_path) == metadata_raw, "preparation-metadata-changed")
        material("intake", "base", intake_path)
        require(
            preparation.get("chain_id") == request["chainId"]
            and preparation.get("security", {}).get("evidence_id") == request["evidenceId"],
            "preparation-chain-drift",
        )
        fragments = preparation.get("fragments")
        require(type(fragments) is list and 0 < len(fragments) <= 256, "preparation-fragments")
        expected = set(GIT.RELEASE_GENERATED_PATHS)
        for entry in fragments:
            require(type(entry) is dict and set(entry) == {"path", "sha256"}, "preparation-fragment-shape")
            path = f"changelogs/fragments/{entry['path']}"
            raw = material("fragment", "base", path)
            require(hashlib.sha256(raw).hexdigest() == entry["sha256"], "fragment-digest-drift")
            expected.add(path)
        changes = dict((path, status) for status, path in GIT.changed_paths(root, source, head_sha))
        require(
            set(changes) <= expected and {receipt_path, "galaxy.yml"} <= changes.keys(),
            "non-generated-preparation-path",
        )
        require(
            all(changes.get(item["path"]) == "D" for item in materials if item["role"] == "fragment"),
            "preparation-fragment-not-deleted",
        )
        # Reuse only the immutable protected producer's parser, with data-only
        # Git materialized inputs; no candidate Python is imported or executed.
        module = GIT.load_release_version_module(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory(prefix="security-premerge-base-") as temporary:
            base_root = Path(temporary)
            paths = {"galaxy.yml", ".lit/security-release-profiles.json", metadata_path, intake_path}
            paths |= {item["path"] for item in materials if item["at"] == "base"}
            for path in paths:
                target = base_root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(blob(root, source, path))
            module.verify_preparation_receipt(
                preparation,
                expected_repository=C.PRODUCER_REPOSITORY,
                expected_repository_id=C.PRODUCER_REPOSITORY_ID,
                expected_base_sha=source,
                expected_version=version,
                root=base_root,
                checked_at=now,
            )
            resolution = module.resolve_version(
                base_root / "galaxy.yml",
                base_root / "changelogs/fragments",
                security_target=version,
                root=base_root,
                checked_at=now,
            )
            require(
                preparation["fragments"] == resolution["fragment_sha256"]
                and preparation["current_version"] == resolution["current_version"]
                and preparation["impact"] == resolution["impact"],
                "preparation-version-or-fragments-drift",
            )
    packet = {
        "version": 1,
        "profile": PROFILE,
        "kind": kind,
        "repository": C.PRODUCER_REPOSITORY,
        "repository_id": int(C.PRODUCER_REPOSITORY_ID),
        "binding": {
            "number": pull["number"],
            "base": source,
            "head": head_sha,
            "base_ref": "main",
            "head_ref": head["ref"],
            "head_repository": C.PRODUCER_REPOSITORY,
            "author": APP,
        },
        "integration_tree": merge_tree,
        "diff_sha256": hashlib.sha256(full_diff).hexdigest(),
        "chain_id": request["chainId"],
        "evidence_id": request["evidenceId"],
        "fixed_version": version,
        "acceptance_profile": request["acceptanceProfile"],
        "issued_at": request["issuedAt"],
        "expires_at": request["expiresAt"],
        "revoked": metadata["validity"]["revoked"],
        "producer": producer,
        "materials": sorted(materials, key=lambda item: (item["role"], item["path"])),
    }
    require(len(canonical(packet)) <= MAX_PACKET, "security-packet-size")
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("route", "locator", "emit"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--source")
    parser.add_argument("--kind", choices=tuple(PRODUCERS))
    parser.add_argument("--pull", type=Path)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--jobs", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "route":
            print(route(args.root, args.source))
        elif args.operation == "locator":
            print(locator(args.kind, int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])))
        else:
            value = emit(
                args.root,
                args.kind,
                args.source,
                context_file(args.pull),
                context_file(args.run),
                context_file(args.jobs),
                os.environ,
            )
            require(not args.output.exists() and not args.output.is_symlink(), "packet-output-exists")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(canonical(value))
    except (ValueError, C.ContractError, GIT.PromotionError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
