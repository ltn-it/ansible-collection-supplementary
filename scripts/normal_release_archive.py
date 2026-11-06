"""Cryptographically bound replay of publication-time native observations.

This module never creates an approval or retries a mutation. Archived API
observations are historical evidence, not simulated fresh native runs.
"""

# Wire identities must reject bool-as-int.
# pylint: disable=unidiomatic-typecheck
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path

SNAPSHOT = "normal-release-native-evidence.json"
BUNDLE = "normal-release-native-evidence.sigstore.json"
MAX_BYTES = 50 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
COMPLETION = "post-release-verification.json"
COMPLETION_BUNDLE = COMPLETION + ".sigstore.json"
MAX_COMPLETION_BYTES = 1024 * 1024
# Existing release-stage-handoff.py bound, shared by all assembled assets.
MAX_ASSET_BYTES = 2_000_000_000
MAX_READS = 4096
WORKFLOW = ".github/workflows/collection-publish.yml"
_OBSERVATIONS = None


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode() + b"\n"


def release_state(published):
    """Keep every release/asset field except mutable per-asset download counts."""
    require(isinstance(published, dict), "archive-release-response")
    result = copy.deepcopy(published)
    if "assets" in result:
        require(isinstance(result["assets"], list), "archive-release-assets")
        for asset in result["assets"]:
            require(isinstance(asset, dict), "archive-release-asset")
            asset.pop("download_count", None)
    return result


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "archive-duplicate-json-key")
        result[key] = value
    return result


def bounded_file(path, maximum):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= maximum, "archive-file-bound")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(0 < len(raw) <= maximum, "archive-file-bound")
    return raw


def decode(raw):
    require(0 < len(raw) <= MAX_BYTES, "archive-size-bound")
    # Bound nesting and structural nodes before allocating decoded JSON.
    quoted = escaped = False
    depth = nodes = 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            nodes += 1
        elif byte in (93, 125):
            depth -= 1
        elif byte in (44, 58):
            nodes += 1
        require(0 <= depth <= 64 and nodes <= 500000, "archive-json-resource-bound")
    value = json.loads(raw, object_pairs_hook=unique)
    require(canonical(value) == raw, "archive-noncanonical-json")
    return value


def binding(repository, repository_id, release, base, head, source):
    require(re.fullmatch(r"lightning-it/[A-Za-z0-9_.-]+", repository), "archive-repository")
    require(type(repository_id) is str and re.fullmatch(r"[1-9][0-9]*", repository_id), "archive-repository-id")
    require(
        all(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) for value in (release, base, head, source)),
        "archive-revision",
    )
    return {
        "repository": repository,
        "repository_id": repository_id,
        "release": release,
        "base": base,
        "head": head,
        "control_source": source,
    }


def artifact_identity(repository, run, name, filename):
    require(
        type(run.get("id")) is int
        and run["id"] > 0
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] > 0
        and re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", "")),
        "archive-artifact-origin",
    )
    if filename == "preparation-inputs.json":
        # The original caller still authenticates the protected producer and
        # requires exact input_record(receipt, prepared) equality on replay.
        require(name == f"normal-release-preparation-{run['run_attempt']}", "archive-preparation-artifact-attempt")
    else:
        require(
            filename in {"control-proof.json", "control-operation.json"}
            and re.fullmatch(r"control-(?:proof|operation)-[1-9][0-9]*", name),
            "archive-artifact-name",
        )
        require(
            name.startswith("control-operation-") == (filename == "control-operation.json"), "archive-artifact-kind"
        )
    return [repository, run["id"], run["run_attempt"], run["head_sha"], name, filename]


def artifact_metadata(value, name):
    require(
        type(value) is dict
        and type(value.get("id")) is int
        and value["id"] > 0
        and value.get("name") == name
        and value.get("expired") is False
        and type(value.get("size_in_bytes")) is int
        and 0 < value["size_in_bytes"] <= MAX_BYTES,
        "archive-artifact-metadata",
    )
    require(
        value.get("digest") is None
        or (type(value["digest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])),
        "archive-artifact-digest",
    )


class ArtifactReads:
    """Pause outer capture only for the original authenticated artifact reader."""

    def __init__(self, api, repository, run):
        self.api = api
        self.path = f"repos/{repository}/actions/runs/{run['id']}/artifacts"
        self.inventory = None

    def pages(self, path, key=None):
        require(path == self.path and key == "artifacts" and self.inventory is None, "archive-artifact-read-scope")
        self.inventory = copy.deepcopy(self.api.pages(path, key))
        return copy.deepcopy(self.inventory)


class Record:
    """Record only completed read responses used by the unchanged verifier."""

    def __init__(self, api, expected):
        self.api = api
        self.expected = expected
        self.reads = []
        self.size = 0

    def add(self, kind, args, value):
        entry = {"kind": kind, "args": args, "value": value}
        self.size += len(canonical(entry))
        require(len(self.reads) < MAX_READS and self.size <= MAX_BYTES, "archive-observation-bound")
        self.reads.append(copy.deepcopy(entry))
        return value

    def path(self, path):
        require(type(path) is str and path.startswith(f"repos/{self.expected['repository']}/"), "archive-read-scope")

    def call(self, path, *, method="GET", data=None):
        self.path(path)
        require(method == "GET" and data is None, "archive-read-only")
        return self.add("call", [path], self.api.call(path))

    def pages(self, path, key=None):
        self.path(path)
        return self.add("pages", [path, key], self.api.pages(path, key))

    def file(self, repository, path, revision):
        require(repository == self.expected["repository"], "archive-read-scope")
        raw = self.api.file(repository, path, revision)
        self.add("file", [repository, path, revision], base64.b64encode(raw).decode("ascii"))
        return raw

    def native_job_log(self, repository, job):
        require(repository == self.expected["repository"], "archive-read-scope")
        return self.add("native_job_log", [repository, job], self.api.native_job_log(repository, job))

    def artifact(self, original, _api, repository, run, name, filename):
        require(repository == self.expected["repository"], "archive-read-scope")
        args = artifact_identity(repository, run, name, filename)
        reader = ArtifactReads(self.api, repository, run)
        value = original(reader, repository, run, name, filename)
        require(type(reader.inventory) is list, "archive-artifact-inventory-missing")
        selected = [item for item in reader.inventory if item.get("name") == name and item.get("expired") is False]
        require(len(selected) == 1, "archive-artifact-selection")
        artifact_metadata(selected[0], name)
        self.add("artifact", args, {"metadata": selected[0], "record": value})
        return value

    def finish(self, result):
        value = {
            "version": 1,
            "kind": "normal-release-native-observations",
            "binding": self.expected,
            "reads": self.reads,
            "result": result,
        }
        raw = canonical(value)
        require(len(raw) <= MAX_BYTES, "archive-size-bound")
        return raw


class Replay:
    """No live API or artifact downloader is reachable through this adapter."""

    def __init__(self, value, expected, current_main):
        require(
            type(value) is dict
            and set(value) == {"version", "kind", "binding", "reads", "result"}
            and type(value["version"]) is int
            and value["version"] == 1
            and value["kind"] == "normal-release-native-observations"
            and value["binding"] == expected,
            "archive-binding",
        )
        require(type(value["reads"]) is list and 0 < len(value["reads"]) <= MAX_READS, "archive-observation-bound")
        self.value = value
        self.expected = expected
        self.current_main = current_main
        self.index = 0

    def take(self, kind, args):
        require(self.index < len(self.value["reads"]), "archive-missing-observation")
        entry = self.value["reads"][self.index]
        require(
            type(entry) is dict
            and set(entry) == {"kind", "args", "value"}
            and entry["kind"] == kind
            and entry["args"] == args,
            "archive-observation-order-or-binding",
        )
        self.index += 1
        return copy.deepcopy(entry["value"])

    def call(self, path, *, method="GET", data=None):
        require(method == "GET" and data is None, "archive-read-only")
        value = self.take("call", [path])
        if path == f"repos/{self.expected['repository']}/git/ref/heads/main":
            require(value.get("object", {}).get("sha") == self.expected["release"], "archive-original-main-drift")
            # Only this tip is a separately authenticated current observation.
            value["object"]["sha"] = self.current_main
        return value

    def pages(self, path, key=None):
        return self.take("pages", [path, key])

    def file(self, repository, path, revision):
        return base64.b64decode(self.take("file", [repository, path, revision]), validate=True)

    def native_job_log(self, repository, job):
        return self.take("native_job_log", [repository, job])

    def artifact(self, _original, _api, repository, run, name, filename):
        value = self.take("artifact", artifact_identity(repository, run, name, filename))
        require(type(value) is dict and set(value) == {"metadata", "record"}, "archive-artifact-record")
        artifact_metadata(value["metadata"], name)
        return value["record"]

    def finish(self, result):
        require(self.index == len(self.value["reads"]) and result == self.value["result"], "archive-incomplete-replay")


@contextmanager
def artifact_reader(core, adapter):
    original = core.artifact_record
    core.artifact_record = lambda api, repo, run, name, filename: adapter.artifact(
        original, api, repo, run, name, filename
    )
    try:
        yield
    finally:
        core.artifact_record = original


def verified_document(snapshot, bundle, repository, release, maximum):
    """Authenticate local bytes before interpreting either fixed document protocol."""
    raw = bounded_file(snapshot, maximum)
    bundle_raw = bounded_file(bundle, MAX_BUNDLE_BYTES)
    executable = shutil.which("gh")
    require(executable, "archive-verifier-unavailable")
    result = subprocess.run(  # noqa: S603, RUF100 -- fixed attestation verifier; no shell.
        [
            executable,
            "attestation",
            "verify",
            str(snapshot),
            "--bundle",
            str(bundle),
            "--repo",
            repository,
            "--cert-identity",
            f"https://github.com/{repository}/{WORKFLOW}@refs/heads/main",
            "--source-ref",
            "refs/heads/main",
            "--source-digest",
            release,
        ],
        capture_output=True,
        timeout=120,
        check=False,
    )
    require(result.returncode == 0, "archive-attestation-verification-failed")
    require(
        bounded_file(snapshot, maximum) == raw and bounded_file(bundle, MAX_BUNDLE_BYTES) == bundle_raw,
        "archive-file-drift",
    )
    return decode(raw)


def verify_files(snapshot, bundle, repository, repository_id, release):
    value = verified_document(snapshot, bundle, repository, release, MAX_BYTES)
    require(
        type(value) is dict
        and type(value.get("binding")) is dict
        and value["binding"].get("repository") == repository
        and value["binding"].get("repository_id") == repository_id
        and value["binding"].get("release") == release,
        "archive-binding",
    )
    return value


def download_assets(published, repository, directory, limits):
    """Download only caller-bound names and sizes from actual positive asset IDs."""
    if _OBSERVATIONS is not None:
        _OBSERVATIONS.assets(published, repository, directory, limits)
        return
    require(
        type(published.get("assets")) is list and all(type(asset) is dict for asset in published["assets"]),
        "archive-release-assets-missing",
    )
    executable = shutil.which("gh")
    require(executable, "archive-downloader-unavailable")
    selected = []
    for name, maximum in limits:
        matches = [asset for asset in published["assets"] if asset.get("name") == name]
        require(len(matches) == 1, "archive-release-asset-missing-or-ambiguous")
        asset = matches[0]
        require(
            type(asset.get("id")) is int
            and asset["id"] > 0
            and asset.get("state") == "uploaded"
            and type(asset.get("size")) is int
            and 0 < asset["size"] <= maximum,
            "archive-release-asset-bound",
        )
        selected.append((name, maximum, asset))
    require(len({asset["id"] for _name, _maximum, asset in selected}) == len(limits), "archive-release-asset-identity")
    for name, maximum, asset in selected:
        with subprocess.Popen(  # noqa: S603, RUF100 -- exact repository asset ID, bounded read, no shell.
            [
                executable,
                "api",
                "--allow-escape-sequences",
                "--header",
                "Accept: application/octet-stream",
                f"repos/{repository}/releases/assets/{asset['id']}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as process:
            deadline = time.monotonic() + 60
            raw = bytearray()
            digest = hashlib.sha256()
            size = 0
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        require(remaining > 0 and selector.select(remaining), "archive-download-timeout")
                        chunk = os.read(process.stdout.fileno(), min(65536, maximum + 1 - size))
                        if not chunk:
                            break
                        size += len(chunk)
                        digest.update(chunk)
                        if directory is not None:
                            raw.extend(chunk)
                        require(size <= maximum, "archive-release-download-bound")
                status = process.wait(timeout=max(0.1, deadline - time.monotonic()))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        require(status == 0 and size == asset["size"] and size <= maximum, "archive-release-download")
        if directory is not None:
            (directory / name).write_bytes(raw)
        else:
            require(asset.get("expected_sha256") == digest.hexdigest(), "completion-asset-bytes")


def download_pair(published, repository, directory):
    download_assets(published, repository, directory, ((SNAPSHOT, MAX_BYTES), (BUNDLE, MAX_BUNDLE_BYTES)))


# Fixed observed identities; presence grants no target admission or publication authority.
GENERIC_PROFILES = {
    "lightning-it/ansible-collection-ubuntu": ("1268102957", "ubuntu"),
    "lightning-it/ansible-collection-rhel": ("1103411913", "rhel"),
    "lightning-it/ansible-collection-foundational": ("1103405635", "foundational"),
    "lightning-it/ansible-collection-cloud": ("1318852819", "cloud"),
    "lightning-it/ansible-collection-ocp": ("1103410706", "ocp"),
}
GENERIC_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
)


def completion_context(repository, repository_id, release, version, galaxy_required):
    """Bind only implemented fixed profiles; never select gates/assets from a receipt."""
    supplementary = repository == "lightning-it/ansible-collection-supplementary" and repository_id == "1103407173"
    generic = repository in GENERIC_PROFILES and GENERIC_PROFILES[repository][0] == repository_id
    require(supplementary or generic, "completion-profile")
    require(
        type(release) is str and re.fullmatch(r"[0-9a-f]{40}", release),
        "completion-release",
    )
    require(
        type(version) is str
        and (
            re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version)
            if supplementary
            else GENERIC_SEMVER.fullmatch(version)
        ),
        "completion-version",
    )
    require(type(galaxy_required) is bool, "completion-publication-policy")
    context = {
        "repository": repository,
        "repository_id": repository_id,
        "release": release,
        "version": version,
        "tag": "v" + version,
        "galaxy_required": galaxy_required,
        "profile": "supplementary-normal/v1" if supplementary else "generic-normal/v1",
    }
    if generic:
        # No completion/GitHub archive is created when this requested option is false.
        context["github_release"] = True
    return context


def completion_assets(context):
    """Full actual CI release-assets plus publisher assembly, never a receipt-selected subset."""
    if context["profile"] == "generic-normal/v1":
        require(context["repository"] in GENERIC_PROFILES, "completion-profile")
        name = GENERIC_PROFILES[context["repository"]][1]
        return {
            f"lit-{name}-{context['version']}.tar.gz",
            "SHA256SUMS",
            "release-evidence.json",
            "release-evidence.md",
            SNAPSHOT,
            BUNDLE,
        }
    require(context["profile"] == "supplementary-normal/v1", "completion-profile")
    release = context["release"]
    candidate = f"lit-supplementary-{context['version']}.tar.gz"
    evidence = f"collection-evidence-{release}.tar.gz"
    long_term = f"collection-release-evidence-{release}.tar.gz"
    names = {
        candidate,
        evidence,
        long_term,
        long_term + ".sha256",
        "evidence-manifest.json",
        "sbom.cdx.json",
        "provenance.json",
        "role-coverage.yml",
        "matrix-results.json",
        "candidate.github-attestation.json",
        "sbom.github-attestation.json",
        "evidence.github-attestation.json",
        "attestation-records.json",
        "vulnerability-report.json",
        "trivy-vulnerability-report.json",
        "secret-scan-summary.json",
        "release-evidence.json",
        "release-evidence.md",
        "ci-release-assets-SHA256SUMS",
        "ci-release-assets-SHA256SUMS.sigstore.json",
        "ci-candidate-SHA256SUMS",
        "checksums.github-attestation.json",
        "checksums-attestation-record.json",
        "release-security-receipt.json",
        "release-security-receipt.github-attestation.json",
        "release-security-receipt-attestation.json",
        "SHA256SUMS",
        "SHA256SUMS.sigstore.json",
        SNAPSHOT,
        BUNDLE,
    }
    names.update(
        name + ".sigstore.json" for name in (candidate, evidence, "sbom.cdx.json", "release-security-receipt.json")
    )
    names.update(
        name + ".attestation.jsonl"
        for name in (candidate, evidence, "sbom.cdx.json", "SHA256SUMS", "release-security-receipt.json")
    )
    return names


def completion_gates(context):
    if context["profile"] == "generic-normal/v1":
        return {"github_release_assets_verified": True, "galaxy_artifact_verified_or_not_required": True}
    require(context["profile"] == "supplementary-normal/v1", "completion-profile")
    return {
        name: True
        for name in (
            "github_release_assets_verified",
            "github_release_install_smoke",
            "galaxy_artifact_verified_or_not_required",
            "galaxy_install_smoke_or_not_required",
        )
    }


def asset_inventory(published, names):
    assets = published.get("assets")
    require(type(assets) is list and all(type(item) is dict for item in assets), "completion-asset-inventory")
    require(len(assets) == len(names) and {item.get("name") for item in assets} == names, "completion-mandatory-assets")
    require(
        all(
            type(item.get("id")) is int
            and item["id"] > 0
            and item.get("state") == "uploaded"
            and type(item.get("size")) is int
            and 0 < item["size"] <= MAX_ASSET_BYTES
            for item in assets
        ),
        "completion-asset-metadata",
    )
    require(len({item["id"] for item in assets}) == len(assets), "completion-asset-identity")
    require(sum(item["size"] for item in assets) <= MAX_ASSET_BYTES, "completion-total-size")
    return {item["name"]: item for item in assets}


def release_identity(published, context):
    prerelease = context["profile"] == "generic-normal/v1" and "-" in context["version"]
    require(
        type(published.get("id")) is int
        and published["id"] > 0
        and published.get("tag_name") == context["tag"]
        and published.get("draft") is False
        and published.get("prerelease") is prerelease
        and published.get("published_at"),
        "completion-release-state",
    )
    return {"id": published["id"], "tag": context["tag"], "sha": context["release"], "prerelease": prerelease}


def local_manifest(directory, names):
    require({item.name for item in directory.iterdir()} == names, "completion-local-assets")
    result = []
    total = 0
    for name in sorted(names):
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "completion-local-file")
        before = path.stat()
        require(0 < before.st_size <= MAX_ASSET_BYTES, "completion-local-size")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(chunk)
                require(size <= before.st_size, "completion-local-drift")
                digest.update(chunk)
        after = path.stat()
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, size, after.st_mtime_ns, after.st_ctime_ns),
            "completion-local-drift",
        )
        total += size
        require(total <= MAX_ASSET_BYTES, "completion-total-size")
        result.append({"name": name, "size": size, "sha256": digest.hexdigest()})
    return result


def verify_manifest(published, context, manifest, completed):
    names = completion_assets(context)
    require(type(manifest) is list and len(manifest) == len(names), "completion-manifest")
    require(
        all(
            type(row) is dict
            and set(row) == {"name", "size", "sha256"}
            and type(row["name"]) is str
            and row["name"] in names
            and type(row["size"]) is int
            and 0 < row["size"] <= MAX_ASSET_BYTES
            and type(row["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
            for row in manifest
        ),
        "completion-manifest-row",
    )
    require([row["name"] for row in manifest] == sorted(names), "completion-manifest-names")
    assets = asset_inventory(published, names | ({COMPLETION, COMPLETION_BUNDLE} if completed else set()))
    for row in manifest:
        asset = assets[row["name"]]
        require(asset["size"] == row["size"], "completion-asset-size")
        if asset.get("digest") is not None:
            require(asset["digest"] == "sha256:" + row["sha256"], "completion-asset-digest")
        else:
            # Older GitHub asset metadata may lack a hash; stream actual bounded bytes.
            download_assets(
                {"assets": [asset | {"expected_sha256": row["sha256"]}]},
                context["repository"],
                None,
                ((row["name"], row["size"]),),
            )


def completion_document(published, context, manifest):
    return {
        "schema_version": 3,
        "kind": "normal-publication-completion",
        "binding": context,
        "release": release_identity(published, context),
        "assets": manifest,
        "gates": completion_gates(context),
    }


def verify_completion_files(directory, published, context):
    value = verified_document(
        directory / COMPLETION,
        directory / COMPLETION_BUNDLE,
        context["repository"],
        context["release"],
        MAX_COMPLETION_BYTES,
    )
    require(
        type(value) is dict and set(value) == {"schema_version", "kind", "binding", "release", "assets", "gates"},
        "completion-document",
    )
    require(
        type(value.get("schema_version")) is int
        and canonical(value) == canonical(completion_document(published, context, value["assets"])),
        "completion-binding-or-gates",
    )
    verify_manifest(published, context, value["assets"], True)
    return value


def verify_completion(published, context, directory):
    asset_inventory(published, completion_assets(context) | {COMPLETION, COMPLETION_BUNDLE})
    download_assets(
        published,
        context["repository"],
        directory,
        ((COMPLETION, MAX_COMPLETION_BYTES), (COMPLETION_BUNDLE, MAX_BUNDLE_BYTES)),
    )
    return verify_completion_files(directory, published, context)


def read_release(context):
    if _OBSERVATIONS is not None:
        return _OBSERVATIONS.release(context)
    executable = shutil.which("gh")
    require(executable, "archive-downloader-unavailable")
    result = subprocess.run(  # noqa: S603, RUF100 -- fixed read-only GitHub endpoint; portable across target Ruff profiles.
        [executable, "api", f"repos/{context['repository']}/releases/tags/{context['tag']}"],
        check=True,
        capture_output=True,
        timeout=60,
    )
    require(len(result.stdout) <= MAX_COMPLETION_BYTES, "completion-release-response-size")
    return json.loads(result.stdout, object_pairs_hook=unique)


@contextmanager
def observation_reads(directory, repository):
    """Read fixed native Release/asset responses offline, with no transport fallback.

    These bytes are untrusted observations. All existing release identity,
    manifest, replay and cryptographic checks still run in their original order.
    """
    global _OBSERVATIONS  # pylint: disable=global-statement
    require(repository == "lightning-it/ansible-collection-supplementary", "observation-repository")
    index = json.loads(bounded_file(directory / "index.json", MAX_COMPLETION_BYTES), object_pairs_hook=unique)
    require(
        type(index) is dict
        and set(index) == {"version", "repository", "calls", "logs", "artifacts", "assets"}
        and type(index["version"]) is int
        and index["version"] == 1
        and index["repository"] == repository,
        "observation-index-binding",
    )
    names = set()
    for kind, pattern in (
        ("calls", r"read-[0-9]+\.json"),
        ("logs", r"log-[0-9]+\.txt"),
        ("artifacts", r"artifact-[0-9]+\.zip"),
        ("assets", r"asset-[0-9]+\.bin"),
    ):
        require(type(index[kind]) is dict, "observation-index-shape")
        for key, name in index[kind].items():
            require(
                type(name) is str and re.fullmatch(pattern, name) and name not in names, "observation-file-identity"
            )
            require(
                type(key) is str
                and (
                    (key == f"repos/{repository}" or key.startswith(f"repos/{repository}/"))
                    if kind == "calls"
                    else re.fullmatch(r"[1-9][0-9]*", key)
                ),
                "observation-read-scope",
            )
            names.add(name)
    require(
        0 < len(names) <= MAX_READS
        and {p.name for p in directory.iterdir()} == names | {"index.json"}
        and all((directory / name).is_file() and not (directory / name).is_symlink() for name in names),
        "observation-file-inventory",
    )
    require(
        sum((directory / name).stat().st_size for name in names if name.startswith("asset-")) <= 16_000_000_000,
        "observation-asset-aggregate",
    )
    require(
        sum((directory / name).stat().st_size for name in names if not name.startswith("asset-")) <= 128 * 1024 * 1024,
        "observation-read-aggregate",
    )

    class Reads:
        def release(self, context):
            require(context["repository"] == repository, "observation-release-repository")
            path = f"repos/{repository}/releases/tags/{context['tag']}"
            require(path in index["calls"], "observation-release-missing")
            return json.loads(
                bounded_file(directory / index["calls"][path], MAX_COMPLETION_BYTES), object_pairs_hook=unique
            )

        def assets(self, published, repo, output, limits):
            require(repo == repository and type(published.get("assets")) is list, "observation-asset-repository")
            selected = []
            for name, maximum in limits:
                matches = [asset for asset in published["assets"] if asset.get("name") == name]
                require(len(matches) == 1, "archive-release-asset-missing-or-ambiguous")
                asset = matches[0]
                require(
                    type(asset.get("id")) is int
                    and asset["id"] > 0
                    and asset.get("state") == "uploaded"
                    and type(asset.get("size")) is int
                    and 0 < asset["size"] <= maximum,
                    "archive-release-asset-bound",
                )
                require(str(asset["id"]) in index["assets"], "observation-asset-missing")
                selected.append(asset["id"])
                path = directory / index["assets"][str(asset["id"])]
                require(path.stat().st_size == asset["size"] <= maximum, "archive-release-download")
                digest = hashlib.sha256()
                with (
                    path.open("rb") as stream,
                    (output / name).open("wb") if output is not None else nullcontext() as target,
                ):
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                        if target is not None:
                            target.write(chunk)
                if asset.get("digest") is not None:
                    require(asset["digest"] == "sha256:" + digest.hexdigest(), "observation-asset-digest")
                if output is None:
                    require(asset.get("expected_sha256") == digest.hexdigest(), "completion-asset-bytes")
            require(len(set(selected)) == len(selected), "archive-release-asset-identity")

    previous = _OBSERVATIONS
    _OBSERVATIONS = Reads()
    try:
        yield
    finally:
        _OBSERVATIONS = previous


def completion_prepare(directory, output, context):
    """After actual publication gates: create unsigned bytes, or reuse the original signed pair."""
    published = read_release(context)
    release_identity(published, context)
    names = completion_assets(context)
    manifest = local_manifest(directory, names)
    expected = completion_document(published, context, manifest)
    present = {item.get("name") for item in published.get("assets", [])} & {COMPLETION, COMPLETION_BUNDLE}
    output.mkdir(parents=True, exist_ok=False)
    if present:
        require(present == {COMPLETION, COMPLETION_BUNDLE}, "completion-partial-pair")
        require(verify_completion(published, context, output) == expected, "completion-existing-bytes")
        reused = True
    else:
        verify_manifest(published, context, manifest, False)
        (output / COMPLETION).write_bytes(canonical(expected))
        reused = False
    require(release_state(read_release(context)) == release_state(published), "completion-release-drift")
    return reused


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--operation", choices=("archive", "completion-prepare", "completion-verify"), default="archive"
    )
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--galaxy-required", choices=("true", "false"))
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--observation-directory", type=Path)
    args = parser.parse_args()
    try:
        context = (
            observation_reads(args.observation_directory, args.repository)
            if args.observation_directory is not None
            else nullcontext()
        )
        with context:
            if args.operation == "archive":
                require(args.snapshot is not None and args.bundle is not None, "archive-files-required")
                verify_files(args.snapshot, args.bundle, args.repository, args.repository_id, args.release)
            else:
                require(args.directory is not None and args.galaxy_required is not None, "completion-arguments")
                context = completion_context(
                    args.repository, args.repository_id, args.release, args.version, args.galaxy_required == "true"
                )
                if args.operation == "completion-prepare":
                    require(args.output is not None, "completion-output-required")
                    print("true" if completion_prepare(args.directory, args.output, context) else "false")
                else:
                    published = read_release(context)
                    args.directory.mkdir(parents=True, exist_ok=False)
                    verify_completion(published, context, args.directory)
                    require(
                        release_state(read_release(context)) == release_state(published), "completion-release-drift"
                    )
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
