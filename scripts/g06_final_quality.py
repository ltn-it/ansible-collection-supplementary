"""Verify Root's final receipt against independently read native job/artifact facts."""

# Exact JSON integer types must reject bools and subclasses at the signed/native boundary.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import argparse
import base64
import contextvars
import datetime
import functools
import hashlib
import http.client
import importlib
import json
import math
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import urllib.request
import weakref
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# The companion is also a script entry point. A fixed module import avoids
# loading its script/package names twice during static checking of that entry.
quality_evidence = importlib.import_module((__package__ + "." if __package__ else "") + "quality_evidence")

ROOT_PUBLIC_KEY_HEX = "15a46de8e59602953884a1fe7138f40cfb3c12245af1f8e93a6f615421fe5788"
SOURCE_REPOSITORY = "ltn-it/ansible-collection-supplementary"
SOURCE_REPOSITORY_ID = 1103407173


class FinalQualityError(ValueError):
    """The supplied final receipt does not prove this exact completed cell."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise FinalQualityError(reason)


# Includes both cells, native/ZIP reads and local verification. Workflow jobs
# additionally start a monotonic clock before checkout/setup, leaving 90 seconds
# of their existing 600-second budget. These values only constrain acceptance.
VERIFICATION_SECONDS = 240
_PHASE_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "g06_final_verification_deadline", default=None
)


def _check_deadline(deadline=None):
    deadline = deadline if deadline is not None else _PHASE_DEADLINE.get()
    _need(deadline is None or time.monotonic() < deadline, "physical verification phase budget exhausted")


def _request_timeout():
    deadline = _PHASE_DEADLINE.get()
    _check_deadline(deadline)
    return min(30, max(0.001, deadline - time.monotonic())) if deadline is not None else 30


def bounded_verification(function):
    @functools.wraps(function)
    def bounded(*args, **kwargs):
        now = time.monotonic()
        deadline = min(now + VERIFICATION_SECONDS, _PHASE_DEADLINE.get() or float("inf"))
        workflow = os.getenv("G06_FINAL_PHASE_DEADLINE", "")
        if workflow:
            _need(bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", workflow)), "workflow verification clock")
            bound = float(workflow)
            _need(math.isfinite(bound), "workflow verification clock")
            deadline = min(deadline, bound)
        token = _PHASE_DEADLINE.set(deadline)
        try:
            _check_deadline()
            result = function(*args, **kwargs)
            _check_deadline()
            return result
        finally:
            _PHASE_DEADLINE.reset(token)

    return bounded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _need(key not in result, "duplicate receipt field")
        result[key] = value
    return result


def _decode(value: str) -> bytes:
    _need(bool(re.fullmatch(r"[A-Za-z0-9_-]+", value)), "invalid JWS encoding")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    _need(base64.urlsafe_b64encode(raw).decode().rstrip("=") == value, "noncanonical JWS encoding")
    return raw


def verify_final_receipt(
    envelope: dict[str, Any],
    *,
    public_key_hex: str,
    expected: dict[str, Any],
    native_execution: dict[str, Any],
    native_artifact: dict[str, Any],
) -> dict[str, Any]:
    """Expected identity, key and provider records must come from outside the receipt.

    This function verifies evidence; it does not contact Root, admit a lease,
    mutate an archive or turn a preliminary manifest into a final result.
    """
    _need(isinstance(envelope, dict) and set(envelope) == {"schema", "receipt", "signature"}, "receipt envelope")
    _need(type(envelope["schema"]) is int and envelope["schema"] == 1, "receipt schema")
    _need(
        isinstance(public_key_hex, str) and bool(re.fullmatch(r"[a-f0-9]{64}", public_key_hex)), "independent key pin"
    )
    signature = envelope["signature"]
    _need(isinstance(signature, str) and len(signature) <= 32768, "receipt signature bound")
    parts = signature.split(".")
    _need(len(parts) == 3, "receipt compact JWS")
    header = json.loads(_decode(parts[0]), object_pairs_hook=_unique_object)
    key_bytes = bytes.fromhex(public_key_hex)
    _need(
        header == {"alg": "EdDSA", "typ": "lit-incus-final-quality+jwt", "kid": hashlib.sha256(key_bytes).hexdigest()},
        "receipt signing domain",
    )
    Ed25519PublicKey.from_public_bytes(key_bytes).verify(_decode(parts[2]), (parts[0] + "." + parts[1]).encode("ascii"))
    payload = json.loads(_decode(parts[1]), object_pairs_hook=_unique_object)
    _need(isinstance(payload, dict) and payload == envelope["receipt"], "receipt signed payload mismatch")
    _need(type(payload.get("schema")) is int and payload["schema"] == 1, "signed schema")
    _need(
        payload.get("purpose") == "urn:lightning-it:g06:final-quality:v1" and payload.get("state") == "closed",
        "receipt not closed",
    )
    _need(payload.get("signer_public_key_hex") == public_key_hex, "receipt key drift")
    identity_keys = {
        "repository",
        "repository_id",
        "run_id",
        "run_attempt",
        "source_sha",
        "controller_sha",
        "profile",
        "scenario",
        "target",
    }
    _need(isinstance(expected, dict) and set(expected) == identity_keys, "independent expected identity incomplete")
    for key in identity_keys:
        _need(
            type(payload.get(key)) is type(expected[key]) and payload[key] == expected[key],
            "receipt identity mismatch: " + key,
        )
    _need(type(payload["run_attempt"]) is int and payload["run_attempt"] == 1, "receipt attempt")
    for key in ("repository_id", "run_id"):
        _need(type(payload[key]) is int and payload[key] > 0, "receipt native identity")
    for key in ("source_sha", "controller_sha"):
        _need(isinstance(payload[key], str) and bool(re.fullmatch(r"[a-f0-9]{40}", payload[key])), "receipt commit")
    execution = payload.get("execution")
    _need(isinstance(execution, dict) and execution == native_execution, "receipt native execution mismatch")
    _need(set(execution) == {"job_id", "check_run_id", "conclusion", "completed_at"}, "receipt execution fields")
    _need(execution["conclusion"] == "success", "receipt native execution did not succeed")
    for key in ("job_id", "check_run_id", "completed_at"):
        _need(type(execution[key]) is int and execution[key] > 0, "receipt execution identity or time")
    artifact = payload.get("artifact")
    _need(isinstance(artifact, dict) and artifact == native_artifact, "receipt native artifact mismatch")
    _need(set(artifact) == {"id", "name", "digest_sha256", "size_in_bytes"}, "receipt artifact fields")
    for key in ("id", "size_in_bytes"):
        _need(type(artifact[key]) is int and artifact[key] > 0, "receipt artifact identity or size")
    _need(isinstance(artifact["name"], str) and bool(artifact["name"]), "receipt artifact name")
    cleanup = payload.get("cleanup")
    _need(
        isinstance(cleanup, dict)
        and set(cleanup) == {"state", "ledger_sha256", "closed_at", "resource_absence_sha256"},
        "receipt cleanup fields",
    )
    _need(cleanup["state"] == "verified", "receipt cleanup unverified")
    _need(
        type(cleanup["closed_at"]) is int and cleanup["closed_at"] >= execution["completed_at"],
        "receipt cleanup predates native end",
    )
    _need(
        type(payload.get("issued_at")) is int and payload["issued_at"] >= cleanup["closed_at"],
        "receipt issue predates cleanup",
    )
    for value in (
        artifact["digest_sha256"],
        cleanup["ledger_sha256"],
        cleanup["resource_absence_sha256"],
        *(
            payload.get(key)
            for key in ("capture_receipt_sha256", "custody_policy_sha256", "cell_sha256", "engine_policy_sha256")
        ),
    ):
        _need(isinstance(value, str) and bool(re.fullmatch(r"[a-f0-9]{64}", value)), "receipt evidence digest")
    _need(isinstance(payload.get("lease_id"), str) and bool(payload["lease_id"]), "receipt lease identity")
    return payload


def verify_physical_evidence(
    root: Path,
    envelope: dict[str, Any],
    *,
    public_key_hex: str,
    expected: dict[str, Any],
    native_execution: dict[str, Any],
    native_artifact: dict[str, Any],
) -> dict[str, Any]:
    """Gate the physical client's direct evidence tree without rewriting it.

    Root's signed artifact tuple binds the provider ZIP whose complete content
    Root compared with its own export. The supplied native records must be read
    independently by the caller, rather than copied out of the envelope.
    """
    receipt = verify_final_receipt(
        envelope,
        public_key_hex=public_key_hex,
        expected=expected,
        native_execution=native_execution,
        native_artifact=native_artifact,
    )
    _need(root.is_dir() and not root.is_symlink(), "physical evidence directory")
    _need(root.name == native_artifact["name"], "physical artifact directory identity")
    count = total = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            _need(not path.is_symlink(), "physical evidence symlink")
            if name in files:
                _need(path.is_file(), "physical evidence nonregular file")
                count += 1
                size = path.stat().st_size
                _need(size <= quality_evidence.MAX_EVIDENCE_FILE_BYTES, "physical evidence member bound")
                total += size
        _need(
            count <= quality_evidence.MAX_EVIDENCE_FILES and total <= quality_evidence.MAX_EVIDENCE_TOTAL_BYTES,
            "physical evidence total bound",
        )
    _need(
        not quality_evidence._validate_checksums(root.resolve(), root.resolve() / "checksums/SHA256SUMS"),
        "physical evidence checksums",
    )
    manifest_path = root / "manifest.json"
    _need(manifest_path.stat().st_size <= 8 * 1024**2, "physical evidence manifest bound")
    manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=_unique_object)
    _need(isinstance(manifest, dict) and manifest.get("schema_version") == 2, "physical evidence manifest schema")
    _need(
        manifest.get("root_finalization") == "pending" and manifest.get("execution_success") is True,
        "physical evidence is not a successful preliminary export",
    )
    _need(
        manifest.get("release_eligible") is False and manifest.get("candidate_execution_passed") is False,
        "physical evidence claimed premature final acceptance",
    )
    _need(
        manifest.get("repository") == expected["repository"]
        and manifest.get("commit_sha") == manifest.get("expected_commit_sha") == expected["source_sha"]
        and manifest.get("workflow_run_id") == str(expected["run_id"])
        and manifest.get("workflow_attempt") == str(expected["run_attempt"]),
        "physical evidence native tuple",
    )
    _need(
        manifest.get("profiles") == [expected["profile"].replace("_", "-")]
        and manifest.get("scenarios") == [expected["scenario"]]
        and manifest.get("targets") == [expected["target"]],
        "physical evidence cell identity",
    )
    _need(
        not quality_evidence._manifest_logic_failures(manifest, release_mode=False, preliminary=True),
        "physical evidence execution results invalid",
    )
    _need(quality_evidence.scan_evidence(root)["clean"] is True, "physical evidence secret scan")
    return receipt


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FinalQualityError("native metadata redirect denied")


def _native_read(path: str) -> dict[str, Any]:
    _need(bool(re.fullmatch(r"/(?:actions/(?:artifacts|jobs)|check-runs)/[1-9][0-9]*", path)), "native metadata path")
    token = os.environ.get("GITHUB_TOKEN", "")
    _need(bool(token) and not any(c.isspace() for c in token), "native read credential unavailable")
    request = urllib.request.Request(
        "https://api.github.com/repos/" + SOURCE_REPOSITORY + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "lit-g06-final-quality/1",
        },
    )
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=_request_timeout()) as response:
        _need(response.status == 200, "native metadata status")
        raw = response.read(8 * 1024**2 + 1)
    _check_deadline()
    _need(len(raw) <= 8 * 1024**2, "native metadata bound")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    _need(isinstance(value, dict), "native metadata object")
    return value


def native_records(payload: dict[str, Any], *, run_id: int, source_sha: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read only fixed provider endpoints, then join the original job and ZIP."""
    execution, artifact = payload.get("execution", {}), payload.get("artifact", {})
    for value in (execution.get("job_id"), execution.get("check_run_id"), artifact.get("id")):
        _need(type(value) is int and value > 0, "native identifier")
    job = _native_read("/actions/jobs/" + str(execution["job_id"]))
    check = _native_read("/check-runs/" + str(execution["check_run_id"]))
    uploaded = _native_read("/actions/artifacts/" + str(artifact["id"]))
    _need(
        job.get("id") == execution["job_id"]
        and job.get("run_id") == run_id
        and type(job.get("run_attempt")) is int
        and job["run_attempt"] == 1
        and job.get("head_sha") == source_sha
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_id") == 78
        and job.get("check_run_url")
        == "https://api.github.com/repos/" + SOURCE_REPOSITORY + "/check-runs/" + str(execution["check_run_id"]),
        "native execution binding",
    )
    _need(
        check.get("id") == execution["check_run_id"]
        and check.get("head_sha") == source_sha
        and check.get("status") == "completed"
        and check.get("conclusion") == "success",
        "native check binding",
    )
    completed = datetime.datetime.strptime(job["completed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)
    native_execution = {
        "job_id": job["id"],
        "check_run_id": check["id"],
        "conclusion": "success",
        "completed_at": int(completed.timestamp()),
    }
    producer = uploaded.get("workflow_run", {})
    _need(
        uploaded.get("id") == artifact["id"]
        and uploaded.get("expired") is False
        and producer.get("id") == run_id
        and producer.get("head_sha") == source_sha,
        "native artifact producer binding",
    )
    digest = uploaded.get("digest", "")
    _need(isinstance(digest, str) and bool(re.fullmatch(r"sha256:[a-f0-9]{64}", digest)), "native ZIP digest")
    native_artifact = {
        "id": uploaded["id"],
        "name": uploaded.get("name"),
        "digest_sha256": digest[7:],
        "size_in_bytes": uploaded.get("size_in_bytes"),
    }
    return native_execution, native_artifact


def compare_provider_zip(stream, root: Path, artifact: dict[str, Any]) -> None:
    """Compare all downloaded bytes with the independently hashed provider ZIP."""
    stream.seek(0)
    digest, size = hashlib.sha256(), 0
    while chunk := stream.read(1024 * 1024):
        size += len(chunk)
        _need(size <= quality_evidence.MAX_EVIDENCE_TOTAL_BYTES, "native ZIP total bound")
        digest.update(chunk)
    _need(
        size == artifact["size_in_bytes"] and digest.hexdigest() == artifact["digest_sha256"],
        "native ZIP bytes mismatch",
    )
    stream.seek(0)
    names, files, total = set(), set(), 0
    with zipfile.ZipFile(stream) as archive:
        _need(len(archive.infolist()) <= quality_evidence.MAX_EVIDENCE_FILES, "native ZIP members bound")
        for member in archive.infolist():
            name = member.filename.rstrip("/") if member.is_dir() else member.filename
            relative = PurePosixPath(name)
            _need(
                not relative.is_absolute()
                and ".." not in relative.parts
                and relative.as_posix() == name
                and name not in {"", "."}
                and name not in names,
                "native ZIP member path",
            )
            names.add(name)
            mode = member.external_attr >> 16
            _need(
                not member.flag_bits & 1 and stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR},
                "native ZIP member type",
            )
            _need(member.file_size <= quality_evidence.MAX_EVIDENCE_FILE_BYTES, "native ZIP member size")
            total += member.file_size
            _need(
                total <= quality_evidence.MAX_EVIDENCE_TOTAL_BYTES and total <= max(size, 1) * 1000,
                "native ZIP expansion bound",
            )
            if member.is_dir():
                continue
            local = root / name
            _need(
                local.is_file() and not local.is_symlink() and local.stat().st_size == member.file_size,
                "native ZIP local member",
            )
            files.add(name)
            with archive.open(member) as provider, local.open("rb") as downloaded:
                while chunk := provider.read(1024 * 1024):
                    _need(downloaded.read(len(chunk)) == chunk, "native ZIP local content mismatch")
                _need(downloaded.read(1) == b"", "native ZIP local content tail")
    _need(
        files == {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()},
        "native ZIP local file inventory",
    )


def verify_provider_zip(root: Path, artifact: dict[str, Any]) -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    _need(bool(token) and not any(c.isspace() for c in token), "native read credential unavailable")
    connection = http.client.HTTPSConnection("api.github.com", timeout=_request_timeout())
    try:
        connection.request(
            "GET",
            "/repos/" + SOURCE_REPOSITORY + "/actions/artifacts/" + str(artifact["id"]) + "/zip",
            headers={"Authorization": "Bearer " + token, "User-Agent": "lit-g06-final-quality/1"},
        )
        response = connection.getresponse()
        _need(response.status == 302, "native ZIP redirect status")
        location = urlsplit(response.getheader("Location", ""))
    finally:
        connection.close()
    _need(
        location.scheme == "https"
        and not location.username
        and not location.password
        and location.port is None
        and not location.fragment
        and (
            location.hostname == "results-receiver.actions.githubusercontent.com"
            or bool(re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", location.hostname or ""))
        ),
        "native ZIP redirect origin",
    )
    _need(
        type(artifact["size_in_bytes"]) is int
        and 0 < artifact["size_in_bytes"] <= quality_evidence.MAX_EVIDENCE_TOTAL_BYTES,
        "native ZIP expected bound",
    )
    deadline = min(time.monotonic() + 300, _PHASE_DEADLINE.get() or float("inf"))
    # The provider's signed URL receives no GitHub Authorization header.
    with (
        urllib.request.build_opener(_NoRedirect).open(location.geturl(), timeout=_request_timeout()) as response,
        tempfile.TemporaryFile() as stream,
    ):
        _need(response.status == 200, "native ZIP download status")
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            _need(time.monotonic() < deadline and size <= artifact["size_in_bytes"], "native ZIP download bound")
            stream.write(chunk)
        _check_deadline()
        compare_provider_zip(stream, root, artifact)
        _check_deadline()


# This directory is transport provenance, never another source of test reports.
PROOF_DIRECTORY = "root-final-inputs"
MAIN_PHYSICAL_CELLS = frozenset(
    {
        ("heavy", "keycloak-heavy", "ubuntu-24.04"),
        ("application_acceptance", "keycloak-application-acceptance", "ubuntu-24.04"),
    }
)
_PROOFS: weakref.WeakKeyDictionary[VerifiedPhysicalInputs, tuple[int, int, list[dict[str, Any]], float]] = (
    weakref.WeakKeyDictionary()
)


class VerifiedPhysicalInputs:
    """Opaque process-local verification result; constructing one grants nothing."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def _inventory(root):
    files = {}
    total = 0
    for path in quality_evidence._bounded_artifact_walk(root):
        _need(not path.is_symlink(), "proof tree symlink")
        if path.is_dir():
            continue
        _need(path.is_file(), "proof tree nonregular member")
        data = quality_evidence._bounded_read(path)
        total += len(data)
        _need(total <= quality_evidence.MAX_EVIDENCE_TOTAL_BYTES, "proof tree total bound")
        files[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
    return files


def _mint(records, *, deadline=None):
    proof = VerifiedPhysicalInputs()
    entries = []
    for root, raw, inventory in records:
        envelope = json.loads(raw, object_pairs_hook=_unique_object)
        _need(raw == _canonical(envelope), "canonical final envelope")
        _need(_inventory(root) == inventory, "verified input changed before proof binding")
        entries.append({"root": root.resolve(), "envelope": raw, "inventory": dict(inventory), "envelope_path": None})
    expires = min(deadline or float("inf"), _PHASE_DEADLINE.get() or time.monotonic() + VERIFICATION_SECONDS)
    _PROOFS[proof] = (os.getpid(), threading.get_ident(), entries, expires)
    return proof


def _entries(proof):
    state = _PROOFS.get(proof) if type(proof) is VerifiedPhysicalInputs else None
    if state is None or state[:2] != (os.getpid(), threading.get_ident()):
        raise FinalQualityError("unregistered final verification")
    _check_deadline(state[3])
    for entry in state[2]:
        _need(_inventory(entry["root"]) == entry["inventory"], "verified physical input changed")
        path = entry["envelope_path"]
        if path is not None:
            _need(
                not path.is_symlink() and quality_evidence._bounded_read(path, 65536) == entry["envelope"],
                "verified final envelope changed",
            )
    _check_deadline(state[3])
    return state[2]


def authorized_roots(proof):
    return {entry["root"] for entry in _entries(proof)}


def scanner_payloads(proof):
    """Mask only the exact verified public signature, scanning every other field."""
    masks = {}
    for entry in _entries(proof):
        if entry["envelope_path"] is not None:
            envelope = json.loads(entry["envelope"])
            envelope["signature"] = "verified-public-final-evidence-signature"
            masks[entry["envelope_path"]] = (entry["envelope"], _canonical(envelope))
    return masks


def retained_paths(proof):
    return {entry["root"] / name for entry in _entries(proof) for name in entry["inventory"]} | {
        entry["envelope_path"] for entry in _entries(proof) if entry["envelope_path"] is not None
    }


def _combined_bound(roots, additional_bytes=0, additional_files=0):
    total, count = additional_bytes, additional_files
    for root in roots:
        if not root.exists():
            continue
        for path in quality_evidence._bounded_artifact_walk(root):
            _need(not path.is_symlink(), "combined evidence symlink")
            if path.is_dir():
                continue
            _need(path.is_file(), "combined evidence member type")
            size = path.stat().st_size
            count += 1
            total += size
            _need(
                size <= quality_evidence.MAX_EVIDENCE_FILE_BYTES
                and total <= quality_evidence.MAX_EVIDENCE_TOTAL_BYTES
                and count <= quality_evidence.MAX_EVIDENCE_FILES,
                "combined evidence total bound",
            )


def persist_inputs(proof, destination):
    """Retain original checksummed exports and signed envelopes, within existing caps."""
    entries = _entries(proof)
    _combined_bound(
        [destination, *(entry["root"] for entry in entries)],
        sum(len(entry["envelope"]) for entry in entries),
        len(entries),
    )
    records = []
    refs = []
    for entry in entries:
        envelope = json.loads(entry["envelope"])
        artifact = envelope["receipt"]["artifact"]
        relative = Path(PROOF_DIRECTORY) / str(artifact["id"])
        cell = relative / "cell" / artifact["name"]
        receipt = relative / "final-quality-receipt.json"
        _need(not (destination / relative).exists(), "duplicate final input artifact")
        shutil.copytree(entry["root"], destination / cell)
        (destination / receipt).write_bytes(entry["envelope"])
        records.append((destination / cell, entry["envelope"], entry["inventory"]))
        refs.append(
            {
                "cell": cell.as_posix(),
                "envelope": receipt.as_posix(),
                "manifest_sha256": entry["inventory"]["manifest.json"],
                "inventory_sha256": hashlib.sha256(_canonical(entry["inventory"])).hexdigest(),
            }
        )
    retained = _mint(records, deadline=_PROOFS[proof][3])
    for entry, ref in zip(_entries(retained), refs, strict=True):
        entry["envelope_path"] = (destination / ref["envelope"]).resolve()
    _PROOFS[proof] = _PROOFS[retained]
    return refs, proof


def relocate_inputs(proof, previous, current):
    # Caller has just atomically renamed the complete stage. Recheck at its new location.
    state = _PROOFS.get(proof)
    if state is None or state[:2] != (os.getpid(), threading.get_ident()):
        raise FinalQualityError("unregistered final verification")
    for entry in state[2]:
        entry["root"] = current / entry["root"].relative_to(previous)
        entry["envelope_path"] = current / entry["envelope_path"].relative_to(previous)
    _entries(proof)


def share_verified_inputs(destination, source):
    _entries(destination) if destination is source else None
    _need(type(destination) is VerifiedPhysicalInputs and destination in _PROOFS, "unregistered final verification")
    _entries(source)
    _PROOFS[destination] = _PROOFS[source]


def _reference_hashes(root, results):
    hashes = []
    for result in results:
        for field in ("junit", "allure_results"):
            for name in result.get(field, []):
                relative = PurePosixPath(name)
                _need(not relative.is_absolute() and ".." not in relative.parts, "final report reference path")
                path = root / name
                _need(not path.is_symlink(), "final report reference symlink")
                hashes.append((field, hashlib.sha256(quality_evidence._bounded_read(path)).hexdigest()))
    return sorted(hashes)


def require_persisted_binding(proof, root, manifest):
    entries = _entries(proof)
    require_main_coverage(proof)
    refs = manifest.get("root_final_quality_inputs")
    _need(isinstance(refs, list) and len(refs) == len(entries), "physical proof mapping missing")
    for entry in entries:
        expected = {
            "cell": entry["root"].relative_to(root).as_posix(),
            "envelope": entry["envelope_path"].relative_to(root).as_posix(),
            "manifest_sha256": entry["inventory"]["manifest.json"],
            "inventory_sha256": hashlib.sha256(_canonical(entry["inventory"])).hexdigest(),
        }
        _need(refs.count(expected) == 1, "physical proof mapping changed")
        payload = json.loads(entry["envelope"])["receipt"]
        _need(
            manifest.get("repository") == payload["repository"]
            and manifest.get("commit_sha") == manifest.get("expected_commit_sha") == payload["source_sha"]
            and manifest.get("workflow_run_id") == str(payload["run_id"])
            and manifest.get("workflow_attempt") == str(payload["run_attempt"]),
            "aggregate original native tuple differs from verified export",
        )
        raw = json.loads(quality_evidence._bounded_read(entry["root"] / "manifest.json"))
        selected = [
            result
            for result in manifest.get("results", [])
            if (result.get("profile", "").replace("-", "_"), result.get("scenario"), result.get("target"))
            == tuple(payload[key] for key in ("profile", "scenario", "target"))
        ]
        _need(
            bool(selected) and _reference_hashes(root, selected) == _reference_hashes(entry["root"], raw["results"]),
            "aggregate physical reports differ from verified export",
        )


def expected_context(source_sha, controller_sha=None, run_id=None):
    controller = controller_sha or os.getenv("G06_VALIDATION_CONTROLLER_SHA", "")
    run = str(run_id or os.getenv("CI_RUN_ID") or os.getenv("GITHUB_RUN_ID") or "")
    _need(
        bool(re.fullmatch(r"[a-f0-9]{40}", source_sha or ""))
        and bool(re.fullmatch(r"[a-f0-9]{40}", controller))
        and bool(re.fullmatch(r"[1-9][0-9]*", run)),
        "physical proof expected controller/run unavailable",
    )
    return source_sha, controller, int(run)


@bounded_verification
def verify_persisted_inputs(root, manifest, *, source_sha, controller_sha=None, run_id=None):
    try:
        return _verify_persisted_inputs(
            root, manifest, source_sha=source_sha, controller_sha=controller_sha, run_id=run_id
        )
    except (ValueError, OSError, KeyError, TypeError, InvalidSignature) as error:
        raise FinalQualityError("persisted physical final proof held") from error


def _verify_persisted_inputs(root, manifest, *, source_sha, controller_sha=None, run_id=None):
    """Fresh independent native/ZIP verification; stored references are locators only."""
    source, controller, run = expected_context(source_sha, controller_sha, run_id)
    refs = manifest.get("root_final_quality_inputs")
    _need(isinstance(refs, list) and 0 < len(refs) <= 2, "physical proof reference inventory")
    records, names = [], set()
    expected_files: set[Path] = set()
    for ref in refs:
        _need(
            isinstance(ref, dict) and set(ref) == {"cell", "envelope", "manifest_sha256", "inventory_sha256"},
            "physical proof reference schema",
        )
        cell, receipt = (PurePosixPath(ref[key]) for key in ("cell", "envelope"))
        _need(
            len(cell.parts) == 4
            and cell.parts[0] == PROOF_DIRECTORY
            and cell.parts[1].isdigit()
            and cell.parts[2] == "cell"
            and cell.name not in {"", ".", ".."}
            and receipt == PurePosixPath(PROOF_DIRECTORY, cell.parts[1], "final-quality-receipt.json")
            and cell.parts[1] not in names,
            "physical proof reference path",
        )
        names.add(cell.parts[1])
        local, envelope_path = root / str(cell), root / str(receipt)
        for component in (local, local.parent, local.parent.parent, local.parent.parent.parent, envelope_path):
            _need(not component.is_symlink(), "physical proof reference symlink")
        raw = quality_evidence._bounded_read(envelope_path, 65536)
        envelope = json.loads(raw, object_pairs_hook=_unique_object)
        _need(raw == _canonical(envelope), "canonical final envelope")
        payload = envelope["receipt"]
        _need(str(payload["artifact"]["id"]) == cell.parts[1], "physical proof artifact locator")
        expected = {
            "repository": SOURCE_REPOSITORY,
            "repository_id": SOURCE_REPOSITORY_ID,
            "run_id": run,
            "run_attempt": 1,
            "source_sha": source,
            "controller_sha": controller,
            **{key: payload[key] for key in ("profile", "scenario", "target")},
        }
        inventory = _inventory(local)
        execution, artifact = native_records(payload, run_id=run, source_sha=source)
        verify_physical_evidence(
            local,
            envelope,
            public_key_hex=ROOT_PUBLIC_KEY_HEX,
            expected=expected,
            native_execution=execution,
            native_artifact=artifact,
        )
        verify_provider_zip(local, artifact)
        _need(_inventory(local) == inventory, "physical input changed during native verification")
        _need(
            ref["manifest_sha256"] == inventory["manifest.json"]
            and ref["inventory_sha256"] == hashlib.sha256(_canonical(inventory)).hexdigest(),
            "physical proof retained inventory",
        )
        records.append((local, raw, inventory))
        expected_files.update((local / name).resolve() for name in inventory)
        expected_files.add(envelope_path.resolve())
    actual = {p.resolve() for p in quality_evidence._bounded_artifact_walk(root / PROOF_DIRECTORY) if p.is_file()}
    _need(actual == expected_files, "physical proof unreferenced member")
    proof = _mint(records)
    for entry, ref in zip(_entries(proof), refs, strict=True):
        entry["envelope_path"] = (root / ref["envelope"]).resolve()
    require_persisted_binding(proof, root, manifest)
    return proof


def physical_cells(proof):
    return {
        tuple(json.loads(entry["envelope"])["receipt"][key] for key in ("profile", "scenario", "target"))
        for entry in _entries(proof)
    }


def require_main_coverage(proof):
    cells = [
        tuple(json.loads(entry["envelope"])["receipt"][key] for key in ("profile", "scenario", "target"))
        for entry in _entries(proof)
    ]
    _need(len(cells) == 2 and set(cells) == MAIN_PHYSICAL_CELLS, "exact Main physical cell coverage")


def combine_inputs(proofs):
    records: dict[int, tuple[Path, bytes, dict[str, str]]] = {}
    for proof in proofs:
        for entry in _entries(proof):
            key = json.loads(entry["envelope"])["receipt"]["artifact"]["id"]
            if key in records:
                _need(
                    records[key][1] == entry["envelope"] and _inventory(records[key][0]) == entry["inventory"],
                    "conflicting physical input provenance",
                )
            records[key] = (entry["root"], entry["envelope"], entry["inventory"])
    return _mint(list(records.values()), deadline=min(_PROOFS[proof][3] for proof in proofs))


def import_physical_inputs(downloaded, receipts, destination, *, run_id, source_sha, controller_sha):
    # Compatibility importer remains non-authoritative: final aggregation needs
    # the opaque result or fresh persisted native verification.
    proof = verified_physical_inputs(
        downloaded, receipts, destination, run_id=run_id, source_sha=source_sha, controller_sha=controller_sha
    )
    return len(_entries(proof))


@bounded_verification
def verified_physical_inputs(
    downloaded: Path, receipts: Path, destination: Path, *, run_id: int, source_sha: str, controller_sha: str
) -> VerifiedPhysicalInputs:
    """Verify every direct physical tree before copying any into the aggregate."""
    _need(
        type(run_id) is int
        and run_id > 0
        and bool(re.fullmatch(r"[a-f0-9]{40}", source_sha))
        and bool(re.fullmatch(r"[a-f0-9]{40}", controller_sha)),
        "aggregate expected native identity",
    )
    receipt_index = {}
    for path in sorted(receipts.glob("*/final-quality-receipt.json")):
        _need(not path.is_symlink() and path.stat().st_size <= 65536, "final receipt file bound")
        envelope = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
        name = envelope.get("receipt", {}).get("artifact", {}).get("name")
        _need(isinstance(name, str) and name not in receipt_index, "duplicate or invalid final artifact receipt")
        receipt_index[name] = envelope
    verified = []
    for root in sorted(downloaded.iterdir()):
        if not (root / "manifest.json").is_file():
            continue  # Legacy profiles use the separately bounded tar importer.
        _need(
            not (destination / root.name).exists() and not (destination / root.name).is_symlink(),
            "physical aggregate destination already exists",
        )
        _need(root.name in receipt_index, "physical artifact lacks final receipt")
        _need(
            not root.is_symlink() and (root / "manifest.json").stat().st_size <= 8 * 1024**2, "physical manifest bound"
        )
        manifest = json.loads((root / "manifest.json").read_bytes(), object_pairs_hook=_unique_object)
        profiles, scenarios, targets = (manifest.get(key) for key in ("profiles", "scenarios", "targets"))
        _need(
            all(
                isinstance(value, list) and len(value) == 1 and isinstance(value[0], str)
                for value in (profiles, scenarios, targets)
            ),
            "physical matrix cell singleton",
        )
        _need(profiles[0] in {"heavy", "application-acceptance"}, "physical profile")
        expected = {
            "repository": SOURCE_REPOSITORY,
            "repository_id": SOURCE_REPOSITORY_ID,
            "run_id": run_id,
            "run_attempt": 1,
            "source_sha": source_sha,
            "controller_sha": controller_sha,
            "profile": profiles[0].replace("-", "_"),
            "scenario": scenarios[0],
            "target": targets[0],
        }
        envelope = receipt_index.pop(root.name)
        inventory = _inventory(root)
        execution, artifact = native_records(envelope["receipt"], run_id=run_id, source_sha=source_sha)
        verify_physical_evidence(
            root,
            envelope,
            public_key_hex=ROOT_PUBLIC_KEY_HEX,
            expected=expected,
            native_execution=execution,
            native_artifact=artifact,
        )
        verify_provider_zip(root, artifact)
        _need(_inventory(root) == inventory, "physical input changed during native verification")
        verified.append((root, envelope, inventory))
    _need(not receipt_index, "unmatched final artifact receipt")
    _combined_bound([destination, *(root for root, _envelope, _inventory_value in verified)])
    records = []
    for root, envelope, inventory in verified:
        copied = destination / root.name
        shutil.copytree(root, copied)
        records.append((copied.resolve(), _canonical(envelope), inventory))
    return _mint(records)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("downloaded", "receipts", "destination"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--controller-sha", required=True)
    parser.add_argument("--aggregate-root", type=Path)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--run-attempt", default="1")
    args = parser.parse_args()
    try:
        return _main_verified(args)
    except Exception:
        # Never print bearer-bearing HTTP request objects or untrusted records.
        print("Final physical evidence verification failed; no final quality acceptance")
        if args.aggregate_root is not None and os.getenv("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write("assemble_exit_code=1\nvalidate_exit_code=1\n")
        return 1


@bounded_verification
def _main_verified(args):
    proof = verified_physical_inputs(
        args.downloaded,
        args.receipts,
        args.destination,
        run_id=args.run_id,
        source_sha=args.source_sha,
        controller_sha=args.controller_sha,
    )
    count = len(_entries(proof))
    print(f"Verified {count} physical evidence trees against final Root and native provider records")
    if args.aggregate_root is not None:
        require_main_coverage(proof)
        assembled = quality_evidence.assemble(
            args.aggregate_root,
            input_roots=[args.destination],
            registry_path=args.registry,
            run_attempt=args.run_attempt,
            expected_commit=args.source_sha,
            release_mode=True,
            final_inputs=proof,
        )
        validated = quality_evidence.validate(
            args.aggregate_root, expected_commit=args.source_sha, release_mode=True, final_inputs=proof
        )
        if os.getenv("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write(f"assemble_exit_code={assembled}\nvalidate_exit_code={validated}\n")
        return 0 if assembled == validated == 0 else 1
    return 0


if __name__ == "__main__":
    # Keep the verifier registry single when quality_evidence imports this module.
    import sys

    if __package__:
        sys.modules[__package__ + ".g06_final_quality"] = sys.modules[__name__]
        vars(importlib.import_module(__package__))["g06_final_quality"] = sys.modules[__name__]
    else:
        sys.modules["g06_final_quality"] = sys.modules[__name__]
    raise SystemExit(main())
