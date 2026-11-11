"""Verify Root's final receipt against independently read native job/artifact facts."""

# Exact JSON integer types must reject bools and subclasses at the signed/native boundary.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import http.client
import json
import os
import re
import shutil
import stat
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts import quality_evidence

ROOT_PUBLIC_KEY_HEX = "15a46de8e59602953884a1fe7138f40cfb3c12245af1f8e93a6f615421fe5788"
SOURCE_REPOSITORY = "ltn-it/ansible-collection-supplementary"
SOURCE_REPOSITORY_ID = 1103407173


class FinalQualityError(ValueError):
    """The supplied final receipt does not prove this exact completed cell."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise FinalQualityError(reason)


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
        _need(count <= quality_evidence.MAX_EVIDENCE_FILES and total <= 2 * 1024**3, "physical evidence total bound")
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
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=30) as response:
        _need(response.status == 200, "native metadata status")
        raw = response.read(8 * 1024**2 + 1)
    _need(len(raw) <= 8 * 1024**2, "native metadata bound")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    _need(isinstance(value, dict), "native metadata object")
    return value


def native_records(payload: dict[str, Any], *, run_id: int, source_sha: str) -> tuple[dict, dict]:
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
        _need(size <= 2 * 1024**3, "native ZIP total bound")
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
            _need(total <= 2 * 1024**3 and total <= max(size, 1) * 1000, "native ZIP expansion bound")
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
    connection = http.client.HTTPSConnection("api.github.com", timeout=30)
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
        type(artifact["size_in_bytes"]) is int and 0 < artifact["size_in_bytes"] <= 2 * 1024**3,
        "native ZIP expected bound",
    )
    deadline = time.monotonic() + 300
    # The provider's signed URL receives no GitHub Authorization header.
    with (
        urllib.request.build_opener(_NoRedirect).open(location.geturl(), timeout=30) as response,
        tempfile.TemporaryFile() as stream,
    ):
        _need(response.status == 200, "native ZIP download status")
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            _need(time.monotonic() < deadline and size <= artifact["size_in_bytes"], "native ZIP download bound")
            stream.write(chunk)
        compare_provider_zip(stream, root, artifact)


def import_physical_inputs(
    downloaded: Path, receipts: Path, destination: Path, *, run_id: int, source_sha: str, controller_sha: str
) -> int:
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
        verified.append(root)
    _need(not receipt_index, "unmatched final artifact receipt")
    for root in verified:
        shutil.copytree(root, destination / root.name)
    return len(verified)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("downloaded", "receipts", "destination"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--controller-sha", required=True)
    args = parser.parse_args()
    try:
        count = import_physical_inputs(
            args.downloaded,
            args.receipts,
            args.destination,
            run_id=args.run_id,
            source_sha=args.source_sha,
            controller_sha=args.controller_sha,
        )
        print(f"Verified {count} physical evidence trees against final Root and native provider records")
        return 0
    except Exception:
        # Never print bearer-bearing HTTP request objects or untrusted records.
        print("Final physical evidence verification failed; no final quality acceptance")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
