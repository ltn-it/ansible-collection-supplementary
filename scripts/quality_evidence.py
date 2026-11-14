#!/usr/bin/env python3
"""Assemble and validate collection-wide, release-grade test evidence.

The module deliberately uses only the Python standard library plus PyYAML (when
an inventory registry is present).  It is also importable so focused tests and
role-specific compatibility entry points can reuse the same implementation.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import importlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

ALLOWED_RESULT_STATUSES = (
    "passed",
    "failed",
    "skipped-with-approved-justification",
    "not-applicable",
    "infrastructure-error",
    "blocked-external-service",
    "blocked-external-license",
    "blocked-external-infrastructure",
)
BLOCKED_STATUSES = {
    "blocked-external-service",
    "blocked-external-license",
    "blocked-external-infrastructure",
}
PROFILES = ("tiny", "heavy", "application-acceptance")
TEST_APPLICATION_MODES = {"runtime-container", "declared-evidence", "not-applicable"}
DECLARED_APPLICATION_TYPES = {"application", "external-api", "host-package", "host-service"}
MUTABLE_APPLICATION_VERSIONS = {
    "latest",
    "n/a",
    "not-applicable",
    "unknown",
    "unversioned",
    "unspecified",
}
MANDATORY_PREREQUISITES = (
    "lint",
    "build",
    "coverage",
    "tiny",
    "heavy",
    "acceptance",
    "cleanup",
    "destroy",
)
PROFILE_REGISTRY_KEYS = {
    "tiny": "tiny",
    "heavy": "heavy",
    "application-acceptance": "application_acceptance",
}
REQUIRED_RELEASE_SECURITY_FILES = (
    "sbom.cdx.json",
    "vulnerability-report.json",
    "trivy-vulnerability-report.json",
    "provenance.json",
    "secret-scan-summary.json",
)
EVIDENCE_DIRECTORIES = (
    "source",
    "collection",
    "matrix",
    "junit",
    "allure-results",
    "allure-report",
    "logs",
    "screenshots",
    "playwright-traces",
    "configuration",
    "dependencies",
    "security",
    "checksums",
)
CANARY = "LIT_EVIDENCE_REDACTION_CANARY_7f38f67e"
CANARY_BYTES = CANARY.encode("ascii")
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_FILES = 10_000
MAX_ARCHIVE_MEMBERS = 4_096
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 200

SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"authorization|proxy[_-]?authorization|cookie|set-cookie|api[_-]?key|x[_-]?api[_-]?key|"
    r"bind[_-]?credential|private[_-]?key|root[_-]?token|"
    r"unseal[_-]?key|recovery[_-]?key|activation[_-]?(?:code|key))"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|authorization|proxy[_-]?authorization|cookie|set-cookie|api[_-]?key|"
    r"x[_-]?api[_-]?key|bind[_-]?credential|private[_-]?key|"
    r"root[_-]?token|unseal[_-]?key|recovery[_-]?key|activation[_-]?(?:code|key))\b"
    r"\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,}\]]+)"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")
BASIC_AUTH_RE = re.compile(r"(?i)\bbasic\s+[a-z0-9+/]{4,}={0,2}")
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"
    r"(?![A-Za-z0-9_-])"
)
API_KEY_RE = re.compile(
    r"(?i)\b(?:gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[a-z0-9-]{10,}|sk-[a-z0-9_-]{20,})\b"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
URL_CREDENTIAL_RE = re.compile(r"(://[^\s/:@]+:)[^\s/@]+(@)")
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*:\s*).+$"
)
XML_SECRET_PROPERTY_RE = re.compile(
    r"(?is)(\bname\s*=\s*[\"'](?:password|passwd|secret|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|authorization|cookie|set-cookie|api[_-]?key|x[_-]?api[_-]?key|"
    r"private[_-]?key)[\"'][^>]*?\bvalue\s*=\s*[\"'])([^\"']*)([\"'])"
)


class EvidenceError(RuntimeError):
    """A fail-closed evidence processing error."""


@dataclass(frozen=True)
class Identity:
    """Required identity of one executed role/profile matrix result."""

    role: str
    profile: str
    scenario: str
    target: str
    run_attempt: str

    @property
    def cell_key(self) -> tuple[str, str, str, str]:
        return (self.scenario, self.profile, self.target, self.run_attempt)

    @property
    def result_key(self) -> tuple[str, str, str, str, str]:
        return (self.role, self.profile, self.scenario, self.target, self.run_attempt)

    @property
    def identifier(self) -> str:
        fields = (self.role, self.profile, self.scenario, self.target, f"attempt-{self.run_attempt}")
        return "/".join(slug(field) for field in fields)


@dataclass(frozen=True)
class CollectionArtifactIdentity:
    """Collection coordinates used to bind release security evidence."""

    namespace: str
    name: str
    version: str

    @property
    def candidate(self) -> str:
        return f"{self.namespace}-{self.name}-{self.version}.tar.gz"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def slug(value: object) -> str:
    rendered = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value).strip()).strip("-.")
    return rendered or "unknown"


def normalize_profile(value: object) -> str:
    profile = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    aliases = {
        "acceptance": "application-acceptance",
        "application": "application-acceptance",
        "application-acceptance": "application-acceptance",
    }
    return aliases.get(profile, profile or "unknown")


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _bounded_read(path: Path, limit: int = MAX_EVIDENCE_FILE_BYTES) -> bytes:
    """Read a regular evidence file without allowing unbounded memory use."""

    size = path.stat().st_size
    if size > limit:
        raise EvidenceError(f"{path}: file exceeds {limit}-byte evidence limit")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise EvidenceError(f"{path}: file exceeds {limit}-byte evidence limit")
    return data


def _strict_json_loads(value: str) -> Any:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key, item in pairs:
            if key in payload:
                raise EvidenceError(f"duplicate JSON key: {key}")
            payload[key] = item
        return payload

    return json.loads(value, object_pairs_hook=object_without_duplicates)


def redact_text(value: str) -> str:
    value = value.replace(CANARY, "[REDACTED]")
    value = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", value)
    value = BEARER_RE.sub("Bearer [REDACTED]", value)
    value = BASIC_AUTH_RE.sub("Basic [REDACTED]", value)
    value = JWT_RE.sub("[REDACTED JWT]", value)
    value = API_KEY_RE.sub("[REDACTED API KEY]", value)
    value = URL_CREDENTIAL_RE.sub(r"\1[REDACTED]\2", value)
    value = SENSITIVE_HEADER_RE.sub(lambda match: match.group(1) + "[REDACTED]", value)
    value = XML_SECRET_PROPERTY_RE.sub(lambda match: match.group(1) + "[REDACTED]" + match.group(3), value)
    return SECRET_ASSIGNMENT_RE.sub(lambda match: match.group(1) + "[REDACTED]", value)


def _structured_secret_label(value: Any) -> bool:
    return isinstance(value, str) and SECRET_KEY_RE.search(value) is not None


def _contains_unredacted_value(value: Any) -> bool:
    if isinstance(value, dict):
        return False
    if isinstance(value, list):
        return any(_contains_unredacted_value(item) for item in value)
    return isinstance(value, (str, bytes)) and value not in {"", "[REDACTED]", b"", b"[REDACTED]"}


def _contains_structured_secret_value(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_structured_secret_value(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_structured_secret_value(item) for item in value)
    return value not in {None, "", "[REDACTED]", b"", b"[REDACTED]"}


def redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {
            str(key): "[REDACTED]" if SECRET_KEY_RE.search(str(key)) else redact_json(item)
            for key, item in value.items()
        }
        label = next(
            (
                item
                for key, item in value.items()
                if str(key).lower() in {"name", "key", "header", "parameter", "field"}
                and _structured_secret_label(item)
            ),
            None,
        )
        if label is not None:
            for key in value:
                if str(key).lower() in {"value", "values", "content", "text", "default"}:
                    redacted[str(key)] = "[REDACTED]"
        return redacted
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value


def redact_strings(value: Any) -> Any:
    """Redact string values while preserving audit-schema field names."""

    if isinstance(value, dict):
        return {key: redact_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_strings(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value


def _redact_payload(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data.replace(CANARY_BYTES, b"[REDACTED]")
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        redacted_text = redact_text(text)
        return data if redacted_text == text else redacted_text.encode("utf-8")
    redacted = redact_json(parsed)
    if redacted == parsed:
        return data
    return (json.dumps(redacted, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _redact_zip(path: Path) -> bool:
    if not zipfile.is_zipfile(path):
        return False
    temporary = path.with_name(path.name + ".redacting")
    try:
        with (
            zipfile.ZipFile(path, "r") as source,
            zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as destination,
        ):
            members = source.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise EvidenceError(f"{path}: ZIP exceeds {MAX_ARCHIVE_MEMBERS}-member limit")
            total_size = sum(info.file_size for info in members if not info.is_dir())
            if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                raise EvidenceError(f"{path}: ZIP exceeds {MAX_ARCHIVE_TOTAL_BYTES}-byte expanded limit")
            for info in members:
                if info.is_dir():
                    destination.writestr(info, b"")
                    continue
                if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise EvidenceError(f"{path}!{info.filename}: member exceeds scan limit")
                compressed = max(info.compress_size, 1)
                if info.file_size / compressed > MAX_ARCHIVE_COMPRESSION_RATIO:
                    raise EvidenceError(f"{path}!{info.filename}: unsafe compression ratio")
                with source.open(info, "r") as member:
                    data = member.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                if len(data) > MAX_ARCHIVE_MEMBER_BYTES:
                    raise EvidenceError(f"{path}!{info.filename}: member exceeds scan limit")
                destination.writestr(info, _redact_payload(data))
        temporary.replace(path)
        return True
    finally:
        temporary.unlink(missing_ok=True)


def _tar_write_mode(path: Path) -> Literal["w", "w:gz", "w:bz2", "w:xz"]:
    lower = path.name.lower()
    if lower.endswith((".tar.gz", ".tgz")):
        return "w:gz"
    if lower.endswith((".tar.bz2", ".tbz2")):
        return "w:bz2"
    if lower.endswith((".tar.xz", ".txz")):
        return "w:xz"
    return "w"


def _redact_tar(path: Path) -> bool:
    try:
        is_tar = tarfile.is_tarfile(path)
    except OSError:
        return False
    if not is_tar:
        return False
    temporary = path.with_name(path.name + ".redacting")
    try:
        with tarfile.open(path, "r:*") as source, tarfile.open(temporary, _tar_write_mode(path)) as destination:
            members = source.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise EvidenceError(f"{path}: TAR exceeds {MAX_ARCHIVE_MEMBERS}-member limit")
            total_size = sum(member.size for member in members if member.isfile())
            if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                raise EvidenceError(f"{path}: TAR exceeds {MAX_ARCHIVE_TOTAL_BYTES}-byte expanded limit")
            if total_size / max(path.stat().st_size, 1) > MAX_ARCHIVE_COMPRESSION_RATIO:
                raise EvidenceError(f"{path}: unsafe TAR compression ratio")
            for member in members:
                cloned = copy.copy(member)
                if not member.isfile():
                    destination.addfile(cloned)
                    continue
                if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise EvidenceError(f"{path}!{member.name}: member exceeds scan limit")
                extracted = source.extractfile(member)
                if extracted is None:
                    destination.addfile(cloned, io.BytesIO())
                    continue
                data = extracted.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                if len(data) > MAX_ARCHIVE_MEMBER_BYTES:
                    raise EvidenceError(f"{path}!{member.name}: member exceeds scan limit")
                data = _redact_payload(data)
                cloned.size = len(data)
                destination.addfile(cloned, io.BytesIO(data))
        temporary.replace(path)
        return True
    finally:
        temporary.unlink(missing_ok=True)


def redact_file(path: Path) -> None:
    """Redact a regular file, including textual members of ZIP/TAR evidence."""

    if path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceError(f"{path}: file exceeds evidence limit")
    if _redact_zip(path) or _redact_tar(path):
        return
    if path.suffix.lower() == ".gz":
        try:
            with gzip.open(path, "rb") as stream:
                payload = stream.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
        except (OSError, EOFError):
            pass
        else:
            if len(payload) > MAX_ARCHIVE_MEMBER_BYTES:
                raise EvidenceError(f"{path}: GZIP payload exceeds scan limit")
            if len(payload) / max(path.stat().st_size, 1) > MAX_ARCHIVE_COMPRESSION_RATIO:
                raise EvidenceError(f"{path}: unsafe GZIP compression ratio")
            path.write_bytes(gzip.compress(_redact_payload(payload), mtime=0))
            return
    path.write_bytes(_redact_payload(_bounded_read(path)))


def _structured_secret_findings(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)) and _contains_unredacted_value(item):
                return True
        label = next(
            (
                item
                for key, item in value.items()
                if str(key).lower() in {"name", "key", "header", "parameter", "field"}
                and _structured_secret_label(item)
            ),
            None,
        )
        if label is not None:
            for key, item in value.items():
                if str(key).lower() in {"value", "values", "content", "text", "default"} and (
                    _contains_structured_secret_value(item)
                ):
                    return True
        return any(_structured_secret_findings(item) for item in value.values())
    if isinstance(value, list):
        return any(_structured_secret_findings(item) for item in value)
    return False


def _scan_payload(data: bytes, display_path: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if CANARY_BYTES in data:
        findings.append({"path": display_path, "kind": "canary"})
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="ignore")
    patterns = (
        ("private-key", PRIVATE_KEY_RE),
        ("bearer-token", BEARER_RE),
        ("basic-authorization", BASIC_AUTH_RE),
        ("jwt", JWT_RE),
        ("api-key", API_KEY_RE),
        ("url-credential", URL_CREDENTIAL_RE),
        ("sensitive-header", SENSITIVE_HEADER_RE),
        ("xml-secret-property", XML_SECRET_PROPERTY_RE),
        ("secret-assignment", SECRET_ASSIGNMENT_RE),
    )
    for kind, pattern in patterns:
        for match in pattern.finditer(text):
            matched = match.group(0)
            if "[REDACTED" in matched:
                continue
            findings.append({"path": display_path, "kind": kind})
            break
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if parsed is not None and _structured_secret_findings(parsed):
        findings.append({"path": display_path, "kind": "structured-secret"})
    return findings


def _scan_archive(path: Path, relative: str) -> tuple[list[dict[str, str]], int, list[str]]:
    findings: list[dict[str, str]] = []
    scanned = 0
    errors: list[str] = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as archive:
                zip_members = archive.infolist()
                if len(zip_members) > MAX_ARCHIVE_MEMBERS:
                    errors.append(f"{relative}: archive exceeds member limit")
                    return findings, scanned, errors
                expanded_total = 0
                for zip_member in zip_members:
                    if zip_member.is_dir():
                        continue
                    expanded_total += zip_member.file_size
                    if expanded_total > MAX_ARCHIVE_TOTAL_BYTES:
                        errors.append(f"{relative}: archive exceeds expanded-size limit")
                        break
                    if zip_member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                        errors.append(f"{relative}!{zip_member.filename}: member exceeds scan limit")
                        continue
                    if zip_member.file_size / max(zip_member.compress_size, 1) > MAX_ARCHIVE_COMPRESSION_RATIO:
                        errors.append(f"{relative}!{zip_member.filename}: unsafe compression ratio")
                        continue
                    with archive.open(zip_member, "r") as member:
                        data = member.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                    if len(data) > MAX_ARCHIVE_MEMBER_BYTES:
                        errors.append(f"{relative}!{zip_member.filename}: member exceeds scan limit")
                        continue
                    findings.extend(_scan_payload(data, f"{relative}!{zip_member.filename}"))
                    scanned += 1
            return findings, scanned, errors
        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                tar_members = archive.getmembers()
                if len(tar_members) > MAX_ARCHIVE_MEMBERS:
                    errors.append(f"{relative}: archive exceeds member limit")
                    return findings, scanned, errors
                tar_size = sum(member.size for member in tar_members if member.isfile())
                if tar_size / max(path.stat().st_size, 1) > MAX_ARCHIVE_COMPRESSION_RATIO:
                    errors.append(f"{relative}: unsafe TAR compression ratio")
                    return findings, scanned, errors
                expanded_total = 0
                for tar_member in tar_members:
                    if not tar_member.isfile():
                        continue
                    expanded_total += tar_member.size
                    if expanded_total > MAX_ARCHIVE_TOTAL_BYTES:
                        errors.append(f"{relative}: archive exceeds expanded-size limit")
                        break
                    if tar_member.size > MAX_ARCHIVE_MEMBER_BYTES:
                        errors.append(f"{relative}!{tar_member.name}: member exceeds scan limit")
                        continue
                    extracted = archive.extractfile(tar_member)
                    if extracted is not None:
                        data = extracted.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                        if len(data) > MAX_ARCHIVE_MEMBER_BYTES:
                            errors.append(f"{relative}!{tar_member.name}: member exceeds scan limit")
                            continue
                        findings.extend(_scan_payload(data, f"{relative}!{tar_member.name}"))
                        scanned += 1
            return findings, scanned, errors
        if path.suffix.lower() == ".gz":
            with gzip.open(path, "rb") as archive:
                data = archive.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
            if len(data) > MAX_ARCHIVE_MEMBER_BYTES:
                errors.append(f"{relative}: GZIP payload exceeds scan limit")
            elif len(data) / max(path.stat().st_size, 1) > MAX_ARCHIVE_COMPRESSION_RATIO:
                errors.append(f"{relative}: unsafe GZIP compression ratio")
            else:
                findings.extend(_scan_payload(data, f"{relative}!gzip-payload"))
                scanned += 1
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile) as error:
        errors.append(f"{relative}: archive scan failed: {error}")
    return findings, scanned, errors


def _final_verifier() -> Any:
    # Package and direct-script entry points share the same fixed sibling. Keep
    # this lazy: copied preliminary/legacy collectors do not need the verifier.
    prefix = __package__ + "." if __package__ else ""
    return importlib.import_module(prefix + "g06_final_quality")


def scan_evidence(root: Path, *, final_inputs=None) -> dict[str, Any]:
    """Scan final text, binary, and archive content without recording values."""

    masks = {}
    if final_inputs is not None:
        g06_final_quality = _final_verifier()

        masks = g06_final_quality.scanner_payloads(final_inputs)
    findings: list[dict[str, str]] = []
    errors: list[str] = []
    files_scanned = 0
    archive_members_scanned = 0
    bytes_scanned = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        files_scanned += 1
        if files_scanned > MAX_EVIDENCE_FILES:
            errors.append(f"evidence set exceeds {MAX_EVIDENCE_FILES}-file limit")
            break
        try:
            size = path.stat().st_size
            bytes_scanned += size
            if bytes_scanned > MAX_EVIDENCE_TOTAL_BYTES:
                errors.append(f"evidence set exceeds {MAX_EVIDENCE_TOTAL_BYTES}-byte limit")
                break
            data = _bounded_read(path)
        except (OSError, EvidenceError) as error:
            errors.append(f"{relative}: {error}")
            continue
        if path.resolve() in masks:
            original, scanned = masks[path.resolve()]
            if data != original:
                raise EvidenceError("verified final envelope changed during scan")
            data = scanned
        findings.extend(_scan_payload(data, relative))
        archive_findings, member_count, archive_errors = _scan_archive(path, relative)
        findings.extend(archive_findings)
        archive_members_scanned += member_count
        errors.extend(archive_errors)
    deduplicated = sorted({(item["path"], item["kind"]) for item in findings})
    return {
        "clean": not deduplicated and not errors,
        "files_scanned": files_scanned,
        "archive_members_scanned": archive_members_scanned,
        "findings": [{"path": path, "kind": kind} for path, kind in deduplicated],
        "errors": errors,
    }


def _properties(root: ET.Element) -> dict[str, str]:
    properties: dict[str, str] = {}
    containers = [element for element in root.iter() if local_name(element.tag) in {"testsuite", "testsuites"}]
    for container in containers:
        for property_container in container:
            if local_name(property_container.tag) != "properties":
                continue
            for element in property_container:
                if local_name(element.tag) != "property":
                    continue
                name = str(element.attrib.get("name", "")).strip().lower().replace(".", "_")
                if not name:
                    continue
                value = element.attrib.get("value")
                properties[name] = str(value if value is not None else element.text or "").strip()
    for key, value in root.attrib.items():
        properties.setdefault(str(key).strip().lower().replace(".", "_"), str(value).strip())
    return properties


def _split_roles(value: object) -> list[str]:
    if isinstance(value, list):
        return sorted({str(item).strip() for item in value if str(item).strip()})
    return sorted({item.strip() for item in str(value or "").split(",") if item.strip()})


def _case_details(testcase: ET.Element) -> dict[str, Any]:
    status = "passed"
    problem: ET.Element | None = None
    for child in testcase:
        kind = local_name(child.tag)
        if kind in {"failure", "error", "skipped"}:
            status = kind
            problem = child
            break
    duration_value = testcase.attrib.get("time", "0")
    try:
        duration = max(float(duration_value), 0.0)
    except (TypeError, ValueError):
        duration = 0.0
    details: dict[str, Any] = {
        "classname": str(testcase.attrib.get("classname", "unknown")),
        "name": str(testcase.attrib.get("name", "unnamed")),
        "status": status,
        "duration_seconds": duration,
    }
    case_properties: dict[str, str] = {}
    for child in testcase:
        if local_name(child.tag) != "properties":
            continue
        for element in child:
            if local_name(element.tag) != "property":
                continue
            name = str(element.attrib.get("name", "")).strip().lower().replace(".", "_")
            value = element.attrib.get("value")
            case_properties[name] = str(value if value is not None else element.text or "").strip()
    explicit_roles = (
        testcase.attrib.get("roles")
        or testcase.attrib.get("role")
        or case_properties.get("roles")
        or case_properties.get("role")
        or ""
    )
    details["roles"] = _split_roles(explicit_roles)
    if problem is not None:
        details["message"] = str(problem.attrib.get("message") or (problem.text or "").strip())[:4000]
        details["type"] = str(problem.attrib.get("type", ""))
        if status == "skipped":
            approved = str(problem.attrib.get("approved", "")).lower() in {"1", "true", "yes"}
            details["approved"] = approved
    return details


def _is_opaque_process_case(test_cases: Sequence[dict[str, Any]]) -> bool:
    if len(test_cases) != 1:
        return False
    rendered = f"{test_cases[0].get('classname', '')} {test_cases[0].get('name', '')}".lower()
    process_tokens = (
        "molecule process",
        "molecule-process",
        "scenario process",
        "scenario execution",
        "process exit",
        "command exit",
        "molecule test",
    )
    return any(token in rendered for token in process_tokens)


def parse_junit(path: Path) -> dict[str, Any]:
    """Parse JUnit from real testcases, ignoring untrustworthy suite counters."""

    raw = _bounded_read(path)
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise EvidenceError("JUnit document contains a forbidden DTD or entity")
    try:
        # ElementTree is safe here because DTD/entity declarations were rejected above.
        root = ET.fromstring(raw)  # noqa: S314
    except ET.ParseError as error:
        raise EvidenceError(f"malformed JUnit: {error}") from error
    if local_name(root.tag) not in {"testsuite", "testsuites"}:
        raise EvidenceError(f"unsupported JUnit root element: {local_name(root.tag)}")
    test_cases = [_case_details(element) for element in root.iter() if local_name(element.tag) == "testcase"]
    if not test_cases:
        raise EvidenceError("JUnit contains no individual testcases")
    properties = _properties(root)
    suite_roles = _split_roles(_property(properties, "roles", "role"))
    if len(suite_roles) == 1:
        for case in test_cases:
            if not case["roles"]:
                case["roles"] = list(suite_roles)
    elif len(suite_roles) > 1:
        for case in test_cases:
            if not case["roles"]:
                continue
            if len(case["roles"]) != 1:
                raise EvidenceError("multi-role JUnit requires exactly one explicit role per testcase")
            if not set(case["roles"]) <= set(suite_roles):
                raise EvidenceError("JUnit testcase role is not declared by the suite")
    totals = {
        "tests": len(test_cases),
        "failures": sum(case["status"] == "failure" for case in test_cases),
        "errors": sum(case["status"] == "error" for case in test_cases),
        "skipped": sum(case["status"] == "skipped" for case in test_cases),
    }
    approved_property = any(
        properties.get(key, "").lower() in {"1", "true", "yes", "approved"}
        for key in ("approved_skip", "skip_approved")
    ) or bool(properties.get("approved_justification", "").strip())
    skipped_cases = [case for case in test_cases if case["status"] == "skipped"]
    skips_approved = bool(skipped_cases) and (
        approved_property or all(case.get("approved") and case.get("message") for case in skipped_cases)
    )
    opaque = _is_opaque_process_case(test_cases)
    evidence_fallback = properties.get("framework", "").lower() == "evidence-fallback"
    if evidence_fallback:
        status = "infrastructure-error"
    elif totals["failures"] or totals["errors"] or opaque:
        status = "failed"
    elif totals["skipped"]:
        status = "skipped-with-approved-justification" if skips_approved else "failed"
    else:
        status = "passed"
    suite_names = [
        str(element.attrib.get("name", ""))
        for element in root.iter()
        if local_name(element.tag) in {"testsuite", "testsuites"}
    ]
    framework = properties.get("framework", "").lower()
    if not framework and any("pytest" in name.lower() for name in suite_names):
        framework = "pytest"
    logical_payload = {
        "test_cases": test_cases,
        "totals": totals,
        "status": status,
    }
    return {
        "status": status,
        "totals": totals,
        "test_cases": test_cases,
        "properties": properties,
        "framework": framework or "junit",
        "meaningful": not opaque,
        "suite_names": [name for name in suite_names if name],
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "logical_sha256": hashlib.sha256(
            json.dumps(logical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def _report_for_role(report: dict[str, Any], role: str, declared_roles: Sequence[str]) -> dict[str, Any]:
    """Return only testcases explicitly attributable to one role."""

    declared = set(declared_roles)
    cases = report["test_cases"]
    if len(declared) > 1:
        missing = [case["name"] for case in cases if not case.get("roles")]
        if missing:
            raise EvidenceError("multi-role JUnit lacks explicit per-test role identity: " + ", ".join(sorted(missing)))
    selected = [copy.deepcopy(case) for case in cases if role in set(case.get("roles", []))]
    if not selected:
        raise EvidenceError(f"JUnit contains no meaningful testcase explicitly assigned to role {role}")
    totals = {
        "tests": len(selected),
        "failures": sum(case["status"] == "failure" for case in selected),
        "errors": sum(case["status"] == "error" for case in selected),
        "skipped": sum(case["status"] == "skipped" for case in selected),
    }
    skipped = [case for case in selected if case["status"] == "skipped"]
    approved = bool(skipped) and all(case.get("approved") and case.get("message") for case in skipped)
    opaque = _is_opaque_process_case(selected)
    if report.get("framework") == "evidence-fallback" or report.get("infrastructure_error"):
        status = "infrastructure-error"
    elif totals["failures"] or totals["errors"] or opaque:
        status = "failed"
    elif totals["skipped"]:
        status = "skipped-with-approved-justification" if approved else "failed"
    else:
        status = "passed"
    logical_payload = {"test_cases": selected, "totals": totals, "status": status}
    scoped = {
        **report,
        "status": status,
        "totals": totals,
        "test_cases": selected,
        "meaningful": not opaque,
        "logical_sha256": hashlib.sha256(
            json.dumps(logical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    return scoped


def load_registry(path: Path | None) -> tuple[dict[str, Any], list[str]]:
    if path is None or not path.is_file():
        return {}, []
    try:
        import yaml
    except ImportError as error:
        raise EvidenceError("PyYAML is required to consume meta/role-coverage.yml") from error
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise EvidenceError(f"cannot parse coverage registry {path}: {error}") from error
    if not isinstance(data, dict):
        raise EvidenceError("coverage registry must be a mapping")
    errors: list[str] = []
    if not isinstance(data.get("roles", {}), (dict, list)):
        errors.append("coverage registry roles must be a mapping or list")
    if not isinstance(data.get("scenarios", {}), (dict, list)):
        errors.append("coverage registry scenarios must be a mapping or list")
    errors.extend(shared_scenario_target_errors(data))
    return data, errors


def _mapping_by_name(value: Any) -> dict[str, dict[str, Any]]:
    if isinstance(value, dict):
        return {str(key): item if isinstance(item, dict) else {} for key, item in value.items()}
    if isinstance(value, list):
        result: dict[str, dict[str, Any]] = {}
        for item in value:
            if isinstance(item, dict) and item.get("name"):
                result[str(item["name"])] = item
        return result
    return {}


def registry_roles(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return _mapping_by_name(registry.get("roles", {}))


def registry_scenarios(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return _mapping_by_name(registry.get("scenarios", {}))


def registry_targets(registry: dict[str, Any]) -> set[str]:
    targets = registry.get("targets", {})
    if isinstance(targets, dict):
        return {str(item) for item in targets}
    if isinstance(targets, list):
        return {str(item.get("name")) if isinstance(item, dict) else str(item) for item in targets}
    return set()


def _shared_scenario_target_set(
    roles: dict[str, dict[str, Any]],
    scenario_name: str,
    production_roles: Sequence[str],
    target_field: str,
) -> set[str]:
    target_sets = {
        role_name: frozenset(str(target) for target in roles[role_name].get(target_field, []))
        for role_name in production_roles
    }
    if len(set(target_sets.values())) > 1:
        detail = ", ".join(f"{role_name}={sorted(targets)}" for role_name, targets in sorted(target_sets.items()))
        raise EvidenceError(
            f"scenario {scenario_name} production roles must declare identical {target_field}; {detail}"
        )
    return set(next(iter(target_sets.values()), frozenset()))


def shared_scenario_target_errors(registry: dict[str, Any]) -> list[str]:
    """Reject target ambiguity before evidence can omit a shared role silently."""

    roles = registry_roles(registry)
    errors: list[str] = []
    for scenario_name, scenario in registry_scenarios(registry).items():
        profile = normalize_profile(scenario.get("profile"))
        if (
            profile not in PROFILES
            or str(scenario.get("state", "")) != "supported"
            or str(scenario.get("implementation", "")) != "real"
        ):
            continue
        scenario_roles = _split_roles(scenario.get("roles", []))
        production_roles = sorted(
            role_name
            for role_name in scenario_roles
            if role_name in roles
            and str(roles[role_name].get("maturity", "")).lower() in {"production", "production-supported", "stable"}
            and str(roles[role_name].get(PROFILE_REGISTRY_KEYS[profile], "")) == "supported"
        )
        if len(production_roles) < 2:
            continue
        for target_field in ("supported_targets", "candidate_targets"):
            try:
                _shared_scenario_target_set(roles, scenario_name, production_roles, target_field)
            except EvidenceError as error:
                errors.append(str(error))
    return errors


def expected_cells(
    registry: dict[str, Any],
    *,
    run_attempt: str,
    role_filter: set[str] | None = None,
    profile_filter: set[str] | None = None,
    scenario_filter: set[str] | None = None,
    target_filter: set[str] | None = None,
    target_disposition: str = "supported",
) -> list[dict[str, Any]]:
    """Build production cells for one explicit target disposition."""

    if target_disposition not in {"supported", "candidate"}:
        raise EvidenceError(f"unknown target disposition: {target_disposition}")

    roles = registry_roles(registry)
    scenarios = registry_scenarios(registry)
    cells: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for scenario_name, scenario in scenarios.items():
        profile = normalize_profile(scenario.get("profile"))
        if profile not in PROFILES or (profile_filter and profile not in profile_filter):
            continue
        if scenario_filter and scenario_name not in scenario_filter:
            continue
        if str(scenario.get("state", "supported")) != "supported":
            continue
        if str(scenario.get("implementation", "real")) != "real":
            continue
        scenario_role_names = scenario.get("roles", [])
        if isinstance(scenario_role_names, str):
            scenario_role_names = [scenario_role_names]
        if not isinstance(scenario_role_names, list):
            continue
        profile_key = PROFILE_REGISTRY_KEYS[profile]
        all_production_roles = sorted(
            role_name
            for role_name in (str(value) for value in scenario_role_names)
            if role_name in roles
            and str(roles[role_name].get("maturity", "")).lower() in {"production", "production-supported", "stable"}
            and str(roles[role_name].get(profile_key, "")) == "supported"
        )
        target_field = "supported_targets" if target_disposition == "supported" else "candidate_targets"
        selected_targets = _shared_scenario_target_set(
            roles,
            scenario_name,
            all_production_roles,
            target_field,
        )
        production_roles = [
            role_name for role_name in all_production_roles if not role_filter or role_name in role_filter
        ]
        if not production_roles:
            continue
        for target in sorted(selected_targets):
            if target_filter and target not in target_filter:
                continue
            if target not in registry_targets(registry):
                continue
            key = (scenario_name, profile, target, run_attempt)
            cells[key] = {
                "scenario": scenario_name,
                "profile": profile,
                "target": target,
                "run_attempt": run_attempt,
                "roles": production_roles,
                "required": True,
                "target_disposition": target_disposition,
                "release_required": target_disposition == "supported",
            }
    return [cells[key] for key in sorted(cells)]


def declared_dispositions(registry: dict[str, Any]) -> list[dict[str, str]]:
    dispositions: list[dict[str, str]] = []
    for role_name, role in registry_roles(registry).items():
        for profile, key in PROFILE_REGISTRY_KEYS.items():
            state = str(role.get(key, ""))
            if state in {"not-applicable", *BLOCKED_STATUSES}:
                dispositions.append({"role": role_name, "profile": profile, "status": state})
    return sorted(dispositions, key=lambda item: (item["role"], item["profile"]))


def _path_contains_token(path: Path, token: str) -> bool:
    normalized_path = path.as_posix().lower().replace("_", "-")
    normalized_token = str(token).lower().replace("_", "-")
    return normalized_token in normalized_path


def _property(properties: dict[str, str], *names: str) -> str:
    for name in names:
        normalized = name.lower().replace(".", "_")
        if properties.get(normalized):
            return properties[normalized]
    return ""


def _valid_commit(value: str) -> bool:
    return re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None


def _tested_commit() -> str:
    """Return the exact source SHA selected and checked out by the workflow."""
    return os.getenv("QUALITY_SOURCE_SHA") or os.getenv("GITHUB_SHA") or "unknown"


def _report_commit(report: dict[str, Any]) -> str:
    return _property(report.get("properties", {}), "commit_sha", "git_commit", "github_sha")


def infer_report_identity(
    report: dict[str, Any],
    source_path: Path,
    registry: dict[str, Any],
    *,
    default_roles: Sequence[str],
    default_profiles: Sequence[str],
    default_scenarios: Sequence[str],
    default_targets: Sequence[str],
    default_attempt: str,
) -> dict[str, Any]:
    properties = report["properties"]
    scenarios = registry_scenarios(registry)
    known_scenarios = set(scenarios) | set(default_scenarios)
    scenario = _property(properties, "scenario", "quality_scenario", "molecule_scenario")
    if not scenario:
        matches = [item for item in known_scenarios if _path_contains_token(source_path, item)]
        if matches:
            scenario = max(matches, key=len)
    if not scenario and len(default_scenarios) == 1:
        scenario = default_scenarios[0]
    scenario = scenario or source_path.stem

    profile = normalize_profile(_property(properties, "profile", "quality_profile", "test_profile"))
    if profile == "unknown" and scenario in scenarios:
        profile = normalize_profile(scenarios[scenario].get("profile"))
    if profile == "unknown":
        for candidate in PROFILES:
            if _path_contains_token(source_path, candidate) or candidate in scenario.replace("_", "-"):
                profile = candidate
                break
    if profile == "unknown" and len(default_profiles) == 1:
        profile = normalize_profile(default_profiles[0])

    role_value = _property(properties, "role", "roles", "quality_role", "ansible_role")
    roles = [item.strip() for item in role_value.split(",") if item.strip()]
    if not roles and scenario in scenarios:
        configured = scenarios[scenario].get("roles", [])
        roles = [configured] if isinstance(configured, str) else [str(item) for item in configured]
    if not roles:
        roles = list(default_roles)
    if not roles:
        known_roles = registry_roles(registry)
        matches = [item for item in known_roles if _path_contains_token(source_path, item)]
        if matches:
            roles = [max(matches, key=len)]
    roles = sorted(set(roles or ["unknown"]))

    target = _property(properties, "target", "quality_target", "target_os", "platform")
    if not target:
        matches = [item for item in registry_targets(registry) if _path_contains_token(source_path, item)]
        if matches:
            target = max(matches, key=len)
    if not target and len(default_targets) == 1:
        target = default_targets[0]
    target = target or "unknown"

    attempt = _property(properties, "run_attempt", "workflow_attempt", "github_run_attempt")
    if not attempt:
        match = re.search(r"(?:run[-_])?attempt[-_]?([0-9]+)", source_path.as_posix(), re.IGNORECASE)
        attempt = match.group(1) if match else default_attempt
    return {
        "roles": roles,
        "profile": profile,
        "scenario": scenario,
        "target": target,
        "run_attempt": str(attempt or "1"),
    }


def _safe_relative(path: Path, base: Path) -> Path:
    try:
        relative = path.resolve().relative_to(base.resolve())
    except ValueError:
        relative = Path(path.name)
    return Path(*(slug(part) for part in relative.parts))


def _copy_unique(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        shutil.copy2(source, destination)
        return destination
    if source.is_file() and sha256(source) == sha256(destination):
        return destination
    suffix = hashlib.sha256(source.as_posix().encode("utf-8")).hexdigest()[:10]
    candidate = destination.with_name(f"{destination.stem}-{suffix}{destination.suffix}")
    shutil.copy2(source, candidate)
    return candidate


def _artifact_category(path: Path) -> str | None:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    suffix = path.suffix.lower()
    if parts & {"junit", "test-results", "test_results"} and suffix == ".xml":
        return "junit"
    if "allure-results" in parts:
        return "allure-results"
    if "allure-report" in parts:
        return "allure-report"
    if parts & {"screenshots", "screenshot"} or "screenshot" in name:
        return "screenshots"
    if parts & {"playwright-traces", "traces", "trace"} or name in {"trace.zip", "playwright-trace.zip"}:
        return "playwright-traces"
    if parts & {"logs", "log", "browser-diagnostics", "diagnostics"} or suffix in {
        ".log",
        ".out",
        ".stderr",
        ".stdout",
    }:
        return "logs"
    if (
        parts & {"configuration", "config"}
        or name in {"environment.json", "result.json"}
        or any(
            token in name for token in ("sanitized-inventory", "effective-vars", "test-matrix", "environment-metadata")
        )
    ):
        return "configuration"
    dependency_names = {
        "requirements.txt",
        "constraints.txt",
        "poetry.lock",
        "pipfile.lock",
        "package-lock.json",
        "yarn.lock",
        "galaxy.yml",
    }
    if "dependencies" in parts or name in dependency_names or name.endswith("-version.txt") or "digest" in name:
        return "dependencies"
    return None


def _is_excluded_artifact_path(path: Path, excluded_resolved: Sequence[Path]) -> bool:
    resolved = path.resolve()
    parent_resolved = path.parent.resolve()
    return any(
        resolved == excluded
        or excluded in resolved.parents
        or parent_resolved == excluded
        or excluded in parent_resolved.parents
        for excluded in excluded_resolved
    )


def _cell_manifest_references(input_root: Path, excluded_resolved: Sequence[Path]) -> tuple[list[Path], set[Path]]:
    """Return assembled cell roots and their exact JUnit/Allure references."""
    cell_roots: list[Path] = []
    references: set[Path] = set()
    input_root_resolved = input_root.resolve()
    for manifest_path in _bounded_artifact_walk(
        input_root,
        name="manifest.json",
        excluded_resolved=excluded_resolved,
    ):
        relative = manifest_path.relative_to(input_root)
        if "root-final-inputs" in relative.parts:
            continue
        current = input_root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise EvidenceError(f"symlinked cell manifest: {relative.as_posix()}")
        manifest_resolved = manifest_path.resolve()
        if input_root_resolved not in manifest_resolved.parents:
            raise EvidenceError(f"cell manifest escapes artifact root: {relative.as_posix()}")
        try:
            payload = _strict_json_loads(_bounded_read(manifest_path).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
            raise EvidenceError(f"invalid cell manifest: {relative.as_posix()}") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise EvidenceError(f"invalid cell manifest schema: {relative.as_posix()}")
        cell_root = manifest_path.parent.resolve()
        cell_roots.append(cell_root)
        for result in payload["results"]:
            if not isinstance(result, dict):
                raise EvidenceError(f"cell manifest has invalid result: {relative.as_posix()}")
            for field in ("junit", "allure_results"):
                values = result.get(field, [])
                if not isinstance(values, list):
                    raise EvidenceError(f"cell manifest has invalid {field} references: {relative.as_posix()}")
                for value in values:
                    if not isinstance(value, str):
                        raise EvidenceError(f"cell manifest has non-string {field} reference: {relative.as_posix()}")
                    reference = PurePosixPath(value)
                    if reference.is_absolute() or ".." in reference.parts or not reference.parts:
                        raise EvidenceError(
                            f"cell manifest has unsafe {field} reference in {relative.as_posix()}: {value}"
                        )
                    unresolved = cell_root / Path(*reference.parts)
                    current = cell_root
                    for part in reference.parts:
                        current /= part
                        if current.is_symlink():
                            raise EvidenceError(
                                f"cell manifest has symlinked {field} reference in {relative.as_posix()}: {value}"
                            )
                    candidate = unresolved.resolve()
                    if candidate == cell_root or cell_root not in candidate.parents:
                        raise EvidenceError(
                            f"cell manifest has unsafe {field} reference in {relative.as_posix()}: {value}"
                        )
                    if not unresolved.is_file():
                        raise EvidenceError(
                            f"cell manifest has missing {field} reference in {relative.as_posix()}: {value}"
                        )
                    references.add(candidate)
    return cell_roots, references


def _bounded_artifact_walk(
    root: Path,
    *,
    name: str | None = None,
    excluded_resolved: Sequence[Path] = (),
) -> Iterable[Path]:
    """Yield artifact entries deterministically without materializing an untrusted tree."""
    examined_entries = 0
    for directory, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        directories[:] = sorted(
            entry for entry in directories if not _is_excluded_artifact_path(current / entry, excluded_resolved)
        )
        filenames = sorted(
            entry for entry in filenames if not _is_excluded_artifact_path(current / entry, excluded_resolved)
        )
        for entry_name in (*directories, *filenames):
            examined_entries += 1
            if examined_entries > MAX_EVIDENCE_FILES:
                raise EvidenceError(f"artifact inputs exceed {MAX_EVIDENCE_FILES}-entry traversal limit")
            if name is None or entry_name == name:
                yield Path(directory) / entry_name


def copy_artifacts(input_roots: Sequence[Path], destination_root: Path, excluded: Sequence[Path]) -> list[Path]:
    junit_destinations: list[Path] = []
    excluded_resolved = [item.resolve() for item in excluded]
    copied_files = 0
    copied_bytes = 0
    examined_files = 0
    for input_root in input_roots:
        if input_root.is_symlink():
            raise EvidenceError(f"symlinked artifact input root: {input_root}")
        if not input_root.exists():
            continue
        input_root_resolved = input_root.resolve()
        cell_roots, cell_references = _cell_manifest_references(input_root, excluded_resolved)
        for source in _bounded_artifact_walk(input_root, excluded_resolved=excluded_resolved):
            relative_source = source.relative_to(input_root)
            if "root-final-inputs" in relative_source.parts:
                continue  # Retained proof bytes are copied separately, never duplicate reports.
            if source.is_symlink():
                raise EvidenceError(f"symlinked artifact input: {relative_source.as_posix()}")
            if not source.is_file():
                continue
            examined_files += 1
            if examined_files > MAX_EVIDENCE_FILES:
                raise EvidenceError(f"artifact inputs exceed {MAX_EVIDENCE_FILES}-file traversal limit")
            resolved = source.resolve()
            if input_root_resolved not in resolved.parents:
                raise EvidenceError(f"artifact input escapes root: {relative_source.as_posix()}")
            if any(resolved == item or item in resolved.parents for item in excluded_resolved):
                continue
            category = _artifact_category(source.relative_to(input_root))
            if category is None:
                continue
            if category in {"junit", "allure-results"} and any(
                resolved == cell_root or cell_root in resolved.parents for cell_root in cell_roots
            ):
                if resolved not in cell_references:
                    continue
            size = source.stat().st_size
            copied_files += 1
            copied_bytes += size
            if copied_files > MAX_EVIDENCE_FILES:
                raise EvidenceError(f"artifact inputs exceed {MAX_EVIDENCE_FILES}-file limit")
            if size > MAX_EVIDENCE_FILE_BYTES or copied_bytes > MAX_EVIDENCE_TOTAL_BYTES:
                raise EvidenceError("artifact inputs exceed bounded evidence size limits")
            relative = _safe_relative(source, input_root)
            category_names = set(EVIDENCE_DIRECTORIES) | {"test-results", "test_results"}
            if cell_roots:
                category_index = next(
                    (index for index, part in enumerate(relative.parts) if part.lower() in category_names),
                    None,
                )
                if category_index is not None:
                    remaining = relative.parts[category_index + 1 :]
                    relative = Path(*remaining) if remaining else Path(source.name)
                # Downloaded Actions artifacts are expanded below an
                # implementation detail such as expanded/archive-1. Strip it
                # only when re-aggregating an already assembled cell bundle.
                while len(relative.parts) >= 2 and relative.parts[0].lower() == "expanded":
                    relative = Path(*relative.parts[2:]) if len(relative.parts) > 2 else Path(source.name)
            elif relative.parts and relative.parts[0].lower() in category_names:
                relative = Path(*relative.parts[1:]) if len(relative.parts) > 1 else Path(source.name)
            destination = _copy_unique(source, destination_root / category / relative)
            if category == "junit":
                junit_destinations.append(destination)
    return sorted(set(junit_destinations))


def _allure_status(case_status: str) -> str:
    return {"passed": "passed", "failure": "failed", "error": "broken", "skipped": "skipped"}.get(case_status, "broken")


def generate_allure_result(
    root: Path,
    identity: Identity,
    case: dict[str, Any],
    *,
    ordinal: int,
    source_junit: str,
) -> str:
    seed = f"{identity.identifier}|{case.get('classname')}|{case.get('name')}|{ordinal}|{source_junit}"
    result_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
    duration_ms = max(int(float(case.get("duration_seconds", 0)) * 1000), 0)
    now_ms = int(time.time() * 1000)
    status = _allure_status(str(case.get("status")))
    payload: dict[str, Any] = {
        "uuid": result_uuid,
        "historyId": hashlib.sha256(seed.encode("utf-8")).hexdigest(),
        "testCaseId": hashlib.sha256(
            f"{identity.role}|{identity.profile}|{case.get('classname')}|{case.get('name')}".encode()
        ).hexdigest(),
        "name": str(case.get("name", "unnamed")),
        "fullName": f"{case.get('classname', 'unknown')}.{case.get('name', 'unnamed')}",
        "status": status,
        "stage": "finished",
        "start": now_ms - duration_ms,
        "stop": now_ms,
        "labels": [
            {"name": "framework", "value": "junit-derived"},
            {"name": "role", "value": identity.role},
            {"name": "profile", "value": identity.profile},
            {"name": "suite", "value": identity.scenario},
            {"name": "host", "value": identity.target},
            {"name": "runAttempt", "value": identity.run_attempt},
            {"name": "commit_sha", "value": _tested_commit()},
        ],
        "parameters": [
            {"name": "role", "value": identity.role},
            {"name": "profile", "value": identity.profile},
            {"name": "scenario", "value": identity.scenario},
            {"name": "target", "value": identity.target},
            {"name": "run_attempt", "value": identity.run_attempt},
        ],
        "attachments": [],
        "links": [],
        "sourceJunit": source_junit,
    }
    if case.get("message"):
        payload["statusDetails"] = {
            "message": str(case["message"]),
            "trace": str(case["message"]),
        }
    relative = Path("allure-results") / f"{result_uuid}-result.json"
    (root / relative).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return relative.as_posix()


def _native_allure_results(root: Path) -> list[tuple[str, dict[str, Any]]]:
    results: list[tuple[str, dict[str, Any]]] = []
    for path in sorted((root / "allure-results").rglob("*-result.json")):
        try:
            payload = _strict_json_loads(_bounded_read(path).decode("utf-8"))
        except (OSError, EvidenceError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("name"):
            results.append((path.relative_to(root).as_posix(), payload))
    return results


def _allure_identity(payload: dict[str, Any]) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}
    for collection in (payload.get("labels", []), payload.get("parameters", [])):
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip().lower().replace("_", "-")
            value = str(item.get("value", "")).strip()
            if name and value:
                values.setdefault(name, set()).add(value)
    return values


def _allure_has_identity(payload: dict[str, Any], identity: Identity, commit_sha: str) -> bool:
    if not _valid_commit(commit_sha):
        return False
    labels = _allure_identity(payload)
    checks = (
        ({"role"}, identity.role),
        ({"profile"}, identity.profile),
        ({"suite", "scenario"}, identity.scenario),
        ({"host", "target"}, identity.target),
        ({"runattempt", "run-attempt"}, identity.run_attempt),
        ({"commit-sha"}, commit_sha),
    )
    for names, expected in checks:
        observed = set().union(*(labels.get(name, set()) for name in names))
        if observed != {expected}:
            return False
    return True


def _allure_has_testcase_identity(payload: dict[str, Any], case: dict[str, Any]) -> bool:
    """Require the native result to identify the same named JUnit testcase."""

    name = str(case.get("name", ""))
    classname = str(case.get("classname", ""))
    full_name = str(payload.get("fullName", ""))
    if not name or not classname or str(payload.get("name", "")) != name or not full_name:
        return False
    normalized = full_name.replace("#", ".").replace("::", ".")
    base_name = name.split("[", 1)[0]
    classnames = tuple(dict.fromkeys((classname, classname.rsplit(".", 1)[-1])))
    test_names = tuple(dict.fromkeys((name, base_name)))
    return any(
        normalized == f"{candidate}.{test_name}" or normalized.endswith(f".{candidate}.{test_name}")
        for candidate in classnames
        for test_name in test_names
    )


def _native_matches(
    cases: Sequence[dict[str, Any]],
    native: Sequence[tuple[str, dict[str, Any]]],
    identity: Identity,
    *,
    commit_sha: str | None = None,
    used_paths: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Match exactly one status- and identity-consistent Allure result per JUnit testcase."""

    matches: list[str] = []
    failures: list[str] = []
    used = used_paths if used_paths is not None else set()
    expected_commit = str(commit_sha or _tested_commit())
    for case in cases:
        case_name = str(case.get("name", ""))
        candidates: list[tuple[str, dict[str, Any]]] = []
        for path, payload in native:
            if path in used:
                continue
            if not _allure_has_testcase_identity(payload, case):
                continue
            if not _allure_has_identity(payload, identity, expected_commit):
                continue
            candidates.append((path, payload))
        if len(candidates) != 1:
            failures.append(f"{identity.identifier}: testcase {case_name!r} has {len(candidates)} exact Allure matches")
            continue
        path, payload = candidates[0]
        used.add(path)
        expected_status = _allure_status(str(case.get("status", "")))
        observed_status = str(payload.get("status", ""))
        if observed_status != expected_status:
            failures.append(
                f"{identity.identifier}: testcase {case_name!r} has Allure status "
                f"{observed_status or '<missing>'}, expected {expected_status}"
            )
            continue
        matches.append(path)
    return sorted(matches), failures


def _fallback_junit(root: Path, identity: Identity, reason: str) -> tuple[str, dict[str, Any]]:
    relative = Path("junit") / "fallback" / f"{identity.identifier.replace('/', '--')}.xml"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    suite = ET.Element(
        "testsuite",
        {"name": identity.scenario, "tests": "1", "failures": "0", "errors": "1", "skipped": "0"},
    )
    properties = ET.SubElement(suite, "properties")
    for name, value in (
        ("role", identity.role),
        ("profile", identity.profile),
        ("scenario", identity.scenario),
        ("target", identity.target),
        ("run_attempt", identity.run_attempt),
        ("framework", "evidence-fallback"),
    ):
        ET.SubElement(properties, "property", {"name": name, "value": value})
    case = ET.SubElement(suite, "testcase", {"classname": "evidence.junit", "name": "JUnit evidence unavailable"})
    error = ET.SubElement(case, "error", {"type": "infrastructure-error", "message": reason})
    error.text = reason
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
    parsed = parse_junit(path)
    parsed["status"] = "infrastructure-error"
    parsed["infrastructure_error"] = reason
    return relative.as_posix(), parsed


def _annotate_junit(path: Path, identity: Identity, roles: Sequence[str]) -> None:
    """Embed matrix identity in a copied JUnit document for later aggregation."""

    # ``parse_junit`` has already rejected DTD/entity declarations in this exact file.
    tree = ET.parse(path)  # noqa: S314
    root = tree.getroot()
    suite = (
        root
        if local_name(root.tag) == "testsuite"
        else next((element for element in root.iter() if local_name(element.tag) == "testsuite"), root)
    )
    properties = next((element for element in suite if local_name(element.tag) == "properties"), None)
    if properties is None:
        properties = ET.Element("properties")
        suite.insert(0, properties)
    existing = {
        str(element.attrib.get("name", "")).lower(): element
        for element in properties
        if local_name(element.tag) == "property"
    }
    values = (
        ("roles", ",".join(roles)),
        ("role", ",".join(roles)),
        ("profile", identity.profile),
        ("scenario", identity.scenario),
        ("target", identity.target),
        ("run_attempt", identity.run_attempt),
        ("commit_sha", _tested_commit()),
        ("workflow_run_id", os.getenv("GITHUB_RUN_ID", "local")),
    )
    for name, value in values:
        if name in existing:
            existing[name].set("value", value)
            existing[name].text = None
        else:
            ET.SubElement(properties, "property", {"name": name, "value": value})
    tree.write(path, encoding="utf-8", xml_declaration=True)


def _annotate_native_allure(
    root: Path,
    report: dict[str, Any],
    identity: Identity,
    source_junit: str,
) -> None:
    cases = report["test_cases"]
    for relative, payload in _native_allure_results(root):
        matching_cases = [case for case in cases if _allure_has_testcase_identity(payload, case)]
        if len(matching_cases) != 1 or len(matching_cases[0].get("roles", [])) != 1:
            continue
        role = str(matching_cases[0]["roles"][0])
        observed_roles = _allure_identity(payload).get("role", set())
        if observed_roles != {role}:
            # The producer must independently bind each native result to one
            # role.  Workflow metadata may enrich that proof, not invent it.
            continue
        labels = payload.get("labels", [])
        if not isinstance(labels, list):
            labels = []
        canonical_names = {"profile", "suite", "scenario", "host", "target", "runattempt", "commit-sha"}
        labels = [
            item
            for item in labels
            if not (
                isinstance(item, dict)
                and str(item.get("name", "")).strip().lower().replace("_", "-") in canonical_names
            )
        ]
        labels.extend(
            [
                {"name": "role", "value": role},
                {"name": "profile", "value": identity.profile},
                {"name": "suite", "value": identity.scenario},
                {"name": "host", "value": identity.target},
                {"name": "runAttempt", "value": identity.run_attempt},
                {"name": "commit_sha", "value": _tested_commit()},
            ]
        )
        payload["labels"] = labels
        payload["sourceJunit"] = source_junit
        (root / relative).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _locate_record_junit(scenario: str, target: str, explicit: Path | None, results_root: Path) -> Path | None:
    candidates: list[Path] = []
    env_path = os.getenv("QUALITY_EVIDENCE_JUNIT")
    if explicit:
        candidates.append(explicit)
    if env_path:
        candidates.append(Path(env_path))
    artifact_root = results_root.parent
    candidates.extend(
        (
            artifact_root / "junit" / f"{scenario}-{target}.xml",
            artifact_root / "junit" / f"{scenario}.xml",
            Path("artifacts") / "junit" / f"{scenario}-{target}.xml",
            Path("artifacts") / "junit" / f"{scenario}.xml",
        )
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def record(
    *,
    scenario: str,
    profile: str,
    target: str,
    roles: Sequence[str],
    exit_code: int,
    log_path: Path | None,
    results_root: Path,
    junit_path: Path | None = None,
    allure_root: Path | None = None,
    run_attempt: str | None = None,
) -> int:
    """Capture one always-run workflow result; eligibility is decided later.

    This command intentionally returns zero after successfully recording a
    failed test process.  The aggregate ``assemble``/``validate`` gates retain
    and enforce the failure state.
    """

    profile = normalize_profile(profile)
    if profile not in PROFILES:
        raise EvidenceError(f"unsupported profile for record: {profile}")
    role_names = sorted({item.strip() for item in roles if item.strip()})
    if not role_names:
        raise EvidenceError("record requires at least one role")
    attempt = str(run_attempt or os.getenv("GITHUB_RUN_ATTEMPT") or "1")
    identity = Identity(role_names[0], profile, scenario, target, attempt)
    result_dir = results_root.resolve() / slug(scenario) / slug(target) / f"attempt-{slug(attempt)}"
    junit_dir = result_dir / "junit"
    allure_dir = result_dir / "allure-results"
    logs_dir = result_dir / "logs"
    for directory in (junit_dir, allure_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)
    if log_path and log_path.is_file():
        shutil.copy2(log_path, logs_dir / log_path.name)

    source_junit = _locate_record_junit(scenario, target, junit_path, results_root)
    parsed: dict[str, Any] | None = None
    parse_error = ""
    if source_junit:
        try:
            parsed = parse_junit(source_junit)
        except (EvidenceError, OSError) as error:
            parse_error = str(error)
        else:
            reported_commit = _report_commit(parsed)
            current_commit = _tested_commit()
            if reported_commit not in {"", "unknown"} and reported_commit != current_commit:
                parse_error = "source JUnit commit differs from the workflow commit"
                parsed = None
    if parsed is not None and source_junit is not None and not (exit_code != 0 and parsed["status"] == "passed"):
        recorded_junit = junit_dir / source_junit.name
        shutil.copy2(source_junit, recorded_junit)
        _annotate_junit(recorded_junit, identity, role_names)
        parsed = parse_junit(recorded_junit)
    else:
        reason = parse_error or (
            f"test process exited with code {exit_code} without failing meaningful JUnit"
            if exit_code
            else "test process produced no meaningful JUnit"
        )
        relative, parsed = _fallback_junit(result_dir, identity, reason)
        generated = result_dir / relative
        recorded_junit = junit_dir / f"{slug(scenario)}.xml"
        if generated != recorded_junit:
            recorded_junit.parent.mkdir(parents=True, exist_ok=True)
            generated.replace(recorded_junit)
            fallback_parent = generated.parent
            if fallback_parent.exists() and not any(fallback_parent.iterdir()):
                fallback_parent.rmdir()
        _annotate_junit(recorded_junit, identity, role_names)
        parsed = parse_junit(recorded_junit)
        parsed["status"] = "infrastructure-error"

    native_source = allure_root
    if native_source is None:
        candidate = results_root.parent / "allure-results"
        native_source = candidate if candidate.is_dir() else None
    if native_source and native_source.is_dir():
        for source in sorted(native_source.rglob("*")):
            if source.is_file() and not source.is_symlink():
                native_relative = source.relative_to(native_source)
                _copy_unique(source, allure_dir / native_relative)

    generated_allure: list[str] = []
    if parsed["framework"] != "pytest":
        for role in role_names:
            role_identity = Identity(role, profile, scenario, target, attempt)
            try:
                role_report = _report_for_role(parsed, role, role_names)
            except EvidenceError:
                continue
            generated_allure.extend(
                generate_allure_result(
                    result_dir,
                    role_identity,
                    case,
                    ordinal=index,
                    source_junit=recorded_junit.relative_to(result_dir).as_posix(),
                )
                for index, case in enumerate(role_report["test_cases"])
            )
    else:
        _annotate_native_allure(
            result_dir,
            parsed,
            identity,
            recorded_junit.relative_to(result_dir).as_posix(),
        )
        generated_allure = [path for path, payload in _native_allure_results(result_dir) if payload]
    record_payload = {
        "schema_version": 1,
        "recorded_at": utc_now(),
        "roles": role_names,
        "profile": profile,
        "scenario": scenario,
        "target": target,
        "run_attempt": attempt,
        "workflow_run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "commit_sha": _tested_commit(),
        "process_exit_code": exit_code,
        "status": "infrastructure-error" if exit_code and parsed["status"] == "passed" else parsed["status"],
        "junit": recorded_junit.relative_to(result_dir).as_posix(),
        "allure_results": sorted(set(generated_allure)),
        "totals": parsed["totals"],
    }
    (result_dir / "result.json").write_text(
        json.dumps(record_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tools, applications = _version_environment()
    (result_dir / "environment.json").write_text(
        json.dumps(
            {
                "repository": os.getenv("GITHUB_REPOSITORY", "local"),
                "commit_sha": _tested_commit(),
                "workflow_run_id": os.getenv("GITHUB_RUN_ID", "local"),
                "workflow_attempt": attempt,
                "scenario": scenario,
                "profile": profile,
                "target": target,
                "roles": role_names,
                "test_parameters": {
                    "scenario": scenario,
                    "profile": profile,
                    "target": target,
                    "roles": role_names,
                },
                "tool_versions": tools,
                "application_versions": applications,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    for path in sorted(result_dir.rglob("*")):
        if path.is_file() and not path.is_symlink():
            redact_file(path)
    record_scan = scan_evidence(result_dir)
    if not record_scan["clean"]:
        problem_paths = [f"{item['path']} ({item['kind']})" for item in record_scan["findings"]] + list(
            record_scan["errors"]
        )
        raise EvidenceError("recorded evidence failed secret scanning: " + "; ".join(problem_paths))
    return 0


def _security_findings_count(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    results = payload.get("results")
    if isinstance(results, dict):
        count = 0
        for items in results.values():
            if not isinstance(items, list):
                continue
            # Count records rather than propagating scanner payload data into
            # public evidence metadata.  The manifest needs only this scalar;
            # finding content remains in the separately redacted scan artifact.
            for _item in items:
                count += 1
        return count
    for key in ("findings", "secrets", "matches"):
        value = payload.get(key)
        if isinstance(value, list):
            count = 0
            for _item in value:
                count += 1
            return count
        if isinstance(value, int) and not isinstance(value, bool):
            if value <= 0:
                return 0
            if value > MAX_EVIDENCE_FILES:
                return MAX_EVIDENCE_FILES + 1
            count = 0
            for _index in range(value):
                count += 1
            return count
    return 0


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _collection_artifact_identity(root: Path) -> tuple[CollectionArtifactIdentity | None, list[str]]:
    galaxy = root / "collection" / "galaxy.yml"
    if not galaxy.is_file() or galaxy.is_symlink():
        return None, ["collection/galaxy.yml is required to bind release security evidence"]
    try:
        content = _bounded_read(galaxy, 1024 * 1024).decode("utf-8")
    except (OSError, EvidenceError, UnicodeDecodeError) as error:
        return None, [f"collection/galaxy.yml cannot identify the release collection: {error}"]

    values: dict[str, str] = {}
    errors: list[str] = []
    for key in ("namespace", "name", "version"):
        match = re.search(
            rf"(?m)^{key}:[ \t]*(?:\"([^\"\r\n]+)\"|'([^'\r\n]+)'|([^#\r\n]+?))[ \t]*(?:#.*)?$",
            content,
        )
        value = next((group.strip() for group in match.groups() if group is not None), "") if match else ""
        if not value:
            errors.append(f"collection/galaxy.yml lacks {key}")
        values[key] = value
    if errors:
        return None, errors
    if re.fullmatch(r"[a-z0-9_]+", values["namespace"]) is None:
        errors.append("collection/galaxy.yml has an unsafe namespace")
    if re.fullmatch(r"[a-z0-9_]+", values["name"]) is None:
        errors.append("collection/galaxy.yml has an unsafe collection name")
    if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]*", values["version"]) is None:
        errors.append("collection/galaxy.yml has an unsafe collection version")
    if errors:
        return None, errors
    return CollectionArtifactIdentity(values["namespace"], values["name"], values["version"]), []


def _validate_sbom(
    payload: Any,
    *,
    collection: CollectionArtifactIdentity,
    candidate_sha256: str,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["security/sbom.cdx.json must be an object"]
    if payload.get("bomFormat") != "CycloneDX":
        errors.append("security/sbom.cdx.json is not a CycloneDX BOM")
    if (
        not _nonempty_text(payload.get("specVersion"))
        or re.fullmatch(r"[0-9]+\.[0-9]+", str(payload.get("specVersion", ""))) is None
    ):
        errors.append("security/sbom.cdx.json lacks specVersion")
    if (
        not isinstance(payload.get("version"), int)
        or isinstance(payload.get("version"), bool)
        or int(payload.get("version", 0)) < 1
    ):
        errors.append("security/sbom.cdx.json lacks a valid BOM version")
    metadata = payload.get("metadata")
    metadata_component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(metadata_component, dict) or not _nonempty_text(metadata_component.get("type")):
        errors.append("security/sbom.cdx.json lacks a metadata candidate component")
        return errors
    expected_coordinates = {
        "group": collection.namespace,
        "name": collection.name,
        "version": collection.version,
    }
    if any(metadata_component.get(key) != value for key, value in expected_coordinates.items()):
        errors.append("security/sbom.cdx.json candidate component does not match the collection identity and version")
    hashes = metadata_component.get("hashes")
    digest_bound = (
        re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) is not None
        and isinstance(hashes, list)
        and any(
            isinstance(item, dict) and item.get("alg") == "SHA-256" and item.get("content") == candidate_sha256
            for item in hashes
        )
    )
    if not digest_bound:
        errors.append("security/sbom.cdx.json candidate component is not bound to candidate_sha256")
    return errors


def _validate_vulnerability_report(payload: Any) -> tuple[list[str], int]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["security/vulnerability-report.json must be an object"], 0
    matches = payload.get("matches")
    if not isinstance(matches, list):
        return ["security/vulnerability-report.json lacks a matches array"], 0
    descriptor = payload.get("descriptor")
    if not isinstance(descriptor, dict) or str(descriptor.get("name", "")).casefold() != "grype":
        errors.append("security/vulnerability-report.json lacks Grype scanner identity")
    elif not _nonempty_text(descriptor.get("version")):
        errors.append("security/vulnerability-report.json lacks scanner version")
    source = payload.get("source")
    source_target = source.get("target") if isinstance(source, dict) else None
    if not isinstance(source, dict) or str(source.get("type", "")).casefold() != "sbom-file":
        errors.append("security/vulnerability-report.json was not produced from an SBOM source")
    if (
        not _nonempty_text(source_target)
        or "\\" in str(source_target)
        or PurePosixPath(str(source_target)).name != "sbom.cdx.json"
    ):
        errors.append("security/vulnerability-report.json does not identify security/sbom.cdx.json as its source")
    blocking = 0
    for match in matches:
        if not isinstance(match, dict):
            errors.append("security/vulnerability-report.json contains a malformed match")
            continue
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        if (
            not isinstance(vulnerability, dict)
            or not _nonempty_text(vulnerability.get("id"))
            or not _nonempty_text(vulnerability.get("severity"))
            or not isinstance(artifact, dict)
            or not _nonempty_text(artifact.get("name"))
        ):
            errors.append("security/vulnerability-report.json contains an incomplete match")
        severity = str(vulnerability.get("severity", "")).lower() if isinstance(vulnerability, dict) else ""
        if severity in {"high", "critical"}:
            blocking += 1
    if blocking:
        errors.append(f"vulnerability scan reports {blocking} high/critical finding(s)")
    return errors, blocking


def _validate_trivy_vulnerability_report(payload: Any) -> tuple[list[str], int]:
    errors: list[str] = []
    report = "security/trivy-vulnerability-report.json"
    if not isinstance(payload, dict):
        return [f"{report} must be an object"], 0
    schema_version = payload.get("SchemaVersion")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version < 2:
        errors.append(f"{report} lacks the supported Trivy schema version")
    artifact_name = payload.get("ArtifactName")
    if (
        not _nonempty_text(artifact_name)
        or "\\" in str(artifact_name)
        or PurePosixPath(str(artifact_name)).name != "sbom.cdx.json"
    ):
        errors.append(f"{report} does not identify security/sbom.cdx.json as its source")
    if not _nonempty_text(payload.get("ArtifactType")):
        errors.append(f"{report} lacks the Trivy artifact type")
    results = payload.get("Results")
    if not isinstance(results, list):
        return [*errors, f"{report} lacks a Results array"], 0
    blocking = 0
    for result in results:
        if not isinstance(result, dict) or not _nonempty_text(result.get("Target")):
            errors.append(f"{report} contains a malformed result")
            continue
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            errors.append(f"{report} contains malformed vulnerabilities")
            continue
        for vulnerability in vulnerabilities:
            if (
                not isinstance(vulnerability, dict)
                or not _nonempty_text(vulnerability.get("VulnerabilityID"))
                or not _nonempty_text(vulnerability.get("PkgName"))
                or not _nonempty_text(vulnerability.get("Severity"))
            ):
                errors.append(f"{report} contains an incomplete vulnerability")
                continue
            if str(vulnerability["Severity"]).casefold() in {"high", "critical"}:
                blocking += 1
    if blocking:
        errors.append(f"Trivy scan reports {blocking} high/critical finding(s)")
    return errors, blocking


def _validate_provenance(
    payload: Any,
    commit_sha: str,
    *,
    collection: CollectionArtifactIdentity | None,
) -> tuple[list[str], str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["security/provenance.json must be an object"], ""
    if payload.get("schema_version") != 1:
        errors.append("security/provenance.json has an unsupported schema version")
    provenance_commit = str(payload.get("commit_sha", ""))
    if not _valid_commit(provenance_commit) or provenance_commit != commit_sha:
        errors.append("security/provenance.json lacks the exact tested commit")
    candidate = str(payload.get("candidate", ""))
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.gz", candidate) is None:
        errors.append("security/provenance.json lacks a safe collection candidate name")
    elif collection is not None and candidate != collection.candidate:
        errors.append("security/provenance.json candidate does not match the collection identity and version")
    candidate_sha = str(payload.get("candidate_sha256", ""))
    if re.fullmatch(r"[0-9a-f]{64}", candidate_sha) is None:
        errors.append("security/provenance.json lacks candidate_sha256")
    for key in ("repository", "workflow_run_id", "workflow_attempt", "generated_at"):
        if not _nonempty_text(payload.get(key)):
            errors.append(f"security/provenance.json lacks {key}")
    generated_at = payload.get("generated_at")
    if _nonempty_text(generated_at):
        try:
            timestamp = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
        except ValueError:
            errors.append("security/provenance.json generated_at is not an ISO-8601 timestamp")
        else:
            if timestamp.tzinfo is None:
                errors.append("security/provenance.json generated_at lacks a timezone")
    return errors, candidate_sha


def _validate_scan_summary(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["security/secret-scan-summary.json must be an object"]
    errors: list[str] = []
    if not _nonempty_text(payload.get("version")):
        errors.append("security/secret-scan-summary.json lacks scanner version")
    plugins = payload.get("plugins_used", payload.get("plugins"))
    if (
        not isinstance(plugins, list)
        or not plugins
        or any(not isinstance(plugin, dict) or not _nonempty_text(plugin.get("name")) for plugin in plugins)
    ):
        errors.append("security/secret-scan-summary.json lacks plugin inventory")
    results = payload.get("results")
    if not isinstance(results, dict) or any(
        not isinstance(path, str)
        or not isinstance(items, list)
        or any(not isinstance(finding, dict) for finding in items)
        for path, items in results.items()
    ):
        errors.append("security/secret-scan-summary.json has malformed results")
    return errors


def assess_security(root: Path, *, release_mode: bool, commit_sha: str) -> tuple[dict[str, Any], list[str]]:
    security = root / "security"
    missing = [
        name
        for name in REQUIRED_RELEASE_SECURITY_FILES
        if not (security / name).is_file() or (security / name).is_symlink()
    ]
    errors: list[str] = []
    parsed: dict[str, Any] = {}
    for name in REQUIRED_RELEASE_SECURITY_FILES:
        path = security / name
        if not path.is_file() or path.is_symlink():
            continue
        try:
            raw = _bounded_read(path)
        except (OSError, EvidenceError, UnicodeDecodeError, json.JSONDecodeError) as error:
            errors.append(f"security/{name} is not valid JSON: {error}")
            continue
        if not raw:
            errors.append(f"security/{name} is empty")
            continue
        try:
            parsed[name] = _strict_json_loads(raw.decode("utf-8"))
        except (EvidenceError, UnicodeDecodeError, json.JSONDecodeError) as error:
            errors.append(f"security/{name} is not valid JSON: {error}")
    scan_summary_payload = parsed.get("secret-scan-summary.json")
    external_findings = _security_findings_count(scan_summary_payload)
    semantic_errors: list[str] = []
    vulnerability_blocking = 0
    candidate_sha = ""
    collection, collection_errors = _collection_artifact_identity(root)
    semantic_errors.extend(collection_errors)
    if "provenance.json" in parsed:
        provenance_errors, candidate_sha = _validate_provenance(
            parsed["provenance.json"], commit_sha, collection=collection
        )
        semantic_errors.extend(provenance_errors)
    if "sbom.cdx.json" in parsed and collection is not None:
        semantic_errors.extend(
            _validate_sbom(parsed["sbom.cdx.json"], collection=collection, candidate_sha256=candidate_sha)
        )
    if "vulnerability-report.json" in parsed:
        vulnerability_errors, grype_blocking = _validate_vulnerability_report(parsed["vulnerability-report.json"])
        vulnerability_blocking += grype_blocking
        semantic_errors.extend(vulnerability_errors)
    if "trivy-vulnerability-report.json" in parsed:
        trivy_errors, trivy_blocking = _validate_trivy_vulnerability_report(parsed["trivy-vulnerability-report.json"])
        vulnerability_blocking += trivy_blocking
        semantic_errors.extend(trivy_errors)
    if "secret-scan-summary.json" in parsed:
        semantic_errors.extend(_validate_scan_summary(parsed["secret-scan-summary.json"]))
    if external_findings:
        errors.append(f"external secret scan reports {external_findings} finding(s)")
    provenance = parsed.get("provenance.json")
    provenance_commit = ""
    if isinstance(provenance, dict):
        provenance_commit = str(provenance.get("commit_sha") or provenance.get("commit") or provenance.get("sha") or "")
    if release_mode:
        errors.extend(semantic_errors)
    if release_mode and missing:
        errors.extend(f"missing security/{name}" for name in missing)
    return {
        "required_for_release": list(REQUIRED_RELEASE_SECURITY_FILES),
        "missing": missing,
        "external_secret_findings": external_findings,
        "vulnerability_blocking_findings": vulnerability_blocking,
        "provenance_commit_sha": provenance_commit or None,
        "candidate_sha256": candidate_sha or None,
        "semantic_valid": not semantic_errors and not missing,
    }, errors


def _dependency_files(root: Path, pattern: str) -> tuple[list[Path], list[str]]:
    dependencies = root / "dependencies"
    files: list[Path] = []
    errors: list[str] = []
    for path in sorted(dependencies.rglob(pattern)):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            errors.append(f"release dependency evidence cannot be a symlink: {relative}")
        elif path.is_file():
            files.append(path)
    return files, errors


def _read_dependency_text(root: Path, path: Path) -> tuple[str | None, str | None]:
    relative = path.relative_to(root).as_posix()
    try:
        # OS package inventories can legitimately exceed 64 KiB, while the
        # dependency format still benefits from a tighter bound than general
        # evidence artifacts.
        return _bounded_read(path, 256 * 1024).decode("utf-8"), None
    except (OSError, EvidenceError, UnicodeDecodeError) as error:
        return None, f"{relative} is not readable dependency evidence: {error}"


def _read_dependency_json(root: Path, path: Path) -> tuple[Any, str | None]:
    text, error = _read_dependency_text(root, path)
    if error is not None or text is None:
        return None, error
    try:
        return _strict_json_loads(text), None
    except (EvidenceError, json.JSONDecodeError) as parse_error:
        relative = path.relative_to(root).as_posix()
        return None, f"{relative} is not valid JSON dependency evidence: {parse_error}"


def _container_image_immutable_digest(image: dict[str, Any]) -> str | None:
    digest_pattern = re.compile(r"sha256:[0-9a-f]{64}")
    image_id_pattern = re.compile(r"(?:sha256:)?[0-9a-f]{64}")
    for key in ("Digest", "digest"):
        value = image.get(key)
        if isinstance(value, str) and digest_pattern.fullmatch(value):
            return value
    for key in ("RepoDigests", "repoDigests", "repo_digests"):
        values = image.get(key)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str):
                    match = re.search(r"@(sha256:[0-9a-f]{64})$", value)
                    if match is not None:
                        return match.group(1)
    for key in ("Id", "ID", "id", "ImageID", "image_id"):
        value = image.get(key)
        if isinstance(value, str) and image_id_pattern.fullmatch(value):
            return f"sha256:{value.removeprefix('sha256:')}"
    return None


def _container_image_has_immutable_identity(image: dict[str, Any]) -> bool:
    return _container_image_immutable_digest(image) is not None


def _registry_test_application_policy(
    *,
    inventory_path: Path,
    scenario: str,
    target: str,
    registry_binding: Any,
    inventory_policy: Any,
    repository_root: Path | None,
    errors: list[str],
) -> dict[str, Any] | None:
    """Bind an inventory policy to the copied and exact coverage registry."""

    relative = inventory_path.as_posix()
    error_count = len(errors)
    if not isinstance(registry_binding, dict) or set(registry_binding) != {
        "path",
        "sha256",
        "evidence_file",
    }:
        errors.append(f"{relative} has malformed role coverage registry binding")
        return None
    registry_path = PurePosixPath(str(registry_binding.get("path", "")))
    evidence_file = PurePosixPath(str(registry_binding.get("evidence_file", "")))
    expected_evidence_file = PurePosixPath(f"role-coverage-{scenario}-{target}.yml")
    registry_sha = registry_binding.get("sha256")
    if (
        registry_path != PurePosixPath("meta/role-coverage.yml")
        or registry_path.is_absolute()
        or ".." in registry_path.parts
        or evidence_file.is_absolute()
        or ".." in evidence_file.parts
        or len(evidence_file.parts) != 1
        or evidence_file != expected_evidence_file
        or not isinstance(registry_sha, str)
        or re.fullmatch(r"[0-9a-f]{64}", registry_sha) is None
    ):
        errors.append(f"{relative} has unsafe role coverage registry binding")
        return None

    evidence_registry = inventory_path.parent / evidence_file.name
    try:
        if evidence_registry.is_symlink():
            raise EvidenceError("registry evidence cannot be a symlink")
        registry_source = _bounded_read(evidence_registry, 8 * 1024 * 1024)
    except (OSError, EvidenceError):
        registry_source = b""
    if hashlib.sha256(registry_source).hexdigest() != registry_sha:
        errors.append(f"{relative} role coverage registry evidence digest differs")

    if repository_root is not None:
        source_registry = repository_root / Path(*registry_path.parts)
        try:
            if source_registry.is_symlink():
                raise EvidenceError("source registry cannot be a symlink")
            source_registry_bytes = _bounded_read(source_registry, 8 * 1024 * 1024)
        except (OSError, EvidenceError):
            source_registry_bytes = b""
        if (
            source_registry_bytes != registry_source
            or hashlib.sha256(source_registry_bytes).hexdigest() != registry_sha
        ):
            errors.append(f"{relative} role coverage registry differs from exact source")

    try:
        import yaml
    except ImportError:
        parsed_registry = None
    else:
        try:
            parsed_registry = yaml.safe_load(registry_source) or {}
        except (ValueError, yaml.YAMLError):
            parsed_registry = None
    scenarios = parsed_registry.get("scenarios") if isinstance(parsed_registry, dict) else None
    scenario_payload = scenarios.get(scenario) if isinstance(scenarios, dict) else None
    policy = scenario_payload.get("test_application") if isinstance(scenario_payload, dict) else None
    if not isinstance(policy, dict):
        errors.append(f"{relative} exact registry lacks a test-application policy for {scenario}")
        return None
    if inventory_policy != policy:
        errors.append(f"{relative} test-application policy differs from the exact registry")

    if set(policy) != {"mode", "reason", "dependencies"}:
        errors.append(f"{relative} exact registry test-application policy has malformed fields")
        return None
    mode = policy.get("mode")
    reason = policy.get("reason")
    dependencies = policy.get("dependencies")
    if mode not in TEST_APPLICATION_MODES:
        errors.append(f"{relative} exact registry has an invalid test-application mode")
    if not isinstance(reason, str) or reason != reason.strip() or not 20 <= len(reason) <= 500:
        errors.append(f"{relative} exact registry has an invalid test-application reason")
    if not isinstance(dependencies, list):
        errors.append(f"{relative} exact registry has malformed test-application claims")
        dependencies = []
    if mode == "declared-evidence" and not dependencies:
        errors.append(f"{relative} exact registry declared-evidence policy has no claims")
    if mode in {"runtime-container", "not-applicable"} and dependencies:
        errors.append(f"{relative} exact registry mode {mode} must not contain declared claims")
    if (
        mode == "not-applicable"
        and isinstance(scenario_payload, dict)
        and scenario_payload.get("state") == "supported"
        and scenario_payload.get("implementation") == "real"
    ):
        errors.append(f"{relative} supported real scenario cannot declare test applications not applicable")

    identities: set[tuple[str, str, str]] = set()
    for index, item in enumerate(dependencies):
        claim_prefix = f"{relative} registry test-application claim {index}"
        if (
            not isinstance(item, dict)
            or not {
                "type",
                "name",
                "version",
                "evidence_path",
            }
            <= set(item)
            or set(item) - {"type", "name", "version", "evidence_path", "digest"}
        ):
            errors.append(f"{claim_prefix} has malformed fields")
            continue
        dependency_type = item.get("type")
        name = item.get("name")
        version = item.get("version")
        evidence_path = PurePosixPath(str(item.get("evidence_path", "")))
        digest = item.get("digest")
        if dependency_type not in DECLARED_APPLICATION_TYPES:
            errors.append(f"{claim_prefix} has an invalid type")
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", name) is None:
            errors.append(f"{claim_prefix} has an unsafe name")
        if (
            not isinstance(version, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,127}", version) is None
            or version.lower() in MUTABLE_APPLICATION_VERSIONS
        ):
            errors.append(f"{claim_prefix} has a mutable or invalid version")
        if (
            evidence_path.is_absolute()
            or ".." in evidence_path.parts
            or evidence_path.parts[:2] != ("test-applications", scenario)
        ):
            errors.append(f"{claim_prefix} has an unsafe evidence path")
        if digest is not None and (not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None):
            errors.append(f"{claim_prefix} has an invalid digest")
        if isinstance(dependency_type, str) and isinstance(name, str) and isinstance(version, str):
            identity = (dependency_type, name, version)
            if identity in identities:
                errors.append(f"{claim_prefix} duplicates an identity")
            identities.add(identity)

    return policy if len(errors) == error_count else None


def assess_dependencies(
    root: Path,
    *,
    release_mode: bool,
    expected_commit: str | None = None,
    repository_root: Path | None = None,
    matrix_cells: Sequence[dict[str, Any]] = (),
) -> list[str]:
    """Validate release dependency inventories without trusting filenames alone."""

    if not release_mode:
        return []
    dependencies = root / "dependencies"
    if not dependencies.is_dir() or dependencies.is_symlink():
        return ["release dependency evidence directory is missing or unsafe"]

    errors: list[str] = []
    version_evidence = (
        (
            "controller Ansible version",
            "ansible-version*.txt",
            re.compile(r"(?im)^ansible(?:[ \t]+\[core)?[ \t]+[0-9]+(?:\.[0-9]+){1,3}"),
        ),
        (
            "controller Molecule version",
            "molecule-version*.txt",
            re.compile(r"(?im)^molecule[ \t]+[0-9]+(?:\.[0-9]+){1,3}"),
        ),
        (
            "controller Python version",
            "python-version*.txt",
            re.compile(r"(?im)^python[ \t]+[0-9]+(?:\.[0-9]+){1,3}"),
        ),
    )
    for label, pattern, version_pattern in version_evidence:
        files, file_errors = _dependency_files(root, pattern)
        errors.extend(file_errors)
        if not files:
            errors.append(f"release dependency evidence lacks {label}")
            continue
        for path in files:
            text, error = _read_dependency_text(root, path)
            if error is not None:
                errors.append(error)
            elif text is None or version_pattern.search(text) is None:
                errors.append(f"{path.relative_to(root).as_posix()} lacks a parseable {label}")

    python_files, file_errors = _dependency_files(root, "python-packages*.json")
    errors.extend(file_errors)
    if not python_files:
        errors.append("release dependency evidence lacks a Python package inventory")
    expected_target_python_cells = {
        (str(cell.get("profile", "")), str(cell.get("scenario", "")), str(cell.get("target", "")))
        for cell in matrix_cells
        if str(cell.get("profile", "")) == "application-acceptance"
        and str(cell.get("scenario", "")) == "keycloak-application-acceptance"
    }
    observed_target_python_cells: set[tuple[str, str, str]] = set()
    target_playwright_versions: dict[tuple[str, str, str], str] = {}
    for path in python_files:
        payload, error = _read_dependency_json(root, path)
        if error is not None:
            errors.append(error)
            continue
        packages: Any = payload
        if isinstance(payload, dict):
            expected_fields = {
                "schema_version",
                "source",
                "profile",
                "scenario",
                "target",
                "source_commit",
                "packages",
            }
            target_python_cell = (
                str(payload.get("profile", "")),
                str(payload.get("scenario", "")),
                str(payload.get("target", "")),
            )
            if (
                set(payload) != expected_fields
                or payload.get("schema_version") != 1
                or payload.get("source") != "target-venv"
                or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", target_python_cell[0]) is None
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", target_python_cell[1]) is None
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", target_python_cell[2]) is None
                or not _valid_commit(str(payload.get("source_commit", "")))
                or (expected_commit is not None and payload.get("source_commit") != expected_commit)
                or (matrix_cells and target_python_cell not in expected_target_python_cells)
            ):
                errors.append(f"{path.relative_to(root).as_posix()} has an unbound target Python package inventory")
            else:
                observed_target_python_cells.add(target_python_cell)
            packages = payload.get("packages")
        if (
            not isinstance(packages, list)
            or not packages
            or any(
                not isinstance(package, dict)
                or not _nonempty_text(package.get("name"))
                or not _nonempty_text(package.get("version"))
                for package in packages
            )
        ):
            errors.append(f"{path.relative_to(root).as_posix()} has an empty or malformed Python package inventory")
        elif isinstance(payload, dict) and target_python_cell[:2] == (
            "application-acceptance",
            "keycloak-application-acceptance",
        ):
            playwright_packages = [
                package for package in packages if str(package.get("name", "")).casefold() == "playwright"
            ]
            if len(playwright_packages) != 1:
                errors.append(f"{path.relative_to(root).as_posix()} lacks exactly one Playwright package identity")
            elif target_python_cell in target_playwright_versions:
                errors.append(f"{path.relative_to(root).as_posix()} duplicates a target Python package inventory cell")
            else:
                target_playwright_versions[target_python_cell] = str(playwright_packages[0]["version"])
    for missing_cell in sorted(expected_target_python_cells - observed_target_python_cells):
        errors.append(
            "release dependency evidence lacks a cell-bound target Python package inventory for "
            + "/".join(missing_cell)
        )

    browser_files, file_errors = _dependency_files(root, "browser-runtime*.json")
    errors.extend(file_errors)
    observed_browser_cells: set[tuple[str, str, str]] = set()
    for path in browser_files:
        payload, error = _read_dependency_json(root, path)
        if error is not None:
            errors.append(error)
            continue
        malformed = not isinstance(payload, dict)
        if isinstance(payload, dict):
            expected_fields = {
                "schema_version",
                "source",
                "profile",
                "scenario",
                "target",
                "source_commit",
                "playwright_version",
                "chromium",
                "operating_system",
                "os_packages",
            }
            browser_cell = (
                str(payload.get("profile", "")),
                str(payload.get("scenario", "")),
                str(payload.get("target", "")),
            )
            chromium = payload.get("chromium")
            operating_system = payload.get("operating_system")
            packages = payload.get("os_packages")
            playwright_version = str(payload.get("playwright_version", ""))
            channel = str(chromium.get("channel", "")) if isinstance(chromium, dict) else ""
            executable = (
                PurePosixPath(str(chromium.get("executable", ""))) if isinstance(chromium, dict) else PurePosixPath()
            )
            malformed = (
                set(payload) != expected_fields
                or payload.get("schema_version") != 1
                or payload.get("source") != "playwright-target-runtime"
                or browser_cell
                != (
                    "application-acceptance",
                    "keycloak-application-acceptance",
                    browser_cell[2],
                )
                or browser_cell[2] not in {"ubuntu-24.04", "rhel-9", "rhel-10"}
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", browser_cell[2]) is None
                or not _valid_commit(str(payload.get("source_commit", "")))
                or (expected_commit is not None and payload.get("source_commit") != expected_commit)
                or (matrix_cells and browser_cell not in expected_target_python_cells)
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,3}", playwright_version) is None
                or target_playwright_versions.get(browser_cell) != playwright_version
                or not isinstance(chromium, dict)
                or set(chromium) != {"name", "channel", "version", "executable", "sha256"}
                or chromium.get("name") != "chromium"
                or channel != "chrome"
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", str(chromium.get("version", ""))) is None
                or executable != PurePosixPath("/opt/google/chrome/chrome")
                or re.fullmatch(r"[0-9a-f]{64}", str(chromium.get("sha256", ""))) is None
                or not isinstance(operating_system, dict)
                or set(operating_system) != {"id", "version_id", "distro"}
                or operating_system.get("distro") != browser_cell[2]
                or (
                    browser_cell[2] == "ubuntu-24.04"
                    and (operating_system.get("id") != "ubuntu" or operating_system.get("version_id") != "24.04")
                )
                or (
                    browser_cell[2] in {"rhel-9", "rhel-10"}
                    and (
                        operating_system.get("id") != "rhel"
                        or re.fullmatch(
                            browser_cell[2].removeprefix("rhel-") + r"(?:\.[0-9]+)*",
                            str(operating_system.get("version_id", "")),
                        )
                        is None
                    )
                )
                or not isinstance(packages, list)
                or not packages
                or any(
                    not isinstance(package, dict)
                    or set(package) != {"name", "version", "architecture", "source_name", "source_version"}
                    or re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9+._-]{0,127}",
                        str(package.get("name", "")),
                    )
                    is None
                    or re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9+._-]{0,127}",
                        str(package.get("source_name", "")),
                    )
                    is None
                    or not _nonempty_text(package.get("version"))
                    or not _nonempty_text(package.get("source_version"))
                    or len(str(package.get("version", ""))) > 256
                    or len(str(package.get("source_version", ""))) > 256
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", str(package.get("architecture", ""))) is None
                    for package in packages
                )
            )
            if not malformed and browser_cell in observed_browser_cells:
                malformed = True
            if not malformed:
                observed_browser_cells.add(browser_cell)
        if malformed:
            errors.append(f"{path.relative_to(root).as_posix()} has a malformed browser runtime inventory")
    for missing_cell in sorted(expected_target_python_cells - observed_browser_cells):
        errors.append(
            "release dependency evidence lacks a cell-bound Playwright Chromium runtime inventory for "
            + "/".join(missing_cell)
        )

    collection_files, file_errors = _dependency_files(root, "collection-dependencies*.json")
    errors.extend(file_errors)
    if not collection_files:
        errors.append("release dependency evidence lacks an Ansible collection inventory")
    for path in collection_files:
        payload, error = _read_dependency_json(root, path)
        if error is not None:
            errors.append(error)
            continue
        malformed = not isinstance(payload, dict) or not payload
        collection_count = 0
        if isinstance(payload, dict):
            for collection_root, collections in payload.items():
                if not _nonempty_text(collection_root) or not isinstance(collections, dict):
                    malformed = True
                    continue
                for fqcn, metadata in collections.items():
                    if (
                        not isinstance(fqcn, str)
                        or re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", fqcn) is None
                        or not isinstance(metadata, dict)
                        or not _nonempty_text(metadata.get("version"))
                    ):
                        malformed = True
                    else:
                        collection_count += 1
        if malformed or collection_count == 0:
            errors.append(f"{path.relative_to(root).as_posix()} has an empty or malformed Ansible collection inventory")

    incus_files, file_errors = _dependency_files(root, "incus-base-image*.json")
    errors.extend(file_errors)
    if not incus_files:
        errors.append("release dependency evidence lacks an Incus base-image identity")
    for path in incus_files:
        payload, error = _read_dependency_json(root, path)
        if error is not None:
            errors.append(error)
            continue
        fingerprint = payload.get("fingerprint") if isinstance(payload, dict) else None
        if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            errors.append(f"{path.relative_to(root).as_posix()} lacks an immutable Incus base-image fingerprint")

    disposition_files, file_errors = _dependency_files(root, "execution-environment-digest*.txt")
    errors.extend(file_errors)
    if not disposition_files:
        errors.append("release dependency evidence lacks an execution-environment disposition")
    for path in disposition_files:
        text, error = _read_dependency_text(root, path)
        if error is not None:
            errors.append(error)
            continue
        values: dict[str, str] = {}
        malformed = False
        for line in (text or "").splitlines():
            if not line.strip():
                continue
            if "=" not in line:
                malformed = True
                continue
            key, value = (item.strip() for item in line.split("=", 1))
            if re.fullmatch(r"[a-z][a-z0-9_-]*", key) is None or key in values or not value:
                malformed = True
            values[key] = value
        mode = values.get("mode")
        digest = values.get("digest")
        reason = values.get("reason")
        valid_disposition = bool(reason) and (
            (mode == "host-native" and digest == "not-applicable")
            or (
                mode == "execution-environment"
                and isinstance(digest, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
            )
        )
        if malformed or not valid_disposition:
            errors.append(f"{path.relative_to(root).as_posix()} has an invalid execution-environment disposition")

    inventory_files, file_errors = _dependency_files(root, "*container-image-digests*.json")
    errors.extend(file_errors)
    container_digests_by_cell: dict[tuple[str, str], set[str]] = {}
    for path in inventory_files:
        payload, error = _read_dependency_json(root, path)
        if error is not None:
            errors.append(error)
            continue
        relative = path.relative_to(root).as_posix()
        inventory_valid = isinstance(payload, dict) and payload.get("schema_version") == 1
        if isinstance(payload, dict):
            inventory_valid = inventory_valid and all(
                _nonempty_text(payload.get(key)) for key in ("scenario", "target", "instance", "requested_image")
            )
            base_fingerprint = payload.get("incus_base_image_fingerprint")
            inventory_valid = (
                inventory_valid
                and isinstance(base_fingerprint, str)
                and (re.fullmatch(r"[0-9a-f]{64}", base_fingerprint) is not None)
            )
            available = payload.get("container_inventory_available")
            images = payload.get("images")
        else:
            available = None
            images = None
        if not inventory_valid or not isinstance(available, bool) or not isinstance(images, list):
            errors.append(f"{relative} has malformed in-target container inventory metadata")
            continue
        if not available:
            continue
        immutable = True
        inventory_digests: set[str] = set()
        for index, image in enumerate(images):
            digest = _container_image_immutable_digest(image) if isinstance(image, dict) else None
            if digest is None:
                errors.append(f"{relative} image {index} lacks an immutable digest or image ID")
                immutable = False
            else:
                inventory_digests.add(digest)
        if immutable:
            cell = (str(payload["scenario"]), str(payload["target"]))
            container_digests_by_cell.setdefault(cell, set()).update(inventory_digests)

    application_files, file_errors = _dependency_files(root, "test-application-dependencies*.json")
    errors.extend(file_errors)
    if not application_files:
        errors.append("release dependency evidence lacks a test-application inventory")
    runtime_digests_by_cell: dict[tuple[str, str], set[str]] = {}
    application_profiles_by_cell: dict[tuple[str, str], str] = {}
    for path in application_files:
        payload, error = _read_dependency_json(root, path)
        if error is not None:
            errors.append(error)
            continue
        relative = path.relative_to(root).as_posix()
        if not isinstance(payload, dict) or payload.get("schema_version") != 2:
            errors.append(f"{relative} has malformed test-application metadata")
            continue
        profile = normalize_profile(payload.get("profile"))
        scenario = payload.get("scenario")
        target = payload.get("target")
        source_commit = payload.get("source_commit")
        scenario_config = payload.get("scenario_config")
        registry_binding = payload.get("registry_policy")
        inventory_policy = payload.get("test_application_policy")
        applications = payload.get("applications")
        disposition = payload.get("disposition")
        descriptor = payload.get("descriptor")
        expected_inventory_fields = {
            "schema_version",
            "profile",
            "scenario",
            "target",
            "source_commit",
            "scenario_config",
            "registry_policy",
            "test_application_policy",
            "applications",
            "disposition",
            "descriptor",
        }
        metadata_valid = (
            set(payload) == expected_inventory_fields
            and profile in {"tiny", "heavy", "application-acceptance"}
            and _nonempty_text(scenario)
            and _nonempty_text(target)
            and isinstance(source_commit, str)
            and _valid_commit(source_commit)
            and isinstance(scenario_config, dict)
            and _nonempty_text(scenario_config.get("path"))
            and _nonempty_text(scenario_config.get("evidence_file"))
            and isinstance(scenario_config.get("sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", scenario_config["sha256"]) is not None
            and isinstance(registry_binding, dict)
            and isinstance(inventory_policy, dict)
            and isinstance(applications, list)
        )
        if not metadata_valid:
            errors.append(f"{relative} has malformed test-application metadata")
            continue
        assert isinstance(scenario_config, dict)
        assert isinstance(applications, list)
        cell = (str(scenario), str(target))
        if cell in application_profiles_by_cell:
            errors.append(f"duplicate test-application inventory for {scenario}/{target}")
            continue
        application_profiles_by_cell[cell] = str(profile)
        if expected_commit is not None and source_commit != expected_commit:
            errors.append(f"{relative} source commit differs from the tested commit")

        config_path = PurePosixPath(str(scenario_config["path"]))
        expected_config = PurePosixPath("molecule") / str(scenario) / "molecule.yml"
        evidence_file = PurePosixPath(str(scenario_config["evidence_file"]))
        if (
            config_path != expected_config
            or config_path.is_absolute()
            or ".." in config_path.parts
            or evidence_file.is_absolute()
            or ".." in evidence_file.parts
            or len(evidence_file.parts) != 1
        ):
            errors.append(f"{relative} has an unsafe or mismatched scenario configuration path")
        else:
            evidence_config = path.parent / evidence_file.name
            try:
                evidence_digest = hashlib.sha256(_bounded_read(evidence_config, 1024 * 1024)).hexdigest()
            except (OSError, EvidenceError):
                evidence_digest = ""
            if evidence_digest != scenario_config["sha256"]:
                errors.append(f"{relative} scenario configuration evidence digest differs")
            if repository_root is not None:
                source_config = repository_root / Path(*config_path.parts)
                try:
                    source_digest = hashlib.sha256(_bounded_read(source_config, 1024 * 1024)).hexdigest()
                except (OSError, EvidenceError):
                    source_digest = ""
                if source_digest != scenario_config["sha256"]:
                    errors.append(f"{relative} scenario configuration differs from exact source")

        policy = _registry_test_application_policy(
            inventory_path=path,
            scenario=str(scenario),
            target=str(target),
            registry_binding=registry_binding,
            inventory_policy=inventory_policy,
            repository_root=repository_root,
            errors=errors,
        )
        if policy is None:
            runtime_digests_by_cell[cell] = set()
            continue
        policy_mode = str(policy["mode"])

        if descriptor is not None:
            errors.append(f"{relative} has forbidden scenario-owned test-application descriptor metadata")

        runtime_digests: set[str] = set()
        application_identities: set[tuple[str, str, str]] = set()
        declared_inventory_claims: list[tuple[str, str, str, str, str]] = []
        observed_sources: list[str] = []
        for index, application in enumerate(applications):
            if not isinstance(application, dict):
                errors.append(f"{relative} application {index} is malformed")
                continue
            application_type = application.get("type")
            name = application.get("name")
            version = application.get("version")
            source = application.get("source")
            observed_sources.append(str(source))
            digest = application.get("digest")
            evidence_sha = application.get("evidence_sha256")
            if not _nonempty_text(name) or not _nonempty_text(version):
                errors.append(f"{relative} application {index} lacks a resolved immutable identity")
                continue
            identity = (str(application_type), str(name), str(version))
            if identity in application_identities:
                errors.append(f"{relative} application {index} duplicates a dependency identity")
                continue
            application_identities.add(identity)
            if not isinstance(evidence_sha, str) or re.fullmatch(r"[0-9a-f]{64}", evidence_sha) is None:
                errors.append(f"{relative} application {index} lacks immutable evidence")
                continue

            if source == "runtime-container":
                if set(application) != {
                    "type",
                    "name",
                    "version",
                    "digest",
                    "source",
                    "source_inventory",
                    "evidence_sha256",
                }:
                    errors.append(f"{relative} application {index} has malformed runtime-container fields")
                    continue
                source_inventory = PurePosixPath(str(application.get("source_inventory", "")))
                if (
                    application_type != "container"
                    or not isinstance(digest, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                    or version != digest
                    or source_inventory.is_absolute()
                    or ".." in source_inventory.parts
                ):
                    errors.append(f"{relative} application {index} has invalid runtime-container evidence")
                    continue
                inventory_path = path.parent / Path(*source_inventory.parts)
                try:
                    inventory_sha = hashlib.sha256(_bounded_read(inventory_path, 16 * 1024 * 1024)).hexdigest()
                except (OSError, EvidenceError):
                    inventory_sha = ""
                if inventory_sha != evidence_sha:
                    errors.append(f"{relative} application {index} runtime evidence digest differs")
                runtime_digests.add(digest)
            elif source == "declared-evidence":
                required_fields = {
                    "type",
                    "name",
                    "version",
                    "source",
                    "evidence_path",
                    "evidence_sha256",
                }
                if not required_fields <= set(application) or set(application) - (required_fields | {"digest"}):
                    errors.append(f"{relative} application {index} has malformed declared-evidence fields")
                    continue
                evidence_path = PurePosixPath(str(application.get("evidence_path", "")))
                if (
                    application_type not in DECLARED_APPLICATION_TYPES
                    or str(version).lower() in MUTABLE_APPLICATION_VERSIONS
                    or evidence_path.is_absolute()
                    or ".." in evidence_path.parts
                    or (
                        digest is not None
                        and (not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None)
                    )
                ):
                    errors.append(f"{relative} application {index} has invalid declared evidence")
                    continue
                declared_path = root / Path(*evidence_path.parts)
                try:
                    if declared_path.is_symlink():
                        raise EvidenceError("declared test-application evidence cannot be a symlink")
                    declared_sha = hashlib.sha256(_bounded_read(declared_path, 16 * 1024 * 1024)).hexdigest()
                except (OSError, EvidenceError):
                    declared_sha = ""
                if declared_sha != evidence_sha:
                    errors.append(f"{relative} application {index} declared evidence digest differs")
                declared_inventory_claims.append(
                    (
                        str(application_type),
                        str(name),
                        str(version),
                        evidence_path.as_posix(),
                        str(digest or ""),
                    )
                )
            else:
                errors.append(f"{relative} application {index} has an unknown evidence source")
        if applications and not application_identities:
            errors.append(f"{relative} has no valid test applications")

        policy_claims = [
            (
                str(item["type"]),
                str(item["name"]),
                str(item["version"]),
                str(item["evidence_path"]),
                str(item.get("digest", "")),
            )
            for item in policy["dependencies"]
        ]
        if policy_mode == "runtime-container":
            if not applications:
                errors.append(f"{relative} runtime-container policy has no test applications")
            if any(source != "runtime-container" for source in observed_sources):
                errors.append(f"{relative} runtime-container policy contains non-runtime evidence")
            if disposition is not None:
                errors.append(f"{relative} runtime-container policy has a disposition")
        elif policy_mode == "declared-evidence":
            if not applications:
                errors.append(f"{relative} declared-evidence policy has no test applications")
            if any(source != "declared-evidence" for source in observed_sources):
                errors.append(f"{relative} declared-evidence policy contains non-declared evidence")
            if disposition is not None:
                errors.append(f"{relative} declared-evidence policy has a disposition")
            if sorted(declared_inventory_claims) != sorted(policy_claims):
                errors.append(f"{relative} declared dependencies differ from the exact registry policy")
        else:
            expected_disposition = {"status": "not-applicable", "reason": policy["reason"]}
            if applications:
                errors.append(f"{relative} not-applicable policy contains test applications")
            if disposition != expected_disposition:
                errors.append(f"{relative} disposition differs from the exact registry policy")
        runtime_digests_by_cell[cell] = runtime_digests

    for cell in sorted(set(container_digests_by_cell) | set(application_profiles_by_cell)):
        container_digests = container_digests_by_cell.get(cell, set())
        runtime_digests = runtime_digests_by_cell.get(cell, set())
        cell_name = "/".join(cell)
        if cell not in application_profiles_by_cell:
            errors.append(f"container evidence {cell_name} has no test-application inventory")
        elif runtime_digests != container_digests:
            errors.append(f"runtime test-application digests differ from container evidence for {cell_name}")

    expected_profiles = {
        (str(item.get("scenario")), str(item.get("target"))): normalize_profile(item.get("profile"))
        for item in matrix_cells
        if isinstance(item, dict) and _nonempty_text(item.get("scenario")) and _nonempty_text(item.get("target"))
    }
    if expected_profiles:
        for cell in sorted(set(expected_profiles) | set(application_profiles_by_cell)):
            if cell not in application_profiles_by_cell:
                errors.append(f"mandatory matrix cell {'/'.join(cell)} lacks a test-application inventory")
            elif cell not in expected_profiles:
                errors.append(f"test-application inventory {'/'.join(cell)} is outside the mandatory matrix")
            elif application_profiles_by_cell[cell] != expected_profiles[cell]:
                errors.append(f"test-application profile differs for {'/'.join(cell)}")
    return sorted(set(errors))


def _version_environment() -> tuple[dict[str, str], dict[str, str]]:
    tools: dict[str, str] = {}
    applications: dict[str, str] = {}
    tool_tokens = ("python", "ansible", "molecule", "pytest", "playwright", "allure")
    for key, value in os.environ.items():
        if not key.endswith("_VERSION") or SECRET_KEY_RE.search(key):
            continue
        normalized = key[:-8].lower().replace("_", "-")
        if any(token in normalized for token in tool_tokens):
            tools[normalized] = value
        else:
            applications[normalized] = value
    return dict(sorted(tools.items())), dict(sorted(applications.items()))


def _prerequisite_statuses(*, preliminary: bool = False) -> tuple[dict[str, str], list[str]]:
    raw = os.getenv("QUALITY_EVIDENCE_PREREQUISITES_JSON") or os.getenv("QUALITY_EVIDENCE_PREREQUISITES")
    if not raw:
        return {}, []
    try:
        payload = _strict_json_loads(raw)
    except (EvidenceError, json.JSONDecodeError) as error:
        return {}, [f"mandatory prerequisite status JSON is malformed: {error}"]
    if not isinstance(payload, dict) or not payload:
        return {}, ["mandatory prerequisite status JSON must be a nonempty object"]
    statuses: dict[str, str] = {}
    errors: list[str] = []
    for key, value in payload.items():
        name = str(key)
        if name not in MANDATORY_PREREQUISITES:
            errors.append(f"unknown mandatory prerequisite status: {name}")
        status = value if isinstance(value, str) else str(value)
        statuses[name] = status
        if status != "success" and not (preliminary and name == "destroy" and status == "pending"):
            errors.append(f"mandatory prerequisite {name} concluded {status or 'unknown'}")
    for name in MANDATORY_PREREQUISITES:
        if name not in statuses:
            errors.append(f"mandatory prerequisite status is missing: {name}")
    return dict(sorted(statuses.items())), errors


def _write_metadata(
    root: Path,
    repository_root: Path,
    registry_path: Path | None,
    *,
    commit_sha: str,
    run_attempt: str,
) -> dict[str, str]:
    metadata = {
        "repository.txt": os.getenv("GITHUB_REPOSITORY", "lightning-it/ansible-collection-supplementary"),
        "branch.txt": os.getenv("GITHUB_REF_NAME", "local"),
        "commit-sha.txt": commit_sha,
        "workflow-run-id.txt": os.getenv("GITHUB_RUN_ID", "local"),
        "workflow-attempt.txt": run_attempt,
    }
    for filename, value in metadata.items():
        (root / "source" / filename).write_text(f"{value}\n", encoding="utf-8")
    galaxy = repository_root / "galaxy.yml"
    if galaxy.is_file():
        shutil.copy2(galaxy, root / "collection" / "galaxy.yml")
    collection_version = os.getenv("COLLECTION_VERSION", "unknown")
    if collection_version == "unknown" and galaxy.is_file():
        match = re.search(r"(?m)^version:\s*[\"']?([^\s\"']+)", galaxy.read_text(encoding="utf-8"))
        if match:
            collection_version = match.group(1)
    (root / "collection" / "collection-version.txt").write_text(f"{collection_version}\n", encoding="utf-8")
    if registry_path and registry_path.is_file():
        shutil.copy2(registry_path, root / "role-coverage.yml")
    return {**metadata, "collection_version": collection_version}


def _prepare_stage(root: Path) -> Path:
    root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{root.name}-", dir=root.parent))
    for directory in EVIDENCE_DIRECTORIES:
        (stage / directory).mkdir(parents=True, exist_ok=True)
    existing_security = root / "security"
    if existing_security.is_dir():
        shutil.copytree(existing_security, stage / "security", dirs_exist_ok=True)
    return stage


def _replace_root(stage: Path, root: Path) -> None:
    backup: Path | None = None
    if root.exists():
        backup = root.with_name(f".{root.name}.previous-{uuid.uuid4().hex[:8]}")
        root.replace(backup)
    try:
        stage.replace(root)
    except Exception:
        if backup and backup.exists() and not root.exists():
            backup.replace(root)
        raise
    finally:
        if backup and backup.exists():
            shutil.rmtree(backup)


def _merge_status(statuses: Iterable[str]) -> str:
    values = set(statuses)
    for status in ("infrastructure-error", "failed", "skipped-with-approved-justification"):
        if status in values:
            return status
    return "passed" if values == {"passed"} else "infrastructure-error"


def _aggregate_reports(report_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    seen_hashes: dict[tuple[str, str, str, str, str], set[str]] = {}
    for row in report_rows:
        identity: Identity = row["identity"]
        key = identity.result_key
        group = groups.setdefault(
            key,
            {
                "id": identity.identifier,
                "role": identity.role,
                "profile": identity.profile,
                "scenario": identity.scenario,
                "target": identity.target,
                "run_attempt": identity.run_attempt,
                "status": "passed",
                "totals": {"tests": 0, "failures": 0, "errors": 0, "skipped": 0},
                "test_cases": [],
                "junit": [],
                "allure_results": [],
                "frameworks": [],
                "meaningful": True,
                "blockers": [],
            },
        )
        digest = row["report"].get("logical_sha256", row["report"].get("content_sha256", row["junit"]))
        if digest in seen_hashes.setdefault(key, set()):
            continue
        seen_hashes[key].add(digest)
        report = row["report"]
        group.setdefault("_statuses", []).append(report["status"])
        for total, value in report["totals"].items():
            group["totals"][total] += int(value)
        group["test_cases"].extend(report["test_cases"])
        group["junit"].append(row["junit"])
        group["allure_results"].extend(row.get("allure_results", []))
        group["frameworks"].append(report.get("framework", "junit"))
        group["meaningful"] = group["meaningful"] and bool(report.get("meaningful"))
        if report.get("infrastructure_error"):
            group["blockers"].append(report["infrastructure_error"])
        if report["status"] == "failed" and report["totals"].get("skipped"):
            group["blockers"].append("mandatory JUnit contains an unapproved skip")
        if not row.get("allure_complete", False):
            group["blockers"].append("missing meaningful Allure results for one or more JUnit testcases")
    results: list[dict[str, Any]] = []
    for key in sorted(groups):
        group = groups[key]
        group["status"] = _merge_status(group.pop("_statuses", []))
        group["junit"] = sorted(set(group["junit"]))
        group["allure_results"] = sorted(set(group["allure_results"]))
        group["frameworks"] = sorted(set(group["frameworks"]))
        group["blockers"] = sorted(set(group["blockers"]))
        if group["blockers"] and group["status"] == "passed":
            group["status"] = "failed"
        results.append(group)
    return results


def _evaluate_expected(expected: list[dict[str, Any]], actual: Sequence[dict[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for cell in expected:
        matching = [
            item
            for item in actual
            if item["scenario"] == cell["scenario"]
            and item["profile"] == cell["profile"]
            and item["target"] == cell["target"]
            and item["run_attempt"] == cell["run_attempt"]
        ]
        matched_roles = {item["role"] for item in matching if item["status"] == "passed"}
        required_roles = set(cell["roles"])
        cell["actual_result_ids"] = sorted(item["id"] for item in matching)
        if required_roles <= matched_roles and all(item["status"] == "passed" for item in matching):
            cell["status"] = "passed"
        else:
            cell["status"] = "infrastructure-error" if not matching else "failed"
            missing_roles = sorted(required_roles - matched_roles)
            if missing_roles:
                blockers.append(
                    f"mandatory cell {cell['scenario']}/{cell['target']}/attempt-{cell['run_attempt']} "
                    f"has no passing evidence for roles: {', '.join(missing_roles)}"
                )
    return blockers


def _manifest_logic_failures(manifest: dict[str, Any], *, release_mode: bool, preliminary: bool = False) -> list[str]:
    failures: list[str] = []
    results = manifest.get("results", [])
    if not isinstance(results, list) or not results:
        failures.append("no executed test results")
        results = []
    for item in results:
        if not isinstance(item, dict):
            failures.append("invalid result record")
            continue
        status = item.get("status")
        if status not in ALLOWED_RESULT_STATUSES:
            failures.append(f"result {item.get('id', '<unknown>')} has disallowed status {status}")
        if status != "passed":
            failures.append(f"result {item.get('id', '<unknown>')} did not pass")
        for key in ("role", "profile", "scenario", "target", "run_attempt"):
            value = str(item.get(key, "")).strip()
            if not value:
                failures.append(f"result {item.get('id', '<unknown>')} lacks {key} identity")
            elif key in {"role", "profile", "target"} and value.lower() == "unknown":
                failures.append(f"result {item.get('id', '<unknown>')} has unknown {key} identity")
        if not item.get("meaningful"):
            failures.append(f"result {item.get('id', '<unknown>')} is an opaque process result")
        if not item.get("allure_results"):
            failures.append(f"result {item.get('id', '<unknown>')} lacks Allure results")
    matrix = manifest.get("matrix")
    expected_matrix = matrix.get("expected", []) if isinstance(matrix, dict) else []
    if not isinstance(expected_matrix, list):
        expected_matrix = []
    for cell in expected_matrix:
        if not isinstance(cell, dict) or cell.get("status") != "passed":
            failures.append(
                f"mandatory matrix cell {cell.get('scenario') if isinstance(cell, dict) else '<invalid>'}/"
                f"{cell.get('target') if isinstance(cell, dict) else '<invalid>'}/"
                f"attempt-{cell.get('run_attempt') if isinstance(cell, dict) else '<invalid>'} did not pass"
            )
    blockers = manifest.get("blockers", [])
    if isinstance(blockers, list):
        failures.extend(str(item) for item in blockers if item)
    scan = manifest.get("secret_scan")
    if not isinstance(scan, dict):
        scan = {}
    if scan.get("clean") is not True or scan.get("findings") or scan.get("errors"):
        failures.append("final evidence secret scan is not clean")
    security = manifest.get("security_evidence")
    if not isinstance(security, dict):
        security = {}
    if release_mode:
        if security.get("missing") or security.get("semantic_valid") is not True:
            failures.append("release security evidence is incomplete or invalid")
        if not security.get("candidate_sha256"):
            failures.append("release security evidence is not bound to a candidate digest")
        if security.get("vulnerability_blocking_findings", 0):
            failures.append("release security evidence has blocking vulnerabilities")
        if manifest.get("support_classification") != "from-role-coverage-registry":
            failures.append("release evidence is not registry-backed")
        if not expected_matrix:
            failures.append("release evidence has an empty expected matrix")
    if security.get("external_secret_findings", 0):
        failures.append("external secret scan has findings")
    tested_commit = str(manifest.get("commit_sha", ""))
    recorded_expected_commit = str(manifest.get("expected_commit_sha", ""))
    if (
        manifest.get("commit_consistent") is not True
        or not _valid_commit(tested_commit)
        or tested_commit != recorded_expected_commit
    ):
        failures.append("tested commit identity is inconsistent")
    prerequisites = manifest.get("prerequisites", {})
    if not isinstance(prerequisites, dict):
        failures.append("mandatory prerequisite statuses are invalid")
    else:
        names = set(prerequisites)
        if names and names != set(MANDATORY_PREREQUISITES):
            failures.append("mandatory prerequisite status names are incomplete or unknown")
        for name, status in prerequisites.items():
            if status != "success" and not (preliminary and name == "destroy" and status == "pending"):
                failures.append(f"mandatory prerequisite {name} did not succeed")
    return sorted(set(failures))


def _input_acceptance(input_roots, previous, *, preliminary, candidate_mode, expected_commit, final_inputs):
    """A copied report cannot shed its original pending/candidate acceptance barrier."""
    manifests = {}
    for root in [*input_roots, previous]:
        if not root.exists():
            continue
        if root.is_symlink():
            raise EvidenceError("symlinked acceptance input")
        for path in _bounded_artifact_walk(root, name="manifest.json"):
            if path.is_symlink() or not path.is_file():
                raise EvidenceError("invalid acceptance manifest")
            value = _strict_json_loads(_bounded_read(path).decode("utf-8"))
            if not isinstance(value, dict):
                raise EvidenceError("invalid acceptance manifest object")
            manifests[path.parent.resolve()] = value
    proofs = []
    if final_inputs is not None:
        proofs.append(final_inputs)
    # Ordinary business evidence never imports cryptographic dependencies or needs network access.
    persisted = [
        (root, value)
        for root, value in manifests.items()
        if "root_final_quality_inputs" in value or (root / "root-final-inputs").exists()
    ]
    if persisted or proofs:
        final_quality = _final_verifier()

        for root, value in persisted:
            proofs.append(final_quality.verify_persisted_inputs(root, value, source_sha=expected_commit))
        proof = final_quality.combine_inputs(proofs)
        authorized = final_quality.authorized_roots(proof)
    else:
        proof, authorized = None, set()
    for root, value in manifests.items():
        if value.get("mode") == "candidate" and not candidate_mode:
            raise EvidenceError("candidate input cannot authorize final evidence")
        if "root_finalization" in value:
            if value["root_finalization"] != "pending":
                raise EvidenceError("unknown Root finalization state")
            if not preliminary and root not in authorized:
                raise EvidenceError("pending input lacks independently verified Root finalization")
    return proof


def assemble(
    root: Path,
    *,
    input_roots: Sequence[Path] | None = None,
    registry_path: Path | None = None,
    repository_root: Path | None = None,
    roles: Sequence[str] = (),
    registry_role_filter: Sequence[str] | None = None,
    profiles: Sequence[str] = (),
    scenarios: Sequence[str] = (),
    targets: Sequence[str] = (),
    run_attempt: str | None = None,
    release_mode: bool = False,
    candidate_mode: bool = False,
    preliminary: bool = False,
    expected_commit: str | None = None,
    mandatory_scenarios: Sequence[str] = (),
    final_inputs=None,
) -> int:
    if preliminary and release_mode:
        raise EvidenceError("preliminary evidence cannot authorize release acceptance")
    root = root.resolve()
    repository_root = (repository_root or Path.cwd()).resolve()
    input_roots = [path.resolve() for path in (input_roots or [root.parent])]
    if root in input_roots:
        raise EvidenceError("evidence output root cannot also be an input root")
    registry_path = registry_path or repository_root / "meta" / "role-coverage.yml"
    registry, registry_errors = load_registry(registry_path)
    attempt = str(run_attempt or os.getenv("QUALITY_EVIDENCE_RUN_ATTEMPT") or os.getenv("GITHUB_RUN_ATTEMPT") or "1")
    commit_sha = _tested_commit()
    expected_commit = expected_commit or os.getenv("QUALITY_EVIDENCE_EXPECTED_COMMIT") or commit_sha
    commit_consistent = _valid_commit(commit_sha) and commit_sha == expected_commit
    try:
        supplied_proof = final_inputs
        final_inputs = _input_acceptance(
            input_roots,
            root,
            preliminary=preliminary,
            candidate_mode=candidate_mode,
            expected_commit=expected_commit,
            final_inputs=final_inputs,
        )
    except (ValueError, ImportError, OSError, KeyError, TypeError) as error:
        raise EvidenceError("input acceptance provenance verification held") from error
    stage = _prepare_stage(root)
    try:
        metadata = _write_metadata(
            stage,
            repository_root,
            registry_path if registry_path.is_file() else None,
            commit_sha=commit_sha,
            run_attempt=attempt,
        )
        junit_paths = copy_artifacts(input_roots, stage, excluded=(root, stage))
        final_references = []
        physical_cells = set()
        retained = set()
        if final_inputs is not None:
            final_quality = _final_verifier()

            final_references, final_inputs = final_quality.persist_inputs(final_inputs, stage)
            retained = final_quality.retained_paths(final_inputs)
            physical_cells = final_quality.physical_cells(final_inputs)
        default_roles = list(roles)
        default_profiles = [normalize_profile(item) for item in profiles]
        default_scenarios = list(scenarios or mandatory_scenarios)
        default_targets = list(targets)
        if not default_roles:
            env_role = os.getenv("QUALITY_EVIDENCE_ROLE")
            if env_role:
                default_roles = [env_role]
        if not default_profiles:
            env_profile = os.getenv("QUALITY_EVIDENCE_PROFILE")
            if env_profile:
                default_profiles = [normalize_profile(env_profile)]
        if not default_scenarios:
            env_scenario = os.getenv("QUALITY_EVIDENCE_SCENARIO")
            if env_scenario:
                default_scenarios = [env_scenario]
        if not default_targets:
            env_target = os.getenv("QUALITY_EVIDENCE_TARGET") or os.getenv("KEYCLOAK_TEST_TARGET")
            if env_target:
                default_targets = [env_target]

        if release_mode and candidate_mode:
            raise EvidenceError("release and candidate evidence modes are mutually exclusive")
        expected = expected_cells(
            registry,
            run_attempt=attempt,
            role_filter=set(roles if registry_role_filter is None else registry_role_filter) or None,
            profile_filter=set(default_profiles) or None,
            scenario_filter=set(default_scenarios) or None,
            target_filter=set(default_targets) or None,
            target_disposition="candidate" if candidate_mode else "supported",
        )
        if not expected and mandatory_scenarios and not registry:
            fallback_target = default_targets[0] if len(default_targets) == 1 else "unknown"
            fallback_roles = default_roles or ["unknown"]
            for scenario in mandatory_scenarios:
                profile = next(
                    (candidate for candidate in PROFILES if candidate in scenario.replace("_", "-")), "unknown"
                )
                expected.append(
                    {
                        "scenario": scenario,
                        "profile": profile,
                        "target": fallback_target,
                        "run_attempt": attempt,
                        "roles": sorted(set(fallback_roles)),
                        "required": True,
                    }
                )

        if release_mode:
            if not registry:
                registry_errors.append("release evidence requires meta/role-coverage.yml")
            if not expected:
                registry_errors.append("release evidence requires a nonempty production matrix")
            if registry:
                complete_expected = expected_cells(registry, run_attempt=attempt)
                expected_keys = {
                    (item["scenario"], item["profile"], item["target"], tuple(item["roles"])) for item in expected
                }
                complete_keys = {
                    (item["scenario"], item["profile"], item["target"], tuple(item["roles"]))
                    for item in complete_expected
                }
                if expected_keys != complete_keys:
                    registry_errors.append("release evidence matrix is a filtered subset of the production registry")

        native_allure = _native_allure_results(stage)
        used_native_allure: set[str] = set()
        report_rows: list[dict[str, Any]] = []
        parse_failures: list[str] = []
        test_commit_failures: list[str] = []
        parsed_inputs: dict[Path, tuple[dict[str, Any], dict[str, Any]]] = {}
        parse_input_errors: dict[Path, str] = {}
        exact_report_keys: set[tuple[Any, ...]] = set()
        for junit_path in junit_paths:
            try:
                parsed_report = parse_junit(junit_path)
            except (EvidenceError, OSError) as error:
                parse_input_errors[junit_path] = str(error)
                continue
            inferred_report = infer_report_identity(
                parsed_report,
                junit_path.relative_to(stage / "junit"),
                registry,
                default_roles=default_roles,
                default_profiles=default_profiles,
                default_scenarios=default_scenarios,
                default_targets=default_targets,
                default_attempt=attempt,
            )
            parsed_inputs[junit_path] = (parsed_report, inferred_report)
            report_key = (
                parsed_report["logical_sha256"],
                inferred_report["scenario"],
                inferred_report["profile"],
                inferred_report["target"],
                inferred_report["run_attempt"],
                tuple(inferred_report["roles"]),
            )
            if _report_commit(parsed_report) == commit_sha and _valid_commit(commit_sha):
                exact_report_keys.add(report_key)
        for junit_path in junit_paths:
            relative = junit_path.relative_to(stage).as_posix()
            if junit_path not in parsed_inputs:
                fallback_reason = parse_input_errors.get(junit_path, "JUnit could not be parsed")
                synthetic_identity = Identity(
                    role=default_roles[0] if len(default_roles) == 1 else "unknown",
                    profile=default_profiles[0] if len(default_profiles) == 1 else "unknown",
                    scenario=default_scenarios[0] if len(default_scenarios) == 1 else junit_path.stem,
                    target=default_targets[0] if len(default_targets) == 1 else "unknown",
                    run_attempt=attempt,
                )
                fallback_relative, fallback_report = _fallback_junit(stage, synthetic_identity, fallback_reason)
                allure = [
                    generate_allure_result(
                        stage,
                        synthetic_identity,
                        case,
                        ordinal=index,
                        source_junit=fallback_relative,
                    )
                    for index, case in enumerate(fallback_report["test_cases"])
                ]
                report_rows.append(
                    {
                        "identity": synthetic_identity,
                        "report": fallback_report,
                        "junit": fallback_relative,
                        "allure_results": allure,
                        "allure_complete": True,
                    }
                )
                parse_failures.append(f"{relative}: {fallback_reason}")
                continue
            report, inferred = parsed_inputs[junit_path]

            report_key = (
                report["logical_sha256"],
                inferred["scenario"],
                inferred["profile"],
                inferred["target"],
                inferred["run_attempt"],
                tuple(inferred["roles"]),
            )
            reported_commit = _report_commit(report)
            if reported_commit != commit_sha or not _valid_commit(reported_commit):
                if reported_commit in {"", "unknown"} and report_key in exact_report_keys:
                    continue
                test_commit_failures.append(f"{relative}: JUnit lacks the exact tested commit")
                commit_consistent = False

            scenario_definition = registry_scenarios(registry).get(inferred["scenario"])
            if registry and scenario_definition is None:
                parse_failures.append(f"{relative}: JUnit scenario is not registered")
                continue
            if scenario_definition is not None:
                allowed_roles = set(_split_roles(scenario_definition.get("roles", [])))
                if normalize_profile(scenario_definition.get("profile")) != inferred["profile"]:
                    parse_failures.append(f"{relative}: JUnit profile differs from its registered scenario")
                    continue
                unknown_report_roles = sorted(set(inferred["roles"]) - allowed_roles)
                if unknown_report_roles:
                    parse_failures.append(
                        f"{relative}: JUnit reports roles outside its scenario: {', '.join(unknown_report_roles)}"
                    )
                    continue
            for role in inferred["roles"]:
                identity = Identity(
                    role=role,
                    profile=inferred["profile"],
                    scenario=inferred["scenario"],
                    target=inferred["target"],
                    run_attempt=inferred["run_attempt"],
                )
                try:
                    role_report = _report_for_role(report, role, inferred["roles"])
                except EvidenceError as error:
                    parse_failures.append(f"{relative}: {error}")
                    continue
                if (
                    role_report["framework"] == "pytest"
                    or (identity.profile.replace("-", "_"), identity.scenario, identity.target) in physical_cells
                ):
                    allure, allure_failures = _native_matches(
                        role_report["test_cases"],
                        native_allure,
                        identity,
                        used_paths=used_native_allure,
                    )
                    parse_failures.extend(allure_failures)
                    allure_complete = not allure_failures and len(allure) == len(role_report["test_cases"])
                else:
                    allure = [
                        generate_allure_result(stage, identity, case, ordinal=index, source_junit=relative)
                        for index, case in enumerate(role_report["test_cases"])
                    ]
                    allure_complete = len(allure) == len(role_report["test_cases"])
                report_rows.append(
                    {
                        "identity": identity,
                        "report": role_report,
                        "junit": relative,
                        "allure_results": allure,
                        "allure_complete": allure_complete,
                    }
                )

        provisional_results = _aggregate_reports(report_rows)
        current_actual_keys = {
            (item["role"], item["profile"], item["scenario"], item["target"], item["run_attempt"])
            for item in provisional_results
        }
        for cell in expected:
            for role in cell["roles"]:
                identity = Identity(role, cell["profile"], cell["scenario"], cell["target"], cell["run_attempt"])
                if identity.result_key in current_actual_keys:
                    continue
                reason = "mandatory matrix cell produced no JUnit report"
                fallback_relative, fallback_report = _fallback_junit(stage, identity, reason)
                allure = [
                    generate_allure_result(stage, identity, case, ordinal=index, source_junit=fallback_relative)
                    for index, case in enumerate(fallback_report["test_cases"])
                ]
                report_rows.append(
                    {
                        "identity": identity,
                        "report": fallback_report,
                        "junit": fallback_relative,
                        "allure_results": allure,
                        "allure_complete": True,
                    }
                )
        results = _aggregate_reports(report_rows)
        matrix_blockers = _evaluate_expected(expected, results)

        # A component scenario may report multiple roles.  Count each executed
        # JUnit shard once globally while retaining role-specific result rows.
        totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        counted_executions: set[tuple[tuple[str, str, str, str], str]] = set()
        for row in report_rows:
            fingerprint = str(row["report"].get("logical_sha256", row["report"].get("content_sha256", row["junit"])))
            execution_key = (row["identity"].cell_key, fingerprint)
            if execution_key in counted_executions:
                continue
            counted_executions.add(execution_key)
            for key in totals:
                totals[key] += int(row["report"]["totals"][key])
        tools, applications = _version_environment()
        environment = {
            "generated_at": utc_now(),
            "repository": metadata["repository.txt"],
            "commit_sha": commit_sha,
            "workflow_run_id": metadata["workflow-run-id.txt"],
            "workflow_attempt": attempt,
            "roles": sorted({item["role"] for item in results}),
            "profiles": sorted({item["profile"] for item in results}),
            "scenarios": sorted({item["scenario"] for item in results}),
            "targets": sorted({item["target"] for item in results}),
            "tool_versions": tools,
            "application_versions": applications,
        }
        (stage / "environment.json").write_text(
            json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        matrix_payload = {
            "schema_version": 1,
            "run_attempt": attempt,
            "expected": expected,
            "actual": [
                {
                    key: result[key]
                    for key in ("id", "role", "profile", "scenario", "target", "run_attempt", "status", "totals")
                }
                for result in results
            ],
            "dispositions": declared_dispositions(registry),
        }
        (stage / "matrix" / "results.json").write_text(
            json.dumps(matrix_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        security_evidence, security_errors = assess_security(stage, release_mode=release_mode, commit_sha=commit_sha)
        dependency_errors = assess_dependencies(
            stage,
            release_mode=release_mode,
            expected_commit=commit_sha,
            repository_root=repository_root,
            matrix_cells=expected,
        )
        prerequisites, prerequisite_errors = _prerequisite_statuses(preliminary=preliminary)
        blockers = (
            list(registry_errors)
            + parse_failures
            + test_commit_failures
            + matrix_blockers
            + security_errors
            + dependency_errors
            + prerequisite_errors
        )
        if not commit_consistent:
            blockers.append("tested commit differs from requested release commit")

        canary_path = stage / "logs" / "redaction-canary-proof.log"
        canary_path.write_text(f"password={CANARY}\n", encoding="utf-8")
        before_scan = scan_evidence(stage, final_inputs=final_inputs)
        if not any(item["kind"] == "canary" for item in before_scan["findings"]):
            raise EvidenceError("evidence scanner did not detect the synthetic canary before redaction")
        for path in sorted(stage.rglob("*")):
            if (
                path.is_file()
                and not path.is_symlink()
                and "checksums" not in path.relative_to(stage).parts
                and path.resolve() not in retained
            ):
                redact_file(path)
        final_scan = scan_evidence(stage, final_inputs=final_inputs)
        scan_summary = {
            "scanner": "quality-evidence-stdlib-v1",
            "canary_detected_before_redaction": True,
            **final_scan,
        }
        (stage / "security" / "evidence-secret-scan.json").write_text(
            json.dumps(scan_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        # Scan the summary itself as part of the final evidence set.
        final_scan = scan_evidence(stage, final_inputs=final_inputs)
        scan_summary.update(
            {
                "clean": final_scan["clean"],
                "files_scanned": final_scan["files_scanned"],
                "archive_members_scanned": final_scan["archive_members_scanned"],
                "findings": final_scan["findings"],
                "errors": final_scan["errors"],
            }
        )
        (stage / "security" / "evidence-secret-scan.json").write_text(
            json.dumps(scan_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if not final_scan["clean"]:
            blockers.append("final text/binary/archive evidence scan is not clean")

        started = os.getenv("QUALITY_EVIDENCE_STARTED_AT", utc_now())
        manifest: dict[str, Any] = {
            "schema_version": 2,
            "mode": "release" if release_mode else "candidate" if candidate_mode else "ci",
            "generated_at": utc_now(),
            "timestamps": {"started_at": started, "completed_at": utc_now()},
            "repository": metadata["repository.txt"],
            "branch": metadata["branch.txt"],
            "commit_sha": commit_sha,
            "expected_commit_sha": expected_commit,
            "commit_consistent": commit_consistent,
            "workflow_run_id": metadata["workflow-run-id.txt"],
            "workflow_attempt": attempt,
            "actor": os.getenv("GITHUB_ACTOR", "local"),
            "runner": os.getenv("RUNNER_NAME", "local"),
            "collection_version": metadata["collection_version"],
            "roles": environment["roles"],
            "profiles": environment["profiles"],
            "scenarios": environment["scenarios"],
            "targets": environment["targets"],
            "tool_versions": tools,
            "application_versions": applications,
            "test_totals": totals,
            "failures": totals["failures"] + totals["errors"],
            "skips": totals["skipped"],
            "results": results,
            "matrix": {"expected": expected, "actual_count": len(results)},
            "coverage_dispositions": declared_dispositions(registry),
            "support_classification": "from-role-coverage-registry" if registry else "unregistered",
            "security_evidence": security_evidence,
            "prerequisites": prerequisites,
            "secret_scan": scan_summary,
            "blockers": sorted(set(blockers)),
            "long_term_archive": os.getenv("QUALITY_EVIDENCE_ARCHIVE_STATUS")
            or os.getenv("KEYCLOAK_EVIDENCE_ARCHIVE_STATUS", "not-configured"),
            "checksums": {
                "algorithm": "sha256",
                "file": "checksums/SHA256SUMS",
                "entry_count": 0,
            },
            "release_eligible": False,
        }
        if final_references:
            manifest["root_final_quality_inputs"] = final_references
        manifest = redact_strings(manifest)
        execution_passed = not _manifest_logic_failures(manifest, release_mode=release_mode, preliminary=preliminary)
        if preliminary:
            # This is a sanitized execution export, before the native job ends.
            # Only Root can subsequently attest terminal success and destruction.
            manifest["root_finalization"] = "pending"
            manifest["execution_success"] = execution_passed
            manifest["candidate_execution_passed"] = False
            manifest["release_eligible"] = False
        elif candidate_mode:
            manifest["candidate_execution_passed"] = execution_passed
            manifest["release_eligible"] = False
        else:
            manifest["release_eligible"] = execution_passed
        manifest_path = stage / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        checksum_file = stage / "checksums" / "SHA256SUMS"
        paths = [path for path in sorted(stage.rglob("*")) if path.is_file() and path != checksum_file]
        manifest["checksums"]["entry_count"] = len(paths)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        checksum_file.write_text(
            "".join(f"{sha256(path)}  {path.relative_to(stage).as_posix()}\n" for path in paths),
            encoding="utf-8",
        )
        post_checksum_scan = scan_evidence(stage, final_inputs=final_inputs)
        if not post_checksum_scan["clean"]:
            problem_paths = [f"{item['path']} ({item['kind']})" for item in post_checksum_scan["findings"]] + list(
                post_checksum_scan["errors"]
            )
            raise EvidenceError(
                "final checksummed evidence failed text/binary/archive secret scanning: " + "; ".join(problem_paths)
            )
        _replace_root(stage, root)
        if final_inputs is not None:
            final_quality.relocate_inputs(final_inputs, stage, root)
            if supplied_proof is not None:
                final_quality.share_verified_inputs(supplied_proof, final_inputs)
        return 0 if execution_passed else 1
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _validate_checksums(root: Path, checksum_path: Path) -> list[str]:
    failures: list[str] = []
    expected_paths: set[str] = set()
    try:
        lines = _bounded_read(checksum_path).decode("utf-8").splitlines()
    except (OSError, EvidenceError, UnicodeDecodeError) as error:
        return [f"cannot read checksums: {error}"]
    if len(lines) > MAX_EVIDENCE_FILES:
        return [f"checksum list exceeds {MAX_EVIDENCE_FILES}-entry limit"]
    for number, line in enumerate(lines, 1):
        if "  " not in line:
            failures.append(f"malformed checksum line {number}")
            continue
        expected, relative = line.split("  ", 1)
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            failures.append(f"invalid SHA-256 on checksum line {number}")
            continue
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in expected_paths:
            failures.append(f"unsafe or duplicate checksum path: {relative}")
            continue
        expected_paths.add(relative)
        path = root.joinpath(*pure.parts)
        resolved_path = path.resolve()
        if root != resolved_path and root not in resolved_path.parents:
            failures.append(f"checksummed evidence path escapes root: {relative}")
        elif not path.is_file() or path.is_symlink() or resolved_path != path.absolute():
            failures.append(f"missing checksummed file: {relative}")
        elif path.stat().st_size > MAX_EVIDENCE_FILE_BYTES:
            failures.append(f"checksummed evidence file exceeds size limit: {relative}")
        elif sha256(path) != expected:
            failures.append(f"checksum mismatch: {relative}")
    actual_paths: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or path == checksum_path or path.is_symlink():
            continue
        actual_paths.add(path.relative_to(root).as_posix())
        if len(actual_paths) > MAX_EVIDENCE_FILES:
            failures.append(f"evidence set exceeds {MAX_EVIDENCE_FILES}-file limit")
            break
    for relative in sorted(actual_paths - expected_paths):
        failures.append(f"unchecksummed evidence file: {relative}")
    for relative in sorted(expected_paths - actual_paths):
        failures.append(f"checksum references absent evidence file: {relative}")
    return failures


def _valid_totals(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"tests", "failures", "errors", "skipped"}:
        return False
    return all(isinstance(value[key], int) and not isinstance(value[key], bool) and value[key] >= 0 for key in value)


def _nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _string_array(value: Any, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (not nonempty or bool(value))
        and all(isinstance(item, str) and bool(item) for item in value)
    )


def _manifest_structure_failures(manifest: dict[str, Any]) -> list[str]:
    """Apply the repository schema without requiring a runtime JSON Schema package."""

    failures: list[str] = []
    required = {
        "schema_version",
        "mode",
        "repository",
        "commit_sha",
        "expected_commit_sha",
        "commit_consistent",
        "workflow_run_id",
        "workflow_attempt",
        "test_totals",
        "failures",
        "skips",
        "results",
        "matrix",
        "security_evidence",
        "secret_scan",
        "checksums",
        "blockers",
        "prerequisites",
        "release_eligible",
    }
    missing = sorted(required - set(manifest))
    failures.extend(f"manifest lacks required field {name}" for name in missing)
    if "root_finalization" in manifest:
        if manifest["root_finalization"] != "pending":
            failures.append("manifest has an unknown Root finalization state")
        failures.append("manifest awaits Root finalization and is not final quality evidence")
    if manifest.get("schema_version") != 2:
        failures.append("manifest schema_version is not 2")
    if manifest.get("mode") not in {"ci", "candidate", "release"}:
        failures.append("manifest mode is invalid")
    if manifest.get("mode") == "candidate":
        if manifest.get("candidate_execution_passed") is not True:
            failures.append("candidate manifest did not record a passing execution")
        if manifest.get("release_eligible") is not False:
            failures.append("candidate evidence must never be release eligible")
    for key in ("repository", "workflow_run_id", "workflow_attempt"):
        if not isinstance(manifest.get(key), str) or not manifest.get(key):
            failures.append(f"manifest {key} is invalid")
    for key in ("commit_sha", "expected_commit_sha"):
        if not isinstance(manifest.get(key), str) or not _valid_commit(str(manifest.get(key, ""))):
            failures.append(f"manifest {key} is not an exact commit")
    if not isinstance(manifest.get("commit_consistent"), bool):
        failures.append("manifest commit_consistent is invalid")
    if not _valid_totals(manifest.get("test_totals")):
        failures.append("manifest test_totals is invalid")
    for key in ("failures", "skips"):
        if not _nonnegative_integer(manifest.get(key)):
            failures.append(f"manifest {key} is invalid")
    results = manifest.get("results")
    if not isinstance(results, list) or not results:
        failures.append("manifest results must be a nonempty array")
        results = []
    for index, result in enumerate(results):
        prefix = f"manifest result {index}"
        if not isinstance(result, dict):
            failures.append(f"{prefix} is not an object")
            continue
        for key in ("id", "role", "profile", "scenario", "target", "run_attempt", "status"):
            if not isinstance(result.get(key), str) or not result.get(key):
                failures.append(f"{prefix} lacks {key}")
        if result.get("profile") not in PROFILES:
            failures.append(f"{prefix} has invalid profile")
        if result.get("status") not in ALLOWED_RESULT_STATUSES:
            failures.append(f"{prefix} has invalid status")
        if not _valid_totals(result.get("totals")):
            failures.append(f"{prefix} has invalid totals")
        if not isinstance(result.get("meaningful"), bool):
            failures.append(f"{prefix} has invalid meaningful flag")
        for key in ("junit", "allure_results"):
            refs = result.get(key)
            if not isinstance(refs, list) or not refs or any(not isinstance(item, str) or not item for item in refs):
                failures.append(f"{prefix} has invalid {key} references")
        cases = result.get("test_cases")
        if not isinstance(cases, list) or not cases:
            failures.append(f"{prefix} has no testcases")
            continue
        for case in cases:
            if not isinstance(case, dict):
                failures.append(f"{prefix} contains a malformed testcase")
                continue
            if not isinstance(case.get("classname"), str):
                failures.append(f"{prefix} contains a testcase with invalid classname")
            if not isinstance(case.get("name"), str) or not case.get("name"):
                failures.append(f"{prefix} contains a testcase with invalid name")
            if case.get("status") not in {"passed", "failure", "error", "skipped"}:
                failures.append(f"{prefix} contains a testcase with invalid status")
            duration = case.get("duration_seconds")
            if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0:
                failures.append(f"{prefix} contains a testcase with invalid duration")
            if case.get("roles") != [result.get("role")]:
                failures.append(f"{prefix} contains a testcase without explicit role identity")
    matrix = manifest.get("matrix")
    if not isinstance(matrix, dict):
        failures.append("manifest matrix is invalid")
    else:
        expected = matrix.get("expected")
        if not isinstance(expected, list):
            failures.append("manifest matrix expected cells are invalid")
        else:
            for index, cell in enumerate(expected):
                prefix = f"manifest matrix cell {index}"
                if not isinstance(cell, dict):
                    failures.append(f"{prefix} is not an object")
                    continue
                for key in ("scenario", "target", "run_attempt"):
                    if not isinstance(cell.get(key), str) or not cell.get(key):
                        failures.append(f"{prefix} lacks {key}")
                if cell.get("profile") not in PROFILES:
                    failures.append(f"{prefix} has invalid profile")
                if cell.get("status") not in ALLOWED_RESULT_STATUSES:
                    failures.append(f"{prefix} has invalid status")
                disposition = cell.get("target_disposition")
                release_required = cell.get("release_required")
                if disposition is not None or release_required is not None or manifest.get("mode") == "candidate":
                    if disposition not in {"supported", "candidate"}:
                        failures.append(f"{prefix} has invalid target disposition")
                    if not isinstance(release_required, bool):
                        failures.append(f"{prefix} has invalid release-required flag")
                    elif release_required != (disposition == "supported"):
                        failures.append(f"{prefix} target disposition contradicts release-required flag")
                    if manifest.get("mode") == "candidate" and disposition != "candidate":
                        failures.append(f"{prefix} is not a candidate target in candidate mode")
                    if manifest.get("mode") == "release" and disposition != "supported":
                        failures.append(f"{prefix} is not a supported target in release mode")
                roles = cell.get("roles")
                if (
                    not isinstance(roles, list)
                    or not _string_array(roles, nonempty=True)
                    or len(roles) != len(set(roles))
                ):
                    failures.append(f"{prefix} has invalid roles")
        if not _nonnegative_integer(matrix.get("actual_count")):
            failures.append("manifest matrix actual_count is invalid")
        elif isinstance(results, list) and matrix.get("actual_count") != len(results):
            failures.append("manifest matrix actual_count differs from results")
    scan = manifest.get("secret_scan")
    if not isinstance(scan, dict):
        failures.append("manifest secret_scan is invalid")
    else:
        if scan.get("canary_detected_before_redaction") is not True or scan.get("clean") is not True:
            failures.append("manifest secret_scan proof is invalid")
        for key in ("files_scanned", "archive_members_scanned"):
            value = scan.get(key)
            if not _nonnegative_integer(value) or (key == "files_scanned" and isinstance(value, int) and value < 1):
                failures.append(f"manifest secret_scan {key} is invalid")
        for key in ("findings", "errors"):
            if not isinstance(scan.get(key), list) or scan.get(key):
                failures.append(f"manifest secret_scan {key} is invalid")
    security = manifest.get("security_evidence")
    if not isinstance(security, dict):
        failures.append("manifest security_evidence is invalid")
    else:
        for key in ("required_for_release", "missing"):
            if not _string_array(security.get(key)):
                failures.append(f"manifest security_evidence.{key} is invalid")
        for key in ("external_secret_findings", "vulnerability_blocking_findings"):
            if not _nonnegative_integer(security.get(key)):
                failures.append(f"manifest security_evidence.{key} is invalid")
        provenance_commit = security.get("provenance_commit_sha")
        if provenance_commit is not None and (
            not isinstance(provenance_commit, str) or not _valid_commit(provenance_commit)
        ):
            failures.append("manifest security_evidence.provenance_commit_sha is invalid")
        candidate_sha = security.get("candidate_sha256")
        if candidate_sha is not None and (
            not isinstance(candidate_sha, str) or re.fullmatch(r"[0-9a-f]{64}", candidate_sha) is None
        ):
            failures.append("manifest security_evidence.candidate_sha256 is invalid")
        if not isinstance(security.get("semantic_valid"), bool):
            failures.append("manifest security_evidence.semantic_valid is invalid")
    checksums = manifest.get("checksums")
    if not isinstance(checksums, dict):
        failures.append("manifest checksums is invalid")
    else:
        if checksums.get("algorithm") != "sha256" or checksums.get("file") != "checksums/SHA256SUMS":
            failures.append("manifest checksum identity is invalid")
        entry_count = checksums.get("entry_count")
        if not _nonnegative_integer(entry_count) or (isinstance(entry_count, int) and entry_count < 1):
            failures.append("manifest checksum entry_count is invalid")
    blockers = manifest.get("blockers")
    if not isinstance(blockers, list) or not _string_array(blockers) or len(blockers) != len(set(blockers)):
        failures.append("manifest blockers is invalid")
    prerequisites = manifest.get("prerequisites")
    if not isinstance(prerequisites, dict):
        failures.append("manifest prerequisites is invalid")
    elif prerequisites and set(prerequisites) != set(MANDATORY_PREREQUISITES):
        failures.append("manifest prerequisites has incomplete or unknown names")
    elif any(status != "success" for status in prerequisites.values()):
        failures.append("manifest prerequisites contains a non-success status")
    if not isinstance(manifest.get("release_eligible"), bool):
        failures.append("manifest release_eligible is invalid")
    return failures


def _evidence_reference(root: Path, relative: str, category: str) -> tuple[Path | None, str | None]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != category:
        return None, f"unsafe {category} evidence reference: {relative}"
    path = root.joinpath(*pure.parts)
    resolved_path = path.resolve()
    if root != resolved_path and root not in resolved_path.parents:
        return None, f"unsafe {category} evidence reference: {relative}"
    if not path.is_file() or path.is_symlink() or resolved_path != path.absolute():
        return None, f"missing {category} evidence reference: {relative}"
    return path, None


def _case_signature(case: dict[str, Any]) -> tuple[Any, ...]:
    try:
        duration = float(case.get("duration_seconds", -1))
    except (TypeError, ValueError):
        duration = -1.0
    roles = case.get("roles", [])
    if not isinstance(roles, list):
        roles = []
    return (
        str(case.get("classname", "")),
        str(case.get("name", "")),
        str(case.get("status", "")),
        duration,
        tuple(sorted(str(role) for role in roles)),
        str(case.get("message", "")),
        str(case.get("type", "")),
    )


def _rederive_manifest_results(root: Path, manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    tested_commit = str(manifest.get("commit_sha", ""))
    used_allure: set[str] = set()
    used_allure_matches: set[str] = set()
    all_rows: list[dict[str, Any]] = []
    manifest_results = manifest.get("results", [])
    if not isinstance(manifest_results, list):
        manifest_results = []
    for item in manifest_results:
        if not isinstance(item, dict):
            continue
        identity = Identity(
            str(item.get("role", "")),
            str(item.get("profile", "")),
            str(item.get("scenario", "")),
            str(item.get("target", "")),
            str(item.get("run_attempt", "")),
        )
        if item.get("id") != identity.identifier:
            failures.append(f"result {item.get('id')} identifier does not match its identity")
        reports: list[tuple[dict[str, Any], str]] = []
        junit_references = item.get("junit", [])
        if not isinstance(junit_references, list):
            junit_references = []
        for relative in junit_references:
            path, error = _evidence_reference(root, str(relative), "junit")
            if error:
                failures.append(error)
                continue
            try:
                report = parse_junit(path)  # type: ignore[arg-type]
            except (EvidenceError, OSError) as parse_error:
                failures.append(f"{relative}: {parse_error}")
                continue
            if _report_commit(report) != tested_commit or not _valid_commit(_report_commit(report)):
                failures.append(f"{relative}: JUnit does not identify the exact tested commit")
            properties = report["properties"]
            observed = {
                "profile": normalize_profile(_property(properties, "profile")),
                "scenario": _property(properties, "scenario"),
                "target": _property(properties, "target"),
                "run_attempt": _property(properties, "run_attempt"),
            }
            for key, expected in (
                ("profile", identity.profile),
                ("scenario", identity.scenario),
                ("target", identity.target),
                ("run_attempt", identity.run_attempt),
            ):
                if observed[key] != expected:
                    failures.append(f"{relative}: JUnit {key} identity differs from manifest")
            declared_roles = _split_roles(_property(properties, "roles", "role"))
            if identity.role not in declared_roles:
                failures.append(f"{relative}: JUnit does not declare role {identity.role}")
                continue
            try:
                reports.append((_report_for_role(report, identity.role, declared_roles), str(relative)))
            except EvidenceError as role_error:
                failures.append(f"{relative}: {role_error}")
        allure_payloads: list[tuple[str, dict[str, Any]]] = []
        allure_references = item.get("allure_results", [])
        if not isinstance(allure_references, list):
            allure_references = []
        for relative in allure_references:
            path, error = _evidence_reference(root, str(relative), "allure-results")
            if error:
                failures.append(error)
                continue
            try:
                payload = _strict_json_loads(_bounded_read(path).decode("utf-8"))  # type: ignore[arg-type]
            except (OSError, EvidenceError, UnicodeDecodeError, json.JSONDecodeError) as parse_error:
                failures.append(f"{relative}: malformed Allure result: {parse_error}")
                continue
            if not isinstance(payload, dict):
                failures.append(f"{relative}: Allure result is not an object")
                continue
            if relative in used_allure:
                failures.append(f"{relative}: Allure result is reused across manifest results")
            used_allure.add(str(relative))
            allure_payloads.append((str(relative), payload))
        rows: list[dict[str, Any]] = []
        for report, relative in reports:
            matched, allure_errors = _native_matches(
                report["test_cases"],
                allure_payloads,
                identity,
                commit_sha=tested_commit,
                used_paths=used_allure_matches,
            )
            failures.extend(allure_errors)
            rows.append(
                {
                    "identity": identity,
                    "report": report,
                    "junit": relative,
                    "allure_results": matched,
                    "allure_complete": not allure_errors and len(matched) == len(report["test_cases"]),
                }
            )
        all_rows.extend(rows)
        derived = _aggregate_reports(rows)
        if len(derived) != 1:
            failures.append(f"result {identity.identifier} cannot be re-derived from referenced evidence")
            continue
        actual = derived[0]
        for key in ("status", "totals", "meaningful"):
            if actual[key] != item.get(key):
                failures.append(f"result {identity.identifier} {key} differs from referenced evidence")
        recorded_cases = item.get("test_cases", [])
        if not isinstance(recorded_cases, list):
            recorded_cases = []
        if sorted(_case_signature(case) for case in actual["test_cases"] if isinstance(case, dict)) != sorted(
            _case_signature(case) for case in recorded_cases if isinstance(case, dict)
        ):
            failures.append(f"result {identity.identifier} testcases differ from referenced JUnit")
        if set(actual["allure_results"]) != set(str(reference) for reference in allure_references):
            failures.append(f"result {identity.identifier} Allure references are not one-to-one")
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    counted_executions: set[tuple[tuple[str, str, str, str], str]] = set()
    for row in all_rows:
        report = row["report"]
        fingerprint = str(report.get("logical_sha256", report.get("content_sha256", row["junit"])))
        execution_key = (row["identity"].cell_key, fingerprint)
        if execution_key in counted_executions:
            continue
        counted_executions.add(execution_key)
        for key in totals:
            totals[key] += int(report["totals"][key])
    if totals != manifest.get("test_totals"):
        failures.append("manifest test_totals differs from referenced JUnit")
    if totals["failures"] + totals["errors"] != manifest.get("failures"):
        failures.append("manifest failures differs from referenced JUnit")
    if totals["skipped"] != manifest.get("skips"):
        failures.append("manifest skips differs from referenced JUnit")
    return failures


def validate(
    root: Path,
    *,
    release_mode: bool | None = None,
    expected_commit: str | None = None,
    repository_root: Path | None = None,
    final_inputs=None,
) -> int:
    root = root.resolve()
    manifest_path = root / "manifest.json"
    checksum_path = root / "checksums" / "SHA256SUMS"
    failures: list[str] = []
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or not checksum_path.is_file()
        or checksum_path.is_symlink()
    ):
        print("evidence validation failed: missing evidence manifest or checksums", file=sys.stderr)
        return 1
    try:
        manifest = _strict_json_loads(_bounded_read(manifest_path).decode("utf-8"))
    except (OSError, EvidenceError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"evidence validation failed: malformed manifest: {error}", file=sys.stderr)
        return 1
    if not isinstance(manifest, dict):
        print("evidence validation failed: manifest is not an object", file=sys.stderr)
        return 1
    if "root_final_quality_inputs" in manifest or (root / "root-final-inputs").exists():
        try:
            final_quality = _final_verifier()

            if final_inputs is None:
                final_inputs = final_quality.verify_persisted_inputs(
                    root,
                    manifest,
                    source_sha=expected_commit or os.getenv("QUALITY_EVIDENCE_EXPECTED_COMMIT") or _tested_commit(),
                )
            else:
                final_quality.require_persisted_binding(final_inputs, root, manifest)
        except (ValueError, ImportError, OSError, KeyError, TypeError):
            print("evidence validation held: physical final proof unavailable or invalid", file=sys.stderr)
            return 1
    elif final_inputs is not None:
        print("evidence validation held: physical proof mapping missing", file=sys.stderr)
        return 1
    failures.extend(_manifest_structure_failures(manifest))
    failures.extend(_validate_checksums(root, checksum_path))
    checksum_metadata = manifest.get("checksums", {})
    if not isinstance(checksum_metadata, dict):
        failures.append("manifest checksum metadata is invalid")
    else:
        if checksum_metadata.get("algorithm") != "sha256":
            failures.append("manifest checksum algorithm is not sha256")
        if checksum_metadata.get("file") != "checksums/SHA256SUMS":
            failures.append("manifest checksum file identity is invalid")
        try:
            checksum_entries = len(_bounded_read(checksum_path).decode("utf-8").splitlines())
        except (OSError, EvidenceError, UnicodeDecodeError):
            checksum_entries = -1
        if checksum_metadata.get("entry_count") != checksum_entries:
            failures.append("manifest checksum entry count differs from SHA256SUMS")
    effective_release_mode = release_mode if release_mode is not None else manifest.get("mode") == "release"
    failures.extend(_manifest_logic_failures(manifest, release_mode=effective_release_mode))
    failures.extend(_rederive_manifest_results(root, manifest))
    candidate_mode = manifest.get("mode") == "candidate"
    if candidate_mode:
        if manifest.get("candidate_execution_passed") is not True:
            failures.append("candidate_execution_passed=false")
        if manifest.get("release_eligible") is not False:
            failures.append("candidate evidence is incorrectly release eligible")
    elif manifest.get("release_eligible") is not True:
        failures.append("release_eligible=false")
    expected = expected_commit or os.getenv("QUALITY_EVIDENCE_EXPECTED_COMMIT") or _tested_commit()
    tested = str(manifest.get("commit_sha", ""))
    if not _valid_commit(tested):
        failures.append("manifest does not identify an exact tested commit")
    if expected and (not _valid_commit(expected) or expected != tested):
        failures.append("tested commit differs from release commit")
    source_commit = root / "source" / "commit-sha.txt"
    try:
        if source_commit.is_symlink():
            raise EvidenceError("source commit identity cannot be a symlink")
        recorded_commit = _bounded_read(source_commit, 1024).decode("utf-8").strip()
    except (OSError, EvidenceError, UnicodeDecodeError):
        recorded_commit = ""
    if recorded_commit != tested:
        failures.append("source commit identity differs from manifest")
    security_evidence, security_errors = assess_security(root, release_mode=effective_release_mode, commit_sha=tested)
    failures.extend(security_errors)
    matrix_payload = manifest.get("matrix")
    raw_manifest_expected = matrix_payload.get("expected", []) if isinstance(matrix_payload, dict) else []
    manifest_expected = raw_manifest_expected if isinstance(raw_manifest_expected, list) else []
    dependency_cells = [item for item in manifest_expected if isinstance(item, dict)]
    failures.extend(
        assess_dependencies(
            root,
            release_mode=effective_release_mode,
            expected_commit=tested,
            repository_root=repository_root,
            matrix_cells=dependency_cells,
        )
    )
    recorded_security = manifest.get("security_evidence", {})
    for key in (
        "missing",
        "external_secret_findings",
        "vulnerability_blocking_findings",
        "provenance_commit_sha",
        "candidate_sha256",
        "semantic_valid",
    ):
        if isinstance(recorded_security, dict) and recorded_security.get(key) != security_evidence.get(key):
            failures.append(f"manifest security_evidence.{key} differs from security files")

    registry_path = root / "role-coverage.yml"
    registry, registry_errors = load_registry(registry_path)
    failures.extend(registry_errors)
    if effective_release_mode and not registry:
        failures.append("release evidence lacks its authoritative role registry")
    if registry:
        attempt = str(manifest.get("workflow_attempt", ""))
        complete_expected = expected_cells(
            registry,
            run_attempt=attempt,
            target_disposition="candidate" if candidate_mode else "supported",
        )
        complete_keys = {
            (item["scenario"], item["profile"], item["target"], tuple(item["roles"])) for item in complete_expected
        }
        manifest_keys = {
            (
                item.get("scenario"),
                item.get("profile"),
                item.get("target"),
                tuple(item.get("roles", [])) if isinstance(item.get("roles"), list) else (),
            )
            for item in manifest_expected
            if isinstance(item, dict)
        }
        if effective_release_mode and manifest_keys != complete_keys:
            failures.append("release manifest matrix differs from the authoritative production matrix")
        actual_results = manifest.get("results", [])
        valid_expected = [item for item in manifest_expected if isinstance(item, dict)]
        valid_results = (
            [item for item in actual_results if isinstance(item, dict)] if isinstance(actual_results, list) else []
        )
        evaluated = copy.deepcopy(valid_expected)
        expected_safe = len(valid_expected) == len(manifest_expected) and all(
            all(key in item for key in ("scenario", "profile", "target", "run_attempt", "roles"))
            and isinstance(item.get("roles"), list)
            for item in valid_expected
        )
        results_safe = (
            isinstance(actual_results, list)
            and len(valid_results) == len(actual_results)
            and all(
                all(key in item for key in ("scenario", "profile", "target", "run_attempt", "role", "status"))
                for item in valid_results
            )
        )
        if expected_safe and results_safe:
            matrix_failures = _evaluate_expected(evaluated, valid_results)
            failures.extend(matrix_failures)
        observed_status = {
            (item.get("scenario"), item.get("profile"), item.get("target")): item.get("status")
            for item in valid_expected
        }
        derived_status = {
            (item.get("scenario"), item.get("profile"), item.get("target")): item.get("status")
            for item in evaluated
            if isinstance(item, dict)
        }
        if observed_status != derived_status:
            failures.append("manifest matrix statuses differ from re-derived results")
    try:
        final_scan = scan_evidence(root, final_inputs=final_inputs)
    except ValueError:
        print("evidence validation held: physical verification phase unavailable or expired", file=sys.stderr)
        return 1
    if not final_scan["clean"]:
        failures.append("final evidence contains secret-like data or an unscannable archive")
    if failures:
        print("evidence validation failed: " + "; ".join(sorted(set(failures))), file=sys.stderr)
        return 1
    return 0


def build_parser(*, default_release: bool = False) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("record", "assemble", "validate"))
    parser.add_argument("--root", type=Path, default=Path("artifacts/evidence"))
    parser.add_argument("--input-root", type=Path, action="append", dest="input_roots")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--registry", type=Path, default=Path("meta/role-coverage.yml"))
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--role", action="append", default=[])
    parser.add_argument("--roles", help="Comma-separated roles for a workflow record")
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--run-attempt")
    parser.add_argument("--expected-commit")
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--allure-root", type=Path)
    parser.add_argument(
        "--mode",
        choices=("ci", "candidate", "release"),
        default="release" if default_release else "ci",
    )
    parser.add_argument("--release", action="store_true", help="Require release supply-chain evidence")
    parser.add_argument(
        "--preliminary", action="store_true", help="Assemble an execution export without final quality acceptance"
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    default_roles: Sequence[str] = (),
    mandatory_scenarios: Sequence[str] = (),
    default_release: bool = False,
) -> int:
    parser = build_parser(default_release=default_release)
    args = parser.parse_args(argv)
    release_mode = bool(args.release or args.mode == "release")
    candidate_mode = args.mode == "candidate"
    roles = args.role or list(default_roles)
    try:
        if args.preliminary and args.command != "assemble":
            raise EvidenceError("--preliminary is only valid for assemble")
        if args.command == "record":
            record_roles = [item for item in (args.roles or "").split(",") if item.strip()] or roles
            if len(args.scenario) != 1 or len(args.profile) != 1 or len(args.target) != 1:
                raise EvidenceError("record requires exactly one --scenario, --profile, and --target")
            return record(
                scenario=args.scenario[0],
                profile=args.profile[0],
                target=args.target[0],
                roles=record_roles,
                exit_code=args.exit_code,
                log_path=args.log,
                results_root=args.results_root or Path("artifacts/results"),
                junit_path=args.junit,
                allure_root=args.allure_root,
                run_attempt=args.run_attempt,
            )
        if args.command == "assemble":
            input_roots = list(args.input_roots or [])
            if args.results_root:
                input_roots.append(args.results_root)
            return assemble(
                args.root,
                input_roots=input_roots or None,
                registry_path=args.registry,
                repository_root=args.repository_root,
                roles=roles,
                registry_role_filter=args.role,
                profiles=args.profile,
                scenarios=args.scenario,
                targets=args.target,
                run_attempt=args.run_attempt,
                release_mode=release_mode,
                candidate_mode=candidate_mode,
                preliminary=args.preliminary,
                expected_commit=args.expected_commit,
                mandatory_scenarios=mandatory_scenarios,
            )
        return validate(
            args.root,
            release_mode=release_mode if args.release or args.mode == "release" else None,
            expected_commit=args.expected_commit,
            repository_root=args.repository_root,
        )
    except EvidenceError as error:
        print(f"evidence {args.command} failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
