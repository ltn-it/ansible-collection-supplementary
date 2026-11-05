# Exact JSON schema types deliberately reject bool as int and subclasses.
# pylint: disable=unidiomatic-typecheck
from __future__ import annotations

import argparse
import base64
import codecs
import contextlib
import functools
import hashlib
import io
import itertools
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import namedtuple
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

UTC = timezone.utc  # noqa: UP017 -- the host-side entrypoint supports Python 3.9.

ENGINE_PATH = Path(__file__)
if ENGINE_PATH.is_symlink():
    raise RuntimeError("engine must not be a symlink")
try:
    ENGINE_PATH = ENGINE_PATH.resolve(strict=True)
except OSError as exc:
    raise RuntimeError("engine path is unsafe") from exc

AUTHORIZED_ROOT = globals().get("_LIT_AUTHORIZED_REPOSITORY_ROOT")
if AUTHORIZED_ROOT is None:
    ROOT = ENGINE_PATH.parents[1]
else:
    if not isinstance(AUTHORIZED_ROOT, str) or not AUTHORIZED_ROOT:
        raise RuntimeError("authorized repository root must be an absolute path")
    authorized_candidate = Path(AUTHORIZED_ROOT)
    if not authorized_candidate.is_absolute():
        raise RuntimeError("authorized repository root must be an absolute path")
    try:
        ROOT = authorized_candidate.resolve(strict=True)
        authorized_engine = (ROOT / "default" / "scripts" / "lit-push-ready.py").resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("authorized repository root cannot be resolved safely") from exc
    if ROOT != ENGINE_PATH.parents[2] or authorized_engine != ENGINE_PATH:
        raise RuntimeError("authorized repository root is not bound to the running engine")
CONFIG = ROOT / ".lit" / "push-ready.json"
COPILOT = ROOT / ".github" / "copilot-instructions.md"
AGENTS = ROOT / "AGENTS.md"
PASS_MARKER = "PUSH_READY: PASS"  # noqa: S105 -- review verdict, not a password.
BLOCKED_MARKER = "PUSH_READY: BLOCKED"
CONTRACT_LINE = "<!-- Managed contract: Codex and Copilot must apply AGENTS.md. -->"
SECRET_PATH_PARTS = {
    ".env",
    ".netrc",
    ".pypirc",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "kubeconfig",
    "secrets",
    "vault-password",
}
SECRET_CONTENT_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{16,}"
    ),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\b(?:xox[baprs]-|sk-(?:proj-)?)[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"(?i)_authToken\s*=\s*[^\s]{12,}"),
)
NPMRC_AUTH_PATTERN = re.compile(r"(?im)(?:^|[+:])\s*(?:_authToken|_auth|_password|username)\s*=")
SECRET_FIXTURE_MANIFEST_PATH = (  # noqa: S105 -- policy path, not a password.
    ".lit/push-ready-secret-fixtures.json"  # noqa: S105
)
SECRET_FIXTURE_PATH_PREFIXES = ("examples/", "molecule/", "tests/")
MAX_SECRET_FIXTURE_MANIFEST_BYTES = 100_000
MAX_SECRET_FIXTURE_SOURCE_BYTES = 10_000_000
INSTRUCTION_PATH_PATTERN = re.compile(
    r"(?:^|/)AGENTS\.md$|^\.github/copilot-instructions\.md$|"
    r"^\.github/instructions/.+\.instructions\.md$"
)
MAX_CONFIG_BYTES = 1_000_000
MAX_LOCAL_REVIEW_FILE_BYTES = 5_000_000
DEFAULT_REVIEW_WARNING_BYTES = 500_000
MAX_TIMEOUT_SECONDS = 3_600
CHECK_TIMEOUT_SECONDS = 3_600
AUTHORITATIVE_BASE_REFS = {
    "refs/remotes/origin/develop": "develop",
    "refs/remotes/origin/main": "main",
}
INTEGRATION_DIRECTORY_PREFIX = ".lit-integration-"
COPILOT_DEVTOOL_IMAGE = "quay.io/l-it/ee-wunder-devtools-ubi9:v1.16.1@sha256:c5e8707e825fcddb3e7bbc7592ebdc99a02e6ba9fa2cad71b88bcd5c71bd4d08"  # noqa: E501
CHECK_PROFILE = {
    "name": "repository-quality-profile",
    "command": ["scripts/lit-ci-profile.sh", "repository-quality"],
}
TRUSTED_CHECK_POLICY_PATHS = (
    ".pre-commit-config.yaml",
    ".lit/push-ready.json",
    ".lit/ltn399-push-ready-origin-adoption.json",
    SECRET_FIXTURE_MANIFEST_PATH,
    "scripts/lit-ci-profile.sh",
    "scripts/devtools-local-quality.sh",
    "default/scripts/lit-push-ready.py",
    "default/scripts/wunder-devtools-ee.sh",
    "default/scripts/wunder-container-run.sh",
    "scripts/lit-push-ready.py",
    "scripts/lit-repository-quality.py",
    "scripts/lit-safe-temp-run.py",
    "scripts/lit-trust-root-base-verifier.py",
    "scripts/validate-embedded-code.py",
    "scripts/wunder-devtools-ee.sh",
    "scripts/wunder-container-run.sh",
    "scripts/test-devtools-molecule-ownership.sh",
)
PARITY_GAPS = (
    {
        "id": "protected-current-revision-review",
        "local": "deterministic history-free snapshot and secret scan; no external AI egress",
        "remote": "protected current-revision review selected by verified PR identity",
        "status": "remote-review-required",
        "remote_gate_required": True,
    },
    {
        "id": "github-actions-runtime",
        "local": "repository checks",
        "remote": "workflow runners and services",
        "status": "remote-runtime",
        "remote_gate_required": True,
    },
    {
        "id": "github-authorization",
        "local": "no GitHub write or policy exercise",
        "remote": "App, token, environment, and branch policy",
        "status": "remote-authorization",
        "remote_gate_required": True,
    },
)
LOCAL_EVIDENCE_TRUST = {
    "level": "developer-advisory",
    "purpose": "staleness and hook enforcement",
    "security_attestation": False,
    "remote_gate_required": True,
}
REVIEW_PROFILE_AGENTS: dict[str, tuple[str, ...]] = {
    "standard": (),
    "trust-root": (),
}
COPILOT_PROMPT_MODE_BOUNDARY = {
    "COPILOT_MCP_TOOL_CACHE": "false",
    "GITHUB_COPILOT_PROMPT_MODE_EXTENSIONS": "false",
    "GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS": "false",
    "GITHUB_COPILOT_PROMPT_MODE_WORKSPACE_MCP": "false",
}
COPILOT_TOKEN_NAMES = ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")
COPILOT_REQUIRED_SAFETY_ARGUMENTS = (
    "-s",
    "--no-ask-user",
    "--no-bash-env",
    "--no-remote",
    "--no-remote-export",
    "--disable-builtin-mcps",
    "--disallow-temp-dir",
    "--no-custom-instructions",
    "--available-tools=view,grep,glob",
    "--allow-tool=read",
    "--deny-tool=write,memory,url,shell",
)


# Content is always spooled to an anonymous temporary file. CHUNK_BYTES is an
# allocation size, never an admission limit on a diff, file, or review.
CHUNK_BYTES = 64 * 1024
# Aggregate tracked-workspace read budget, independent of PR/diff sizing.
MAX_TRACKED_WORKSPACE_SCAN_BYTES = 500_000_000


class PatchSpool:
    """Complete private patch bytes with incremental identity and bounded reads."""

    def __init__(self):
        self.file = tempfile.TemporaryFile(mode="w+b")
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, payload: bytes) -> None:
        self.file.write(payload)
        self.digest.update(payload)
        self.size += len(payload)

    def chunks(self):
        self.file.flush()
        self.file.seek(0)
        digest = hashlib.sha256()
        size = 0
        while True:
            value = self.file.read(CHUNK_BYTES)
            if not value:
                break
            digest.update(value)
            size += len(value)
            yield value
        if size != self.size or digest.digest() != self.digest.digest():
            raise RuntimeError("private patch spool changed after construction")

    def text_chunks(self, *, errors="strict"):
        decoder: Any = codecs.getincrementaldecoder("utf-8")(errors=errors)
        for value in self.chunks():
            yield decoder.decode(value)
        yield decoder.decode(b"", final=True)

    def close(self):
        self.file.close()

    def __del__(self):
        if hasattr(self, "file"):
            self.file.close()

    def __bool__(self):
        return self.size != 0

    # Explicit compatibility accessors for historical diagnostic callers. The
    # production pipeline never uses these materializing string operations.
    def as_text(self):
        return "".join(self.text_chunks())

    def __contains__(self, value):
        tail = ""
        for chunk in self.text_chunks():
            text = tail + chunk
            if value in text:
                return True
            tail = text[-len(value) :] if value else ""
        return False

    def replace(self, *args):
        return self.as_text().replace(*args)

    def encode(self, *args, **kwargs):
        return self.as_text().encode(*args, **kwargs)


def patch_chunks(value):
    if hasattr(value, "text_chunks"):
        yield from value.text_chunks()
    else:
        for offset in range(0, len(value), CHUNK_BYTES):
            yield value[offset : offset + CHUNK_BYTES]


def stream_git(*args: str, cwd=None):
    """Read stdout in bounded blocks; stderr never joins authenticated bytes."""
    environment = isolated_git_environment()
    directory = cwd or ROOT
    try:
        directory.resolve().relative_to(ROOT)
    except ValueError:
        for variable in ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE"):
            environment.pop(variable, None)
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(  # noqa: S603 -- fixed repository/fixture command and isolated environment.
            ["git", *args],  # noqa: S607 -- fixed executable from the pinned runtime.
            cwd=directory,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=errors,
        ) as process:
            assert process.stdout is not None
            try:
                while True:
                    chunk = process.stdout.read(CHUNK_BYTES)
                    if not chunk:
                        break
                    yield chunk
                if process.wait():
                    errors.seek(0)
                    diagnostic = errors.read(CHUNK_BYTES).decode("utf-8", "replace")
                    raise RuntimeError("streamed Git operation failed: " + diagnostic.strip())
            finally:
                # A read/write/decoder failure must not leave a pipe writer
                # blocked while Popen.__exit__ waits for it.
                if process.poll() is None:
                    process.kill()
                process.stdout.close()
                process.wait()


def decoded_git_chunks(*args, cwd=None, errors="surrogateescape", universal_newlines=True):
    decoder: Any = codecs.getincrementaldecoder("utf-8")(errors=errors)
    # Match subprocess text=True universal-newline semantics across blocks.
    if universal_newlines:
        decoder = io.IncrementalNewlineDecoder(decoder, translate=True)
    for value in stream_git(*args, cwd=cwd):
        yield decoder.decode(value)
    yield decoder.decode(b"", final=True)


def hash_open_file(stream):
    digest = hashlib.sha256()
    size = 0
    while True:
        value = stream.read(CHUNK_BYTES)
        if not value:
            break
        digest.update(value)
        size += len(value)
    return digest.hexdigest(), size


def hash_repository_file(root, name, *, purpose):
    descriptor = open_regular_below(root, name, purpose=purpose)
    with os.fdopen(descriptor, "rb") as stream:
        return hash_open_file(stream)


def fingerprint_stream(cwd, untracked, *, integration=False):
    """Hash exactly the historical sorted JSON bytes without buffering diff."""
    digest = hashlib.sha256()
    digest.update(b'{"diff":"')
    for chunk in decoded_git_chunks(
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--binary",
        "HEAD",
        "--",
        cwd=cwd,
    ):
        digest.update(json.dumps(chunk, ensure_ascii=True)[1:-1].encode("ascii"))
    digest.update(b'","head":')
    head = git_output_at(cwd, "rev-parse", "HEAD").strip()
    digest.update(json.dumps(head).encode("ascii"))
    if integration:
        digest.update(b',"index_tree":')
        tree = git_output_at(cwd, "write-tree").strip()
        digest.update(json.dumps(tree).encode("ascii"))
    digest.update(b',"status":"')
    for chunk in decoded_git_chunks(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "-z",
        cwd=cwd,
    ):
        digest.update(json.dumps(chunk, ensure_ascii=True)[1:-1].encode("ascii"))
    digest.update(b'","untracked":')
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    for part in encoder.iterencode(untracked):
        digest.update(part.encode("ascii"))
    digest.update(b"}")
    return digest.hexdigest()


def split_text_fragments(chunks):
    """Yield bounded fragments and exact str.splitlines-style separators."""
    pending_cr = False
    for chunk in chunks:
        if not chunk:
            continue
        if pending_cr:
            if chunk.startswith("\n"):
                yield "", "\r\n"
                chunk = chunk[1:]
            else:
                yield "", "\r"
            pending_cr = False
        start = 0
        for match in re.finditer(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]", chunk):
            if match[0] == "\r" and match.end() == len(chunk):
                yield chunk[start : match.start()], None
                pending_cr = True
            else:
                yield chunk[start : match.start()], match[0]
            start = match.end()
        if start < len(chunk):
            yield chunk[start:], None
    if pending_cr:
        yield "", "\r"


class StreamingPatterns:
    """Finite-state execution of the existing governed regexes, without buffers.

    Only the syntax used by those fixed patterns is supported. Unknown syntax
    fails closed. Matching keeps states, never subject text or an unbounded
    line, token, whitespace run, PEM modifier, or JWT component.
    """

    def __init__(self, patterns):
        try:
            from re import _parser as parser  # type: ignore[attr-defined]  # CPython parser fallback below.
        except ImportError:  # Python 3.9/3.10 compatibility
            import sre_parse as parser
        self.edges: list[Any] = []
        self.accepts = {}
        self.starts = []

        def state():
            self.edges.append([])
            return len(self.edges) - 1

        def build(tokens, flags):
            first = current = state()
            for operation, argument in tokens:
                end = state()
                kind = str(operation)
                if kind == "LITERAL":
                    matcher = re.compile(re.escape(chr(argument)), flags).fullmatch
                    self.edges[current].append(("char", matcher, end))
                elif kind == "IN":
                    pieces = []
                    for op, arg in argument:
                        tag = str(op)
                        if tag == "NEGATE":
                            pieces.append("^")
                        elif tag == "LITERAL":
                            pieces.append(re.escape(chr(arg)))
                        elif tag == "RANGE":
                            pieces.append(re.escape(chr(arg[0])) + "-" + re.escape(chr(arg[1])))
                        elif tag == "CATEGORY":
                            categories = {
                                "CATEGORY_SPACE": r"\s",
                                "CATEGORY_NOT_SPACE": r"\S",
                                "CATEGORY_WORD": r"\w",
                                "CATEGORY_DIGIT": r"\d",
                            }
                            if str(arg) not in categories:
                                raise RuntimeError("unsupported streaming regex category")
                            pieces.append(categories[str(arg)])
                        else:
                            raise RuntimeError("unsupported streaming regex character class")
                    matcher = re.compile("[" + "".join(pieces) + "]", flags).fullmatch
                    self.edges[current].append(("char", matcher, end))
                elif kind == "SUBPATTERN":
                    _unused_value_1, add, remove, body = argument
                    a, b = build(body, (flags | add) & ~remove)
                    self.edges[current].append(("epsilon", None, a))
                    self.edges[b].append(("epsilon", None, end))
                elif kind == "BRANCH":
                    for branch in argument[1]:
                        a, b = build(branch, flags)
                        self.edges[current].append(("epsilon", None, a))
                        self.edges[b].append(("epsilon", None, end))
                elif kind == "MAX_REPEAT":
                    minimum, maximum, body = argument
                    cursor = current
                    for _unused_value_2 in range(minimum):
                        a, b = build(body, flags)
                        self.edges[cursor].append(("epsilon", None, a))
                        cursor = b
                    if maximum == parser.MAXREPEAT:
                        self.edges[cursor].append(("epsilon", None, end))
                        a, b = build(body, flags)
                        self.edges[cursor].append(("epsilon", None, a))
                        self.edges[b].append(("epsilon", None, cursor))
                    else:
                        for _unused_value_3 in range(maximum - minimum):
                            self.edges[cursor].append(("epsilon", None, end))
                            a, b = build(body, flags)
                            self.edges[cursor].append(("epsilon", None, a))
                            cursor = b
                        self.edges[cursor].append(("epsilon", None, end))
                elif kind == "AT":
                    self.edges[current].append(("assert", (str(argument), flags), end))
                else:
                    raise RuntimeError("unsupported governed streaming regex: " + kind)
                current = end
            return first, current

        for number, pattern in enumerate(patterns):
            parsed = parser.parse(pattern.pattern, pattern.flags)
            first, last = build(parsed, parsed.state.flags)
            self.starts.append(first)
            self.accepts[last] = 1 << number
        self.step = functools.lru_cache(maxsize=4096)(self._step)

    def _step(self, active, previous, character, beginning):
        states = set(active) | set(self.starts)
        pending = list(states)
        matches = 0
        while pending:
            current = pending.pop()
            matches |= self.accepts.get(current, 0)
            for kind, value, target in self.edges[current]:
                passed = kind == "epsilon"
                if kind == "assert":
                    assertion, flags = value
                    if assertion == "AT_BOUNDARY":
                        left = previous is not None and (previous.isalnum() or previous == "_")
                        right = character is not None and (character.isalnum() or character == "_")
                        passed = left != right
                    elif assertion in {"AT_BEGINNING", "AT_BEGINNING_STRING"}:
                        passed = beginning or (
                            assertion == "AT_BEGINNING" and flags & re.MULTILINE and previous == "\n"
                        )
                    elif assertion == "AT_END_STRING":
                        passed = character is None
                    else:
                        raise RuntimeError("unsupported streaming regex assertion: " + assertion)
                if passed and target not in states:
                    states.add(target)
                    pending.append(target)
        following = set()
        if character is not None:
            for current in states:
                for kind, matcher, target in self.edges[current]:
                    if kind == "char" and matcher(character):
                        following.add(target)
        return tuple(sorted(following)), matches

    def scanner(self):
        return PatternScanner(self)


class PatternScanner:
    def __init__(self, machine):
        self.machine = machine
        self.active = ()
        self.previous = None
        self.beginning = True
        self.matches = 0

    def feed(self, text):
        for character in text:
            self.active, matches = self.machine.step(self.active, self.previous, character, self.beginning)
            self.matches |= matches
            self.previous = character
            self.beginning = False

    def finish(self):
        _unused_value_4, matches = self.machine.step(self.active, self.previous, None, self.beginning)
        return self.matches | matches


_STREAM_PATTERNS = None


def content_scanner():
    global _STREAM_PATTERNS
    if _STREAM_PATTERNS is None:
        _STREAM_PATTERNS = StreamingPatterns((*SECRET_CONTENT_PATTERNS, NPMRC_AUTH_PATTERN))
    return _STREAM_PATTERNS.scanner()


def apply_patch_stream(command, *, patch, cwd, capture=True):
    """Keep git-apply input and potentially large diagnostics out of RAM."""
    owned = not hasattr(patch, "text_chunks")
    if owned:
        value = patch
        patch = PatchSpool()
        for chunk in patch_chunks(value):
            patch.write(chunk.encode("utf-8"))
    try:
        patch.file.flush()
        patch.file.seek(0)
        environment = isolated_git_environment()
        for variable in ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE"):
            environment.pop(variable, None)
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(  # noqa: S603 -- fixed repository/fixture command and isolated environment.
                command,
                cwd=cwd,
                env=environment,
                stdin=patch.file,
                stdout=output,
                stderr=output,
                check=False,
            )
            output.seek(0)
            diagnostic = output.read(CHUNK_BYTES).decode("utf-8", "replace")
            return subprocess.CompletedProcess(command, result.returncode, diagnostic)
    finally:
        if owned:
            patch.close()


def file_text_chunks(stream, *, errors="replace"):
    decoder: Any = codecs.getincrementaldecoder("utf-8")(errors=errors)
    while True:
        value = stream.read(CHUNK_BYTES)
        if not value:
            break
        yield decoder.decode(value)
    yield decoder.decode(b"", final=True)


def filtered_scan_chunks(chunks, documented, *, path=None, diff=False, redact=False, packer=False):
    """Apply existing exact-line exceptions with bounded line spooling.

    A line may exceed memory: only its digest, parser prefix and finite regex
    states are retained. No content is discarded by the scan or patch spool.
    """
    old_path = new_path = None
    old_number = new_number = 0
    in_hunk = False
    line_number = 0
    packer_machine = None
    if packer:
        packer_machine = StreamingPatterns(
            [re.compile(r"\A(?:" + globals()["PACKER_VARIABLE_REFERENCE_LINE"].pattern + r")\Z")]
        )
    with tempfile.SpooledTemporaryFile(max_size=CHUNK_BYTES, mode="w+b") as line_file:
        prefix = ""
        digest = hashlib.sha256()
        first = True
        pending = False
        line_scan = content_scanner()
        packer_scan = packer_machine.scanner() if packer_machine else None
        # Flush an unterminated last line without inventing an empty one.
        for fragment, ending in itertools.chain(split_text_fragments(chunks), [("", "EOF")]):
            if ending == "EOF" and not pending:
                break
            pending = True
            line_file.write(fragment.encode("utf-8"))
            prefix += fragment[: max(0, CHUNK_BYTES - len(prefix))]
            digest.update((fragment[1:] if first and diff else fragment).encode("utf-8"))
            if fragment:
                first = False
            line_scan.feed(fragment)
            if packer_scan:
                packer_scan.feed(fragment)
            if ending is None:
                continue
            line_number += 1
            mask = False
            old_content = False
            match_path = path
            match_number = line_number
            if diff:
                match_path = None
                if prefix.startswith("diff --git "):
                    old_path = new_path = None
                    in_hunk = False
                elif not in_hunk and prefix.startswith("--- "):
                    old_path = unquote_diff_path(prefix[4:], "a")
                elif not in_hunk and prefix.startswith("+++ "):
                    new_path = unquote_diff_path(prefix[4:], "b") if documented else None
                elif prefix.startswith("@@"):
                    hunk = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", prefix)
                    if hunk is None or (documented and old_path is None and new_path is None):
                        raise RuntimeError("planned diff has a malformed hunk header or no governed file path")
                    old_number, new_number = map(int, hunk.groups())
                    in_hunk = True
                elif in_hunk and prefix[:1] in {"+", "-", " "}:
                    if prefix.startswith("+"):
                        match_path, match_number = new_path, new_number
                        new_number += 1
                    elif prefix.startswith("-"):
                        match_path, match_number = old_path, old_number
                        old_number += 1
                        old_content = True
                    else:
                        match_path, match_number = (
                            old_path or new_path,
                            old_number or new_number,
                        )
                        old_number += 1
                        new_number += 1
            entry = documented.get(match_path or "", {}).get(match_number)
            if entry is not None and digest.hexdigest() == entry[0]:
                mask = True
            flags = line_scan.finish()
            if redact and old_content and old_path not in documented and flags & ~1:
                mask = True
            if packer_scan and packer_scan.finish():
                mask = True
            if mask:
                yield "DOCUMENTED_SYNTHETIC_FIXTURE\n"
            else:
                line_file.seek(0)
                yield from file_text_chunks(line_file, errors="strict")
                yield "\n"
            line_file.seek(0)
            line_file.truncate()
            prefix = ""
            digest = hashlib.sha256()
            first = True
            pending = False
            line_scan = content_scanner()
            packer_scan = packer_machine.scanner() if packer_machine else None


def scan_chunks(chunks):
    scanner = content_scanner()
    for chunk in chunks:
        scanner.feed(chunk)
    return scanner.finish()


def streaming_review_safe(change, documented, *, redact=False):
    unsafe = [path for path in change.paths if is_secret_like_path(path)]
    if unsafe:
        raise RuntimeError("local review refused for secret-like paths: " + ", ".join(sorted(unsafe)))
    if redact and scan_chunks(patch_chunks(change.patch)) & 1:
        raise RuntimeError("local review refused because the planned patch contains PEM private key material")
    scanned = scan_chunks(filtered_scan_chunks(patch_chunks(change.patch), documented, diff=True, redact=redact))
    secret_mask = (1 << len(SECRET_CONTENT_PATTERNS)) - 1
    if scanned & secret_mask:
        raise RuntimeError("local review refused because the planned review input contains secret-like content")
    # Fixture exceptions never authorize .npmrc authentication configuration.
    if any(Path(path).name.lower() == ".npmrc" for path in change.paths):
        npm = scan_chunks(filtered_scan_chunks(patch_chunks(change.patch), {}, diff=True, redact=redact))
        if npm & (1 << len(SECRET_CONTENT_PATTERNS)):
            raise RuntimeError(
                "local review refused because planned .npmrc content contains authentication configuration"
            )


def streaming_workspace_safe(workspace, documented, *, allow_packer=False):
    names = git_output_at(workspace, "ls-files", "-z").split("\0")
    total = 0
    unsafe = []
    basenames = {
        ".env",
        ".netrc",
        ".pypirc",
        "auth.json",
        "credentials",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "kubeconfig",
        "vault-password",
    }
    for name in filter(None, names):
        parts = tuple(part.lower() for part in Path(name).parts)
        if parts[-1] in basenames or any(part in {".aws", ".ssh", "secrets"} for part in parts[:-1]):
            unsafe.append(name)
        descriptor = open_regular_below(workspace, name, purpose="Sanitized review")
        with os.fdopen(descriptor, "rb") as stream:
            packer = allow_packer and name.endswith(".pkr.hcl")
            tail = b""
            while True:
                chunk = stream.read(CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TRACKED_WORKSPACE_SCAN_BYTES:
                    raise RuntimeError("tracked workspace scan exceeds its 500000000-byte resource budget")
                if any(marker in tail + chunk for marker in (b"/*", b"*/", b"<<")):
                    packer = False
                tail = chunk[-1:]
            stream.seek(0)
            if parts[-1] == ".npmrc":
                if scan_chunks(file_text_chunks(stream)) & (1 << len(SECRET_CONTENT_PATTERNS)):
                    raise RuntimeError(
                        "local review refused because tracked .npmrc contains authentication configuration"
                    )
                stream.seek(0)
            try:
                matches = scan_chunks(
                    filtered_scan_chunks(
                        file_text_chunks(stream, errors="strict"), documented, path=name, packer=packer
                    )
                )
            except UnicodeDecodeError as exc:
                raise RuntimeError(f"sanitized review file is not UTF-8: {name}") from exc
            if matches & ((1 << len(SECRET_CONTENT_PATTERNS)) - 1):
                raise RuntimeError(f"secret-like review content: {name}")
    if unsafe:
        raise RuntimeError("local review refused for secret-like tracked paths: " + ", ".join(sorted(unsafe)))


def is_secret_like_path(path: str) -> bool:
    return any(part in path.lower() for part in SECRET_PATH_PARTS)


class PlannedChange(
    namedtuple(
        "PlannedChangeRecord",
        "base_ref base_tip base_commit head_commit patch paths untracked_sha256 tree_fingerprint",
    )
):
    """Immutable identity with a complete disk-backed patch in production.

    The historical .diff string accessor remains explicit for diagnostic
    callers; the pipeline uses .patch and never materializes that accessor.
    """

    __slots__ = ()

    def __new__(
        cls,
        base_ref,
        base_tip,
        base_commit,
        head_commit,
        diff,
        paths,
        untracked_sha256,
        tree_fingerprint,
    ):
        return super().__new__(
            cls,
            base_ref,
            base_tip,
            base_commit,
            head_commit,
            diff,
            paths,
            untracked_sha256,
            tree_fingerprint,
        )

    @property
    def diff(self):
        if self.patch is None:
            raise RuntimeError("planned patch has not been materialized")
        return self.patch.as_text() if hasattr(self.patch, "text_chunks") else self.patch

    def _replace(self, **values):
        if "diff" in values:
            values["patch"] = values.pop("diff")
        return super()._replace(**values)

    @property
    def diff_sha256(self) -> str:
        if self.patch is None:
            raise RuntimeError("planned patch has not been materialized")
        return self.patch.digest.hexdigest() if hasattr(self.patch, "text_chunks") else sha256_text(self.patch)


class ReviewTopology(NamedTuple):
    head_tree: str
    head_parents: tuple[str, ...]
    base_tree: str
    integration_tree: str
    workspace_commit: str


class ReviewClassification(NamedTuple):
    profile: str
    agents: tuple[str, ...]
    policy_sha256: str
    reason: str


def is_full_git_object_id(value: str) -> bool:
    return (
        re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
            value,
        )
        is not None
    )


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_text(payload: str) -> str:
    try:
        encoded = payload.encode("utf-8")
    except UnicodeError as exc:
        raise RuntimeError("text input cannot be represented safely as UTF-8") from exc
    return sha256_bytes(encoded)


def utf8_size(payload: str) -> int:
    try:
        return len(payload.encode("utf-8"))
    except UnicodeError as exc:
        raise RuntimeError("planned review input cannot be represented safely as UTF-8") from exc


GIT_IDENTITY_ENVIRONMENT = frozenset(
    {
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_DATE",
    }
)


def trusted_container_git_binding(source: Mapping[str, str]) -> dict[str, str]:
    required = ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE")
    if any(name not in source for name in required):
        return {}
    try:
        work_tree = Path(source["GIT_WORK_TREE"]).resolve(strict=True)
        common = Path(source["GIT_COMMON_DIR"])
        git_dir = Path(source["GIT_DIR"])
    except (OSError, ValueError):
        return {}
    mount_root = Path("/run/wunder-git/common")
    if work_tree != ROOT or not common.is_absolute() or common != mount_root or not git_dir.is_absolute():
        return {}
    try:
        relative_git_dir = git_dir.relative_to(common)
    except ValueError:
        return {}
    if (
        len(relative_git_dir.parts) < 2
        or relative_git_dir.parts[0] != "worktrees"
        or any(part in {"", ".", ".."} for part in relative_git_dir.parts)
    ):
        return {}
    return {name: source[name] for name in required}


def isolated_git_environment(
    environment: dict[str, str] | None = None,
) -> dict[str, str]:
    source = environment if environment is not None else os.environ
    result = {name: value for name, value in source.items() if not name.startswith("GIT_")}
    for name in GIT_IDENTITY_ENVIRONMENT:
        if name in source:
            result[name] = source[name]
    result.update(trusted_container_git_binding(source))
    result.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return result


def assert_safe_git_configuration(cwd: Path) -> None:
    configured = run(
        ["git", "config", "--local", "--null", "--name-only", "--list"],
        capture=True,
        cwd=cwd,
    )
    if configured.returncode:
        raise RuntimeError("could not inspect local Git configuration safely")
    unsafe: list[str] = []
    for name in (entry for entry in configured.stdout.split("\0") if entry):
        lowered = name.lower()
        if (
            lowered
            in {
                "core.attributesfile",
                "core.fsmonitor",
                "core.hookspath",
            }
            or lowered.startswith("filter.")
            or (lowered.startswith("merge.") and lowered.endswith(".driver"))
        ):
            unsafe.append(name)
    if unsafe:
        raise RuntimeError(
            "local Git configuration can alter or execute the reviewed tree: " + ", ".join(sorted(unsafe))
        )


def run(
    command: list[str],
    *,
    capture: bool = False,
    input_text: str | None = None,
    timeout: int | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    resolved_environment = env
    if command and command[0] == "git":
        resolved_environment = isolated_git_environment(env)
        if cwd is not None and cwd.resolve() != ROOT:
            for name in ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE"):
                resolved_environment.pop(name, None)
    return subprocess.run(  # noqa: S603 -- callers provide validated fixed argv.
        command,
        cwd=cwd or ROOT,
        check=False,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        input=input_text,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        timeout=timeout,
        env=resolved_environment,
    )


def git_output(*args: str) -> str:
    result = run(["git", *args], capture=True)
    if result.returncode:
        raise RuntimeError(result.stdout.strip())
    return result.stdout


def evidence_path() -> Path:
    git_dir = Path(git_output("rev-parse", "--git-dir").strip())
    if not git_dir.is_absolute():
        git_dir = ROOT / git_dir
    return git_dir.resolve() / "lit-push-ready-evidence.json"


def write_evidence_text(value: str) -> None:
    target = evidence_path()
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    directory = os.open(target.parent, directory_flags)
    temporary = f".{target.name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        try:
            existing = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(existing.st_mode) or existing.st_uid != os.geteuid():
                raise RuntimeError("evidence target is unsafe")
        descriptor = os.open(temporary, file_flags, 0o600, dir_fd=directory)
        created = os.fstat(descriptor)
        identity = created.st_dev, created.st_ino
        payload = value.encode("utf-8")
        while payload:
            written = os.write(descriptor, payload)
            if written <= 0:
                raise RuntimeError("evidence write stalled")
            payload = payload[written:]
        os.fsync(descriptor)
        os.replace(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = ""
        os.fsync(directory)
    except OSError as exc:
        raise RuntimeError("evidence write failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary and identity is not None:
            try:
                current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
                    os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def open_regular_below(root: Path, name: str, *, purpose: str) -> int:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    missing_flags = [flag for flag in required_flags if not isinstance(getattr(os, flag, None), int)]
    if missing_flags or os.open not in os.supports_dir_fd:
        unsupported = ", ".join(missing_flags) or "open(dir_fd=...)"
        raise RuntimeError(f"{purpose} requires unavailable safe-open capability: {unsupported}")

    candidate = Path(name)
    parts = candidate.parts
    if candidate.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise RuntimeError(f"{purpose} refused for unsafe repository path: {name}")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_descriptors: list[int] = []
    descriptor = -1
    keep_descriptor = False
    try:
        current = os.open(root, directory_flags)
        directory_descriptors.append(current)
        for component in parts[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            directory_descriptors.append(current)
        descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f"{purpose} refused for non-regular repository path: {name}")
        keep_descriptor = True
        return descriptor
    except OSError as exc:
        raise RuntimeError(f"{purpose} could not safely inspect repository path: {name}") from exc
    finally:
        if descriptor >= 0 and not keep_descriptor:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)


def open_repository_regular(name: str, *, purpose: str) -> int:
    return open_regular_below(ROOT, name, purpose=purpose)


def open_untracked_regular(name: str, *, purpose: str) -> int:
    return open_repository_regular(name, purpose=purpose)


def read_repository_file(name: str, *, purpose: str, max_bytes: int) -> tuple[bytes, int]:
    if max_bytes < 0:
        raise RuntimeError(f"{purpose} input exceeds its aggregate byte limit")
    descriptor = open_repository_regular(name, purpose=purpose)
    try:
        mode = os.fstat(descriptor).st_mode
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(max_bytes + 1)
    except OSError as exc:
        raise RuntimeError(f"{purpose} could not read repository path: {name}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > max_bytes:
        raise RuntimeError(f"{purpose} input exceeds {max_bytes} bytes")
    return payload, mode


def untracked_names() -> list[str]:
    names = git_output("ls-files", "--others", "--exclude-standard", "-z")
    return [entry for entry in names.split("\0") if entry]


def untracked_file_hashes(max_bytes: int | None = None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    total = 0
    for name in untracked_names():
        digest, size = hash_repository_file(ROOT, name, purpose="Fingerprint")
        total += size
        if max_bytes is not None and total > max_bytes:
            raise RuntimeError("Fingerprint input exceeds its explicit caller byte limit")
        hashes[name] = digest
    return hashes


def tree_fingerprint() -> str:
    reject_hidden_index_entries()
    return fingerprint_stream(ROOT, untracked_file_hashes())


def reject_hidden_index_entries() -> None:
    entries = git_output("ls-files", "-v", "-z").split("\0")
    hidden: list[str] = []
    for entry in entries:
        if not entry:
            continue
        if len(entry) < 3 or entry[1] != " ":
            raise RuntimeError("malformed Git index entry")
        marker = entry[0]
        if marker == "S" or marker.islower():
            hidden.append(entry[2:])
    if hidden:
        preview = ", ".join(sorted(hidden)[:20])
        raise RuntimeError(f"hidden index entries are forbidden: {preview}")


def require_policy_files_committed() -> None:
    reject_hidden_index_entries()
    try:
        running_engine = Path(__file__).resolve().relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise RuntimeError("engine is outside repository") from exc
    for path in (
        ".lit/push-ready.json",
        "AGENTS.md",
        ".github/copilot-instructions.md",
        "scripts/lit-ci-profile.sh",
        running_engine,
    ):
        candidate = ROOT / path
        if not candidate.exists():
            raise RuntimeError(f"policy file is missing: {path}")
        if not candidate.is_file() or candidate.is_symlink():
            raise RuntimeError(f"policy file is unsafe: {path}")
        unstaged = run(
            ["git", "diff", "--quiet", "--", path],
            capture=True,
        )
        staged = run(
            ["git", "diff", "--cached", "--quiet", "HEAD", "--", path],
            capture=True,
        )
        if unstaged.returncode or staged.returncode:
            raise RuntimeError(f"policy differs from HEAD: {path}")


def require_clean_head() -> None:
    require_policy_files_committed()
    status_value = git_output("status", "--porcelain=v1", "--untracked-files=all", "-z")
    if status_value:
        raise RuntimeError("clean committed HEAD required")


def current_branch_ref() -> str:
    branch = git_output("symbolic-ref", "--quiet", "HEAD").strip()
    if not branch.startswith("refs/heads/"):
        raise RuntimeError("attached branch required")
    if branch in {"refs/heads/develop", "refs/heads/main"}:
        raise RuntimeError("develop and main pushes are forbidden")
    return branch


def github_https_authorization() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token is None:
        result = run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            capture=True,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError("GitHub origin authentication unavailable")
        token = result.stdout.strip()
    if not token or len(token) > 4096 or any(ord(character) < 32 or ord(character) == 127 for character in token):
        raise RuntimeError("GitHub token is invalid")
    credentials = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
    return f"AUTHORIZATION: basic {credentials}"


def fetch_authoritative_base(branch: str, base_ref: str) -> subprocess.CompletedProcess[str]:
    origin_url = git_output("remote", "get-url", "origin").strip()
    push_url = git_output("remote", "get-url", "--push", "origin").strip()
    fetch_remote = governed_push_remote_from_url("origin", origin_url)
    push_remote = governed_push_remote_from_url("origin", push_url)
    if fetch_remote["repository"] != push_remote["repository"]:
        raise RuntimeError("origin fetch and push URLs must target the same governed repository")
    command = [
        "git",
        "fetch",
        "--quiet",
        "--no-tags",
        "origin",
        f"+refs/heads/{branch}:{base_ref}",
    ]
    if not origin_url.startswith("https://github.com/"):
        return run(command, capture=True, timeout=120)
    environment = isolated_git_environment()
    environment.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": github_https_authorization(),
        }
    )
    return subprocess.run(  # noqa: S603 -- fixed Git argv; token stays in env.
        command,
        cwd=ROOT,
        check=False,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        env=environment,
    )


def refresh_authoritative_base(config: dict[str, Any]) -> str:
    base_ref = config["base_ref"]
    branch = AUTHORITATIVE_BASE_REFS.get(base_ref)
    if branch is None:
        raise RuntimeError("cannot refresh an ungoverned base ref")
    result = fetch_authoritative_base(branch, base_ref)
    if result.returncode:
        raise RuntimeError(f"could not refresh the authoritative origin/{branch} base")
    return git_output(
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{base_ref}^{{commit}}",
    ).strip()


def require_nonempty_string(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise RuntimeError(f"{description} must be non-empty")
    return value


def require_positive_integer(value: Any, description: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
        raise RuntimeError(f"{description} must be 1..{maximum}")
    return value


def validate_command(value: Any, description: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(argument, str) or not argument for argument in value)
    ):
        raise RuntimeError(f"{description} must be a non-empty string array")
    return value


def validate_agent_config(name: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise RuntimeError(f"agents.{name} must be an object")
    enabled = value.get("enabled")
    required = value.get("required")
    if not isinstance(enabled, bool) or not isinstance(required, bool):
        raise RuntimeError(f"agents.{name} flags must be booleans")
    if enabled is not False or required is not False:
        raise RuntimeError(f"agents.{name} must be disabled because local AI egress is prohibited")
    command = validate_command(value.get("command"), f"agents.{name}.command")
    if command != [name]:
        raise RuntimeError(f"agents.{name}.command must be [{name!r}]")
    require_positive_integer(
        value.get("timeout_seconds"),
        f"agents.{name}.timeout_seconds",
        maximum=MAX_TIMEOUT_SECONDS,
    )
    model = value.get("model")
    if model is not None:
        require_nonempty_string(model, f"agents.{name}.model")
        if len(model) > 100 or model.startswith("-"):
            raise RuntimeError(f"agents.{name}.model is unsafe")


def validate_remote_only_checks(value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise RuntimeError("remote_only_checks must be non-empty")
    identifiers: list[str] = []
    required_keys = {"id", "workflow", "job", "reason", "owner"}
    for item in value:
        if not isinstance(item, dict) or set(item) != required_keys:
            raise RuntimeError("remote_only_checks keys are invalid")
        identifier = require_nonempty_string(item.get("id"), "remote_only_checks id")
        workflow = require_nonempty_string(item.get("workflow"), "remote_only_checks workflow")
        job = require_nonempty_string(item.get("job"), "remote_only_checks job")
        reason = require_nonempty_string(item.get("reason"), "remote_only_checks reason")
        owner = require_nonempty_string(item.get("owner"), "remote_only_checks owner")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identifier):
            raise RuntimeError("remote_only_checks id is unsafe")
        if not re.fullmatch(
            r"\.github/workflows/[A-Za-z0-9_.-]+\.(?:yml|yaml)",
            workflow,
        ):
            raise RuntimeError("remote_only_checks workflow is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", job):
            raise RuntimeError("remote_only_checks job is unsafe")
        if len(reason) > 1_000 or len(owner) > 200:
            raise RuntimeError("remote_only_checks text is too large")
        identifiers.append(identifier)
    if len(identifiers) != len(set(identifiers)):
        raise RuntimeError("remote_only_checks ids must be unique")


def validate_review_path(value: Any, description: str, *, prefix: bool) -> str:
    path = require_nonempty_string(value, description)
    path_body = path[:-1] if prefix and path.endswith("/") else path
    if (
        len(path) > 500
        or path.startswith("/")
        or "\\" in path
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        or Path(path_body).as_posix() != path_body
        or any(part in {"", ".", "..", ".git"} for part in Path(path_body).parts)
        or path.endswith("/") != prefix
    ):
        raise RuntimeError(f"{description} is unsafe")
    return path


def review_warning_bytes(review: dict[str, Any]) -> int | None:
    """Read the advisory amendment while accepting historical v3 policy."""
    if "max_diff_bytes" in review:
        legacy = review["max_diff_bytes"]
        if type(legacy) is not int or legacy <= 0:
            raise RuntimeError("review.max_diff_bytes must be a positive integer")
    warning = review.get("warn_diff_bytes", DEFAULT_REVIEW_WARNING_BYTES)
    if warning is None:
        return None
    if type(warning) is not int or warning <= 0:
        raise RuntimeError("review.warn_diff_bytes must be a positive integer or null")
    return warning


def validate_review_policy(value: Any) -> None:
    if not isinstance(value, dict):
        raise RuntimeError("review policy must be an object")
    required = {"profiles", "classification"}
    sizing = set(value) - required
    if not required.issubset(value) or sizing not in ({"max_diff_bytes"}, {"warn_diff_bytes"}):
        raise RuntimeError("review policy keys are invalid")
    review_warning_bytes(value)
    expected_profiles: dict[str, dict[str, list[str]]] = {
        name: {"agents": list(agents)} for name, agents in REVIEW_PROFILE_AGENTS.items()
    }
    if value.get("profiles") != expected_profiles:
        raise RuntimeError("review profiles must be standard and trust-root")
    classification = value.get("classification")
    if not isinstance(classification, dict) or set(classification) != {
        "version",
        "standard_paths",
        "standard_prefixes",
        "trust_root_terms",
    }:
        raise RuntimeError("review classification keys are invalid")
    if classification.get("version") != 2:
        raise RuntimeError("review classification version is invalid")
    for key, prefix in (("standard_paths", False), ("standard_prefixes", True)):
        paths = classification.get(key)
        if not isinstance(paths, list) or not paths:
            raise RuntimeError(f"review classification {key} must be non-empty")
        normalized = [validate_review_path(path, f"review.classification.{key}", prefix=prefix) for path in paths]
        if normalized != sorted(set(normalized)):
            raise RuntimeError(f"review classification {key} must be sorted and unique")
    trust_root_terms = classification.get("trust_root_terms")
    if (
        not isinstance(trust_root_terms, list)
        or not trust_root_terms
        or any(
            not isinstance(term, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", term) for term in trust_root_terms
        )
        or trust_root_terms != sorted(set(trust_root_terms))
    ):
        raise RuntimeError("review classification trust_root_terms must be safe, sorted, and unique")


def load_config() -> dict[str, Any]:
    reject_hidden_index_entries()
    if not CONFIG.is_file() or CONFIG.is_symlink():
        raise RuntimeError(f"configuration is missing: {CONFIG.relative_to(ROOT)}")
    if CONFIG.stat().st_size > MAX_CONFIG_BYTES:
        raise RuntimeError("configuration is too large")
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("version") != 3
        or not isinstance(data.get("checks"), list)
        or not data.get("checks")
    ):
        raise RuntimeError("version 3 must define checks")
    base_ref = require_nonempty_string(data.get("base_ref"), "base_ref")
    if base_ref not in AUTHORITATIVE_BASE_REFS:
        raise RuntimeError("base_ref is not governed: " + ", ".join(sorted(AUTHORITATIVE_BASE_REFS)))
    if data["checks"] != [CHECK_PROFILE]:
        raise RuntimeError("checks differ from the quality profile")
    agents = data.get("agents")
    if not isinstance(agents, dict) or set(agents) != {"copilot", "codex"}:
        raise RuntimeError("agents must be copilot and codex")
    for name in ("copilot", "codex"):
        validate_agent_config(name, agents[name])
    validate_review_policy(data.get("review"))
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        raise RuntimeError("evidence must be an object")
    require_positive_integer(
        evidence.get("max_age_seconds"),
        "evidence.max_age_seconds",
        maximum=7 * 24 * 60 * 60,
    )
    validate_remote_only_checks(data.get("remote_only_checks"))
    return data


def instructions_digest() -> str:
    if not AGENTS.is_file() or AGENTS.is_symlink():
        raise RuntimeError("AGENTS.md must be a regular file")
    return sha256_bytes(AGENTS.read_bytes())


def instruction_file_hashes() -> dict[str, str]:
    if not COPILOT.is_file() or COPILOT.is_symlink():
        raise RuntimeError(".github/copilot-instructions.md must be a regular file")
    names = git_output("ls-files", "--cached", "-z")
    candidates = {name for name in names.split("\0") if name and INSTRUCTION_PATH_PATTERN.search(name)}
    candidates.update({"AGENTS.md", ".github/copilot-instructions.md"})
    hashes: dict[str, str] = {}
    for name in sorted(candidates):
        payload, _mode = read_repository_file(
            name,
            purpose="Instruction hashing",
            max_bytes=MAX_CONFIG_BYTES,
        )
        hashes[name] = sha256_bytes(payload)
    return hashes


def check_instruction_contract() -> None:
    reject_hidden_index_entries()
    expected = instructions_digest()
    marker = f"<!-- AGENTS_SHA256: {expected} -->"
    if not COPILOT.is_file() or COPILOT.is_symlink():
        raise RuntimeError("review instructions are missing or unsafe")
    lines = COPILOT.read_text(encoding="utf-8").splitlines()
    if lines[-2:] != [CONTRACT_LINE, marker]:
        raise RuntimeError("Copilot instructions are stale; run sync-instructions")


def sync_instructions() -> None:
    if not AGENTS.is_file() or AGENTS.is_symlink() or not COPILOT.is_file() or COPILOT.is_symlink():
        raise RuntimeError("review instructions are missing or unsafe")
    lines = COPILOT.read_text(encoding="utf-8").splitlines()
    lines = [line for line in lines if not line.startswith("<!-- AGENTS_SHA256:") and line != CONTRACT_LINE]
    while lines and not lines[-1]:
        lines.pop()
    lines.extend(
        [
            "",
            CONTRACT_LINE,
            f"<!-- AGENTS_SHA256: {instructions_digest()} -->",
        ]
    )
    COPILOT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def existing_unix_socket(value: str) -> str | None:
    candidate_value = value.removeprefix("unix://")
    try:
        candidate = Path(candidate_value).expanduser().resolve(strict=True)
        mode = candidate.stat().st_mode
    except OSError:
        return None
    if not stat.S_ISSOCK(mode):
        return None
    return str(candidate)


def minimal_check_environment(state_root: Path) -> dict[str, str]:
    path_value = os.environ.get("PATH")
    if not path_value:
        raise RuntimeError("deterministic checks require PATH")
    state_root = state_root.resolve(strict=True)
    state_root.chmod(0o700)
    home = state_root / "home"
    temporary = state_root / "tmp"
    runner_temporary = state_root / "runner-temp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    runner_temporary.mkdir(mode=0o700)
    home.chmod(0o700)
    temporary.chmod(0o700)
    runner_temporary.chmod(0o700)
    environment = {
        "CI": "1",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": path_value,
        "RUNNER_TEMP": str(runner_temporary),
        "TMPDIR": str(temporary),
    }
    selected_engine = os.environ.get("WUNDER_CONTAINER_ENGINE")
    if selected_engine:
        if selected_engine not in {"docker", "podman"}:
            raise RuntimeError("WUNDER_CONTAINER_ENGINE must be docker or podman when set")
        environment["WUNDER_CONTAINER_ENGINE"] = selected_engine
    configured_host = os.environ.get("DOCKER_HOST")
    if configured_host and not configured_host.startswith("unix://"):
        raise RuntimeError("deterministic checks refuse a non-local DOCKER_HOST")
    socket_candidates = []
    if configured_host:
        socket_candidates.append(configured_host)
    socket_candidates.extend(
        [
            str(Path.home() / ".docker" / "run" / "docker.sock"),
            f"/run/user/{os.getuid()}/podman/podman.sock",
            "/var/run/docker.sock",
        ]
    )
    for value in socket_candidates:
        socket_path = existing_unix_socket(value)
        if socket_path:
            environment["DOCKER_HOST"] = f"unix://{socket_path}"
            break
    runtime_directory = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_directory:
        runtime_path = Path(runtime_directory)
        if runtime_path.is_absolute() and runtime_path.is_dir():
            environment["XDG_RUNTIME_DIR"] = str(runtime_path.resolve())
    return environment


def execute_checks(config: dict[str, Any], *, cwd: Path | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    check_cwd = (cwd or ROOT).resolve()
    with tempfile.TemporaryDirectory(prefix="lit-check-environment-") as temporary:
        environment = minimal_check_environment(Path(temporary))
        for check in config["checks"]:
            if not isinstance(check, dict):
                raise RuntimeError("each check must be an object")
            name = require_nonempty_string(check.get("name"), "each check name")
            command = validate_command(check.get("command"), "each check command")
            runtime_command = [sys.executable, *command[1:]] if command[0] in {"python", "python3"} else command
            started_at = now_utc()
            started = time.monotonic()
            print(f"==> {name}: {shlex.join(runtime_command)}", flush=True)
            try:
                result = run(
                    runtime_command,
                    cwd=check_cwd,
                    env=environment,
                    timeout=CHECK_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"check timed out after {CHECK_TIMEOUT_SECONDS} seconds: {name}") from exc
            completed_at = now_utc()
            elapsed = round(time.monotonic() - started, 3)
            results.append(
                {
                    "name": name,
                    "command": runtime_command,
                    "exit_code": result.returncode,
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "duration_seconds": elapsed,
                }
            )
            if result.returncode:
                raise RuntimeError(f"check failed: {name}")
    return results


def resolve_base(config: dict[str, Any], override: str | None = None) -> tuple[str, str, str]:
    base_ref = override or config["base_ref"]
    require_nonempty_string(base_ref, "base_ref")
    if len(base_ref) > 200 or base_ref.startswith("-") or any(character.isspace() for character in base_ref):
        raise RuntimeError("base_ref is unsafe")
    base_tip = git_output("rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}").strip()
    head_commit = git_output("rev-parse", "--verify", "HEAD^{commit}").strip()
    base_commit = git_output("merge-base", base_tip, head_commit).strip()
    if not is_full_git_object_id(base_commit):
        raise RuntimeError("Git returned an invalid merge-base commit")
    return base_ref, base_tip, base_commit


def git_output_at(cwd: Path, *args: str) -> str:
    result = run(["git", *args], capture=True, cwd=cwd)
    if result.returncode:
        raise RuntimeError(result.stdout.strip())
    return result.stdout


def expected_integration_tree(change: PlannedChange) -> str:
    assert_safe_git_configuration(ROOT)
    merged = run(
        [
            "git",
            "merge-tree",
            "--write-tree",
            change.base_tip,
            change.head_commit,
        ],
        capture=True,
    )
    lines = merged.stdout.splitlines()
    if merged.returncode or not lines or not is_full_git_object_id(lines[0]):
        raise RuntimeError(f"HEAD conflicts with base {change.base_tip}: {merged.stdout.strip()}")
    return lines[0].lower()


def git_tree_entry(commit: str, path: str) -> str:
    result = run(
        ["git", "ls-tree", "-z", commit, "--", path],
        capture=True,
    )
    if result.returncode:
        raise RuntimeError(f"cannot inspect policy path: {path}")
    return result.stdout


def require_trusted_check_policy(
    change: PlannedChange,
    *,
    allow_fixture_manifest_bootstrap: bool = False,
) -> None:
    try:
        running_engine = Path(__file__).resolve().relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise RuntimeError("engine is outside repository") from exc
    policy_paths = tuple(dict.fromkeys((*TRUSTED_CHECK_POLICY_PATHS, running_engine)))
    required_paths = {
        ".pre-commit-config.yaml",
        ".lit/push-ready.json",
        "scripts/lit-ci-profile.sh",
        running_engine,
    }
    for path in policy_paths:
        if path == SECRET_FIXTURE_MANIFEST_PATH and allow_fixture_manifest_bootstrap:
            continue
        base_entry = git_tree_entry(change.base_tip, path)
        head_entry = git_tree_entry(change.head_commit, path)
        if path in required_paths and (not base_entry or not head_entry):
            raise RuntimeError(f"required policy path is missing: {path}")
        if base_entry != head_entry:
            raise RuntimeError(f"policy differs from base: {path}; use trust-root review")


def require_review_bootstrap_contract(change: PlannedChange) -> bool:
    try:
        running_engine = Path(__file__).resolve().relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise RuntimeError("engine is outside repository") from exc
    required_paths = (
        ".pre-commit-config.yaml",
        ".lit/push-ready.json",
        "scripts/lit-ci-profile.sh",
        running_engine,
    )
    base_entries = [git_tree_entry(change.base_tip, path) for path in required_paths]
    if all(base_entries):
        if not all(git_tree_entry(change.head_commit, path) for path in required_paths):
            raise RuntimeError("trust-root review lacks policy")
        return False
    if any(base_entries):
        raise RuntimeError("trust-root bootstrap is incomplete on base")
    if not all(git_tree_entry(change.head_commit, path) for path in required_paths):
        raise RuntimeError("trust-root bootstrap lacks policy")
    return True


def require_trusted_review_policy(
    change: PlannedChange,
    *,
    allow_fixture_manifest_bootstrap: bool = False,
) -> bool:
    trust_root_bootstrap = require_review_bootstrap_contract(change)
    if not trust_root_bootstrap:
        require_trusted_check_policy(
            change,
            allow_fixture_manifest_bootstrap=allow_fixture_manifest_bootstrap,
        )
    return trust_root_bootstrap


def require_trust_root_update_contract(change: PlannedChange) -> None:
    if require_review_bootstrap_contract(change):
        raise RuntimeError("trust-root update requires an existing base policy")
    running_engine = Path(__file__).resolve().relative_to(ROOT).as_posix()
    paths = tuple(dict.fromkeys((*TRUSTED_CHECK_POLICY_PATHS, running_engine)))
    if not any(git_tree_entry(change.base_tip, path) != git_tree_entry(change.head_commit, path) for path in paths):
        raise RuntimeError("trust-root update changes no governed policy")


def integration_worktree_fingerprint(cwd: Path, *, include_ignored: bool = False) -> str:
    untracked_command = ["ls-files", "--others"]
    if not include_ignored:
        untracked_command.append("--exclude-standard")
    untracked_command.append("-z")
    names = git_output_at(cwd, *untracked_command).split("\0")
    hashes = {}
    for name in filter(None, names):
        digest, _size = hash_repository_file(cwd, name, purpose="Worktree fingerprint")
        hashes[name] = digest
    return fingerprint_stream(cwd, hashes, integration=True)


def synthetic_integration_commit(change: PlannedChange, integration_tree: str) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Lightning IT push-ready",
            "GIT_AUTHOR_EMAIL": "push-ready@invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_NAME": "Lightning IT push-ready",
            "GIT_COMMITTER_EMAIL": "push-ready@invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
    )
    result = run(
        [
            "git",
            "-c",
            "commit.gpgSign=false",
            "commit-tree",
            integration_tree,
            "-p",
            change.base_tip,
            "-p",
            change.head_commit,
            "-m",
            "Synthetic pull-request integration",
        ],
        capture=True,
        env=environment,
    )
    commit = result.stdout.strip()
    if result.returncode or not is_full_git_object_id(commit):
        raise RuntimeError("integration commit creation failed")
    return commit


def create_integration_directory() -> tuple[Path, tuple[int, int, int, int]]:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    missing_flags = [flag for flag in required_flags if not isinstance(getattr(os, flag, None), int)]
    required_dir_fd_calls = (os.mkdir, os.rmdir, os.stat)
    if missing_flags or any(call not in os.supports_dir_fd for call in required_dir_fd_calls):
        unsupported = ", ".join(missing_flags) or "directory-relative filesystem calls"
        raise RuntimeError(f"integration safe-open unavailable: {unsupported}")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_descriptor = os.open(ROOT, directory_flags)
    except OSError as exc:
        raise RuntimeError("integration repository open failed") from exc
    created_name: str | None = None
    created_identity: tuple[int, int] | None = None
    completed = False
    try:
        root_stat = os.fstat(root_descriptor)
        path_stat = os.stat(ROOT, follow_symlinks=False)
        if not stat.S_ISDIR(root_stat.st_mode) or (root_stat.st_dev, root_stat.st_ino) != (
            path_stat.st_dev,
            path_stat.st_ino,
        ):
            raise RuntimeError("repository identity changed")
        for _attempt in range(128):
            candidate = f"{INTEGRATION_DIRECTORY_PREFIX}{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=root_descriptor)
            except FileExistsError:
                continue
            except OSError as exc:
                raise RuntimeError("integration directory creation failed") from exc
            created_name = candidate
            break
        if created_name is None:
            raise RuntimeError("integration directory collision")

        created_stat = os.stat(
            created_name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        created_identity = created_stat.st_dev, created_stat.st_ino
        if (
            not stat.S_ISDIR(created_stat.st_mode)
            or created_stat.st_uid != os.geteuid()
            or stat.S_IMODE(created_stat.st_mode) & 0o077
        ):
            raise RuntimeError("integration directory permissions are unsafe")
        directory = ROOT / created_name
        try:
            resolved = directory.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("integration directory is unresolved") from exc
        if resolved != directory or resolved.parent != ROOT:
            raise RuntimeError("integration directory escaped repository")
        identity = (
            root_stat.st_dev,
            root_stat.st_ino,
            created_stat.st_dev,
            created_stat.st_ino,
        )
        completed = True
        return directory, identity
    finally:
        if created_name is not None and not completed:
            try:
                current_stat = os.stat(
                    created_name,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                if (
                    stat.S_ISDIR(current_stat.st_mode)
                    and current_stat.st_uid == os.geteuid()
                    and (current_stat.st_dev, current_stat.st_ino) == created_identity
                ):
                    os.rmdir(created_name, dir_fd=root_descriptor)
            except OSError:
                pass
        os.close(root_descriptor)


def remove_integration_directory(directory: Path, identity: tuple[int, int, int, int]) -> None:
    if directory.parent != ROOT or not directory.name.startswith(INTEGRATION_DIRECTORY_PREFIX):
        raise RuntimeError("integration cleanup is unbound")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_descriptor = os.open(ROOT, directory_flags)
    except OSError as exc:
        raise RuntimeError("integration cleanup reopen failed") from exc
    try:
        root_stat = os.fstat(root_descriptor)
        try:
            current_stat = os.stat(
                directory.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise RuntimeError("integration identity changed") from exc
        expected = identity
        current = (
            root_stat.st_dev,
            root_stat.st_ino,
            current_stat.st_dev,
            current_stat.st_ino,
        )
        if current != expected or not stat.S_ISDIR(current_stat.st_mode) or current_stat.st_uid != os.geteuid():
            raise RuntimeError("integration identity changed")
        try:
            os.rmdir(directory.name, dir_fd=root_descriptor)
        except OSError as exc:
            raise RuntimeError("integration directory is not empty") from exc
    finally:
        os.close(root_descriptor)


@contextlib.contextmanager
def isolated_integration_directory():
    directory, identity = create_integration_directory()
    try:
        yield directory
    finally:
        active_error = sys.exc_info()[1]
        try:
            remove_integration_directory(directory, identity)
        except RuntimeError as cleanup_error:
            if active_error is not None:
                raise RuntimeError(f"{active_error}; cleanup failed: {cleanup_error}") from active_error
            raise


def directory_identity(path: Path, *, purpose: str) -> tuple[int, int]:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{purpose} is unavailable") from exc
    if not stat.S_ISDIR(path_stat.st_mode) or path.is_symlink():
        raise RuntimeError(f"{purpose} is not a real directory")
    return path_stat.st_dev, path_stat.st_ino


def execute_integration_checks(
    config: dict[str, Any], change: PlannedChange
) -> tuple[list[dict[str, Any]], str, str, str]:
    integration_tree = expected_integration_tree(change)
    integration_commit = synthetic_integration_commit(
        change,
        integration_tree,
    )
    with isolated_integration_directory() as temporary:
        worktree = temporary / "worktree"
        added = run(
            [
                "git",
                "worktree",
                "add",
                "--detach",
                str(worktree),
                integration_commit,
            ],
            capture=True,
        )
        if added.returncode:
            raise RuntimeError("integration worktree failed: " + added.stdout.strip())
        worktree_identity = directory_identity(
            worktree,
            purpose="isolated integration worktree",
        )
        try:
            checked_tree = git_output_at(worktree, "write-tree").strip()
            if checked_tree != integration_tree:
                raise RuntimeError("integration differs from merge-tree")
            status_value = git_output_at(
                worktree,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "-z",
            )
            if status_value:
                raise RuntimeError("integration checkout is dirty")
            parents = (
                git_output_at(
                    worktree,
                    "show",
                    "-s",
                    "--format=%P",
                    "HEAD",
                )
                .strip()
                .split()
            )
            if parents != [change.base_tip, change.head_commit]:
                raise RuntimeError("integration parents are invalid")
            before = integration_worktree_fingerprint(worktree)
            checks = execute_checks(config, cwd=worktree)
            after = integration_worktree_fingerprint(worktree)
            if after != before:
                raise RuntimeError("a check changed the integration checkout")
            return checks, integration_tree, integration_commit, before
        finally:
            if (
                directory_identity(
                    worktree,
                    purpose="isolated integration worktree",
                )
                != worktree_identity
            ):
                raise RuntimeError("integration worktree identity changed")
            removed = run(
                ["git", "worktree", "remove", str(worktree)],
                capture=True,
            )
            if removed.returncode:
                raise RuntimeError("integration removal failed: " + removed.stdout.strip())


def quote_diff_path(prefix: str, name: str) -> str:
    value = f"{prefix}/{name}"
    if re.search(r"[\s\"\\\x00-\x1f\x7f-\xff]", value):
        encoded = value.encode("utf-8", errors="surrogateescape")
        escaped: list[str] = []
        for byte in encoded:
            if byte == ord("\\"):
                escaped.append("\\\\")
            elif byte == ord('"'):
                escaped.append('\\"')
            elif byte == ord("\t"):
                escaped.append("\\t")
            elif byte == ord("\n"):
                escaped.append("\\n")
            elif byte == ord("\r"):
                escaped.append("\\r")
            elif 0x20 <= byte <= 0x7E:
                escaped.append(chr(byte))
            else:
                escaped.append(f"\\{byte:03o}")
        return '"' + "".join(escaped) + '"'
    return value


def unquote_diff_path(value: str, prefix: str) -> str | None:
    if value == "/dev/null":
        return None
    if value.startswith('"'):
        if len(value) < 2 or not value.endswith('"'):
            raise RuntimeError("malformed quoted diff path")
        payload = value[1:-1]
        decoded = bytearray()
        index = 0
        escapes = {
            "a": 0x07,
            "b": 0x08,
            "t": 0x09,
            "n": 0x0A,
            "v": 0x0B,
            "f": 0x0C,
            "r": 0x0D,
            '"': 0x22,
            "\\": 0x5C,
        }
        while index < len(payload):
            character = payload[index]
            if character != "\\":
                decoded.extend(character.encode("utf-8"))
                index += 1
                continue
            index += 1
            if index >= len(payload):
                raise RuntimeError("diff path ends in escape")
            escaped = payload[index]
            if escaped in escapes:
                decoded.append(escapes[escaped])
                index += 1
                continue
            if escaped not in "01234567":
                raise RuntimeError("diff path escape is unsafe")
            octal = payload[index : index + 3]
            if len(octal) != 3 or any(octal_character not in "01234567" for octal_character in octal):
                raise RuntimeError("diff path octal is invalid")
            decoded.append(int(octal, 8))
            index += 3
        try:
            path_value = decoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("diff path is not UTF-8") from exc
    else:
        if any(character.isspace() for character in value):
            raise RuntimeError("diff path contains whitespace")
        path_value = value
    expected = f"{prefix}/"
    if not path_value.startswith(expected):
        raise RuntimeError("diff path prefix is invalid")
    path = path_value[len(expected) :]
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        or Path(path).as_posix() != path
        or any(part in {"", ".", "..", ".git"} for part in Path(path).parts)
    ):
        raise RuntimeError("diff path is unsafe")
    return path


def spool_untracked_patch(name, patch):
    raw = PatchSpool()
    try:
        descriptor = open_repository_regular(name, purpose="Untracked fingerprint")
        with os.fdopen(descriptor, "rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            while True:
                payload = stream.read(CHUNK_BYTES)
                if not payload:
                    break
                if b"\0" in payload:
                    raise RuntimeError(f"local review refused for binary untracked path: {name}")
                raw.write(payload)
        lines = 0
        partial = False
        try:
            for _fragment, ending in split_text_fragments(raw.text_chunks()):
                partial = True
                if ending is not None:
                    lines += 1
                    partial = False
            lines += partial
        except UnicodeError as exc:
            raise RuntimeError(f"local review refused for non-UTF-8 untracked path: {name}") from exc
        old_path = quote_diff_path("a", name)
        new_path = quote_diff_path("b", name)
        mode_value = "100755" if mode & 0o111 else "100644"
        header = f"diff --git {old_path} {new_path}\nnew file mode {mode_value}\n"
        if not raw.size:
            header += "index 0000000..e69de29\n"
        else:
            header += f"--- /dev/null\n+++ {new_path}\n@@ -0,0 +1,{lines} @@\n"
        patch.write(header.encode("utf-8"))
        beginning = True
        for fragment, ending in split_text_fragments(raw.text_chunks()):
            if beginning:
                patch.write(b"+")
                beginning = False
            patch.write(fragment.encode("utf-8"))
            if ending is not None:
                patch.write(ending.encode("utf-8"))
                if not ending.endswith("\n"):
                    patch.write(b"\n\\ No newline at end of file\n")
                beginning = True
        if not beginning:
            patch.write(b"\n\\ No newline at end of file\n")
        return raw.digest.hexdigest(), raw.size
    finally:
        raw.close()


def render_untracked_patch(name: str, payload: bytes, mode: int) -> str:
    if b"\0" in payload:
        raise RuntimeError(f"binary untracked path: {name}")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"non-UTF-8 untracked path: {name}") from exc
    old_path = quote_diff_path("a", name)
    new_path = quote_diff_path("b", name)
    file_mode = "100755" if mode & 0o111 else "100644"
    parts = [
        f"diff --git {old_path} {new_path}\n",
        f"new file mode {file_mode}\n",
    ]
    if not text:
        parts.append("index 0000000..e69de29\n")
        return "".join(parts)
    parts.extend(
        [
            "--- /dev/null\n",
            f"+++ {new_path}\n",
        ]
    )
    lines = text.splitlines(keepends=True)
    if lines:
        parts.append(f"@@ -0,0 +1,{len(lines)} @@\n")
        for line in lines:
            if line.endswith("\n"):
                parts.append("+" + line)
            else:
                parts.append("+" + line + "\n")
                parts.append("\\ No newline at end of file\n")
    return "".join(parts)


def planned_change(
    config: dict[str, Any],
    *,
    base_override: str | None = None,
    fixture_manifest_bootstrap: bool = False,
    include_patch: bool = True,
) -> PlannedChange:
    if any(path.name.startswith(INTEGRATION_DIRECTORY_PREFIX) for path in ROOT.iterdir()):
        raise RuntimeError("stale integration directory")
    initial_tree_fingerprint = tree_fingerprint()
    base_ref, base_tip, base_commit = resolve_base(config, base_override)
    head_commit = git_output("rev-parse", "--verify", "HEAD^{commit}").strip()
    tracked_names = git_output("diff", "--name-only", "--no-renames", "-z", base_commit, "--").split("\0")
    patch = PatchSpool() if include_patch else None
    untracked_hashes = {}
    try:
        if include_patch:
            assert patch is not None
            tail = ""
            for chunk in decoded_git_chunks(
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "--no-renames",
                "--full-index",
                base_commit,
                "--",
                errors="strict",
                universal_newlines=False,
            ):
                inspection = tail + chunk
                if "GIT binary patch\n" in inspection or "\nBinary files " in inspection:
                    raise RuntimeError("local review refused because the planned tracked diff contains binary content")
                tail = inspection[-32:]
                patch.write(chunk.encode("utf-8"))
            total = 0
            for name in untracked_names():
                digest, size = spool_untracked_patch(name, patch)
                total += size
                untracked_hashes[name] = digest
            if not patch.size:
                raise RuntimeError("planned diff is empty")
            warning = review_warning_bytes(config["review"])
            if warning is not None and patch.size >= warning:
                print(
                    f"Planning notice: complete diff is {patch.size} bytes (advisory threshold {warning}); "
                    "all deterministic checks still run. No automatic PR splitting.",
                    file=sys.stderr,
                )
        paths = tuple(sorted(set(filter(None, tracked_names)) | set(untracked_hashes)))
        final_tree_fingerprint = tree_fingerprint()
        if final_tree_fingerprint != initial_tree_fingerprint:
            raise RuntimeError("Git tree changed while constructing the exact planned push patch")
        change = PlannedChange(
            base_ref,
            base_tip,
            base_commit,
            head_commit,
            patch,
            paths,
            untracked_hashes,
            final_tree_fingerprint,
        )
        if include_patch:
            ensure_review_safe(
                change,
                secret_fixture_manifest_for_change(change, bootstrap=fixture_manifest_bootstrap),
            )
        return change
    except BaseException:
        if patch is not None:
            patch.close()
        raise


def config_at_commit(commit: str) -> dict[str, Any] | None:
    if not is_full_git_object_id(commit):
        raise RuntimeError("base policy commit is invalid")
    relative_config = CONFIG.relative_to(ROOT).as_posix()
    result = run(
        ["git", "show", f"{commit}:{relative_config}"],
        capture=True,
    )
    if result.returncode:
        return None
    if utf8_size(result.stdout) > MAX_CONFIG_BYTES:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def classify_review_profile(change: PlannedChange) -> ReviewClassification:
    base_config = config_at_commit(change.base_tip)
    if base_config is None or base_config.get("version") != 3:
        policy_sha256 = sha256_text("trust-root-bootstrap-v1")
        return ReviewClassification(
            "trust-root",
            REVIEW_PROFILE_AGENTS["trust-root"],
            policy_sha256,
            "base-policy-unavailable",
        )
    review = base_config.get("review")
    try:
        validate_review_policy(review)
    except RuntimeError:
        policy_sha256 = sha256_text("trust-root-invalid-base-policy-v1")
        return ReviewClassification(
            "trust-root",
            REVIEW_PROFILE_AGENTS["trust-root"],
            policy_sha256,
            "base-policy-invalid",
        )
    assert isinstance(review, dict)
    classification = review["classification"]
    policy_sha256 = sha256_text(
        json.dumps(
            {
                "profiles": review["profiles"],
                "classification": classification,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    standard_paths = set(classification["standard_paths"])
    standard_prefixes = tuple(classification["standard_prefixes"])
    # Match the existing local terms over every patch fragment, retaining only
    # enough overlap to prove word boundaries across chunk edges.
    terms = classification["trust_root_terms"]
    overlap = max((len(term) for term in terms), default=0) + 2
    matched = set()
    tail = ""
    chunks = itertools.chain(("\n".join(change.paths) + "\n",), patch_chunks(change.patch), ("\n",))
    for chunk in chunks:
        text = tail + chunk.lower()
        for term in terms:
            pattern = rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])"
            # Earlier matches were already checked with their real left context.
            # Recheck a term ending at the old boundary once its right context
            # arrives, but ignore false word starts at the truncated tail edge.
            if any(len(tail) <= match.end() < len(text) for match in re.finditer(pattern, text)):
                matched.add(term)
        tail = text[-overlap:]
    matched_term = next((term for term in terms if term in matched), None)
    known_standard_paths = all(path in standard_paths or path.startswith(standard_prefixes) for path in change.paths)
    standard = known_standard_paths and matched_term is None
    profile = "standard" if standard else "trust-root"
    if matched_term is not None:
        reason = f"trust-root-term:{matched_term}"
    elif known_standard_paths:
        reason = "all-paths-standard"
    else:
        reason = "unknown-or-trust-root-path"
    return ReviewClassification(
        profile,
        REVIEW_PROFILE_AGENTS[profile],
        policy_sha256,
        reason,
    )


def review_classification_evidence(classification: ReviewClassification) -> dict[str, Any]:
    return {
        "profile": classification.profile,
        "agents": list(classification.agents),
        "policy_sha256": classification.policy_sha256,
        "reason": classification.reason,
    }


def review_size_evidence(config: dict[str, Any], change: PlannedChange) -> dict[str, Any]:
    warning = review_warning_bytes(config["review"])
    measured = change.patch.size if hasattr(change.patch, "text_chunks") else utf8_size(change.patch)
    if measured <= 0:
        raise RuntimeError("planned diff is empty")
    return {
        "profile": "advisory/v1",
        "bytes": measured,
        "warning_bytes": warning,
        "warning_exceeded": warning is not None and measured >= warning,
        "path_count": len(change.paths),
    }


def report_review_size(config: dict[str, Any], change: PlannedChange) -> None:
    measurement = review_size_evidence(config, change)
    print(
        f"Review input: {measurement['bytes']} bytes; {measurement['path_count']} paths; sha256:{change.diff_sha256}",
        flush=True,
    )
    if measurement["warning_exceeded"]:
        print(
            "Planning notice: full diff exceeds the advisory threshold; "
            "all deterministic checks still run. No automatic PR splitting.",
            flush=True,
        )


def changed_paths() -> list[str]:
    values = git_output(
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    ).split("\0")
    paths: list[str] = []
    index = 0
    while index < len(values):
        entry = values[index]
        index += 1
        if not entry:
            continue
        if len(entry) < 4:
            raise RuntimeError("malformed porcelain status entry")
        status_value = entry[:2]
        paths.append(entry[3:])
        if "R" in status_value or "C" in status_value:
            if index >= len(values) or not values[index]:
                raise RuntimeError("rename/copy lacks paired path")
            paths.append(values[index])
            index += 1
    return paths


def planned_paths(
    config: dict[str, Any] | None = None,
    *,
    base_override: str | None = None,
) -> list[str]:
    if config is None:
        config = load_config()
    return list(planned_change(config, base_override=base_override).paths)


def planned_diff(
    config: dict[str, Any] | None = None,
    *,
    base_override: str | None = None,
) -> str:
    if config is None:
        config = load_config()
    return planned_change(config, base_override=base_override).diff


def untracked_review_text(max_bytes: int = 1_000_000) -> str:
    chunks: list[str] = []
    total = 0
    for name in untracked_names():
        payload, _mode = read_repository_file(
            name,
            purpose="Local review",
            max_bytes=max_bytes - total,
        )
        total += len(payload)
        try:
            chunks.append(payload.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise RuntimeError(f"non-UTF-8 untracked path: {name}") from exc
    return "\n".join(chunks)


def parse_secret_fixture_manifest(
    payload: str,
) -> dict[str, dict[int, tuple[str, str]]]:
    document = json.loads(payload)
    if not isinstance(document, dict) or set(document) != {
        "version",
        "fixtures",
    }:
        raise RuntimeError("fixture manifest fields are invalid")
    if document["version"] != 1:
        raise RuntimeError("fixture manifest version must be 1")
    fixtures = document["fixtures"]
    if not isinstance(fixtures, list) or not 1 <= len(fixtures) <= 100:
        raise RuntimeError("fixture count must be 1..100")
    parsed: dict[str, dict[int, tuple[str, str]]] = {}
    for entry in fixtures:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "line_hex",
            "line_number",
            "purpose",
        }:
            raise RuntimeError("fixture fields are invalid")
        path = entry["path"]
        encoded = entry["line_hex"]
        line_number = entry["line_number"]
        if entry["purpose"] != "synthetic-test-fixture":
            raise RuntimeError("fixture purpose is invalid")
        if isinstance(line_number, bool) or not isinstance(line_number, int) or not 1 <= line_number <= 10_000_000:
            raise RuntimeError("fixture line must be positive")
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 500
            or path.startswith("/")
            or "\\" in path
            or ":" in path
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
            or Path(path).as_posix() != path
            or any(part in {"", ".", "..", ".git"} for part in Path(path).parts)
            or not path.startswith(SECRET_FIXTURE_PATH_PREFIXES)
        ):
            raise RuntimeError("fixture path is unsafe")
        lowered = path.lower()
        if any(part in lowered for part in SECRET_PATH_PARTS) or Path(path).name.lower() == ".npmrc":
            raise RuntimeError("fixture path is secret-like")
        if (
            not isinstance(encoded, str)
            or not re.fullmatch(r"[0-9a-f]+", encoded)
            or len(encoded) % 2
            or len(encoded) > 20_000
        ):
            raise RuntimeError("fixture line_hex must be bounded lowercase hex")
        try:
            line = bytes.fromhex(encoded).decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("fixture line_hex is not UTF-8") from exc
        if not line or "\n" in line or "\r" in line:
            raise RuntimeError("fixture must encode one line")
        if not any(pattern.search(line) for pattern in SECRET_CONTENT_PATTERNS):
            raise RuntimeError("fixture is not secret-like")
        digest = sha256_text(line)
        path_entries = parsed.setdefault(path, {})
        if line_number in path_entries:
            raise RuntimeError("duplicate fixture line")
        path_entries[line_number] = (digest, line)
    return parsed


def repository_blob_at_commit(
    commit: str,
    path: str,
    *,
    max_bytes: int,
) -> str | None:
    if not is_full_git_object_id(commit):
        raise RuntimeError("fixture commit is invalid")
    object_name = f"{commit}:{path}"
    exists = run(["git", "cat-file", "-e", object_name], capture=True)
    if exists.returncode:
        return None
    size_value = git_output("cat-file", "-s", object_name).strip()
    if not size_value.isdigit() or int(size_value) > max_bytes:
        raise RuntimeError("fixture source is too large")
    value = git_output("cat-file", "-p", object_name)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise RuntimeError("fixture source is not UTF-8") from exc
    return value


def secret_fixture_manifest_at_commit(
    commit: str,
) -> dict[str, dict[int, tuple[str, str]]]:
    payload = repository_blob_at_commit(
        commit,
        SECRET_FIXTURE_MANIFEST_PATH,
        max_bytes=MAX_SECRET_FIXTURE_MANIFEST_BYTES,
    )
    if payload is None:
        return {}
    return parse_secret_fixture_manifest(payload)


def bootstrap_secret_fixture_manifest(
    change: PlannedChange,
) -> dict[str, dict[int, tuple[str, str]]]:
    if SECRET_FIXTURE_MANIFEST_PATH not in change.paths:
        raise RuntimeError("fixture bootstrap needs a changed manifest")
    changelog_paths = [path for path in change.paths if re.fullmatch(r"changelogs/fragments/[^/]+\.ya?ml", path)]
    disallowed = [
        path
        for path in change.paths
        if path != SECRET_FIXTURE_MANIFEST_PATH and not re.fullmatch(r"changelogs/fragments/[^/]+\.ya?ml", path)
    ]
    if disallowed or len(changelog_paths) > 1:
        raise RuntimeError("fixture bootstrap scope is invalid")
    if secret_fixture_manifest_at_commit(change.base_tip):
        raise RuntimeError("fixture base manifest must be absent")
    manifest = secret_fixture_manifest_at_commit(change.head_commit)
    if not manifest:
        raise RuntimeError("fixture head manifest must be committed")
    for path, entries in manifest.items():
        if path in change.paths:
            raise RuntimeError("fixture source must be unchanged")
        source = repository_blob_at_commit(
            change.base_tip,
            path,
            max_bytes=MAX_SECRET_FIXTURE_SOURCE_BYTES,
        )
        if source is None:
            raise RuntimeError(f"fixture source absent from base: {path}")
        source_lines = source.splitlines()
        for line_number, (_digest, line) in entries.items():
            if line_number > len(source_lines) or source_lines[line_number - 1] != line:
                raise RuntimeError(
                    f"secret fixture bootstrap line is absent from its exact base position: {path}:{line_number}"
                )
    return manifest


def secret_fixture_manifest_for_change(
    change: PlannedChange,
    *,
    bootstrap: bool = False,
) -> dict[str, dict[int, tuple[str, str]]]:
    if bootstrap:
        return bootstrap_secret_fixture_manifest(change)
    if SECRET_FIXTURE_MANIFEST_PATH in change.paths:
        raise RuntimeError("fixture changes require bootstrap review")
    return secret_fixture_manifest_at_commit(change.base_tip)


def mask_documented_secret_fixture_lines(
    value: str,
    documented: dict[str, dict[int, tuple[str, str]]],
    *,
    path: str | None = None,
    diff: bool = False,
) -> str:
    if diff:
        return mask_documented_secret_fixture_diff(value, documented)
    entries = documented.get(path or "", {})
    if not entries:
        return value
    masked: list[str] = []
    for line_number, line in enumerate(value.splitlines(), start=1):
        if documented_secret_fixture_matches(
            documented,
            path,
            line_number,
            line,
        ):
            masked.append("DOCUMENTED_SYNTHETIC_FIXTURE")
        else:
            masked.append(line)
    return "\n".join(masked)


def documented_secret_fixture_matches(
    documented: dict[str, dict[int, tuple[str, str]]],
    path: str | None,
    line_number: int,
    line: str,
) -> bool:
    if path is None:
        return False
    entry = documented.get(path, {}).get(line_number)
    return entry is not None and sha256_text(line) == entry[0]


def mask_documented_secret_fixture_diff(
    diff: str,
    documented: dict[str, dict[int, tuple[str, str]]],
) -> str:
    if not documented:
        return diff
    masked: list[str] = []
    old_path: str | None = None
    new_path: str | None = None
    old_line_number = 0
    new_line_number = 0
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            old_path = None
            new_path = None
            in_hunk = False
        elif not in_hunk and line.startswith("--- "):
            old_path = unquote_diff_path(line[4:], "a")
        elif not in_hunk and line.startswith("+++ "):
            new_path = unquote_diff_path(line[4:], "b")
        elif line.startswith("@@"):
            if old_path is None and new_path is None:
                raise RuntimeError("planned diff hunk has no governed file path")
            hunk = re.match(
                r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@",
                line,
            )
            if hunk is None:
                raise RuntimeError("planned diff has a malformed hunk header")
            old_line_number = int(hunk.group(1))
            new_line_number = int(hunk.group(2))
            in_hunk = True
        elif in_hunk and line[:1] in {"+", "-", " "}:
            if line.startswith("+"):
                path = new_path
                line_number = new_line_number
                new_line_number += 1
            elif line.startswith("-"):
                path = old_path
                line_number = old_line_number
                old_line_number += 1
            else:
                path = old_path or new_path
                line_number = old_line_number or new_line_number
                old_line_number += 1
                new_line_number += 1
            if documented_secret_fixture_matches(
                documented,
                path,
                line_number,
                line[1:],
            ):
                masked.append("DOCUMENTED_SYNTHETIC_FIXTURE")
                continue
        masked.append(line)
    return "\n".join(masked)


def ensure_review_safe(change: PlannedChange, documented=None) -> None:
    streaming_review_safe(change, documented or {})


def checkout_sanitized_commit(
    source: Path,
    commit: str,
    destination: Path,
    hooks: Path,
) -> None:
    if not is_full_git_object_id(commit):
        raise RuntimeError("invalid review commit")
    object_format = git_output_at(
        source,
        "rev-parse",
        "--show-object-format",
    ).strip()
    if object_format not in {"sha1", "sha256"}:
        raise RuntimeError("unsupported object format")
    initialized = run(
        [
            "git",
            "-c",
            "init.templateDir=",
            "-c",
            f"core.hooksPath={hooks}",
            "init",
            "-q",
            f"--object-format={object_format}",
            "-b",
            "review-base",
        ],
        capture=True,
        cwd=destination,
    )
    if initialized.returncode:
        raise RuntimeError("review init failed: " + initialized.stdout.strip())
    fetched = run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "-q",
            "--no-tags",
            "--no-recurse-submodules",
            str(source),
            commit,
        ],
        capture=True,
        cwd=destination,
    )
    if fetched.returncode:
        raise RuntimeError("review fetch failed: " + fetched.stdout.strip())
    checked_out = run(
        ["git", "checkout", "-q", "--detach", commit],
        capture=True,
        cwd=destination,
    )
    if checked_out.returncode:
        raise RuntimeError("review checkout failed: " + checked_out.stdout.strip())


def sanitized_root_commit(repository: Path, tree: str) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Lightning IT push-ready",
            "GIT_AUTHOR_EMAIL": "push-ready@invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_NAME": "Lightning IT push-ready",
            "GIT_COMMITTER_EMAIL": "push-ready@invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
    )
    result = run(
        [
            "git",
            "-c",
            "commit.gpgSign=false",
            "commit-tree",
            tree,
            "-m",
            "Sanitized review integration root",
        ],
        capture=True,
        cwd=repository,
        env=environment,
    )
    commit = result.stdout.strip()
    if result.returncode or not is_full_git_object_id(commit):
        raise RuntimeError("review root creation failed")
    return commit


def verified_review_topology(
    change: PlannedChange,
    *,
    integration_tree: str,
    workspace_commit: str,
) -> ReviewTopology:
    head_line = git_output("rev-list", "--parents", "-n", "1", change.head_commit).strip().split()
    if (
        not head_line
        or head_line[0] != change.head_commit
        or any(not is_full_git_object_id(value) for value in head_line)
    ):
        raise RuntimeError("review topology check failed")
    head_tree = git_output("rev-parse", "--verify", f"{change.head_commit}^{{tree}}").strip()
    base_tree = git_output("rev-parse", "--verify", f"{change.base_tip}^{{tree}}").strip()
    if any(
        not is_full_git_object_id(value)
        for value in (
            head_tree,
            base_tree,
            integration_tree,
            workspace_commit,
        )
    ):
        raise RuntimeError("review topology ID is invalid")
    return ReviewTopology(
        head_tree=head_tree,
        head_parents=tuple(head_line[1:]),
        base_tree=base_tree,
        integration_tree=integration_tree,
        workspace_commit=workspace_commit,
    )


def require_history_free_review_workspace(
    workspace: Path,
    *,
    source_commits: tuple[str, ...],
) -> str:
    workspace_commit = git_output_at(workspace, "rev-parse", "HEAD").strip()
    root_line = git_output_at(workspace, "rev-list", "--parents", "-n", "1", "HEAD").strip().split()
    if root_line != [workspace_commit]:
        raise RuntimeError("review commit has history")
    all_objects = {
        line.strip()
        for line in git_output_at(
            workspace,
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ).splitlines()
        if line.strip()
    }
    reachable_objects = {
        line.split(" ", 1)[0] for line in git_output_at(workspace, "rev-list", "--objects", "HEAD").splitlines() if line
    }
    if not all_objects or all_objects != reachable_objects:
        raise RuntimeError("review store has non-snapshot objects")
    for commit in dict.fromkeys(source_commits):
        present = run(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
            capture=True,
            cwd=workspace,
        )
        if present.returncode == 0:
            raise RuntimeError("review store contains source history")
    checked = run(
        ["git", "fsck", "--strict", "--no-reflogs"],
        capture=True,
        cwd=workspace,
    )
    if checked.returncode:
        raise RuntimeError("review store integrity failed")
    return workspace_commit


@contextlib.contextmanager
def sanitized_review_workspace(
    change: PlannedChange,
    *,
    fixture_manifest_bootstrap: bool = False,
):
    assert_safe_git_configuration(ROOT)
    documented = secret_fixture_manifest_for_change(
        change,
        bootstrap=fixture_manifest_bootstrap,
    )
    source_status = git_output(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "-z",
    )
    with tempfile.TemporaryDirectory(prefix="lit-agent-review-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        disabled_hooks = root / "disabled-hooks"
        disabled_hooks.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(
            prefix="builder-",
            dir=root,
        ) as builder_name:
            builder = Path(builder_name)
            checkout_sanitized_commit(
                ROOT,
                change.base_tip,
                builder,
                disabled_hooks,
            )
            if change.patch:
                applied = apply_patch_stream(
                    [
                        "git",
                        "-c",
                        f"core.hooksPath={disabled_hooks}",
                        "apply",
                        "--3way",
                        "--index",
                        "--binary",
                        "--whitespace=nowarn",
                        "-",
                    ],
                    capture=True,
                    patch=change.patch,
                    cwd=builder,
                )
                if applied.returncode:
                    raise RuntimeError("review patch failed: " + applied.stdout.strip())
            actual_tree = git_output_at(builder, "write-tree").strip()
            integration_tree = expected_integration_tree(change) if not source_status else actual_tree
            if actual_tree != integration_tree:
                raise RuntimeError("review tree differs from integration")
            root_commit = sanitized_root_commit(builder, integration_tree)
            checkout_sanitized_commit(
                builder,
                root_commit,
                workspace,
                disabled_hooks,
            )
        workspace_tree = git_output_at(workspace, "write-tree").strip()
        if workspace_tree != integration_tree:
            raise RuntimeError("review workspace tree changed")
        workspace_commit = git_output_at(workspace, "rev-parse", "HEAD").strip()
        topology = verified_review_topology(
            change,
            integration_tree=integration_tree,
            workspace_commit=workspace_commit,
        )
        verified_workspace_commit = require_history_free_review_workspace(
            workspace,
            source_commits=tuple(
                dict.fromkeys(
                    (
                        change.base_commit,
                        change.base_tip,
                        change.head_commit,
                        *topology.head_parents,
                    )
                )
            ),
        )
        if verified_workspace_commit != topology.workspace_commit:
            raise RuntimeError("review root changed")
        ensure_workspace_review_safe(workspace, documented)
        yield workspace, root, topology


def ensure_workspace_review_safe(workspace: Path, documented=None) -> None:
    streaming_workspace_safe(workspace, documented or {})


def tracked_instruction_bundle(workspace: Path) -> str:
    names = git_output_at(workspace, "ls-files", "-z").split("\0")
    chunks: list[str] = []
    total = 0
    for name in sorted(entry for entry in names if entry and INSTRUCTION_PATH_PATTERN.search(entry)):
        candidate = workspace / name
        if not candidate.is_file() or candidate.is_symlink():
            raise RuntimeError(f"sanitized instruction is not a regular file: {name}")
        descriptor = open_regular_below(workspace, name, purpose="Tracked instruction")
        with os.fdopen(descriptor, "rb") as stream:
            payload = stream.read(2_000_001 - total)
        total += len(payload)
        if total > 2_000_000:
            raise RuntimeError("tracked instruction bundle exceeds 2 MB")
        try:
            text_value = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError(f"tracked instruction is not UTF-8: {name}") from exc
        chunks.append(f"----- BEGIN {name} -----\n{text_value}\n----- END {name} -----")
    if not any(chunk.startswith("----- BEGIN AGENTS.md -----") for chunk in chunks):
        raise RuntimeError("sanitized review repository lacks tracked AGENTS.md")
    return "\n\n".join(chunks)


def minimal_agent_environment(*, state_root: Path, agent: str, workspace: Path | None = None) -> dict[str, str]:
    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "LOGNAME",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TMPDIR",
        "USER",
    }
    if agent == "copilot":
        allowed.update(
            {
                "COPILOT_GH_HOST",
                "GH_HOST",
                "COPILOT_GITHUB_TOKEN",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "NO_PROXY",
            }
        )
    else:
        allowed.update({"CODEX_API_KEY", "OPENAI_API_KEY"})
    environment = {key: value for key, value in os.environ.items() if key in allowed and value}
    environment["CI"] = "1"
    environment["TMPDIR"] = str(state_root / "tmp")
    Path(environment["TMPDIR"]).mkdir(mode=0o700, exist_ok=True)
    if agent == "copilot":
        environment["COPILOT_HOME"] = str(state_root / "copilot-home")
        Path(environment["COPILOT_HOME"]).mkdir(mode=0o700, exist_ok=True)
        environment.update(COPILOT_PROMPT_MODE_BOUNDARY)
        selected = next((name for name in COPILOT_TOKEN_NAMES if environment.get(name)), None)
        if selected:
            value = environment[selected]
            for name in COPILOT_TOKEN_NAMES:
                environment.pop(name, None)
            environment[selected] = value
        else:
            gh = shutil.which("gh")
            if gh is not None:
                token = run(
                    [gh, "auth", "token"],
                    capture=True,
                    timeout=30,
                    env=environment,
                )
                if token.returncode == 0 and token.stdout.strip():
                    environment["COPILOT_GITHUB_TOKEN"] = token.stdout.strip()
    else:
        if workspace is None:
            raise RuntimeError("Codex isolation requires an explicit workspace")
        isolated_home = state_root / "codex-home"
        isolated_home.mkdir(mode=0o700, exist_ok=True)
        source_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
        source_auth = source_home / "auth.json"
        if (
            not environment.get("CODEX_API_KEY")
            and not environment.get("OPENAI_API_KEY")
            and source_auth.is_file()
            and not source_auth.is_symlink()
        ):
            target_auth = isolated_home / "auth.json"
            shutil.copy2(source_auth, target_auth)
            target_auth.chmod(0o600)
        workspace_key = json.dumps(str(workspace.resolve()))
        permission_profile = codex_permission_profile_name(state_root)
        (isolated_home / "config.toml").write_text(
            "\n".join(
                [
                    f'default_permissions = "{permission_profile}"',
                    'approval_policy = "never"',
                    "allow_login_shell = false",
                    'web_search = "disabled"',
                    "",
                    "[features]",
                    "apps = false",
                    "hooks = false",
                    "memories = false",
                    "multi_agent = false",
                    "remote_plugin = false",
                    "",
                    f"[permissions.{permission_profile}.filesystem]",
                    '":minimal" = "read"',
                    "",
                    (f'[permissions.{permission_profile}.filesystem.":workspace_roots"]'),
                    '"." = "read"',
                    "",
                    f"[permissions.{permission_profile}.network]",
                    "enabled = false",
                    "",
                    f"[projects.{workspace_key}]",
                    'trust_level = "untrusted"',
                    "",
                    "[shell_environment_policy]",
                    'inherit = "none"',
                    "ignore_default_excludes = false",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        environment["CODEX_HOME"] = str(isolated_home)
    process_home = state_root / f"{agent}-process-home"
    process_home.mkdir(mode=0o700, exist_ok=True)
    environment["HOME"] = str(process_home)
    return environment


def require_copilot_prompt_mode_boundary(environment: dict[str, str], arguments: list[str]) -> None:
    invalid_environment = [
        name for name, expected in COPILOT_PROMPT_MODE_BOUNDARY.items() if environment.get(name) != expected
    ]
    missing_arguments = [argument for argument in COPILOT_REQUIRED_SAFETY_ARGUMENTS if argument not in arguments]
    if invalid_environment or missing_arguments:
        details = []
        if invalid_environment:
            details.append("environment: " + ", ".join(sorted(invalid_environment)))
        if missing_arguments:
            details.append("arguments: " + ", ".join(missing_arguments))
        raise RuntimeError("Copilot safety boundary: " + "; ".join(details))


def codex_permission_profile_name(state_root: Path) -> str:
    suffix = sha256_text(str(state_root.resolve()))[:16]
    return f"lit-local-review-{suffix}"


def require_codex_permission_profile_version(version: str) -> None:
    match = re.search(r"\b(\d+)\.(\d+)\.(\d+)(?:[-+.\w]*)?\b", version)
    if match is None:
        raise RuntimeError("Codex version cannot prove permission profiles")
    current = tuple(int(value) for value in match.groups())
    if current < (0, 138, 0):
        raise RuntimeError("Codex 0.138.0+ is required")


def verify_codex_permission_profile(
    command: list[str],
    *,
    environment: dict[str, str],
    workspace: Path,
    state_root: Path,
) -> None:
    true_command = shutil.which("true")
    cat_command = shutil.which("cat")
    if true_command is None or cat_command is None:
        raise RuntimeError("Codex self-test requires true and cat")
    profile = codex_permission_profile_name(state_root)
    common = [
        *command,
        "sandbox",
        "--include-managed-config",
        "--permission-profile",
        profile,
        "--cd",
        str(workspace),
        "--",
    ]
    allowed = run(
        [*common, true_command],
        capture=True,
        timeout=30,
        cwd=workspace,
        env=environment,
    )
    if allowed.returncode:
        raise RuntimeError("Codex self-test execution failed")
    workspace_read = run(
        [*common, cat_command, str(workspace / "AGENTS.md")],
        capture=True,
        timeout=30,
        cwd=workspace,
        env=environment,
    )
    if workspace_read.returncode:
        raise RuntimeError("Codex workspace read failed")
    canary = state_root / "codex-denied-read-canary"
    canary.write_text(
        "LIT_CODEX_PERMISSION_PROFILE_CANARY\n",
        encoding="utf-8",
    )
    canary.chmod(0o600)
    try:
        denied = run(
            [*common, cat_command, str(canary)],
            capture=True,
            timeout=30,
            cwd=workspace,
            env=environment,
        )
    finally:
        canary.unlink(missing_ok=True)
    if denied.returncode == 0:
        raise RuntimeError("Codex read escaped workspace")


def resolve_command(command: list[str], name: str) -> list[str]:
    executable = command[0]
    if "/" not in executable and "\\" not in executable:
        resolved = shutil.which(executable)
        if resolved is None:
            raise RuntimeError(f"{name} executable unavailable")
        return [resolved, *command[1:]]
    candidate = Path(executable)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
        current = ROOT
        try:
            relative_parts = candidate.relative_to(ROOT).parts
        except ValueError as exc:
            raise RuntimeError(f"{name} command escapes repository") from exc
        if any(part in {"", ".", ".."} for part in relative_parts):
            raise RuntimeError(f"{name} command path is unsafe")
        for part in relative_parts:
            current /= part
            if current.is_symlink():
                raise RuntimeError(f"{name} command contains symlink")
        try:
            candidate.resolve(strict=True).relative_to(ROOT)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"{name} command unavailable") from exc
    if not candidate.is_file() or candidate.is_symlink():
        raise RuntimeError(f"{name} command unavailable")
    return [str(candidate.resolve()), *command[1:]]


def local_container_environment(environment: dict[str, str], engine: str) -> dict[str, str]:
    result = dict(environment)
    if engine == "docker":
        configured_host = os.environ.get("DOCKER_HOST")
        if configured_host and not configured_host.startswith("unix://"):
            raise RuntimeError("remote DOCKER_HOST is forbidden")
        configured_home = os.environ.get("HOME")
        user_socket = str(Path(configured_home) / ".docker" / "run" / "docker.sock") if configured_home else None
        candidates = (configured_host, user_socket, "/var/run/docker.sock")
        for value in candidates:
            if value and (socket_path := existing_unix_socket(value)):
                result["DOCKER_HOST"] = f"unix://{socket_path}"
                break
    elif runtime_directory := os.environ.get("XDG_RUNTIME_DIR"):
        runtime_path = Path(runtime_directory)
        if runtime_path.is_absolute() and runtime_path.is_dir():
            result["XDG_RUNTIME_DIR"] = str(runtime_path.resolve())
    return result


def copilot_container_command(
    environment: dict[str, str], workspace: Path, *, include_credentials: bool = True
) -> list[str]:
    requested_engine = os.environ.get("WUNDER_CONTAINER_ENGINE")
    if requested_engine and requested_engine not in {"docker", "podman"}:
        raise RuntimeError("invalid WUNDER_CONTAINER_ENGINE")
    engine_names = [requested_engine] if requested_engine else ["docker", "podman"]
    engine = None
    engine_environment = None
    for name in engine_names:
        resolved = shutil.which(name) if name else None
        if resolved is None:
            continue
        engine_candidate_environment = local_container_environment(environment, name)
        probe_environment = {
            key: value for key, value in engine_candidate_environment.items() if key not in COPILOT_TOKEN_NAMES
        }
        try:
            if run([resolved, "info"], capture=True, timeout=30, env=probe_environment).returncode:
                continue
        except subprocess.TimeoutExpired:
            continue
        engine = resolved
        engine_environment = engine_candidate_environment
        break
    if engine is None or engine_environment is None:
        raise RuntimeError("no usable Docker or Podman")
    environment.clear()
    environment.update(engine_environment)
    canonical_workspace = workspace.resolve(strict=True)
    if (
        not canonical_workspace.is_dir()
        or workspace.is_symlink()
        or any(character in str(canonical_workspace) for character in (":", ","))
    ):
        raise RuntimeError("Copilot workspace mount is unsafe")
    workspace_mount = f"{canonical_workspace}:/workspace:ro"
    if Path(engine).name == "podman" and platform.system() == "Linux":
        workspace_mount += ",z"
    command = [
        engine,
        "run",
        "--rm",
        "-i",
        "--network",
        "bridge",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/tmp:rw,exec,nosuid,nodev,size=256m",  # noqa: S108 -- isolated tmpfs mount.
        "--tmpfs",
        "/copilot-cache:rw,exec,nosuid,nodev,size=256m",
        "--tmpfs",
        "/copilot-home:rw,exec,nosuid,nodev,size=256m",
        "--tmpfs",
        "/home/wunder:rw,exec,nosuid,nodev,size=256m,mode=1777",
        "-e",
        "CI=1",
        "-e",
        "HOME=/home/wunder",
        "-e",
        "XDG_CACHE_HOME=/copilot-cache",
        "-e",
        "COPILOT_HOME=/copilot-home",
        "-v",
        workspace_mount,
        "-w",
        "/workspace",
    ]
    if Path(engine).name == "podman":
        command.append("--read-only-tmpfs=false")
    for name, value in COPILOT_PROMPT_MODE_BOUNDARY.items():
        if environment.get(name) != value:
            raise RuntimeError("Copilot prompt boundary lacks " + name)
        command.extend(["-e", f"{name}={value}"])
    if include_credentials:
        for name in COPILOT_TOKEN_NAMES:
            if environment.get(name):
                command.extend(["-e", name])
    command.extend([COPILOT_DEVTOOL_IMAGE, "copilot"])
    return command


def tool_version(
    command: list[str],
    name: str,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> str:
    try:
        result = run(
            [*command, "--version"],
            capture=True,
            timeout=30,
            cwd=cwd,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{name} version check timed out") from exc
    version = result.stdout.strip()
    if result.returncode or not version:
        raise RuntimeError(f"{name} did not report a version")
    return version[:500]


def review_prompt(
    change: PlannedChange,
    *,
    agent: str,
    instructions: str,
    topology: ReviewTopology,
) -> str:
    local_boundary = "Local only; server current-head review and Actions gates remain mandatory."
    task = (
        "Review the exact patch against tracked instructions for correctness, "
        "security, tests, scope, and CI. The verified workspace is history-free; "
        "check dependencies there. Do not modify, use network, or expose credentials."
    )
    if agent == "copilot":
        verdict = f"End exactly {PASS_MARKER!r} only without findings; otherwise {BLOCKED_MARKER!r}."
        prefix = ""
    else:
        verdict = "Use the supplied schema; PASS requires no findings."
        prefix = ""
    return (
        prefix
        + local_boundary
        + "\n\n"
        + task
        + "\n\n"
        + verdict
        + "\n\n"
        + f"Base ref: {change.base_ref}\n"
        + f"Base tip: {change.base_tip}\n"
        + f"Merge-base: {change.base_commit}\n"
        + f"HEAD: {change.head_commit}\n"
        + f"HEAD tree: {topology.head_tree}\n"
        + "HEAD parents: "
        + (" ".join(topology.head_parents) or "(none)")
        + "\n"
        + f"Authoritative base tree: {topology.base_tree}\n"
        + (f"Locally verified review workspace tree: {topology.integration_tree}\n")
        + f"Sanitized workspace root: {topology.workspace_commit}\n"
        + f"Patch SHA-256: {change.diff_sha256}\n"
        + "\n----- BEGIN TRACKED REVIEW INSTRUCTIONS -----\n"
        + instructions
        + "\n----- END TRACKED REVIEW INSTRUCTIONS -----\n"
        + "\n----- BEGIN EXACT PLANNED PUSH PATCH -----\n"
        + change.diff
        + "\n----- END EXACT PLANNED PUSH PATCH -----\n"
    )


def copilot_review(
    config: dict[str, Any],
    change: PlannedChange,
    expected_tree_fingerprint: str,
    *,
    workspace: Path,
    state_root: Path,
    instructions: str,
    topology: ReviewTopology,
) -> dict[str, Any]:
    agent = config["agents"]["copilot"]
    environment = minimal_agent_environment(
        state_root=state_root,
        agent="copilot",
    )
    command = copilot_container_command(environment, workspace)
    version_environment = {name: value for name, value in environment.items() if name not in COPILOT_TOKEN_NAMES}
    container_runtime = Path(command[0]).name
    container_runtime_version = tool_version(
        [command[0]],
        "Copilot container runtime",
        cwd=workspace,
        env=version_environment,
    )
    version = tool_version(
        copilot_container_command(version_environment, workspace, include_credentials=False),
        "Copilot CLI",
        cwd=workspace,
        env=version_environment,
    )
    args = [
        *command,
        *COPILOT_REQUIRED_SAFETY_ARGUMENTS,
        "--no-auto-update",
        "--secret-env-vars=COPILOT_GITHUB_TOKEN,GH_TOKEN,GITHUB_TOKEN,"
        "CODEX_API_KEY,OPENAI_API_KEY,AWS_ACCESS_KEY_ID,"
        "AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN",
    ]
    if agent.get("model"):
        args.extend(["--model", agent["model"]])
    require_copilot_prompt_mode_boundary(environment, args)
    started_at = now_utc()
    started = time.monotonic()
    try:
        result = run(
            args,
            capture=True,
            input_text=review_prompt(
                change,
                agent="copilot",
                instructions=instructions,
                topology=topology,
            ),
            timeout=agent["timeout_seconds"],
            cwd=workspace,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Copilot review timed out: {agent['timeout_seconds']}s") from exc
    completed_at = now_utc()
    review = result.stdout
    final_line = next(
        (line.strip() for line in reversed(review.splitlines()) if line.strip()),
        "",
    )
    if tree_fingerprint() != expected_tree_fingerprint:
        raise RuntimeError("Copilot changed reviewed tree")
    if (
        result.returncode
        or final_line != PASS_MARKER
        or any(line.strip() == BLOCKED_MARKER for line in review.splitlines())
    ):
        print(review)
        raise RuntimeError("Copilot review did not pass")
    if COPILOT_DEVTOOL_IMAGE not in command:
        raise RuntimeError("Copilot image is not pinned")
    print(review)
    return {
        "agent": "copilot",
        "surface": "GitHub Copilot CLI read-only exact-diff review",
        "authoritative_pr_review": False,
        "required": agent["required"],
        "command": (
            "copilot <pinned-devtool-container> -s --no-ask-user "
            "--available-tools=view,grep,glob --allow-tool=read "
            "--deny-tool=write,memory,url,shell"
        ),
        "model": agent.get("model", "cli-default"),
        "execution_mode": "pinned-devtool-container",
        "container_image": COPILOT_DEVTOOL_IMAGE,
        "container_runtime": container_runtime,
        "container_runtime_version": container_runtime_version,
        "tool_version": version,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": sha256_text(review),
        "result": "pass",
    }


def codex_output_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["pass", "blocked"]},
            "summary": {"type": "string"},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["title", "description"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["verdict", "summary", "findings"],
        "additionalProperties": False,
    }


def codex_review(
    config: dict[str, Any],
    change: PlannedChange,
    expected_tree_fingerprint: str,
    *,
    workspace: Path,
    state_root: Path,
    instructions: str,
    topology: ReviewTopology,
) -> dict[str, Any]:
    agent = config["agents"]["codex"]
    command = resolve_command(agent["command"], "Codex CLI")
    environment = minimal_agent_environment(
        state_root=state_root,
        agent="codex",
        workspace=workspace,
    )
    version = tool_version(
        command,
        "Codex CLI",
        cwd=workspace,
        env=environment,
    )
    require_codex_permission_profile_version(version)
    verify_codex_permission_profile(
        command,
        environment=environment,
        workspace=workspace,
        state_root=state_root,
    )
    started_at = now_utc()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(
        prefix="lit-codex-review-",
        dir=state_root,
    ) as temporary:
        temp = Path(temporary)
        schema = temp / "review-schema.json"
        output = temp / "last-message.json"
        schema.write_text(
            json.dumps(codex_output_schema(), sort_keys=True),
            encoding="utf-8",
        )
        args = [
            *command,
            "--strict-config",
            "exec",
            "--ephemeral",
            "--ignore-rules",
            "--color",
            "never",
            "--output-schema",
            str(schema),
            "--output-last-message",
            str(output),
        ]
        if agent.get("model"):
            args.extend(["--model", agent["model"]])
        args.append("-")
        codex_prompt = (
            review_prompt(
                change,
                agent="codex",
                instructions=instructions,
                topology=topology,
            )
            + "\nReturn only a JSON object matching the supplied schema. Use "
            "'pass' with an empty findings array only when the exact patch has "
            "no blocking finding; otherwise use 'blocked' and list findings.\n"
        )
        try:
            result = run(
                args,
                capture=True,
                input_text=codex_prompt,
                timeout=agent["timeout_seconds"],
                cwd=workspace,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Codex review timed out: {agent['timeout_seconds']}s") from exc
        if not output.is_file():
            if result.stdout:
                print(result.stdout)
            raise RuntimeError("Codex output is unstructured")
        raw_review = output.read_text(encoding="utf-8")
    completed_at = now_utc()
    if tree_fingerprint() != expected_tree_fingerprint:
        raise RuntimeError("Codex changed reviewed tree")
    try:
        review = json.loads(raw_review)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Codex output is not JSON") from exc
    valid_shape = (
        isinstance(review, dict)
        and set(review) == {"verdict", "summary", "findings"}
        and isinstance(review.get("summary"), str)
        and isinstance(review.get("findings"), list)
        and all(
            isinstance(finding, dict)
            and set(finding) == {"title", "description"}
            and isinstance(finding.get("title"), str)
            and isinstance(finding.get("description"), str)
            for finding in review.get("findings", [])
        )
    )
    if not valid_shape:
        raise RuntimeError("Codex output schema is invalid")
    if result.returncode or review.get("verdict") != "pass" or review.get("findings") != []:
        print(raw_review)
        raise RuntimeError("Codex review did not pass")
    print(raw_review)
    return {
        "agent": "codex",
        "surface": "Codex CLI exec read-only exact-diff review",
        "authoritative_pr_review": False,
        "required": agent["required"],
        "command": (
            "codex <configured-prefix> exec --ephemeral "
            "--permission-profile local-review --output-schema <schema> "
            "--output-last-message <output> -"
        ),
        "model": agent.get("model", "cli-default"),
        "execution_mode": "host",
        "container_image": None,
        "container_runtime": None,
        "container_runtime_version": None,
        "tool_version": version,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": sha256_text(raw_review),
        "result": "pass",
    }


def run_agent_reviews(
    config: dict[str, Any],
    change: PlannedChange,
    *,
    classification: ReviewClassification | None = None,
    fixture_manifest_bootstrap: bool = False,
) -> list[dict[str, Any]]:
    expected = change.tree_fingerprint
    if tree_fingerprint() != expected:
        raise RuntimeError("exact planned push patch is stale before local review")
    classification = classification or classify_review_profile(change)
    if classification.agents:
        raise RuntimeError("local external AI reviewers are prohibited")
    if any(agent["enabled"] or agent["required"] for agent in config["agents"].values()):
        raise RuntimeError("local external AI reviewers must remain disabled")
    integration_tree = expected_integration_tree(change)
    with sanitized_review_workspace(
        change,
        fixture_manifest_bootstrap=fixture_manifest_bootstrap,
    ) as (workspace, _state_root, topology):
        if topology.integration_tree != integration_tree:
            raise RuntimeError("sanitized workspace has a different integration tree")
        workspace_fingerprint = integration_worktree_fingerprint(
            workspace,
            include_ignored=True,
        )
        if (
            integration_worktree_fingerprint(
                workspace,
                include_ignored=True,
            )
            != workspace_fingerprint
        ):
            raise RuntimeError("deterministic scan changed its sanitized exact-patch workspace")
    if tree_fingerprint() != expected:
        raise RuntimeError("deterministic review scan changed the reviewed Git tree")
    return []


def review_execution_evidence(
    classification: ReviewClassification,
    reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    if not classification.agents:
        if reviews:
            raise RuntimeError("local external AI review evidence is prohibited")
        return {
            "mode": "deterministic-only",
            "maximum_parallelism": 0,
            "reviewers": [],
            "workspace_count": 0,
            "input_sha256": None,
            "overlap_seconds": 0.0,
        }
    if len(reviews) != len(classification.agents):
        raise RuntimeError("review execution has the wrong reviewer count")
    by_name = {review.get("agent"): review for review in reviews if isinstance(review, dict)}
    if set(by_name) != set(classification.agents):
        raise RuntimeError("review execution has invalid reviewer identities")
    workspaces = {review.get("workspace_sha256") for review in reviews}
    inputs = {review.get("input_sha256") for review in reviews}
    if (
        len(workspaces) != len(reviews)
        or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in workspaces)
        or len(inputs) != 1
        or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in inputs)
    ):
        raise RuntimeError("review workspace or input binding is invalid")
    intervals = [
        evidence_interval(
            {
                "started_at": review.get("started_at"),
                "completed_at": review.get("completed_at"),
                "duration_seconds": review.get("duration_seconds"),
            },
            f"{review['agent']} external review",
        )
        for review in reviews
    ]
    overlap = 0.0
    if len(reviews) > 1:
        overlap = (
            min(interval[1] for interval in intervals) - max(interval[0] for interval in intervals)
        ).total_seconds()
        if overlap <= 0:
            raise RuntimeError("required external reviewers did not execute concurrently")
    return {
        "mode": "parallel" if len(reviews) > 1 else "single",
        "maximum_parallelism": len(reviews),
        "reviewers": list(classification.agents),
        "workspace_count": len(reviews),
        "input_sha256": next(iter(inputs)),
        "overlap_seconds": round(overlap, 3),
    }


def execution_metrics(checks: list[dict[str, Any]], reviews: list[dict[str, Any]]) -> dict[str, Any]:
    if reviews:
        raise RuntimeError("local external AI review metrics are prohibited")
    check_names = [str(check.get("name")) for check in checks]
    return {
        "schema_version": 1,
        "check_executions": len(checks),
        "repeated_check_executions": len(check_names) - len(set(check_names)),
        "local_external_review_invocations": 0,
        "local_codex_review_invocations": 0,
        "local_copilot_review_invocations": 0,
        "reviewer_seconds": {},
        "review_serial_seconds": 0.0,
        "review_wall_seconds": 0.0,
        "cache_hits": 0,
        "cache_misses": 0,
        "maximum_parallelism": 0,
    }


def command_version(command: list[str]) -> str:
    try:
        result = run(command, capture=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"tool version check timed out: {command[0]}") from exc
    if result.returncode or not result.stdout.strip():
        raise RuntimeError(f"tool did not report a version: {command[0]}")
    return result.stdout.strip()[:500]


def platform_evidence() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
    }


def runtime_versions() -> dict[str, str]:
    return {
        "git": command_version(["git", "--version"]),
        "python": sys.version.replace("\n", " "),
    }


def governed_push_remote_from_url(name: str, url: str) -> dict[str, str]:
    if name != "origin" or not url or any(ord(character) < 32 or ord(character) == 127 for character in url):
        raise RuntimeError("push-ready requires the governed origin remote")
    value = url[:-4] if url.endswith(".git") else url
    # Preserve the owner in the binding: legacy installations and their exact
    # evidence remain distinct from remotes using the renamed organization.
    prefixes = tuple(
        (owner, prefix)
        for owner in ("ltn-it", "lightning-it")
        for prefix in (
            f"https://github.com/{owner}/",
            f"ssh://git@github.com/{owner}/",
            f"git@github.com:{owner}/",
        )
    )
    repository_owner = ""
    repository_name = ""
    for owner, prefix in prefixes:
        if value.startswith(prefix):
            repository_owner = owner
            repository_name = value[len(prefix) :]
            break
    if repository_name != ".github" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository_name):
        raise RuntimeError("origin push URL must target a Lightning IT repository on github.com")
    return {
        "name": "origin",
        "host": "github.com",
        "repository": f"{repository_owner}/{repository_name}",
        "url_sha256": sha256_text(url),
    }


def governed_push_remote() -> dict[str, str]:
    url = git_output("remote", "get-url", "--push", "origin").strip()
    return governed_push_remote_from_url("origin", url)


def config_sha256() -> str:
    return sha256_bytes(CONFIG.read_bytes())


def review_input_sha256(
    change: PlannedChange,
    integration_tree: str,
    instruction_files: dict[str, str],
    classification: ReviewClassification,
) -> str:
    return sha256_text(
        json.dumps(
            [
                change.base_ref,
                change.base_tip,
                change.base_commit,
                change.head_commit,
                change.tree_fingerprint,
                integration_tree,
                change.diff_sha256,
                instruction_files,
                review_classification_evidence(classification),
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def write_evidence(
    config: dict[str, Any],
    checks: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    change: PlannedChange,
    *,
    started_at: str,
    started_monotonic: float,
    integration_tree: str,
    integration_commit: str,
    integration_fingerprint: str,
    classification: ReviewClassification,
    fixture_manifest_bootstrap: bool = False,
) -> None:
    if not isinstance(fixture_manifest_bootstrap, bool):
        raise RuntimeError("secret fixture bootstrap evidence flag is invalid")
    if tree_fingerprint() != change.tree_fingerprint:
        raise RuntimeError("patch is stale before evidence write")
    completed_at = now_utc()
    payload = {
        "version": 3,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": round(time.monotonic() - started_monotonic, 3),
        "base_ref": change.base_ref,
        "base_tip": change.base_tip,
        "base_commit": change.base_commit,
        "head_commit": change.head_commit,
        "local_branch_ref": current_branch_ref(),
        "tree_fingerprint": change.tree_fingerprint,
        "integration_tree": integration_tree,
        "integration_commit": integration_commit,
        "integration_fingerprint": integration_fingerprint,
        "planned_diff_sha256": change.diff_sha256,
        "review_size": review_size_evidence(config, change),
        "planned_paths": list(change.paths),
        "untracked_sha256": change.untracked_sha256,
        "config_sha256": config_sha256(),
        "instruction_files": instruction_file_hashes(),
        "platform": platform_evidence(),
        "runtime_versions": runtime_versions(),
        "push_remote": governed_push_remote(),
        "checks": checks,
        "agent_reviews": reviews,
        "review_classification": review_classification_evidence(classification),
        "review_execution": review_execution_evidence(classification, reviews),
        "metrics": execution_metrics(checks, reviews),
        "local_ai_egress": "prohibited",
        "remote_only_checks": config["remote_only_checks"],
        "parity_gaps": list(PARITY_GAPS),
        "remote_pr_review_authoritative": True,
        "push_scope": "clean-head",
        "fixture_manifest_bootstrap": fixture_manifest_bootstrap,
        "trust_root_bootstrap": require_review_bootstrap_contract(change),
        "evidence_trust": LOCAL_EVIDENCE_TRUST,
    }
    write_evidence_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def parse_timestamp(value: Any, description: str) -> datetime:
    if not isinstance(value, str):
        raise RuntimeError(f"evidence {description} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"evidence {description} is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeError(f"evidence {description} has no timezone")
    return parsed


def evidence_interval(
    record: dict[str, Any],
    description: str,
    bounds: tuple[datetime, datetime] | None = None,
) -> tuple[datetime, datetime]:
    started = parse_timestamp(record.get("started_at"), f"{description} started_at")
    completed = parse_timestamp(record.get("completed_at"), f"{description} completed_at")
    duration = record.get("duration_seconds")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        duration = -1
    if (
        duration < 0
        or started > completed
        or abs((completed - started).total_seconds() - duration) > 5
        or (bounds is not None and (started < bounds[0] or completed > bounds[1]))
    ):
        raise RuntimeError(f"evidence has invalid timing for {description}")
    return started, completed


def verify_evidence(config: dict[str, Any]) -> dict[str, Any]:
    evidence = evidence_path()
    if not evidence.is_file() or evidence.is_symlink():
        raise RuntimeError("evidence is not a regular file")
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 3:
        raise RuntimeError("evidence must use version 3")
    started, completed = evidence_interval(payload, "run")
    age = (datetime.now(UTC) - completed).total_seconds()
    max_age = config["evidence"]["max_age_seconds"]
    if age < -300 or age > max_age:
        raise RuntimeError(f"evidence exceeds age {max_age}")
    fixture_manifest_bootstrap = payload.get("fixture_manifest_bootstrap")
    if not isinstance(fixture_manifest_bootstrap, bool):
        raise RuntimeError("evidence fixture bootstrap is invalid")
    trust_root_bootstrap = payload.get("trust_root_bootstrap")
    if not isinstance(trust_root_bootstrap, bool):
        raise RuntimeError("evidence trust-root bootstrap is invalid")
    change = planned_change(
        config,
        fixture_manifest_bootstrap=fixture_manifest_bootstrap,
    )
    classification = classify_review_profile(change)
    if require_review_bootstrap_contract(change) is not trust_root_bootstrap:
        raise RuntimeError("evidence trust-root bootstrap is stale")
    if not trust_root_bootstrap:
        require_trusted_check_policy(change, allow_fixture_manifest_bootstrap=fixture_manifest_bootstrap)
    expected_integration = expected_integration_tree(change)
    expected = {
        "config_sha256": config_sha256(),
        "instruction_files": instruction_file_hashes(),
        "base_ref": change.base_ref,
        "base_tip": change.base_tip,
        "base_commit": change.base_commit,
        "head_commit": change.head_commit,
        "local_branch_ref": current_branch_ref(),
        "tree_fingerprint": change.tree_fingerprint,
        "integration_tree": expected_integration,
        "integration_commit": synthetic_integration_commit(
            change,
            expected_integration,
        ),
        "planned_diff_sha256": change.diff_sha256,
        "review_size": review_size_evidence(config, change),
        "planned_paths": list(change.paths),
        "untracked_sha256": change.untracked_sha256,
        "platform": platform_evidence(),
        "runtime_versions": runtime_versions(),
        "push_remote": governed_push_remote(),
        "remote_only_checks": config["remote_only_checks"],
        "review_classification": review_classification_evidence(classification),
        "parity_gaps": list(PARITY_GAPS),
        "remote_pr_review_authoritative": True,
        "push_scope": "clean-head",
        "fixture_manifest_bootstrap": fixture_manifest_bootstrap,
        "trust_root_bootstrap": trust_root_bootstrap,
        "evidence_trust": LOCAL_EVIDENCE_TRUST,
        "local_ai_egress": "prohibited",
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise RuntimeError(f"evidence is stale or malformed: {key}")
    integration_fingerprint = payload.get("integration_fingerprint")
    if not isinstance(integration_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", integration_fingerprint):
        raise RuntimeError("evidence integration fingerprint is invalid")
    checks = payload.get("checks")
    if not isinstance(checks, list) or len(checks) != len(config["checks"]):
        raise RuntimeError("evidence skipped a required check")
    review_binding = review_input_sha256(
        change,
        expected_integration,
        expected["instruction_files"],
        classification,
    )
    # Length equality is enforced above; strict= is unavailable on Python 3.9.
    for configured, recorded in zip(config["checks"], checks):  # noqa: B905
        expected_command = (
            [sys.executable, *configured["command"][1:]]
            if configured["command"][0] in {"python", "python3"}
            else configured["command"]
        )
        if (
            not isinstance(recorded, dict)
            or recorded.get("name") != configured["name"]
            or recorded.get("command") != expected_command
            or recorded.get("exit_code") != 0
        ):
            raise RuntimeError(f"evidence lacks passing check {configured['name']}")
        evidence_interval(recorded, f"check {configured['name']}", (started, completed))
    reviews = payload.get("agent_reviews")
    if not isinstance(reviews, list):
        raise RuntimeError("evidence agent reviews are invalid")
    by_name = {review.get("agent"): review for review in reviews if isinstance(review, dict)}
    enabled_agents = set(classification.agents)
    if len(by_name) != len(reviews) or set(by_name) != enabled_agents:
        raise RuntimeError("evidence agent reviews are incomplete")
    for name in classification.agents:
        agent = config["agents"][name]
        review = by_name.get(name)
        if (
            not isinstance(review, dict)
            or review.get("result") != "pass"
            or review.get("required") is not agent["required"]
            or not isinstance(review.get("tool_version"), str)
            or not review.get("tool_version")
            or review.get("authoritative_pr_review") is not False
            or not isinstance(review.get("output_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", review["output_sha256"])
            or review.get("input_sha256") != review_binding
            or not isinstance(review.get("workspace_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", review["workspace_sha256"])
        ):
            raise RuntimeError(f"evidence lacks passing {name} review")
        execution_mode = review.get("execution_mode")
        if name == "copilot":
            if execution_mode != "pinned-devtool-container":
                raise RuntimeError("invalid Copilot execution mode")
            if (
                review.get("container_image") != COPILOT_DEVTOOL_IMAGE
                or review.get("container_runtime") not in {"docker", "podman"}
                or not isinstance(review.get("container_runtime_version"), str)
                or not review.get("container_runtime_version")
            ):
                raise RuntimeError("invalid Copilot container binding")
        elif (
            execution_mode != "host"
            or review.get("container_image") is not None
            or review.get("container_runtime") is not None
            or review.get("container_runtime_version") is not None
        ):
            raise RuntimeError("invalid Codex execution mode")
        evidence_interval(review, f"{name} review", (started, completed))
        evidence_interval(
            {
                "started_at": review.get("worker_started_at"),
                "completed_at": review.get("worker_completed_at"),
                "duration_seconds": review.get("worker_duration_seconds"),
            },
            f"{name} review worker",
            (started, completed),
        )
    if payload.get("review_execution") != review_execution_evidence(classification, reviews):
        raise RuntimeError("push-ready evidence has invalid review execution")
    if payload.get("metrics") != execution_metrics(checks, reviews):
        raise RuntimeError("push-ready evidence has invalid execution metrics")
    return payload


def verify_pre_push_updates(
    payload: dict[str, Any],
    hook_input: str,
    *,
    remote_name: str,
    remote_url: str,
) -> None:
    supplied_remote = governed_push_remote_from_url(remote_name, remote_url)
    if payload.get("push_remote") != supplied_remote:
        raise RuntimeError("pre-push remote differs from evidence")
    updates = [line for line in hook_input.splitlines() if line.strip()]
    if not updates:
        raise RuntimeError("pre-push update input is missing")
    if len(updates) != 1:
        raise RuntimeError(
            "push-ready evidence authorizes exactly one branch update; push "
            "tags, notes, releases, and additional branches separately"
        )
    expected_head = payload.get("head_commit")
    expected_branch = payload.get("local_branch_ref")
    for line in updates:
        fields = line.split()
        if len(fields) != 4:
            raise RuntimeError("malformed pre-push input")
        local_ref, local_oid, remote_ref, remote_oid = fields
        if (
            local_ref != expected_branch
            or remote_ref != expected_branch
            or not local_ref.startswith("refs/heads/")
            or not is_full_git_object_id(local_oid)
            or not is_full_git_object_id(remote_oid)
        ):
            raise RuntimeError("unsafe pre-push ref update")
        if set(local_oid) == {"0"}:
            raise RuntimeError("evidence forbids ref deletion")
        creates_remote_branch = set(remote_oid) == {"0"}
        pushed_commit = git_output(
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{local_oid}^{{commit}}",
        ).strip()
        if pushed_commit != expected_head:
            raise RuntimeError("pre-push head is not bound")
        if not creates_remote_branch:
            ancestry = run(
                ["git", "merge-base", "--is-ancestor", remote_oid, local_oid],
                capture=True,
            )
            if ancestry.returncode:
                raise RuntimeError("evidence forbids non-fast-forward push")


def install_pre_push_hook() -> None:
    hooks = Path(git_output("rev-parse", "--git-path", "hooks").strip())
    if not hooks.is_absolute():
        hooks = ROOT / hooks
    payload = (
        b'#!/bin/sh\nexec python3 "$(git rev-parse --show-toplevel)/scripts/lit-push-ready.py" pre-push '
        b'--remote-name "$1" --remote-url "$2"\n'
    )
    directory = os.open(hooks, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = -1
    try:
        try:
            existing = os.stat("pre-push", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            descriptor = os.open(
                "pre-push",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o700,
                dir_fd=directory,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        else:
            if not stat.S_ISREG(existing.st_mode) or existing.st_uid != os.geteuid():
                raise RuntimeError("unsafe hook")
            with os.fdopen(
                os.open("pre-push", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory),
                "rb",
            ) as stream:
                if stream.read(len(payload) + 1) != payload or not existing.st_mode & 0o111:
                    raise RuntimeError("pre-push hook differs")
    except OSError as exc:
        raise RuntimeError("hook install failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def verified_diff_sha256(change: PlannedChange) -> str:
    if change.patch is None:
        raise RuntimeError("planned patch has not been materialized")
    digest = hashlib.sha256()
    # Exhaust the stream so PatchSpool also verifies its cached size and digest.
    for chunk in patch_chunks(change.patch):
        digest.update(chunk.encode("utf-8"))
    return digest.hexdigest()


def produce_evidence(
    config: dict[str, Any],
    change: PlannedChange,
    *,
    fixture_manifest_bootstrap: bool,
) -> None:
    require_trusted_review_policy(
        change,
        allow_fixture_manifest_bootstrap=fixture_manifest_bootstrap,
    )
    branch = current_branch_ref()
    started_at, started = now_utc(), time.monotonic()
    checks, tree, commit, fingerprint = execute_integration_checks(config, change)
    require_clean_head()
    if (
        git_output("rev-parse", "HEAD").strip() != change.head_commit
        or current_branch_ref() != branch
        or tree_fingerprint() != change.tree_fingerprint
    ):
        raise RuntimeError("checks changed branch or tree")
    current = planned_change(config, fixture_manifest_bootstrap=fixture_manifest_bootstrap)
    if current._replace(patch=None) != change._replace(patch=None) or verified_diff_sha256(
        current
    ) != verified_diff_sha256(change):
        raise RuntimeError("change binding drifted")
    classification = classify_review_profile(current)
    print(f"Review profile: {classification.profile} ({classification.reason})", flush=True)
    reviews = run_agent_reviews(
        config,
        current,
        classification=classification,
        fixture_manifest_bootstrap=fixture_manifest_bootstrap,
    )
    install_pre_push_hook()
    write_evidence(
        config,
        checks,
        reviews,
        current,
        started_at=started_at,
        started_monotonic=started,
        integration_tree=tree,
        integration_commit=commit,
        integration_fingerprint=fingerprint,
        classification=classification,
        fixture_manifest_bootstrap=fixture_manifest_bootstrap,
    )
    verify_evidence(config)
    print(f"Push-ready evidence: {evidence_path()}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "instructions",
            "validate",
            "review",
            "push-ready",
            "verify",
            "pre-push",
            "sync-instructions",
        ),
    )
    parser.add_argument(
        "--base",
        help="diagnostic review base",
    )
    parser.add_argument(
        "--remote-name",
        help="pre-push remote name",
    )
    parser.add_argument(
        "--remote-url",
        help="pre-push remote URL",
    )
    parser.add_argument(
        "--bootstrap-secret-fixtures",
        dest="fixture_manifest_bootstrap",
        action="store_true",
        help="review a bounded secret-fixture bootstrap",
    )
    parser.add_argument("--trust-root-update", action="store_true", help="review an existing trust-root update")
    args = parser.parse_args()
    try:
        if args.base and args.command != "review":
            raise RuntimeError("--base requires review")
        if args.fixture_manifest_bootstrap and args.command not in {
            "review",
            "push-ready",
        }:
            raise RuntimeError("fixture bootstrap requires review or push-ready")
        if args.fixture_manifest_bootstrap and args.base:
            raise RuntimeError("fixture bootstrap cannot override base")
        if args.trust_root_update and (args.command != "review" or args.base or args.fixture_manifest_bootstrap):
            raise RuntimeError("trust-root update requires review without another mode")
        if args.command == "sync-instructions":
            sync_instructions()
            return 0
        check_instruction_contract()
        if args.command == "instructions":
            return 0
        config = load_config()
        if args.command == "verify":
            verify_evidence(config)
            print(f"Verified push-ready evidence: {evidence_path()}")
            return 0
        if args.command == "pre-push":
            if not args.remote_name or not args.remote_url:
                raise RuntimeError("pre-push requires the native Git hook arguments")
            require_clean_head()
            refresh_authoritative_base(config)
            payload = verify_evidence(config)
            verify_pre_push_updates(
                payload,
                sys.stdin.read(),
                remote_name=args.remote_name,
                remote_url=args.remote_url,
            )
            print(f"Verified push-ready evidence: {evidence_path()}")
            return 0
        if args.command == "validate":
            require_clean_head()
            refresh_authoritative_base(config)
            change = planned_change(config)
            report_review_size(config, change)
            require_review_bootstrap_contract(change)
            classification = classify_review_profile(change)
            print(f"Review profile: {classification.profile} ({classification.reason})", flush=True)
            if classification.profile == "standard":
                require_trusted_check_policy(change)
            execute_integration_checks(config, change)
            return 0
        if args.command == "review":
            require_clean_head()
            if not args.base:
                refresh_authoritative_base(config)
            change = planned_change(
                config,
                base_override=args.base,
                fixture_manifest_bootstrap=args.fixture_manifest_bootstrap,
            )
            report_review_size(config, change)
            require_review_bootstrap_contract(change)
            if args.trust_root_update:
                require_trust_root_update_contract(change)
                classification = classify_review_profile(change)
                print(f"Review profile: {classification.profile} ({classification.reason})", flush=True)
                run_agent_reviews(config, change, classification=classification)
            elif args.base:
                classification = classify_review_profile(change)
                print(f"Review profile: {classification.profile} ({classification.reason})", flush=True)
                run_agent_reviews(
                    config,
                    change,
                    classification=classification,
                    fixture_manifest_bootstrap=args.fixture_manifest_bootstrap,
                )
            else:
                produce_evidence(config, change, fixture_manifest_bootstrap=args.fixture_manifest_bootstrap)
            return 0
        require_clean_head()
        refresh_authoritative_base(config)
        change = planned_change(
            config,
            fixture_manifest_bootstrap=args.fixture_manifest_bootstrap,
        )
        report_review_size(config, change)
        produce_evidence(config, change, fixture_manifest_bootstrap=args.fixture_manifest_bootstrap)
        return 0
    except (
        OSError,
        RuntimeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"push-ready: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
