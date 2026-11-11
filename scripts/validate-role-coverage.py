#!/usr/bin/env python3
"""Validate and render the authoritative role quality coverage registry."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = Path("meta/role-coverage.yml")
DOC_PATH = Path("docs/testing/role-coverage.md")
MATRIX_PATH = Path("docs/testing/generated/role-coverage-matrix.json")
README_PATH = Path("README.md")
AAP_OVERLAY_PATH = Path("collections/requirements-rh.yml")
README_TABLE_MARKERS = (
    "<!-- role-coverage-table:start -->",
    "<!-- role-coverage-table:end -->",
)
PROFILES = ("tiny", "heavy", "application_acceptance")
PROFILE_LABELS = {
    "tiny": "Tiny",
    "heavy": "Heavy",
    "application_acceptance": "Application Acceptance",
}
REQUIRED_PROFILE_STATES = {
    "supported",
    "experimental",
    "not-applicable",
    "blocked-external-service",
    "blocked-external-license",
    "blocked-external-infrastructure",
    "deprecated",
}
REQUIRED_ROLE_FIELDS = {
    "component",
    "classification",
    "maturity",
    "supported_targets",
    "candidate_targets",
    "tiny",
    "heavy",
    "application_acceptance",
    "acceptance_surface",
    "dependencies",
    "external_dependencies",
    "known_limitations",
    "deprecation_state",
    "scenario_support",
}
REQUIRED_SCENARIO_FIELDS = {
    "profile",
    "state",
    "implementation",
    "roles",
    "junit",
    "allure",
    "evidence",
    "test_application",
}
IMPLEMENTATIONS = {"real", "partial", "stub", "skip", "deprecation-contract"}
MATURITIES = {"production", "experimental", "deprecated"}
DEPRECATION_STATES = {"active", "deprecated"}
TEST_APPLICATION_MODES = {"runtime-container", "declared-evidence", "not-applicable"}
TEST_APPLICATION_TYPES = {"application", "external-api", "host-package", "host-service"}
TEST_APPLICATION_POLICY_FIELDS = {"mode", "reason", "dependencies"}
TEST_APPLICATION_DEPENDENCY_FIELDS = {"type", "name", "version", "evidence_path"}
TEST_APPLICATION_DEPENDENCY_OPTIONAL_FIELDS = {"digest"}
MUTABLE_TEST_APPLICATION_VERSIONS = {
    "latest",
    "n/a",
    "not-applicable",
    "unknown",
    "unversioned",
    "unspecified",
}
GOVERNANCE_MARKERS = (
    "<!-- role-quality-governance:start -->",
    "<!-- role-quality-governance:end -->",
)
GOVERNANCE_TOKENS = (
    "meta/role-coverage.yml",
    "tiny",
    "heavy",
    "application acceptance",
    "evidence",
    "release",
)
GALAXY_TARGETS = {
    "rhel-8": ("EL", "8"),
    "rhel-9": ("EL", "9"),
    "rhel-10": ("EL", "10"),
    "ubuntu-22.04": ("Ubuntu", "jammy"),
    "ubuntu-24.04": ("Ubuntu", "noble"),
}
SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
SAFE_ROLE = re.compile(r"[a-z][a-z0-9_]{0,62}")
SAFE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}")
SAFE_IMAGE_VARIABLE = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
SAFE_RUNNER_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
SAFE_APPLICATION_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,127}")
SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
APPROVED_RUNNER_SETS = {
    ("self-hosted", "linux", "x64", "incus"),
    ("self-hosted", "linux", "x64", "incus", "keycloak-test"),
}
IMPORT_PLAYBOOK_KEYS = {"ansible.builtin.import_playbook", "import_playbook"}
ROLE_ACTION_KEYS = {
    "ansible.builtin.import_role",
    "ansible.builtin.include_role",
    "import_role",
    "include_role",
}
TASK_CONTAINER_KEYS = {"always", "block", "post_tasks", "pre_tasks", "tasks"}
FORBIDDEN_SUPPORTED_MARKERS = (
    "deprecated_refusal",
    "fake_runtime",
    "skip_mode",
    "syntax_stub",
)
REQUIRED_LIFECYCLE_PHASES = {
    "tiny": ("dependency", "syntax", "create", "converge", "idempotence", "verify", "cleanup", "destroy"),
    "heavy": (
        "dependency",
        "syntax",
        "create",
        "prepare",
        "converge",
        "idempotence",
        "verify",
        "cleanup",
        "destroy",
    ),
    "application_acceptance": (
        "dependency",
        "syntax",
        "create",
        "prepare",
        "converge",
        "verify",
        "cleanup",
        "destroy",
    ),
}
MARKER_ONLY_ACTIONS = {"assert", "copy", "debug", "file", "set_fact", "slurp", "stat"}
EVIDENCE_CLEANUP_ACTIONS = {
    "archive",
    "assemble",
    "copy",
    "fetch",
    "import_tasks",
    "include_tasks",
    "synchronize",
    "template",
}
NOOP_COMMANDS = {":", "echo", "false", "printf", "true"}
SUBSTANTIVE_VERIFY_ACTIONS = {
    "assert",
    "command",
    "fail",
    "get_url",
    "package_facts",
    "service_facts",
    "shell",
    "slurp",
    "stat",
    "uri",
    "wait_for",
}
EVIDENCE_SOURCE_ACTIONS = {
    "archive",
    "assemble",
    "command",
    "fetch",
    "get_url",
    "shell",
    "slurp",
    "synchronize",
    "uri",
}
NONPRODUCTION_SUPPORT_CLAIM = re.compile(
    r"(?i)\b(?:is|provides)\s+(?:the|a)\s+supported\b|"
    r"\b(?:production[- ]supported|supported\s+(?:deployment|upgrade|backup|restore|platform|target|path))\b"
)
EXTERNAL_AAP_COLLECTION_PREFIXES = {"ansible", "infra"}
EXCLUDED_AAP_COLLECTIONS = {
    "ansible.builtin",
    # Supplied inside the entitled AAP installer bundle, not as an EE overlay.
    "ansible.containerized_installer",
}
IMMUTABLE_COLLECTION_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")


def load_registry(root: Path = ROOT) -> dict[str, Any]:
    path = root / REGISTRY_PATH
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"missing registry: {path}") from error
    except yaml.YAMLError as error:
        raise ValueError(f"invalid YAML in {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"registry root must be a mapping: {path}")
    return payload


def discovered_roles(root: Path) -> set[str]:
    roles_root = root / "roles"
    return {path.name for path in roles_root.iterdir() if path.is_dir()}


def discovered_scenarios(root: Path) -> set[str]:
    molecule_root = root / "molecule"
    return {path.name for path in molecule_root.iterdir() if path.is_dir() and (path / "molecule.yml").is_file()}


def role_local_scenarios(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in (root / "roles").glob("*/molecule/*/molecule.yml"))


def _require_string_list(value: Any, field: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        errors.append(f"{field} must be a list of strings")
        return []
    if len(value) != len(set(value)):
        errors.append(f"{field} contains duplicate values")
    return value


def _set_difference_message(label: str, expected: set[str], actual: set[str]) -> list[str]:
    errors: list[str] = []
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(f"{label} missing entries: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} references missing filesystem entries: {', '.join(extra)}")
    return errors


def _scenario_has_verify(root: Path, scenario: str, errors: list[str]) -> None:
    scenario_root = root / "molecule" / scenario
    if not (scenario_root / "verify.yml").is_file():
        errors.append(f"scenario {scenario} is missing verify.yml")
    try:
        config = yaml.safe_load((scenario_root / "molecule.yml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as error:
        errors.append(f"scenario {scenario} has unreadable molecule.yml: {error}")
        return
    sequence = (config.get("scenario") or {}).get("test_sequence")
    if not isinstance(sequence, list) or "verify" not in sequence:
        errors.append(f"scenario {scenario} must include verify in scenario.test_sequence")


def _walk_mappings(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk_mappings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_mappings(item)


def _walk_task_mappings(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from _walk_task_mappings(item)
        return
    if not isinstance(value, dict):
        return
    if "hosts" not in value:
        yield value
    for key in TASK_CONTAINER_KEYS:
        if key in value:
            yield from _walk_task_mappings(value[key])


def _display_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _resolve_repository_path(root: Path, parent: Path, value: Any, errors: list[str], label: str) -> Path | None:
    if not isinstance(value, str) or not value.strip() or "{{" in value or "${" in value:
        errors.append(f"{label} must use a static repository-relative playbook path")
        return None
    path = (parent / value).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        errors.append(f"{label} escapes the repository: {value}")
        return None
    return path


def _load_playbook_graph(
    root: Path,
    entrypoint: Path,
    errors: list[str],
    *,
    seen: set[Path] | None = None,
) -> list[tuple[Path, Any, str]]:
    seen = seen if seen is not None else set()
    entrypoint = entrypoint.resolve()
    if entrypoint in seen:
        return []
    seen.add(entrypoint)
    display = _display_path(root, entrypoint)
    try:
        raw = entrypoint.read_text(encoding="utf-8")
        document = yaml.safe_load(raw) or []
    except FileNotFoundError:
        errors.append(f"supported scenario playbook is missing: {display}")
        return []
    except (OSError, yaml.YAMLError) as error:
        errors.append(f"supported scenario playbook is unreadable: {display}: {error}")
        return []

    records = [(entrypoint, document, raw)]
    for mapping in _walk_mappings(document):
        for key in IMPORT_PLAYBOOK_KEYS:
            if key not in mapping:
                continue
            imported = _resolve_repository_path(
                root,
                entrypoint.parent,
                mapping[key],
                errors,
                f"{display} {key}",
            )
            if imported is not None:
                records.extend(_load_playbook_graph(root, imported, errors, seen=seen))
    return records


def _literal_boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"false", "no", "off", "0"}:
            return False
        if normalized in {"true", "yes", "on", "1"}:
            return True
    return None


def _condition_is_statically_false(value: Any, variables: dict[str, Any]) -> bool:
    literal = _literal_boolean(value)
    if literal is not None:
        return not literal
    if isinstance(value, list):
        return any(_condition_is_statically_false(item, variables) for item in value)
    if not isinstance(value, str):
        return False

    expression = value.strip()
    while expression.startswith("(") and expression.endswith(")"):
        depth = 0
        wraps_expression = True
        for index, character in enumerate(expression):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            if depth == 0 and index < len(expression) - 1:
                wraps_expression = False
                break
        if not wraps_expression or depth != 0:
            break
        expression = expression[1:-1].strip()
    defaulted = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*\|\s*default\(\s*(false|true)"
        r"(?:\s*,\s*(false|true))?\s*\)\s*(?:\|\s*bool)?",
        expression,
        flags=re.IGNORECASE,
    )
    if defaulted:
        resolved = _literal_boolean(variables.get(defaulted.group(1)))
        use_default_for_false = defaulted.group(3) is not None and defaulted.group(3).lower() == "true"
        if resolved is None or (resolved is False and use_default_for_false):
            resolved = defaulted.group(2).lower() == "true"
        return resolved is False
    direct = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\|\s*bool)?", expression)
    if direct:
        resolved = _literal_boolean(variables.get(direct.group(1)))
        return resolved is False
    negated = re.fullmatch(r"not\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\|\s*bool)?", expression)
    if negated:
        resolved = _literal_boolean(variables.get(negated.group(1)))
        return resolved is True
    comparison = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|is)\s*(false|true)",
        expression,
        flags=re.IGNORECASE,
    )
    if comparison:
        resolved = _literal_boolean(variables.get(comparison.group(1)))
        expected = comparison.group(2).lower() == "true"
        return resolved is not None and resolved != expected
    return False


def _normalize_role_name(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("role") or value.get("name")
    if not isinstance(value, str) or "{{" in value:
        return None
    return value.strip().split(".")[-1] or None


def _collect_active_roles(
    value: Any,
    variables: dict[str, Any] | None = None,
    *,
    disabled: bool = False,
) -> set[str]:
    variables = dict(variables or {})
    roles: set[str] = set()
    if isinstance(value, list):
        for item in value:
            roles.update(_collect_active_roles(item, variables, disabled=disabled))
        return roles
    if not isinstance(value, dict):
        return roles

    local_variables = dict(variables)
    declared_variables = value.get("vars")
    if isinstance(declared_variables, dict):
        local_variables.update({str(key): item for key, item in declared_variables.items()})
    locally_disabled = disabled or _condition_is_statically_false(value.get("when"), local_variables)

    declared_roles = value.get("roles") if "hosts" in value else None
    if isinstance(declared_roles, list):
        for role_item in declared_roles:
            role_disabled = locally_disabled
            if isinstance(role_item, dict):
                role_disabled = role_disabled or _condition_is_statically_false(role_item.get("when"), local_variables)
            role_name = _normalize_role_name(role_item)
            if role_name and not role_disabled:
                roles.add(role_name)

    for action in ROLE_ACTION_KEYS:
        if action not in value:
            continue
        role_name = _normalize_role_name(value[action])
        if role_name and not locally_disabled:
            roles.add(role_name)

    for key in TASK_CONTAINER_KEYS:
        if key in value:
            roles.update(_collect_active_roles(value[key], local_variables, disabled=locally_disabled))
    return roles


def _collect_reachable_playbook_roles(
    root: Path,
    entrypoint: Path,
    records: list[tuple[Path, Any, str]],
    errors: list[str],
    variables: dict[str, Any] | None = None,
    *,
    disabled: bool = False,
    stack: set[Path] | None = None,
) -> set[str]:
    entrypoint = entrypoint.resolve()
    stack = set(stack or ())
    if entrypoint in stack:
        return set()
    stack.add(entrypoint)
    documents = {record[0].resolve(): record[1] for record in records}
    document = documents.get(entrypoint)
    if document is None:
        return set()

    inherited_variables = dict(variables or {})
    roles = _collect_active_roles(document, inherited_variables, disabled=disabled)
    statements = document if isinstance(document, list) else []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        import_variables = dict(inherited_variables)
        declared_variables = statement.get("vars")
        if isinstance(declared_variables, dict):
            import_variables.update({str(key): value for key, value in declared_variables.items()})
        import_disabled = disabled or _condition_is_statically_false(statement.get("when"), import_variables)
        for key in IMPORT_PLAYBOOK_KEYS:
            if key not in statement:
                continue
            imported = _resolve_repository_path(
                root,
                entrypoint.parent,
                statement[key],
                errors,
                f"{_display_path(root, entrypoint)} {key}",
            )
            if imported is not None:
                roles.update(
                    _collect_reachable_playbook_roles(
                        root,
                        imported,
                        records,
                        errors,
                        import_variables,
                        disabled=import_disabled,
                        stack=stack,
                    )
                )
    return roles


def _ordered_subsequence(required: tuple[str, ...], actual: list[Any]) -> bool:
    position = 0
    for phase in actual:
        if position < len(required) and phase == required[position]:
            position += 1
    return position == len(required)


def _configured_playbook(
    root: Path,
    scenario_root: Path,
    config: dict[str, Any],
    phase: str,
    errors: list[str],
    *,
    required_configuration: bool = False,
) -> Path | None:
    provisioner = config.get("provisioner") or {}
    playbooks = provisioner.get("playbooks") if isinstance(provisioner, dict) else {}
    playbooks = playbooks if isinstance(playbooks, dict) else {}
    configured = playbooks.get(phase)
    if configured is None and required_configuration:
        errors.append(f"supported scenario {scenario_root.name} must configure a {phase} playbook")
        return None
    value = configured if configured is not None else f"{phase}.yml"
    return _resolve_repository_path(
        root,
        scenario_root,
        value,
        errors,
        f"supported scenario {scenario_root.name} {phase}",
    )


def _supported_forbidden_constructs(
    records: list[tuple[Path, Any, str]],
    root: Path,
    scenario: str,
    reported_roles: list[str],
) -> list[str]:
    errors: list[str] = []
    bypass_names = {
        f"{role}_{suffix}" for role in reported_roles for suffix in ("skip_apply", "skip_deploy", "skip_runtime")
    }
    execute_role = re.compile(r"[A-Za-z0-9_]+_molecule_execute_role$")
    for path, document, _raw in records:
        display = _display_path(root, path)
        lowered = yaml.safe_dump(document, sort_keys=True).lower()
        for marker in FORBIDDEN_SUPPORTED_MARKERS:
            if marker in lowered:
                errors.append(f"supported scenario {scenario} contains forbidden marker {marker!r} in {display}")
        for mapping in _walk_mappings(document):
            if "when" in mapping and _condition_is_statically_false(mapping["when"], {}):
                errors.append(f"supported scenario {scenario} contains literal when: false in {display}")
            for key, value in mapping.items():
                name = str(key)
                boolean = _literal_boolean(value)
                if execute_role.fullmatch(name) and boolean is False:
                    errors.append(f"supported scenario {scenario} disables role execution with {name} in {display}")
                if name in bypass_names and boolean is True:
                    errors.append(f"supported scenario {scenario} enables reported-role bypass {name} in {display}")
    return errors


def _marker_only_verify(records: list[tuple[Path, Any, str]]) -> bool:
    raw = "\n".join(yaml.safe_dump(record[1], sort_keys=True) for record in records).lower()
    actions = {
        str(key).rsplit(".", maxsplit=1)[-1]
        for record in records
        for document in (record[1],)
        for mapping in _walk_task_mappings(document)
        for key in mapping
        if str(key).startswith("ansible.builtin.") or str(key) in MARKER_ONLY_ACTIONS
    }
    if not actions or not actions <= MARKER_ONLY_ACTIONS:
        return False
    if "marker" in raw:
        return True
    assertions: list[Any] = []
    for record in records:
        document = record[1]
        for mapping in _walk_task_mappings(document):
            for key, value in mapping.items():
                if str(key).rsplit(".", maxsplit=1)[-1] != "assert" or not isinstance(value, dict):
                    continue
                conditions = value.get("that", [])
                assertions.extend(conditions if isinstance(conditions, list) else [conditions])
    return not assertions or all(_literal_boolean(condition) is True for condition in assertions)


def _static_junit_summary(content: Any, scenario_name: str, reported_roles: set[str]) -> tuple[int, set[str]] | None:
    if not isinstance(content, str):
        return None
    try:
        document = ET.fromstring(content.strip())  # noqa: S314 - parse repository-owned fixture text only
    except (ET.ParseError, ValueError):
        return None
    root_name = document.tag.rsplit("}", maxsplit=1)[-1]
    if root_name not in {"testsuite", "testsuites"}:
        return None
    suites = [element for element in document.iter() if element.tag.rsplit("}", maxsplit=1)[-1] == "testsuite"]
    cases = [element for element in document.iter() if element.tag.rsplit("}", maxsplit=1)[-1] == "testcase"]
    if not suites or not cases:
        return None
    suite_names = {str(suite.get("name", "")).strip() for suite in suites}
    if scenario_name not in suite_names:
        return None
    declared_total = 0
    for suite in suites:
        try:
            counts = {key: int(suite.get(key, "0")) for key in ("tests", "failures", "errors", "skipped")}
        except ValueError:
            return None
        if any(value < 0 for value in counts.values()) or counts["failures"] or counts["errors"]:
            return None
        declared_total += counts["tests"]
    if declared_total != len(cases):
        return None
    case_roles = {str(case.get("role", "")).strip() for case in cases}
    if not case_roles or "" in case_roles or not reported_roles <= case_roles or not case_roles <= reported_roles:
        return None
    if any(not str(case.get("name", "")).strip() or not str(case.get("classname", "")).strip() for case in cases):
        return None
    return len(cases), case_roles


def _command_tokens(value: Any) -> list[str]:
    if isinstance(value, dict):
        argv = value.get("argv")
        if isinstance(argv, list) and all(isinstance(item, str) for item in argv):
            return argv
        value = value.get("cmd") or value.get("_raw_params")
    if not isinstance(value, str):
        return []
    try:
        return shlex.split(value)
    except ValueError:
        return []


def _is_junit_test_command(value: Any) -> bool:
    tokens = _command_tokens(value)
    if not tokens:
        return False
    executable = Path(tokens[0]).name.lower()
    if executable in {"py.test", "pytest"}:
        return True
    return executable.startswith("python") and len(tokens) >= 3 and tokens[1:3] == ["-m", "pytest"]


def _command_is_noop(value: Any) -> bool:
    tokens = _command_tokens(value)
    if not tokens:
        return True
    return Path(tokens[0]).name.lower() in NOOP_COMMANDS


def _pytest_has_explicit_test_target(value: Any) -> bool:
    tokens = _command_tokens(value)
    if not _is_junit_test_command(value):
        return False
    start = 3 if Path(tokens[0]).name.lower().startswith("python") else 1
    skip_next = False
    value_options = {
        "--alluredir",
        "--browser",
        "--junit-xml",
        "--junit_xml",
        "--junitxml",
        "-k",
        "-m",
        "-o",
    }
    for token in tokens[start:]:
        if skip_next:
            skip_next = False
            continue
        if token in value_options:
            skip_next = True
            continue
        if token.startswith("-") or token.endswith(".xml"):
            continue
        return True
    return False


def _dynamic_assertion(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    conditions = value.get("that", [])
    conditions = conditions if isinstance(conditions, list) else [conditions]
    return bool(conditions) and any(_literal_boolean(condition) is None for condition in conditions)


def _substantive_verification_count(records: list[tuple[Path, Any, str]]) -> int:
    count = 0
    for record in records:
        for mapping in _walk_task_mappings(record[1]):
            for key, value in mapping.items():
                action = str(key).rsplit(".", maxsplit=1)[-1]
                if action not in SUBSTANTIVE_VERIFY_ACTIONS:
                    continue
                if action in {"command", "shell"} and _command_is_noop(value):
                    continue
                if action == "assert" and not _dynamic_assertion(value):
                    continue
                if mapping.get("failed_when") is False or _literal_boolean(mapping.get("failed_when")) is False:
                    continue
                count += 1
                break
    return count


def _has_junit_producer(
    records: list[tuple[Path, Any, str]],
    scenario_name: str,
    reported_roles: set[str],
) -> bool:
    exact_report = f"{scenario_name}.xml".lower()
    substantive_checks = _substantive_verification_count(records)
    for record in records:
        document = record[1]
        for mapping in _walk_task_mappings(document):
            for key, value in mapping.items():
                action = str(key).rsplit(".", maxsplit=1)[-1]
                if action in {"command", "shell"}:
                    payload = yaml.safe_dump(value, sort_keys=True).lower()
                    if (
                        _pytest_has_explicit_test_target(value)
                        and exact_report in payload
                        and any(option in payload for option in ("--junitxml", "--junit-xml", "--junit_xml"))
                    ):
                        return True
                if action == "copy" and isinstance(value, dict):
                    destination = str(value.get("dest", "")).lower()
                    summary = _static_junit_summary(value.get("content"), scenario_name, reported_roles)
                    if exact_report in destination and summary is not None and substantive_checks >= summary[0]:
                        return True
    return False


def _has_evidence_cleanup(records: list[tuple[Path, Any, str]]) -> bool:
    path_fields = {"dest", "destination", "path", "src"}
    has_source = False
    has_write = False
    for record in records:
        document = record[1]
        for mapping in _walk_task_mappings(document):
            for key, value in mapping.items():
                action = str(key).rsplit(".", maxsplit=1)[-1]
                if action in EVIDENCE_SOURCE_ACTIONS:
                    if action not in {"command", "shell"} or not _command_is_noop(value):
                        has_source = True
                if action not in EVIDENCE_CLEANUP_ACTIONS:
                    continue
                if action in {"import_tasks", "include_tasks"}:
                    task_path = value.get("file", "") if isinstance(value, dict) else value
                    if "evidence" in str(task_path).lower():
                        has_write = True
                if isinstance(value, dict) and any(
                    "evidence" in str(value.get(field, "")).lower() for field in path_fields
                ):
                    if action == "copy" and str(value.get("content", "")).strip() in {"", "{}", "[]", "null"}:
                        continue
                    has_write = True
    return has_source and has_write


def supported_scenario_structure_errors(
    root: Path,
    scenario_name: str,
    scenario: dict[str, Any],
) -> list[str]:
    """Reject structural Stub/Skip coverage behind a supported+real declaration."""

    errors: list[str] = []
    scenario_root = root / "molecule" / scenario_name
    try:
        config_path = scenario_root / "molecule.yml"
        config_raw = config_path.read_text(encoding="utf-8")
        config = yaml.safe_load(config_raw) or {}
    except (OSError, yaml.YAMLError) as error:
        return [f"supported scenario {scenario_name} has unreadable molecule.yml: {error}"]
    if not isinstance(config, dict):
        return [f"supported scenario {scenario_name} molecule.yml must be a mapping"]

    profile = scenario.get("profile")
    sequence = (config.get("scenario") or {}).get("test_sequence")
    required_phases = REQUIRED_LIFECYCLE_PHASES.get(str(profile))
    if required_phases and (not isinstance(sequence, list) or not _ordered_subsequence(required_phases, sequence)):
        errors.append(f"supported scenario {scenario_name} must preserve lifecycle order: {', '.join(required_phases)}")

    converge = _configured_playbook(root, scenario_root, config, "converge", errors)
    verify = _configured_playbook(root, scenario_root, config, "verify", errors)
    cleanup = _configured_playbook(
        root,
        scenario_root,
        config,
        "cleanup",
        errors,
        required_configuration=True,
    )
    converge_records = _load_playbook_graph(root, converge, errors) if converge else []
    verify_records = _load_playbook_graph(root, verify, errors) if verify else []
    cleanup_records = _load_playbook_graph(root, cleanup, errors) if cleanup else []
    lifecycle_records: list[tuple[Path, Any, str]] = []
    required_playbook_phases = ["create"]
    if profile in {"heavy", "application_acceptance"}:
        required_playbook_phases.append("prepare")
    required_playbook_phases.append("destroy")
    for phase in required_playbook_phases:
        playbook = _configured_playbook(root, scenario_root, config, phase, errors)
        if playbook is not None:
            lifecycle_records.extend(_load_playbook_graph(root, playbook, errors))
    provisioner = config.get("provisioner") or {}
    playbooks = provisioner.get("playbooks") if isinstance(provisioner, dict) else {}
    if isinstance(playbooks, dict):
        for phase, configured in playbooks.items():
            if phase in {"converge", "verify", "cleanup", *required_playbook_phases} or phase not in (sequence or []):
                continue
            path = _resolve_repository_path(
                root,
                scenario_root,
                configured,
                errors,
                f"supported scenario {scenario_name} {phase}",
            )
            if path is not None:
                lifecycle_records.extend(_load_playbook_graph(root, path, errors))
    all_records = (
        [(config_path, config, config_raw)] + lifecycle_records + converge_records + verify_records + cleanup_records
    )

    reported_roles = [str(role) for role in scenario.get("roles", []) if isinstance(role, str)]
    active_roles = (
        _collect_reachable_playbook_roles(root, converge, converge_records, errors) if converge is not None else set()
    )
    missing_roles = sorted(set(reported_roles) - active_roles)
    if missing_roles:
        errors.append(
            f"supported scenario {scenario_name} has no active converge role edge for: {', '.join(missing_roles)}"
        )
    errors.extend(_supported_forbidden_constructs(all_records, root, scenario_name, reported_roles))

    reported_role_set = set(reported_roles)
    substantive_verify_count = _substantive_verification_count(verify_records)
    if substantive_verify_count == 0:
        errors.append(f"supported scenario {scenario_name} verify has no substantive runtime assertion")
    if scenario.get("junit") is True:
        if not _has_junit_producer(verify_records, scenario_name, reported_role_set):
            errors.append(f"supported scenario {scenario_name} declares JUnit without a concrete verify producer")
    if _marker_only_verify(verify_records):
        errors.append(f"supported scenario {scenario_name} verify is marker-only")

    if scenario.get("evidence") is True and not _has_evidence_cleanup(cleanup_records):
        errors.append(f"supported scenario {scenario_name} declares evidence without evidence-aware cleanup")
    return sorted(set(errors))


def validate_test_application_policy(
    scenario_name: str,
    scenario: dict[str, Any],
    errors: list[str],
) -> None:
    """Validate the registry-owned test-application evidence decision."""

    prefix = f"scenario {scenario_name}.test_application"
    policy = scenario.get("test_application")
    if not isinstance(policy, dict):
        errors.append(f"{prefix} must be a mapping")
        return

    missing_fields = sorted(TEST_APPLICATION_POLICY_FIELDS - set(policy))
    unexpected_fields = sorted(set(policy) - TEST_APPLICATION_POLICY_FIELDS)
    if missing_fields:
        errors.append(f"{prefix} missing fields: {', '.join(missing_fields)}")
    if unexpected_fields:
        errors.append(f"{prefix} has unexpected fields: {', '.join(unexpected_fields)}")

    mode = policy.get("mode")
    if mode not in TEST_APPLICATION_MODES:
        errors.append(f"{prefix}.mode has invalid value: {mode!r}")

    reason = policy.get("reason")
    if (
        not isinstance(reason, str)
        or reason != reason.strip()
        or not 20 <= len(reason) <= 500
        or any(ord(character) < 32 for character in reason)
    ):
        errors.append(f"{prefix}.reason must be a trimmed single-line string of 20 to 500 characters")

    dependencies = policy.get("dependencies")
    if not isinstance(dependencies, list):
        errors.append(f"{prefix}.dependencies must be a list")
        dependencies = []

    if mode == "declared-evidence" and not dependencies:
        errors.append(f"{prefix} declared-evidence mode requires at least one dependency claim")
    if mode in {"runtime-container", "not-applicable"} and dependencies:
        errors.append(f"{prefix} {mode} mode must not declare dependency claims")
    if mode == "runtime-container" and scenario.get("implementation") not in {"real", "partial"}:
        errors.append(f"{prefix} runtime-container mode requires a real or partial implementation")
    if mode == "not-applicable" and scenario.get("state") == "supported" and scenario.get("implementation") == "real":
        errors.append(f"{prefix} supported real scenarios cannot declare not-applicable")

    identities: set[tuple[str, str, str]] = set()
    allowed_dependency_fields = TEST_APPLICATION_DEPENDENCY_FIELDS | TEST_APPLICATION_DEPENDENCY_OPTIONAL_FIELDS
    for index, dependency in enumerate(dependencies):
        dependency_prefix = f"{prefix}.dependencies[{index}]"
        if not isinstance(dependency, dict):
            errors.append(f"{dependency_prefix} must be a mapping")
            continue
        missing_dependency_fields = sorted(TEST_APPLICATION_DEPENDENCY_FIELDS - set(dependency))
        unexpected_dependency_fields = sorted(set(dependency) - allowed_dependency_fields)
        if missing_dependency_fields:
            errors.append(f"{dependency_prefix} missing fields: {', '.join(missing_dependency_fields)}")
        if unexpected_dependency_fields:
            errors.append(f"{dependency_prefix} has unexpected fields: {', '.join(unexpected_dependency_fields)}")

        dependency_type = dependency.get("type")
        name = dependency.get("name")
        version = dependency.get("version")
        evidence_path_value = dependency.get("evidence_path")
        if dependency_type not in TEST_APPLICATION_TYPES:
            errors.append(f"{dependency_prefix}.type has invalid value: {dependency_type!r}")
        if not isinstance(name, str) or SAFE_IDENTIFIER.fullmatch(name) is None:
            errors.append(f"{dependency_prefix}.name must be a safe identifier of at most 63 characters")
        if (
            not isinstance(version, str)
            or SAFE_APPLICATION_VERSION.fullmatch(version) is None
            or version.lower() in MUTABLE_TEST_APPLICATION_VERSIONS
        ):
            errors.append(f"{dependency_prefix}.version must be an immutable, explicit version")

        evidence_path = (
            PurePosixPath(evidence_path_value) if isinstance(evidence_path_value, str) else PurePosixPath(".")
        )
        expected_evidence_root = PurePosixPath("test-applications") / scenario_name
        if (
            not isinstance(evidence_path_value, str)
            or not evidence_path_value
            or evidence_path.is_absolute()
            or ".." in evidence_path.parts
            or evidence_path == PurePosixPath(".")
            or evidence_path.parts[:2] != expected_evidence_root.parts
            or len(evidence_path_value) > 255
        ):
            errors.append(
                f"{dependency_prefix}.evidence_path must be a safe path below {expected_evidence_root.as_posix()}"
            )

        digest = dependency.get("digest")
        if digest is not None and (not isinstance(digest, str) or SHA256_DIGEST.fullmatch(digest) is None):
            errors.append(f"{dependency_prefix}.digest must be a lowercase sha256 digest")

        if isinstance(dependency_type, str) and isinstance(name, str) and isinstance(version, str):
            identity = (dependency_type, name, version)
            if identity in identities:
                errors.append(f"{dependency_prefix} duplicates dependency identity {dependency_type}:{name}@{version}")
            identities.add(identity)


def _collection_name(value: str) -> str | None:
    parts = value.split(".")
    if len(parts) < 2 or parts[0] not in EXTERNAL_AAP_COLLECTION_PREFIXES:
        return None
    return ".".join(parts[:2])


def _referenced_aap_collections(root: Path, registry: dict[str, Any]) -> set[str]:
    references: set[str] = set()
    roles = registry.get("roles") or {}
    for role_name, role in roles.items():
        if not str(role_name).startswith("aap") or not isinstance(role, dict):
            continue
        for dependency in role.get("dependencies") or []:
            if isinstance(dependency, str) and (collection := _collection_name(dependency)):
                references.add(collection)
        role_root = root / "roles" / str(role_name)
        for path in role_root.rglob("*"):
            if path.suffix.lower() not in {".yml", ".yaml"}:
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for namespace, name in re.findall(
                r"\b(ansible|infra)\.([a-z][a-z0-9_]+)\.(?:[a-z{])",
                content,
            ):
                references.add(f"{namespace}.{name}")
    try:
        galaxy = yaml.safe_load((root / "galaxy.yml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        galaxy = {}
    core_dependencies = set((galaxy.get("dependencies") or {}) if isinstance(galaxy, dict) else {})
    return references - EXCLUDED_AAP_COLLECTIONS - core_dependencies - {"lit.supplementary"}


def validate_aap_overlay(root: Path, registry: dict[str, Any]) -> list[str]:
    """Require one exact, complete overlay for optional AAP/Red Hat content."""

    errors: list[str] = []
    expected = _referenced_aap_collections(root, registry)
    path = root / AAP_OVERLAY_PATH
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as error:
        return [f"AAP overlay requirements are unreadable: {error}"]
    entries = payload.get("collections") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return ["AAP overlay requirements must contain a collections list"]
    actual: set[str] = set()
    for index, entry in enumerate(entries):
        prefix = f"AAP overlay collections[{index}]"
        if not isinstance(entry, dict) or set(entry) != {"name", "version"}:
            errors.append(f"{prefix} must contain exactly name and version")
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or _collection_name(name) != name:
            errors.append(f"{prefix}.name must be a canonical ansible.* or infra.* collection")
            continue
        if name in actual:
            errors.append(f"AAP overlay duplicates {name}")
        actual.add(name)
        if not isinstance(version, str) or IMMUTABLE_COLLECTION_VERSION.fullmatch(version) is None:
            errors.append(f"{prefix}.version must be an exact immutable collection version")
    errors.extend(_set_difference_message("AAP overlay", expected, actual))

    try:
        galaxy = yaml.safe_load((root / "galaxy.yml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as error:
        errors.append(f"galaxy.yml is unreadable while validating the AAP overlay: {error}")
        galaxy = {}
    core_dependencies = set((galaxy.get("dependencies") or {}) if isinstance(galaxy, dict) else {})
    overlap = sorted(expected & core_dependencies)
    if overlap:
        errors.append("optional AAP overlay collections must not be duplicated in galaxy.yml: " + ", ".join(overlap))

    documentation = {
        "README.md": expected,
        "roles/aap_cac/README.md": {
            "ansible.controller",
            "infra.aap_configuration",
            "infra.controller_configuration",
            "infra.ee_utilities",
        },
        "roles/aap_deploy/README.md": {"infra.aap_utilities"},
        "roles/aap_destroy/README.md": {"infra.aap_utilities"},
        "roles/aap_ops/README.md": {"infra.aap_utilities"},
    }
    for relative, required_names in documentation.items():
        document_path = root / relative
        content = document_path.read_text(encoding="utf-8") if document_path.is_file() else ""
        if AAP_OVERLAY_PATH.as_posix() not in content:
            errors.append(f"{relative} must name the authoritative {AAP_OVERLAY_PATH.as_posix()} overlay")
        for name in sorted(required_names):
            if name not in content:
                errors.append(f"{relative} must disclose AAP overlay dependency {name}")
    return errors


def _shared_scenario_target_set(
    roles: dict[str, Any],
    scenario_name: str,
    production_roles: list[str],
    target_field: str,
) -> set[str]:
    """Return one exact target set or reject ambiguous shared-scenario coverage."""

    target_sets = {
        role_name: frozenset(str(target) for target in roles[role_name].get(target_field, []))
        for role_name in production_roles
    }
    if len(set(target_sets.values())) > 1:
        detail = ", ".join(f"{role_name}={sorted(targets)}" for role_name, targets in sorted(target_sets.items()))
        raise ValueError(f"scenario {scenario_name} production roles must declare identical {target_field}; {detail}")
    return set(next(iter(target_sets.values()), frozenset()))


def validate_registry(
    root: Path,
    registry: dict[str, Any],
    *,
    check_generated: bool = True,
    check_governance: bool = True,
    check_role_local: bool = True,
) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    states = _require_string_list(registry.get("allowed_profile_states"), "allowed_profile_states", errors)
    if set(states) != REQUIRED_PROFILE_STATES:
        errors.append("allowed_profile_states must exactly equal: " + ", ".join(sorted(REQUIRED_PROFILE_STATES)))

    targets = registry.get("targets")
    if not isinstance(targets, dict) or not targets:
        errors.append("targets must be a non-empty mapping")
        targets = {}
    for name, target in targets.items():
        if not isinstance(name, str) or not isinstance(target, dict):
            errors.append("every targets entry must be a named mapping")
            continue
        if SAFE_IDENTIFIER.fullmatch(name) is None:
            errors.append(f"target {name!r} must be a safe identifier of at most 63 characters")
        if not isinstance(target.get("family"), str) or not isinstance(target.get("version"), str):
            errors.append(f"target {name} must declare string family and version")
        images = [field for field in ("image", "image_variable") if target.get(field)]
        if len(images) != 1:
            errors.append(f"target {name} must declare exactly one of image or image_variable")
        elif not isinstance(target[images[0]], str):
            errors.append(f"target {name}.{images[0]} must be a string")
        elif images[0] == "image" and SAFE_IMAGE.fullmatch(target[images[0]]) is None:
            errors.append(f"target {name}.image contains unsafe characters or is too long")
        elif images[0] == "image_variable" and SAFE_IMAGE_VARIABLE.fullmatch(target[images[0]]) is None:
            errors.append(f"target {name}.image_variable must be a safe uppercase variable name")
        if target.get("instance_type") not in {"container", "vm"}:
            errors.append(f"target {name}.instance_type must be container or vm")
        runner = _require_string_list(target.get("runner"), f"target {name}.runner", errors)
        if any(SAFE_RUNNER_LABEL.fullmatch(label) is None for label in runner):
            errors.append(f"target {name}.runner contains an unsafe label")
        if tuple(runner) not in APPROVED_RUNNER_SETS:
            errors.append(f"target {name}.runner is not an approved protected Incus runner label set")

    roles = registry.get("roles")
    if not isinstance(roles, dict):
        errors.append("roles must be a mapping keyed by role name")
        roles = {}
    errors.extend(_set_difference_message("roles registry", discovered_roles(root), set(roles)))

    scenarios = registry.get("scenarios")
    if not isinstance(scenarios, dict):
        errors.append("scenarios must be a mapping keyed by root Molecule scenario")
        scenarios = {}
    errors.extend(_set_difference_message("scenarios registry", discovered_scenarios(root), set(scenarios)))

    for role_name, role in roles.items():
        prefix = f"role {role_name}"
        if SAFE_ROLE.fullmatch(role_name) is None:
            errors.append(f"{prefix} name must be a safe role identifier of at most 63 characters")
        if not isinstance(role, dict):
            errors.append(f"{prefix} must be a mapping")
            continue
        missing_fields = sorted(REQUIRED_ROLE_FIELDS - set(role))
        if missing_fields:
            errors.append(f"{prefix} missing fields: {', '.join(missing_fields)}")
        maturity = role.get("maturity")
        if maturity not in MATURITIES:
            errors.append(f"{prefix} has invalid maturity: {maturity!r}")
        deprecation_state = role.get("deprecation_state")
        if deprecation_state not in DEPRECATION_STATES:
            errors.append(f"{prefix} has invalid deprecation_state: {deprecation_state!r}")
        if maturity == "deprecated" and deprecation_state != "deprecated":
            errors.append(f"{prefix} maturity deprecated requires deprecation_state deprecated")
        if deprecation_state == "deprecated" and maturity != "deprecated":
            errors.append(f"{prefix} deprecation_state deprecated requires maturity deprecated")

        supported_targets = _require_string_list(role.get("supported_targets"), f"{prefix}.supported_targets", errors)
        candidate_targets = _require_string_list(role.get("candidate_targets"), f"{prefix}.candidate_targets", errors)
        undefined_targets = sorted((set(supported_targets) | set(candidate_targets)) - set(targets))
        if undefined_targets:
            errors.append(f"{prefix} uses undefined targets: {', '.join(undefined_targets)}")
        overlap = sorted(set(supported_targets) & set(candidate_targets))
        if overlap:
            errors.append(f"{prefix} targets cannot be both supported and candidate: {', '.join(overlap)}")

        for field in ("dependencies", "external_dependencies"):
            _require_string_list(role.get(field), f"{prefix}.{field}", errors)
        known_limitations = _require_string_list(role.get("known_limitations"), f"{prefix}.known_limitations", errors)
        if not known_limitations:
            errors.append(f"{prefix}.known_limitations must explicitly describe support boundaries")
        if not isinstance(role.get("component"), str) or not role.get("component"):
            errors.append(f"{prefix}.component must be a non-empty string")
        elif SAFE_IDENTIFIER.fullmatch(role["component"]) is None:
            errors.append(f"{prefix}.component must be a safe identifier of at most 63 characters")
        if not isinstance(role.get("classification"), str) or not role.get("classification"):
            errors.append(f"{prefix}.classification must be a non-empty string")
        if not isinstance(role.get("acceptance_surface"), str) or not role.get("acceptance_surface"):
            errors.append(f"{prefix}.acceptance_surface must be a non-empty string")

        support = role.get("scenario_support")
        if not isinstance(support, dict) or set(support) != set(PROFILES):
            errors.append(f"{prefix}.scenario_support must map exactly {', '.join(PROFILES)}")
            support = {}

        for profile in PROFILES:
            state = role.get(profile)
            if state not in REQUIRED_PROFILE_STATES:
                errors.append(f"{prefix}.{profile} has invalid state: {state!r}")
            scenario_names = _require_string_list(support.get(profile), f"{prefix}.scenario_support.{profile}", errors)
            for scenario_name in scenario_names:
                scenario = scenarios.get(scenario_name)
                if not isinstance(scenario, dict):
                    errors.append(f"{prefix} references unknown scenario {scenario_name}")
                    continue
                if scenario.get("profile") != profile:
                    errors.append(
                        f"{prefix} maps {scenario_name} under {profile}, but scenario profile is "
                        f"{scenario.get('profile')!r}"
                    )
                if role_name not in (scenario.get("roles") or []):
                    errors.append(f"{prefix} maps {scenario_name}, but scenario does not report the role")

        if maturity == "production":
            if not supported_targets:
                errors.append(f"{prefix} production maturity requires supported_targets")
            for profile in PROFILES:
                if role.get(profile) != "supported":
                    errors.append(f"{prefix} production maturity requires {profile}: supported")
                    continue
                scenario_names = (support or {}).get(profile) or []
                if not scenario_names:
                    errors.append(f"{prefix} production {profile} requires a scenario")
                for scenario_name in scenario_names:
                    scenario = scenarios.get(scenario_name) or {}
                    if scenario.get("state") != "supported":
                        errors.append(f"{prefix} production scenario {scenario_name} must be supported")
                    if scenario.get("implementation") != "real":
                        errors.append(f"{prefix} production scenario {scenario_name} must be real")
                    for evidence_field in ("junit", "allure", "evidence"):
                        if scenario.get(evidence_field) is not True:
                            errors.append(
                                f"{prefix} production scenario {scenario_name} requires {evidence_field}: true"
                            )
            metadata_path = root / "roles" / role_name / "meta" / "main.yml"
            try:
                metadata = yaml.safe_load(metadata_path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError) as error:
                errors.append(f"{prefix} has unreadable Galaxy metadata: {error}")
            else:
                declared_platforms = {
                    (str(platform.get("name", "")), str(version))
                    for platform in (metadata.get("galaxy_info") or {}).get("platforms", [])
                    if isinstance(platform, dict)
                    for version in platform.get("versions", [])
                }
                expected_platforms = {
                    GALAXY_TARGETS[target] for target in supported_targets if target in GALAXY_TARGETS
                }
                if declared_platforms != expected_platforms:
                    errors.append(
                        f"{prefix} Galaxy platforms {sorted(declared_platforms)} must exactly match "
                        f"registry-supported targets {sorted(expected_platforms)}"
                    )

    for scenario_name, scenario in scenarios.items():
        prefix = f"scenario {scenario_name}"
        if SAFE_IDENTIFIER.fullmatch(scenario_name) is None:
            errors.append(f"{prefix} name must be a safe identifier of at most 63 characters")
        if not isinstance(scenario, dict):
            errors.append(f"{prefix} must be a mapping")
            continue
        missing_fields = sorted(REQUIRED_SCENARIO_FIELDS - set(scenario))
        if missing_fields:
            errors.append(f"{prefix} missing fields: {', '.join(missing_fields)}")
        scenario_profile = scenario.get("profile")
        if scenario_profile not in PROFILES:
            errors.append(f"{prefix} has invalid profile: {scenario_profile!r}")
        if "instance_type" in scenario and (
            not isinstance(scenario["instance_type"], str) or scenario["instance_type"] not in {"container", "vm"}
        ):
            errors.append(f"{prefix}.instance_type must be container or vm when declared")
        state = scenario.get("state")
        if state not in REQUIRED_PROFILE_STATES:
            errors.append(f"{prefix} has invalid state: {state!r}")
        implementation = scenario.get("implementation")
        if implementation not in IMPLEMENTATIONS:
            errors.append(f"{prefix} has invalid implementation: {implementation!r}")
        if implementation == "deprecation-contract" and state != "deprecated":
            errors.append(f"{prefix} deprecation-contract implementation requires deprecated state")
        if state == "deprecated" and implementation != "deprecation-contract":
            errors.append(f"{prefix} deprecated state requires deprecation-contract implementation")
        scenario_roles = _require_string_list(scenario.get("roles"), f"{prefix}.roles", errors)
        if not scenario_roles:
            errors.append(f"{prefix}.roles must report at least one role")
        unknown_roles = sorted(set(scenario_roles) - set(roles))
        if unknown_roles:
            errors.append(f"{prefix} reports unknown roles: {', '.join(unknown_roles)}")
        for field in ("junit", "allure", "evidence"):
            if not isinstance(scenario.get(field), bool):
                errors.append(f"{prefix}.{field} must be boolean")
        validate_test_application_policy(scenario_name, scenario, errors)
        exercised_dependencies = _require_string_list(
            scenario.get("exercised_dependencies", []),
            f"{prefix}.exercised_dependencies",
            errors,
        )
        unknown_dependencies = sorted(set(exercised_dependencies) - set(roles))
        if unknown_dependencies:
            errors.append(f"{prefix} exercises unknown role dependencies: {', '.join(unknown_dependencies)}")
        for role_name in scenario_roles:
            role = roles.get(role_name) or {}
            support = role.get("scenario_support") or {}
            if scenario_name not in (support.get(scenario_profile) or []):
                errors.append(f"{prefix} reports {role_name}, but role scenario_support.{scenario_profile} omits it")
        production_roles = sorted(
            role_name
            for role_name in scenario_roles
            if isinstance(roles.get(role_name), dict)
            and roles[role_name].get("maturity") == "production"
            and roles[role_name].get(scenario_profile) == "supported"
        )
        if state == "supported" and implementation == "real" and len(production_roles) > 1:
            for target_field in ("supported_targets", "candidate_targets"):
                try:
                    _shared_scenario_target_set(roles, scenario_name, production_roles, target_field)
                except ValueError as error:
                    errors.append(str(error))
        _scenario_has_verify(root, scenario_name, errors)
        if state == "supported" and implementation == "real":
            errors.extend(supported_scenario_structure_errors(root, scenario_name, scenario))

    errors.extend(validate_aap_overlay(root, registry))

    if check_role_local:
        local_scenarios = role_local_scenarios(root)
        if local_scenarios:
            errors.append("role-local Molecule scenarios are forbidden; migrate/remove: " + ", ".join(local_scenarios))

    if check_governance:
        agents_path = root / "AGENTS.md"
        agents = agents_path.read_text(encoding="utf-8") if agents_path.is_file() else ""
        lowered = agents.lower()
        for marker in GOVERNANCE_MARKERS:
            if marker not in agents:
                errors.append(f"AGENTS.md missing governance marker: {marker}")
        for token in GOVERNANCE_TOKENS:
            if token not in lowered:
                errors.append(f"AGENTS.md governance section missing token: {token}")

    for role_name, role in roles.items():
        readme = root / "roles" / role_name / "README.md"
        if not readme.is_file():
            errors.append(f"role {role_name} is missing README.md")
            continue
        content = readme.read_text(encoding="utf-8")
        lowered = content.lower()
        if role.get("maturity") != "production" and NONPRODUCTION_SUPPORT_CLAIM.search(content):
            errors.append(f"role {role_name} README claims support but registry maturity is not production")
        if not role.get("supported_targets") and "## supported platforms" in lowered:
            errors.append(f"role {role_name} README has a supported-platform heading but registry has none")

    if check_generated:
        errors.extend(generated_freshness_errors(root, registry))
    return errors


def _cell(value: Any) -> str:
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value) or "—"
    text = str(value) if value not in (None, "") else "—"
    return text.replace("|", "\\|").replace("\n", " ")


def render_document(registry: dict[str, Any]) -> str:
    roles = registry["roles"]
    scenarios = registry["scenarios"]
    candidate_matrix_roles = {
        role_name
        for profile in PROFILES
        for cell in build_matrix(registry, profile, target_disposition="candidate")["include"]
        for role_name in cell["roles"]
    }
    maturity_counts = Counter(role["maturity"] for role in roles.values())
    test_application_counts = Counter(scenario["test_application"]["mode"] for scenario in scenarios.values())
    lines = [
        "# Role Coverage Registry",
        "",
        "<!-- Generated by scripts/validate-role-coverage.py; do not edit directly. -->",
        "",
        "Authoritative source: [`meta/role-coverage.yml`](../../meta/role-coverage.yml).",
        "",
        "## Summary",
        "",
        f"- Roles: {len(roles)}",
        f"- Root Molecule scenarios: {len(scenarios)}",
        f"- Production roles: {maturity_counts.get('production', 0)}",
        f"- Experimental roles: {maturity_counts.get('experimental', 0)}",
        f"- Deprecated roles: {maturity_counts.get('deprecated', 0)}",
        f"- Runtime-container application policies: {test_application_counts.get('runtime-container', 0)}",
        f"- Declared-evidence application policies: {test_application_counts.get('declared-evidence', 0)}",
        f"- Reviewed not-applicable application policies: {test_application_counts.get('not-applicable', 0)}",
        "",
        "Profile states are dispositions, not inferred test results. Only `supported` profiles backed by real,",
        "evidence-producing scenarios are release-eligible.",
        "Candidate-target matrices are scheduled or manually dispatched from protected `main`; their results are",
        "promotion input only and never satisfy the release-required supported-target matrix.",
        "",
        "## Roles",
        "",
        "| Role | Component | Classification | Maturity | Supported targets | Candidate targets | "
        "Tiny | Heavy | Application Acceptance | Acceptance surface | Dependencies | "
        "External dependencies | Known limitations | Scenarios |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, role in sorted(roles.items()):
        scenario_names = sorted({scenario for profile in PROFILES for scenario in role["scenario_support"][profile]})
        values = (
            name,
            role["component"],
            role["classification"],
            role["maturity"],
            role["supported_targets"],
            role["candidate_targets"],
            role["tiny"],
            role["heavy"],
            role["application_acceptance"],
            role["acceptance_surface"],
            role["dependencies"],
            role["external_dependencies"],
            role["known_limitations"],
            scenario_names,
        )
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")

    lines.extend(["", "## Per-role operating contracts", ""])
    for name, role in sorted(roles.items()):
        scenario_names = sorted({scenario for profile in PROFILES for scenario in role["scenario_support"][profile]})
        scenario_commands = [f"`molecule test -s {scenario}`" for scenario in scenario_names]
        report_kinds = sorted(
            {
                report
                for scenario_name in scenario_names
                for report, enabled in (
                    ("JUnit", scenarios[scenario_name]["junit"]),
                    ("Allure", scenarios[scenario_name]["allure"]),
                    ("structured evidence", scenarios[scenario_name]["evidence"]),
                )
                if enabled
            }
        )
        exercised = sorted(
            {
                dependency
                for scenario_name in scenario_names
                for dependency in scenarios[scenario_name].get("exercised_dependencies", [])
            }
        )
        limitations = role["known_limitations"] or ["No registry-specific limitation recorded."]
        secret_policy = (
            "Protected non-production credentials or licensed inputs are required for the "
            "declared external dependencies."
            if role["external_dependencies"]
            else "Use ephemeral test credentials and protected runtime secret providers; never commit secret values."
        )
        lines.extend(
            [
                f"### `{name}`",
                "",
                f"- Purpose/classification: `{role['classification']}` in component `{role['component']}`.",
                f"- Maturity/deprecation: `{role['maturity']}` / `{role['deprecation_state']}`.",
                (
                    f"- Supported targets: {_cell(role['supported_targets'])}; "
                    f"candidate targets: {_cell(role['candidate_targets'])}."
                ),
                (
                    f"- Profiles: Tiny `{role['tiny']}`, Heavy `{role['heavy']}`, "
                    f"Application Acceptance `{role['application_acceptance']}`."
                ),
                f"- Acceptance surface: `{role['acceptance_surface']}`.",
                (
                    f"- Role dependencies: {_cell(role['dependencies'])}; "
                    f"exercised scenario dependencies: {_cell(exercised)}."
                ),
                f"- External dependencies/blockers: {_cell(role['external_dependencies'])}.",
                f"- Required-secret policy: {secret_policy}",
                (
                    f"- Local execution: {_cell(scenario_commands)}; CI matrix execution: "
                    + (
                        "mandatory for supported, real production scenarios on registry-supported targets."
                        if role["maturity"] == "production"
                        else "not mandatory until a profile is supported, real, and production-eligible."
                    )
                ),
                (
                    "- Candidate-target execution: scheduled protected-develop or manual "
                    "protected-main validation; "
                    "a reviewed registry change is required to promote a passing candidate into supported targets."
                    if name in candidate_matrix_roles
                    else "- Candidate-target execution: no runnable candidate matrix is currently declared."
                ),
                (
                    f"- Reports/evidence: {_cell(report_kinds)}. Failed mandatory runs "
                    "remain failures or infrastructure errors."
                ),
                (
                    "- Backup/restore and upgrade behavior are support claims only when "
                    "the acceptance surface or an executed scenario proves them."
                ),
                f"- Known limitations: {_cell(limitations)}",
                "",
            ]
        )

    lines.extend(
        [
            "",
            "## Scenarios",
            "",
            "A scenario may explicitly declare `instance_type: container` or `instance_type: vm`; "
            "otherwise its matrix cells retain the target's instance type. This execution setting "
            "does not change scenario eligibility, role maturity, target disposition, or release requirements.",
            "",
            "| Scenario | Profile | State | Implementation | Reported roles | "
            "Exercised dependencies | Test application mode | Application claims | "
            "Application policy rationale | JUnit | Allure | Evidence |",
            "|---|---|---|---|---|---|---|---|---|---:|---:|---:|",
        ]
    )
    for name, scenario in sorted(scenarios.items()):
        test_application = scenario["test_application"]
        application_claims = [
            f"{dependency['type']}:{dependency['name']}@{dependency['version']}"
            for dependency in test_application["dependencies"]
        ]
        scenario_values = (
            name,
            PROFILE_LABELS[scenario["profile"]],
            scenario["state"],
            scenario["implementation"],
            scenario["roles"],
            scenario.get("exercised_dependencies", []),
            test_application["mode"],
            application_claims,
            test_application["reason"],
            scenario["junit"],
            scenario["allure"],
            scenario["evidence"],
        )
        lines.append("| " + " | ".join(_cell(value) for value in scenario_values) + " |")
    lines.append("")
    return "\n".join(lines)


def render_readme_role_table(registry: dict[str, Any]) -> str:
    """Render the concise generated coverage table embedded in the root README."""

    lines = [
        README_TABLE_MARKERS[0],
        "",
        "| Role | Maturity | Supported targets | Tiny | Heavy | Application Acceptance |",
        "|---|---|---|---|---|---|",
    ]
    for name, role in sorted(registry["roles"].items()):
        values = (
            name,
            role["maturity"],
            role["supported_targets"],
            role["tiny"],
            role["heavy"],
            role["application_acceptance"],
        )
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    lines.extend(["", README_TABLE_MARKERS[1]])
    return "\n".join(lines)


def _managed_readme_block(root: Path) -> str | None:
    path = root / README_PATH
    if not path.is_file():
        return None
    content = path.read_text(encoding="utf-8")
    start = content.find(README_TABLE_MARKERS[0])
    end = content.find(README_TABLE_MARKERS[1])
    if start < 0 or end < start:
        return None
    return content[start : end + len(README_TABLE_MARKERS[1])]


def build_matrix(
    registry: dict[str, Any],
    profile: str,
    *,
    target_disposition: str = "supported",
) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    if target_disposition not in {"supported", "candidate"}:
        raise ValueError(f"unknown target disposition: {target_disposition}")
    roles = registry["roles"]
    include: list[dict[str, Any]] = []
    for scenario_name, scenario in sorted(registry["scenarios"].items()):
        if scenario["profile"] != profile or scenario["state"] != "supported" or scenario["implementation"] != "real":
            continue
        production_roles = sorted(
            role_name
            for role_name in scenario["roles"]
            if roles[role_name]["maturity"] == "production" and roles[role_name][profile] == "supported"
        )
        if not production_roles:
            continue
        target_field = "supported_targets" if target_disposition == "supported" else "candidate_targets"
        scenario_targets = _shared_scenario_target_set(roles, scenario_name, production_roles, target_field)
        for target in sorted(scenario_targets & set(registry["targets"])):
            target_definition = registry["targets"][target]
            instance_type = scenario.get("instance_type", target_definition["instance_type"])
            if not isinstance(instance_type, str) or instance_type not in {"container", "vm"}:
                raise ValueError(f"scenario {scenario_name}.instance_type must be container or vm when declared")
            components = sorted({roles[role]["component"] for role in production_roles})
            cell: dict[str, Any] = {
                "scenario": scenario_name,
                "component": components[0] if len(components) == 1 else "+".join(components),
                "profile": profile,
                "target": target,
                "target_disposition": target_disposition,
                "release_required": target_disposition == "supported",
                "instance_type": instance_type,
                "runner": target_definition["runner"],
                "roles": production_roles,
                "junit": scenario["junit"],
                "allure": scenario["allure"],
                "evidence": scenario["evidence"],
            }
            if "image" in target_definition:
                cell["image"] = target_definition["image"]
            else:
                cell["image_variable"] = target_definition["image_variable"]
            include.append(cell)
    return {"include": include}


def render_matrix_bundle(registry: dict[str, Any]) -> str:
    payload = {
        "schema_version": registry["schema_version"],
        "generated_from": REGISTRY_PATH.as_posix(),
        "profiles": {profile: build_matrix(registry, profile) for profile in PROFILES},
        "candidate_profiles": {
            profile: build_matrix(registry, profile, target_disposition="candidate") for profile in PROFILES
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def generated_freshness_errors(root: Path, registry: dict[str, Any]) -> list[str]:
    expected = {
        DOC_PATH: render_document(registry),
        MATRIX_PATH: render_matrix_bundle(registry),
    }
    errors: list[str] = []
    for relative, content in expected.items():
        path = root / relative
        if not path.is_file():
            errors.append(f"missing generated file: {relative.as_posix()}")
        elif path.read_text(encoding="utf-8") != content:
            errors.append(f"stale generated file: {relative.as_posix()} (run validate-role-coverage.py generate)")
    if _managed_readme_block(root) != render_readme_role_table(registry):
        errors.append("stale or missing generated README role table (run validate-role-coverage.py generate)")
    return errors


def generate_outputs(root: Path, registry: dict[str, Any]) -> None:
    outputs = {
        DOC_PATH: render_document(registry),
        MATRIX_PATH: render_matrix_bundle(registry),
    }
    for relative, content in outputs.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"generated {relative.as_posix()}")

    readme_path = root / README_PATH
    readme = readme_path.read_text(encoding="utf-8")
    current = _managed_readme_block(root)
    if current is None:
        raise ValueError("README.md is missing role coverage table markers")
    readme_path.write_text(readme.replace(current, render_readme_role_table(registry), 1), encoding="utf-8")
    print(f"generated {README_PATH.as_posix()} role table")


def _print_errors(errors: Iterable[str]) -> None:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)


def command_validate(args: argparse.Namespace) -> int:
    try:
        registry = load_registry(args.root)
    except ValueError as error:
        _print_errors([str(error)])
        return 1
    errors = validate_registry(
        args.root,
        registry,
        check_generated=True,
        check_governance=not args.skip_governance,
        check_role_local=True,
    )
    if errors:
        _print_errors(errors)
        return 1
    print(f"role coverage valid: {len(registry['roles'])} roles, {len(registry['scenarios'])} root scenarios")
    return 0


def command_generate(args: argparse.Namespace) -> int:
    try:
        registry = load_registry(args.root)
    except ValueError as error:
        _print_errors([str(error)])
        return 1
    errors = validate_registry(
        args.root,
        registry,
        check_generated=False,
        check_governance=False,
        check_role_local=False,
    )
    if errors:
        _print_errors(errors)
        return 1
    generate_outputs(args.root, registry)
    return 0


def command_matrix(args: argparse.Namespace) -> int:
    try:
        registry = load_registry(args.root)
    except ValueError as error:
        _print_errors([str(error)])
        return 1
    errors = validate_registry(
        args.root,
        registry,
        check_generated=False,
        check_governance=False,
        check_role_local=False,
    )
    if errors:
        _print_errors(errors)
        return 1
    print(
        json.dumps(
            build_matrix(registry, args.profile, target_disposition=args.target_disposition),
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.set_defaults(root=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "check"):
        subparser = subparsers.add_parser(command, help=f"{command} registry and repository policy")
        subparser.add_argument(
            "--skip-governance",
            action="store_true",
            help="temporarily omit AGENTS.md marker validation during governance migration",
        )
        subparser.set_defaults(handler=command_validate)
    generate = subparsers.add_parser("generate", help="regenerate tracked documentation and matrix")
    generate.set_defaults(handler=command_generate)
    matrix = subparsers.add_parser("matrix", help="print the runnable CI matrix for one profile")
    matrix.add_argument("--profile", choices=PROFILES, required=True)
    matrix.add_argument(
        "--target-disposition",
        choices=("supported", "candidate"),
        default="supported",
        help="select release-required supported targets or non-release candidate targets",
    )
    matrix.set_defaults(handler=command_matrix)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
