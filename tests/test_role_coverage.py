"""Tests for the authoritative role quality coverage registry."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate-role-coverage.py"
SPEC = importlib.util.spec_from_file_location("validate_role_coverage", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"unable to import {SCRIPT}")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RoleCoverageRegistryTests(unittest.TestCase):
    """Exercise registry completeness, release eligibility, and generated outputs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = VALIDATOR.load_registry(ROOT)

    @staticmethod
    def _write_fixture(root: Path, relative: str, content: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    @staticmethod
    def _supported_scenario(profile: str = "application_acceptance") -> dict[str, object]:
        return {
            "profile": profile,
            "state": "supported",
            "implementation": "real",
            "roles": ["demo_role"],
            "junit": True,
            "allure": True,
            "evidence": True,
            "test_application": {
                "mode": "runtime-container",
                "reason": "The scenario deploys an independently versioned application container.",
                "dependencies": [],
            },
        }

    def test_registry_exactly_covers_repository(self) -> None:
        self.assertEqual(101, len(self.registry["roles"]))
        self.assertEqual(60, len(self.registry["scenarios"]))
        self.assertEqual(
            VALIDATOR.discovered_roles(ROOT),
            set(self.registry["roles"]),
        )
        self.assertEqual(
            VALIDATOR.discovered_scenarios(ROOT),
            set(self.registry["scenarios"]),
        )

    def test_only_canonical_keycloak_roles_are_production(self) -> None:
        production = {name for name, role in self.registry["roles"].items() if role["maturity"] == "production"}
        self.assertEqual({"keycloak_cac", "keycloak_deploy"}, production)
        for name in production:
            role = self.registry["roles"][name]
            for profile in VALIDATOR.PROFILES:
                self.assertEqual("supported", role[profile], f"{name}.{profile}")

    def test_every_role_has_an_explicit_support_limitation(self) -> None:
        for name, role in self.registry["roles"].items():
            self.assertTrue(role["known_limitations"], name)

        registry = deepcopy(self.registry)
        registry["roles"]["coredns_deploy"]["known_limitations"] = []
        errors = VALIDATOR.validate_registry(
            ROOT,
            registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        self.assertTrue(
            any("known_limitations must explicitly describe" in error for error in errors),
            errors,
        )

    def test_production_scenarios_are_real_and_evidence_eligible(self) -> None:
        for name in ("keycloak_cac", "keycloak_deploy"):
            role = self.registry["roles"][name]
            for profile in VALIDATOR.PROFILES:
                scenario_names = role["scenario_support"][profile]
                self.assertTrue(scenario_names, f"{name}.{profile} has no scenario")
                for scenario_name in scenario_names:
                    scenario = self.registry["scenarios"][scenario_name]
                    self.assertEqual("supported", scenario["state"])
                    self.assertEqual("real", scenario["implementation"])
                    self.assertTrue(scenario["junit"])
                    self.assertTrue(scenario["allure"])
                    self.assertTrue(scenario["evidence"])

    def test_test_application_policy_covers_every_scenario_with_reviewed_modes(self) -> None:
        runtime = {
            name
            for name, scenario in self.registry["scenarios"].items()
            if scenario["test_application"]["mode"] == "runtime-container"
        }
        declared = {
            name
            for name, scenario in self.registry["scenarios"].items()
            if scenario["test_application"]["mode"] == "declared-evidence"
        }
        not_applicable = {
            name
            for name, scenario in self.registry["scenarios"].items()
            if scenario["test_application"]["mode"] == "not-applicable"
        }
        self.assertEqual(
            {
                "atlas-observability-incus_heavy",
                "keycloak-application-acceptance",
                "keycloak-heavy",
                "keycloak-tiny",
                "rsyslog-lifecycle-incus_heavy",
                "samba-lifecycle-incus_heavy",
            },
            runtime,
        )
        self.assertEqual(
            {
                "vault-backup-restore-basic",
                "vault-ops-basic",
                "vault-raft-snapshot-basic",
                "vault-scoped-approle-basic",
                "vault-validate-basic",
            },
            declared,
        )
        self.assertEqual(49, len(not_applicable))
        self.assertEqual(set(self.registry["scenarios"]), runtime | declared | not_applicable)
        for name in declared:
            self.assertEqual(
                [
                    {
                        "type": "external-api",
                        "name": "MoleculeVault",
                        "version": "1.0",
                        "evidence_path": (f"test-applications/{name}/MoleculeVault-1.0-requests.log"),
                    }
                ],
                self.registry["scenarios"][name]["test_application"]["dependencies"],
            )

    def test_registry_rejects_missing_or_self_declared_not_applicable_policy(self) -> None:
        registry = deepcopy(self.registry)
        del registry["scenarios"]["keycloak-tiny"]["test_application"]
        errors = VALIDATOR.validate_registry(
            ROOT,
            registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        self.assertTrue(any("missing fields: test_application" in error for error in errors), errors)

        registry = deepcopy(self.registry)
        policy = registry["scenarios"]["keycloak-tiny"]["test_application"]
        policy["mode"] = "not-applicable"
        policy["reason"] = "The scenario has no application dependency for this negative fixture."
        errors = VALIDATOR.validate_registry(
            ROOT,
            registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        self.assertTrue(
            any("supported real scenarios cannot declare not-applicable" in error for error in errors), errors
        )

    def test_registry_rejects_unversioned_or_malformed_application_claims(self) -> None:
        registry = deepcopy(self.registry)
        policy = registry["scenarios"]["vault-validate-basic"]["test_application"]
        policy["dependencies"][0]["version"] = "latest"
        policy["dependencies"][0]["evidence_path"] = "unreviewed.json"
        policy["dependencies"][0]["unreviewed_field"] = True
        policy["dependencies"].append(deepcopy(policy["dependencies"][0]))
        errors = VALIDATOR.validate_registry(
            ROOT,
            registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        rendered = "\n".join(errors)
        self.assertIn("version must be an immutable, explicit version", rendered)
        self.assertIn("evidence_path must be a safe path", rendered)
        self.assertIn("unexpected fields: unreviewed_field", rendered)
        self.assertIn("duplicates dependency identity", rendered)

    def test_registry_rejects_claims_for_runtime_or_not_applicable_modes(self) -> None:
        for scenario_name in ("keycloak-tiny", "aap-basic"):
            with self.subTest(scenario=scenario_name):
                registry = deepcopy(self.registry)
                policy = registry["scenarios"][scenario_name]["test_application"]
                policy["dependencies"] = [{"type": "external-api", "name": "UnreviewedAPI", "version": "1.0"}]
                errors = VALIDATOR.validate_registry(
                    ROOT,
                    registry,
                    check_generated=False,
                    check_governance=False,
                    check_role_local=False,
                )
                self.assertTrue(
                    any("mode must not declare dependency claims" in error for error in errors),
                    errors,
                )

    def test_partial_runtime_container_scenarios_use_owned_evidence_lifecycle(self) -> None:
        for scenario_name in (
            "atlas-observability-incus_heavy",
            "rsyslog-lifecycle-incus_heavy",
            "samba-lifecycle-incus_heavy",
        ):
            with self.subTest(scenario=scenario_name):
                scenario_root = ROOT / "molecule" / scenario_name
                config = VALIDATOR.yaml.safe_load((scenario_root / "molecule.yml").read_text(encoding="utf-8"))
                self.assertEqual("cleanup.yml", config["provisioner"]["playbooks"]["cleanup"])
                self.assertIn("cleanup", config["scenario"]["test_sequence"])
                self.assertIn(
                    "../shared/incus/create.yml",
                    (scenario_root / "create.yml").read_text(encoding="utf-8"),
                )
                self.assertIn(
                    "../shared/incus/cleanup.yml",
                    (scenario_root / "cleanup.yml").read_text(encoding="utf-8"),
                )
                self.assertIn(
                    "../shared/incus/destroy.yml",
                    (scenario_root / "destroy.yml").read_text(encoding="utf-8"),
                )

    def test_declared_vault_dependencies_preserve_registry_owned_evidence_paths(self) -> None:
        for scenario_name, scenario in self.registry["scenarios"].items():
            policy = scenario["test_application"]
            if policy["mode"] != "declared-evidence":
                continue
            with self.subTest(scenario=scenario_name):
                config = VALIDATOR.yaml.safe_load(
                    (ROOT / "molecule" / scenario_name / "molecule.yml").read_text(encoding="utf-8")
                )
                self.assertEqual("cleanup.yml", config["provisioner"]["playbooks"]["cleanup"])
                self.assertIn("cleanup", config["scenario"]["test_sequence"])
                self.assertIn(
                    "../shared/vault/collect-test-application-evidence.yml",
                    (ROOT / "molecule" / scenario_name / "cleanup.yml").read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    f"test-applications/{scenario_name}/MoleculeVault-1.0-requests.log",
                    policy["dependencies"][0]["evidence_path"],
                )

    def test_registry_structure_is_valid_during_policy_migration(self) -> None:
        errors = VALIDATOR.validate_registry(
            ROOT,
            self.registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        self.assertEqual([], errors)

    def test_generated_outputs_are_fresh(self) -> None:
        errors = VALIDATOR.generated_freshness_errors(ROOT, self.registry)
        self.assertEqual([], errors)

    def test_matrix_is_deduplicated_and_workflow_ready(self) -> None:
        for profile in VALIDATOR.PROFILES:
            matrix = VALIDATOR.build_matrix(self.registry, profile)
            cells = matrix["include"]
            self.assertEqual(1, len(cells))
            identities = {(cell["scenario"], cell["profile"], cell["target"]) for cell in cells}
            self.assertEqual(len(cells), len(identities))
            for cell in cells:
                self.assertEqual("keycloak", cell["component"])
                self.assertEqual(profile, cell["profile"])
                self.assertEqual("supported", cell["target_disposition"])
                self.assertTrue(cell["release_required"])
                self.assertEqual(["keycloak_cac", "keycloak_deploy"], cell["roles"])
                self.assertIn("instance_type", cell)
                self.assertEqual("container" if profile == "tiny" else "vm", cell["instance_type"])
                self.assertIsInstance(cell["runner"], list)
                self.assertTrue(("image" in cell) ^ ("image_variable" in cell))
                self.assertTrue(cell["junit"] and cell["allure"] and cell["evidence"])

    def test_shared_production_scenario_rejects_asymmetric_target_sets(self) -> None:
        registry = deepcopy(self.registry)
        role = registry["roles"]["keycloak_cac"]
        role["supported_targets"] = ["rhel-9"]
        role["candidate_targets"] = ["ubuntu-24.04", "rhel-10"]
        errors = VALIDATOR.validate_registry(
            ROOT,
            registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        self.assertTrue(any("must declare identical supported_targets" in error for error in errors), errors)
        self.assertTrue(any("must declare identical candidate_targets" in error for error in errors), errors)
        with self.assertRaisesRegex(ValueError, "must declare identical supported_targets"):
            VALIDATOR.build_matrix(registry, "tiny")

    def test_unexecuted_rhel_targets_remain_candidates(self) -> None:
        for name in ("keycloak_cac", "keycloak_deploy"):
            role = self.registry["roles"][name]
            self.assertEqual(["ubuntu-24.04"], role["supported_targets"])
            self.assertEqual(["rhel-9", "rhel-10"], role["candidate_targets"])

    def test_candidate_matrix_is_runnable_but_explicitly_not_release_required(self) -> None:
        for profile in VALIDATOR.PROFILES:
            matrix = VALIDATOR.build_matrix(self.registry, profile, target_disposition="candidate")
            self.assertEqual({"rhel-9", "rhel-10"}, {cell["target"] for cell in matrix["include"]})
            for cell in matrix["include"]:
                self.assertEqual("candidate", cell["target_disposition"])
                self.assertFalse(cell["release_required"])
                self.assertEqual(["keycloak_cac", "keycloak_deploy"], cell["roles"])

    def test_only_supported_heavy_and_acceptance_scenarios_override_target_instance_type(self) -> None:
        overrides = {
            name: scenario["instance_type"]
            for name, scenario in self.registry["scenarios"].items()
            if "instance_type" in scenario
        }
        self.assertEqual({"keycloak-heavy": "vm", "keycloak-application-acceptance": "vm"}, overrides)
        self.assertTrue(all(target["instance_type"] == "container" for target in self.registry["targets"].values()))
        for profile in VALIDATOR.PROFILES:
            supported = VALIDATOR.build_matrix(self.registry, profile)["include"]
            self.assertEqual(1, len(supported))
            self.assertEqual("ubuntu-24.04", supported[0]["target"])
            self.assertEqual(["keycloak_cac", "keycloak_deploy"], supported[0]["roles"])
            self.assertTrue(supported[0]["release_required"])
            candidates = VALIDATOR.build_matrix(self.registry, profile, target_disposition="candidate")["include"]
            self.assertEqual({"rhel-9", "rhel-10"}, {cell["target"] for cell in candidates})
            self.assertTrue(
                all(
                    cell["instance_type"] == ("container" if profile == "tiny" else "vm")
                    and not cell["release_required"]
                    for cell in candidates
                )
            )

    def test_scenario_instance_type_falls_back_only_when_absent(self) -> None:
        registry = deepcopy(self.registry)
        del registry["scenarios"]["keycloak-heavy"]["instance_type"]
        old = VALIDATOR.build_matrix(registry, "heavy")["include"][0]
        current = VALIDATOR.build_matrix(self.registry, "heavy")["include"][0]
        self.assertEqual("container", old["instance_type"])
        self.assertEqual(old | {"instance_type": "vm"}, current)
        self.assertEqual(VALIDATOR.build_matrix(registry, "tiny"), VALIDATOR.build_matrix(self.registry, "tiny"))

    def test_explicit_invalid_instance_type_denies_without_silent_target_fallback(self) -> None:
        for invalid in (None, True, 1, "", "machine", [], {}):
            registry = deepcopy(self.registry)
            registry["scenarios"]["keycloak-heavy"]["instance_type"] = invalid
            errors = VALIDATOR.validate_registry(
                ROOT, registry, check_generated=False, check_governance=False, check_role_local=False
            )
            self.assertTrue(
                any("scenario keycloak-heavy.instance_type must be container or vm" in error for error in errors),
                errors,
            )
            with self.assertRaisesRegex(ValueError, "instance_type must be container or vm"):
                VALIDATOR.build_matrix(registry, "heavy")

    def test_aap_overlay_exactly_covers_registry_and_role_references(self) -> None:
        expected = {
            "ansible.controller",
            "infra.aap_configuration",
            "infra.aap_utilities",
            "infra.controller_configuration",
            "infra.ee_utilities",
        }
        self.assertEqual(expected, VALIDATOR._referenced_aap_collections(ROOT, self.registry))
        self.assertEqual([], VALIDATOR.validate_aap_overlay(ROOT, self.registry))

    def test_aap_overlay_rejects_missing_and_mutable_entries(self) -> None:
        for version in ("latest", "1.x", "1.2.3-dev"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._write_fixture(root, "galaxy.yml", "---\ndependencies: {}\n")
                self._write_fixture(
                    root,
                    "collections/requirements-rh.yml",
                    f"---\ncollections:\n  - name: infra.aap_utilities\n    version: {version}\n",
                )
                registry = {"roles": {}}
                errors = VALIDATOR.validate_aap_overlay(root, registry)
                self.assertTrue(any("exact immutable collection version" in error for error in errors), errors)

    def test_production_galaxy_platforms_match_supported_targets(self) -> None:
        for name in ("keycloak_cac", "keycloak_deploy"):
            metadata = VALIDATOR.yaml.safe_load(
                (ROOT / "roles" / name / "meta" / "main.yml").read_text(encoding="utf-8")
            )
            declared = {
                (platform["name"], str(version))
                for platform in metadata["galaxy_info"]["platforms"]
                for version in platform["versions"]
            }
            self.assertEqual({("Ubuntu", "noble")}, declared)

    def test_root_readme_table_and_detailed_role_contracts_are_generated(self) -> None:
        self.assertEqual(
            VALIDATOR.render_readme_role_table(self.registry),
            VALIDATOR._managed_readme_block(ROOT),
        )
        rendered = VALIDATOR.render_document(self.registry)
        for role in self.registry["roles"]:
            self.assertIn(f"### `{role}`", rendered)

    def test_generated_contract_distinguishes_local_from_mandatory_ci_execution(self) -> None:
        rendered = VALIDATOR.render_document(self.registry)
        self.assertNotIn("CI uses the same registry-selected scenarios and targets", rendered)
        self.assertIn(
            "CI matrix execution: mandatory for supported, real production scenarios on registry-supported targets",
            rendered,
        )
        self.assertIn(
            "CI matrix execution: not mandatory until a profile is supported, real, and production-eligible",
            rendered,
        )

    def test_generated_contract_only_claims_candidate_execution_for_matrix_roles(self) -> None:
        rendered = VALIDATOR.render_document(self.registry)

        keycloak_contract = rendered.split("### `keycloak_cac`", 1)[1].split("### `", 1)[0]
        aap_contract = rendered.split("### `aap`", 1)[1].split("### `", 1)[0]

        self.assertIn("scheduled protected-develop or manual protected-main validation", keycloak_contract)
        self.assertIn("no runnable candidate matrix is currently declared", aap_contract)

    def test_acceptance_preserves_pytest_evidence_before_enforcing_failure(self) -> None:
        document = VALIDATOR.yaml.safe_load(
            (ROOT / "molecule/keycloak-application-acceptance/verify.yml").read_text(encoding="utf-8")
        )
        wrapper = next(
            task
            for task in document[0]["tasks"]
            if task["name"] == "Execute acceptance and always preserve its evidence"
        )
        pytest_task = next(
            task for task in wrapper["block"] if task["name"] == "Execute browser and protocol acceptance suite"
        )
        by_name = {task["name"]: (index, task) for index, task in enumerate(wrapper["always"])}
        archive_index = by_name["Package acceptance evidence without secret-bearing runtime inputs"][0]
        fetch_index = by_name["Fetch acceptance evidence to the controller"][0]
        enforce_index, enforce_task = by_name["Enforce acceptance suite result after preserving evidence"]

        self.assertEqual("Execute browser and protocol acceptance suite", pytest_task["name"])
        self.assertEqual("keycloak_acceptance_pytest", pytest_task["register"])
        self.assertNotIn("failed_when", pytest_task)
        self.assertLess(archive_index, fetch_index)
        self.assertLess(fetch_index, enforce_index)
        self.assertIn(
            "keycloak_acceptance_pytest.rc | default(1) == 0",
            enforce_task["ansible.builtin.assert"]["that"],
        )

    def test_matrix_serializes_as_compact_github_json(self) -> None:
        matrix = VALIDATOR.build_matrix(self.registry, "tiny")
        encoded = json.dumps(matrix, sort_keys=True)
        self.assertEqual(matrix, json.loads(encoded))
        self.assertIn('"include"', encoded)

    def test_registry_rejects_unapproved_runner_labels(self) -> None:
        registry = deepcopy(self.registry)
        registry["targets"]["ubuntu-24.04"]["runner"] = [
            "self-hosted",
            "production-secrets",
        ]
        errors = VALIDATOR.validate_registry(
            ROOT,
            registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        self.assertTrue(
            any("not an approved protected Incus runner label set" in error for error in errors),
            errors,
        )

    def test_registry_rejects_shell_unsafe_matrix_values(self) -> None:
        registry = deepcopy(self.registry)
        registry["targets"]["ubuntu-24.04"]["image"] = "images:ubuntu/24.04$(id)"
        errors = VALIDATOR.validate_registry(
            ROOT,
            registry,
            check_generated=False,
            check_governance=False,
            check_role_local=False,
        )
        self.assertTrue(any("image contains unsafe characters" in error for error in errors), errors)

    def test_role_local_molecule_scenarios_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "roles/example/molecule/default/molecule.yml"
            path.parent.mkdir(parents=True)
            path.write_text("---\n", encoding="utf-8")
            self.assertEqual(
                ["roles/example/molecule/default/molecule.yml"],
                VALIDATOR.role_local_scenarios(root),
            )

    def test_supported_structure_accepts_recursive_import_playbook(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_fixture(
                root,
                "molecule/demo-accept/molecule.yml",
                """---
provisioner:
  playbooks:
    converge: converge.yml
    verify: verify.yml
    cleanup: cleanup.yml
scenario:
  test_sequence:
    - dependency
    - destroy
    - syntax
    - create
    - prepare
    - converge
    - verify
    - cleanup
    - destroy
""",
            )
            for phase in ("create", "prepare", "destroy"):
                self._write_fixture(
                    root,
                    f"molecule/demo-accept/{phase}.yml",
                    f"""---
- name: Exercise the {phase} lifecycle
  hosts: localhost
  tasks:
    - name: Record the {phase} phase
      ansible.builtin.debug:
        msg: {phase}
""",
                )
            self._write_fixture(
                root,
                "molecule/demo-accept/converge.yml",
                """---
- name: Reuse the real deployment foundation
  ansible.builtin.import_playbook: ../demo-foundation/converge.yml
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-foundation/converge.yml",
                """---
- name: Deploy the demo
  hosts: all
  roles:
    - role: lit.supplementary.demo_role
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-accept/verify.yml",
                """---
- name: Verify the demo
  hosts: all
  tasks:
    - name: Run native acceptance checks
      ansible.builtin.command:
        argv:
          - pytest
          - --junitxml
          - artifacts/junit/demo-accept.xml
          - tests/test_demo.py
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-accept/cleanup.yml",
                """---
- name: Capture evidence before cleanup
  ansible.builtin.import_playbook: ../shared/incus/cleanup.yml
""",
            )
            self._write_fixture(
                root,
                "molecule/shared/incus/cleanup.yml",
                """---
- name: Preserve evidence
  hosts: localhost
  tasks:
    - name: Observe the runtime before cleanup
      ansible.builtin.command:
        argv:
          - democtl
          - status
      register: demo_runtime_status
      changed_when: false
    - name: Record evidence metadata
      ansible.builtin.copy:
        dest: artifacts/evidence.json
        content: '{"schema_version": 1, "scenario": "demo-accept"}'
""",
            )

            errors = VALIDATOR.supported_scenario_structure_errors(
                root,
                "demo-accept",
                self._supported_scenario(),
            )
            self.assertEqual([], errors)

    def test_supported_structure_rejects_noop_fabricated_junit_and_empty_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_fixture(
                root,
                "molecule/demo-tiny/molecule.yml",
                """---
provisioner:
  playbooks:
    converge: converge.yml
    verify: verify.yml
    cleanup: cleanup.yml
scenario:
  test_sequence:
    - dependency
    - syntax
    - create
    - converge
    - idempotence
    - verify
    - cleanup
    - destroy
""",
            )
            for phase in ("create", "destroy"):
                self._write_fixture(
                    root,
                    f"molecule/demo-tiny/{phase}.yml",
                    f"""---
- name: Exercise {phase}
  hosts: localhost
  tasks:
    - ansible.builtin.debug:
        msg: {phase}
""",
                )
            self._write_fixture(
                root,
                "molecule/demo-tiny/converge.yml",
                """---
- name: Claim a real role edge
  hosts: localhost
  roles:
    - role: lit.supplementary.demo_role
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-tiny/verify.yml",
                """---
- name: Fabricate success
  hosts: localhost
  tasks:
    - name: Run a no-op
      ansible.builtin.command:
        argv: [/bin/true]
    - name: Fabricate JUnit
      ansible.builtin.copy:
        dest: artifacts/junit/demo-tiny.xml
        content: >-
          <testsuite name="demo-tiny" tests="1" failures="0" errors="0" skipped="0">
          <testcase classname="fake" name="fabricated" role="demo_role"/></testsuite>
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-tiny/cleanup.yml",
                """---
- name: Fabricate evidence
  hosts: localhost
  tasks:
    - ansible.builtin.copy:
        dest: artifacts/evidence.json
        content: '{}'
""",
            )

            errors = VALIDATOR.supported_scenario_structure_errors(
                root,
                "demo-tiny",
                self._supported_scenario("tiny"),
            )
            rendered = "\n".join(errors)
            self.assertIn("verify has no substantive runtime assertion", rendered)
            self.assertIn("declares JUnit without a concrete verify producer", rendered)
            self.assertIn("declares evidence without evidence-aware cleanup", rendered)

    def test_supported_structure_rejects_false_guarded_syntax_stub(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_fixture(
                root,
                "molecule/demo-tiny/molecule.yml",
                """---
provisioner:
  playbooks:
    converge: converge.yml
    verify: verify.yml
    cleanup: cleanup.yml
scenario:
  test_sequence:
    - dependency
    - destroy
    - syntax
    - create
    - converge
    - idempotence
    - verify
    - cleanup
    - destroy
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-tiny/converge.yml",
                """---
- name: Import a disabled deployment foundation
  ansible.builtin.import_playbook: ../demo-disabled/converge.yml
  when: false

- name: Pretend to deploy the demo
  hosts: localhost
  vars:
    demo_role_molecule_execute_role: false
    demo_role_skip_runtime: true
    demo_enabled: false
  tasks:
    - name: Import the role only for syntax
      ansible.builtin.import_role:
        name: lit.supplementary.demo_role
      when: demo_enabled | default(false) | bool
    - name: Record syntax stub
      ansible.builtin.set_fact:
        demo_coverage_mode: syntax_stub
        roles:
          - lit.supplementary.demo_role
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-disabled/converge.yml",
                """---
- name: Deployment path hidden behind a disabled import
  hosts: all
  roles:
    - role: lit.supplementary.demo_role
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-tiny/verify.yml",
                """---
- name: Verify the coverage marker
  hosts: localhost
  tasks:
    - name: Read marker
      ansible.builtin.slurp:
        src: demo-marker
    - name: Assert marker
      ansible.builtin.assert:
        that: true
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-tiny/cleanup.yml",
                """---
- name: Preserve evidence
  hosts: localhost
  tasks:
    - name: Record evidence
      ansible.builtin.copy:
        dest: evidence.json
        content: '{}'
""",
            )

            errors = VALIDATOR.supported_scenario_structure_errors(
                root,
                "demo-tiny",
                self._supported_scenario("tiny"),
            )
            rendered = "\n".join(errors)
            self.assertIn("no active converge role edge", rendered)
            self.assertIn("disables role execution", rendered)
            self.assertIn("enables reported-role bypass", rendered)
            self.assertIn("forbidden marker 'syntax_stub'", rendered)
            self.assertIn("verify is marker-only", rendered)

    def test_supported_structure_rejects_handler_only_role_fake_junit_and_evidence_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_fixture(
                root,
                "molecule/demo-tiny/molecule.yml",
                """---
provisioner:
  playbooks:
    converge: converge.yml
    verify: verify.yml
    cleanup: cleanup.yml
scenario:
  test_sequence:
    - dependency
    - syntax
    - create
    - converge
    - idempotence
    - verify
    - cleanup
    - destroy
""",
            )
            for phase in ("create", "destroy"):
                self._write_fixture(
                    root,
                    f"molecule/demo-tiny/{phase}.yml",
                    f"""---
- name: Exercise the {phase} lifecycle
  hosts: localhost
  tasks:
    - name: Record the {phase} phase
      ansible.builtin.debug:
        msg: {phase}
""",
                )
            self._write_fixture(
                root,
                "molecule/demo-tiny/converge.yml",
                """---
- name: Hide the role in a never-notified handler
  hosts: localhost
  vars:
    demo_enabled: false
  tasks:
    - name: Do not notify the handler
      ansible.builtin.debug:
        msg: no deployment happened
    - name: Hide the reported role behind a parenthesized false guard
      ansible.builtin.include_role:
        name: lit.supplementary.demo_role
      when: (demo_enabled | bool)
  handlers:
    - name: Apply the reported role
      ansible.builtin.include_role:
        name: lit.supplementary.demo_role
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-tiny/verify.yml",
                """---
- name: Write invalid JUnit text
  hosts: localhost
  tasks:
    - name: Pretend to produce JUnit
      ansible.builtin.copy:
        dest: demo-tiny.xml
        content: not-xml
    - name: Echo JUnit arguments without running tests
      ansible.builtin.command:
        argv:
          - echo
          - --junitxml
          - demo-tiny.xml
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-tiny/cleanup.yml",
                """---
- name: Delete evidence instead of preserving it
  hosts: localhost
  tasks:
    - name: Delete the evidence directory
      ansible.builtin.file:
        path: /tmp/evidence
        state: absent
    - name: Echo the word evidence without preserving anything
      ansible.builtin.command:
        argv:
          - echo
          - evidence
""",
            )

            errors = VALIDATOR.supported_scenario_structure_errors(
                root,
                "demo-tiny",
                self._supported_scenario("tiny"),
            )
            rendered = "\n".join(errors)
            self.assertIn("no active converge role edge", rendered)
            self.assertIn("declares JUnit without a concrete verify producer", rendered)
            self.assertIn("declares evidence without evidence-aware cleanup", rendered)

    def test_supported_structure_requires_lifecycle_junit_and_evidence_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_fixture(
                root,
                "molecule/demo-heavy/molecule.yml",
                """---
provisioner:
  playbooks:
    converge: converge.yml
    verify: verify.yml
scenario:
  test_sequence:
    - converge
    - verify
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-heavy/converge.yml",
                """---
- name: Deploy the demo
  hosts: all
  roles:
    - role: lit.supplementary.demo_role
""",
            )
            self._write_fixture(
                root,
                "molecule/demo-heavy/verify.yml",
                """---
- name: Verify the demo
  hosts: all
  tasks:
    - name: Query health
      ansible.builtin.uri:
        url: http://127.0.0.1:8080/health
""",
            )

            errors = VALIDATOR.supported_scenario_structure_errors(
                root,
                "demo-heavy",
                self._supported_scenario("heavy"),
            )
            rendered = "\n".join(errors)
            self.assertIn("must preserve lifecycle order", rendered)
            self.assertIn("must configure a cleanup playbook", rendered)
            self.assertIn("supported scenario playbook is missing: molecule/demo-heavy/create.yml", rendered)
            self.assertIn("supported scenario playbook is missing: molecule/demo-heavy/prepare.yml", rendered)
            self.assertIn("supported scenario playbook is missing: molecule/demo-heavy/destroy.yml", rendered)
            self.assertIn("declares JUnit without a concrete verify producer", rendered)
            self.assertIn("declares evidence without evidence-aware cleanup", rendered)


if __name__ == "__main__":
    unittest.main()
