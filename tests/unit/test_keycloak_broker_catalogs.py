"""Offline broker-interface tests, not live Keycloak or cross-tier acceptance."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles/keycloak_cac"
CATALOGS = ("authentication_flows", "identity_providers", "required_actions", "realm_flow_bindings")
VALID_OBJECTS = {
    "authentication_flows": {"realm": "example", "alias": "upstream-only"},
    "identity_providers": {"realm": "example", "alias": "upstream"},
    "required_actions": {
        "realm": "example",
        "state": "present",
        "required_actions": [{"alias": "idp_link", "enabled": False}],
    },
    "realm_flow_bindings": {"realm": "example", "browser_flow": "upstream-only"},
}


class KeycloakBrokerCatalogTests(unittest.TestCase):
    def precheck(self, variables: dict, success: bool, binding_probe: bool = False) -> None:
        """Run the real side-effect-free assertions, never the API tasksets."""
        play = [
            {
                "name": "Check broker catalog inputs offline",
                "hosts": "localhost",
                "gather_facts": False,
                "vars": {**yaml.safe_load((ROLE / "defaults/main.yml").read_text()), **variables},
                "tasks": [{"ansible.builtin.import_tasks": str(ROLE / "tasks/assert.yml")}],
            }
        ]
        with tempfile.TemporaryDirectory(prefix="keycloak-broker-contract-") as temporary:
            if binding_probe:
                # Keep the actual include, include vars and realm-task loop expression.
                # Replace only the API call with an offline assertion on its loop input.
                binding_file = Path(temporary) / "binding.yml"
                binding_file.write_text((ROLE / "tasks/cac_21_realm_flow_bindings.yml").read_text())
                realm_task = yaml.safe_load((ROLE / "tasks/cac_11_realms.yml").read_text())[0]
                probe = {
                    "name": "Verify the exact deferred realm input without an API call",
                    "ansible.builtin.assert": {
                        "that": ["keycloak_cac_realm_definition == keycloak_cac_realm_flow_bindings[0]"]
                    },
                    "loop": realm_task["loop"],
                    "loop_control": realm_task["loop_control"],
                }
                (Path(temporary) / "cac_11_realms.yml").write_text(yaml.safe_dump([probe]))
                play[0]["tasks"].append({"ansible.builtin.include_tasks": str(binding_file)})
            path = Path(temporary) / "precheck.yml"
            path.write_text(yaml.safe_dump(play), encoding="utf-8")
            config = Path(temporary) / "ansible.cfg"
            config.write_text("[defaults]\n", encoding="utf-8")
            environment = {
                **os.environ,
                "ANSIBLE_CONFIG": str(config),
                "ANSIBLE_STDOUT_CALLBACK": "default",
                "ANSIBLE_NOCOLOR": "1",
                "ANSIBLE_LOCAL_TEMP": str(Path(temporary) / "ansible"),
            }
            executable = shutil.which("ansible-playbook")
            self.assertIsNotNone(executable, "The pinned Devtools Ansible runtime is required.")
            arguments = [executable, "-i", "localhost,", "-c", "local", str(path)]
            if binding_probe:
                extra_file = Path(temporary) / "extra.yml"
                extra_file.write_text(yaml.safe_dump({"keycloak_cac_realms": variables["keycloak_cac_realms"]}))
                arguments.extend(["-e", f"@{extra_file}"])
            # Fixed command and generated, non-secret test fixture; no shell or external input.
            result = subprocess.run(  # noqa: S603
                arguments,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        output = result.stdout + result.stderr
        self.assertNotIn("BROKER_CONTRACT_CANARY_SECRET", output)
        if success:
            self.assertEqual(result.returncode, 0, output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn("failed=1", output)
            self.assertNotIn("couldn't resolve module/action", output)

    def test_default_catalogs_are_empty_and_secret_safe(self) -> None:
        defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
        options = yaml.safe_load((ROLE / "meta/argument_specs.yml").read_text())["argument_specs"]["main"]["options"]
        for catalog in CATALOGS:
            name = f"keycloak_cac_{catalog}"
            self.assertEqual(defaults[name], [])
            self.assertEqual(options[name]["type"], "list")
            self.assertEqual(options[name]["elements"], "dict")
            self.assertIs(options[name]["no_log"], True)
        self.precheck({}, success=True)

    def test_valid_explicit_targets_pass_without_api_access(self) -> None:
        self.precheck(
            {
                "keycloak_cac_authentication_flows": [
                    {
                        "realm": "example",
                        "alias": "restricted-login",
                        "copyFrom": "first broker login",
                        "state": "present",
                    }
                ],
                "keycloak_cac_identity_providers": [
                    {
                        "realm": "example",
                        "alias": "upstream",
                        "provider_id": "oidc",
                        "enabled": False,
                        "first_broker_login_flow_alias": "restricted-login",
                        "config": {"clientSecret": "BROKER_CONTRACT_CANARY_SECRET"},
                    }
                ],
                "keycloak_cac_realms": [{"realm": "example"}],
                "keycloak_cac_required_actions": [
                    {
                        "realm": "example",
                        "state": "present",
                        "required_actions": [{"alias": "idp_link", "enabled": False}],
                    }
                ],
                "keycloak_cac_realm_flow_bindings": [{"realm": "example", "browser_flow": "upstream-only"}],
            },
            success=True,
        )

    def test_malformed_catalogs_fail(self) -> None:
        for catalog in CATALOGS:
            for invalid in ("not-a-list", {"realm": "example"}, [42]):
                with self.subTest(catalog=catalog, invalid=invalid):
                    self.precheck({f"keycloak_cac_{catalog}": invalid}, success=False)

    def test_missing_or_blank_targets_fail(self) -> None:
        for catalog in CATALOGS:
            for invalid in ({"alias": "upstream"}, {"realm": "example", "alias": " "}):
                with self.subTest(catalog=catalog, invalid=invalid):
                    self.precheck({f"keycloak_cac_{catalog}": [invalid]}, success=False)

    def test_per_object_authentication_overrides_fail(self) -> None:
        for catalog in CATALOGS:
            base = {"keycloak_cac_realms": [{"realm": "example"}]}
            self.precheck({**base, f"keycloak_cac_{catalog}": [VALID_OBJECTS[catalog]]}, success=True)
            for override in ("token", "url", "auth_password", "validate_certs"):
                with self.subTest(catalog=catalog, override=override):
                    self.precheck(
                        {
                            **base,
                            f"keycloak_cac_{catalog}": [
                                {
                                    **VALID_OBJECTS[catalog],
                                    override: "BROKER_CONTRACT_CANARY_SECRET",
                                }
                            ],
                        },
                        success=False,
                    )

    def test_tasks_forward_objects_with_role_owned_connection(self) -> None:
        environment = NativeEnvironment()
        environment.filters["combine"] = lambda original, bound: {**original, **bound}
        connection = {
            "auth_keycloak_url": "https://keycloak.example.invalid",
            "auth_realm": "administration",
            "auth_username": "api-user",
            "auth_password": "test-only-placeholder",
            "validate_certs": True,
            "connection_timeout": 30,
        }
        role_inputs = dict(
            zip(
                (
                    "keycloak_cac_url",
                    "keycloak_cac_realm",
                    "keycloak_cac_admin_user",
                    "keycloak_cac_admin_password",
                    "keycloak_cac_validate_certs",
                    "keycloak_cac_request_timeout",
                ),
                connection.values(),
                strict=True,
            )
        )
        for filename, module, variable, catalog in (
            ("cac_17_authentication_flows.yml", "keycloak_authentication", "flow", CATALOGS[0]),
            ("cac_18_identity_providers.yml", "keycloak_identity_provider", "provider", CATALOGS[1]),
            ("cac_19_required_actions.yml", "keycloak_authentication_required_actions", "action", CATALOGS[2]),
        ):
            task = yaml.safe_load((ROLE / "tasks" / filename).read_text())[0]
            definition = {"realm": "example", "alias": "upstream"}
            inputs = {**role_inputs, f"keycloak_cac_{variable}_definition": definition}
            rendered = environment.from_string(task[f"community.general.{module}"]).render(**inputs)
            self.assertEqual(rendered, {**definition, **connection})
            self.assertIs(task["no_log"], True)
            self.assertEqual(task["loop"], "{{ keycloak_cac_" + catalog + " }}")
        main = (ROLE / "tasks/main.yml").read_text()
        self.assertIn("| sort", main)
        self.assertIn("when: not keycloak_cac_skip_apply | bool", main)
        tasks = sorted(path.name for path in (ROLE / "tasks").glob("cac_*.yml"))
        self.assertLess(tasks.index("cac_17_authentication_flows.yml"), tasks.index("cac_18_identity_providers.yml"))
        self.assertLess(tasks.index("cac_18_identity_providers.yml"), tasks.index("cac_19_required_actions.yml"))
        self.assertLess(tasks.index("cac_19_required_actions.yml"), tasks.index("cac_21_realm_flow_bindings.yml"))
        realm_tasks = yaml.safe_load((ROLE / "tasks/cac_11_realms.yml").read_text())
        self.assertEqual(len(realm_tasks), 1)
        realm_task = realm_tasks[0]
        self.assertEqual(realm_task["name"], "Reconcile Keycloak realms")
        self.assertNotIn("check_mode", realm_task)
        self.assertNotIn("register", realm_task)
        self.assertNotIn("changed_when", realm_task)
        self.assertEqual(
            realm_task["loop"],
            "{{ keycloak_cac_realm_reconciliation_catalog | default(keycloak_cac_realms) }}",
        )
        readme = (ROLE / "README.md").read_text()
        self.assertIn("reusing direct realm\nreconciliation", readme)
        self.assertNotIn("plan/reconciliation path", readme)
        binding = yaml.safe_load((ROLE / "tasks/cac_21_realm_flow_bindings.yml").read_text())[0]
        self.assertEqual(binding["ansible.builtin.include_tasks"], "cac_11_realms.yml")
        self.assertEqual(
            binding["vars"]["keycloak_cac_realm_reconciliation_catalog"], "{{ keycloak_cac_realm_flow_bindings }}"
        )

    def test_deferred_binding_survives_public_realm_catalog_from_extra_vars(self) -> None:
        self.precheck(
            {
                "keycloak_cac_realms": [{"realm": "example", "enabled": False}],
                "keycloak_cac_realm_flow_bindings": [VALID_OBJECTS["realm_flow_bindings"]],
            },
            success=True,
            binding_probe=True,
        )

    def test_binding_rejects_undeclared_absent_or_duplicate_realms(self) -> None:
        for realms in (
            [],
            [{"realm": "different"}],
            [{"realm": "example", "state": "absent"}],
            [{"realm": "example"}, {"realm": "example"}],
        ):
            with self.subTest(realms=realms):
                self.precheck(
                    {
                        "keycloak_cac_realms": realms,
                        "keycloak_cac_realm_flow_bindings": [{"realm": "example", "browser_flow": "upstream-only"}],
                    },
                    success=False,
                )

    def test_binding_rejects_duplicate_binding_realms(self) -> None:
        self.precheck(
            {
                "keycloak_cac_realms": [{"realm": "example"}],
                "keycloak_cac_realm_flow_bindings": [
                    {"realm": "example", "browser_flow": "upstream-only"},
                    {"realm": "example", "browser_flow": "fallback-browser"},
                ],
            },
            success=False,
        )

    def test_binding_realm_uniqueness_is_case_sensitive(self) -> None:
        self.precheck(
            {
                "keycloak_cac_realms": [{"realm": "Tier"}, {"realm": "tier"}],
                "keycloak_cac_realm_flow_bindings": [
                    {"realm": "Tier", "browser_flow": "upper-browser"},
                    {"realm": "tier", "browser_flow": "lower-browser"},
                ],
            },
            success=True,
        )

    def test_required_actions_reject_missing_state_or_wrong_action_list(self) -> None:
        for definition in (
            {"realm": "example", "required_actions": []},
            {"realm": "example", "state": "present", "required_actions": "idp_link"},
            {"realm": "example", "state": "present", "required_actions": {}},
        ):
            with self.subTest(definition=definition):
                self.precheck({"keycloak_cac_required_actions": [definition]}, success=False)


def load_tests(loader, tests, pattern):  # noqa: ARG001
    """Keep Ansible execution in the pinned EE even from host-side discovery."""
    if Path("/run/.containerenv").exists() or Path("/.dockerenv").exists():
        return tests

    def run_in_devtools() -> None:
        result = subprocess.run(  # noqa: S603
            [
                "/bin/bash",
                str(ROOT / "scripts/wunder-devtools-ee.sh"),
                "python3",
                "/workspace/tests/unit/test_keycloak_broker_catalogs.py",
                "-v",
            ],
            cwd=ROOT,
            env=dict(os.environ, WUNDER_DEVTOOLS_RUN_AS_HOST_UID="1"),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)

    return unittest.TestSuite([unittest.FunctionTestCase(run_in_devtools)])


if __name__ == "__main__":
    unittest.main()
