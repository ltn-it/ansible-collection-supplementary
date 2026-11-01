"""Keep dependent-role API defaults reachable across both deployment scopes."""

import unittest
from pathlib import Path

import yaml
from ansible.plugins.filter.core import regex_replace
from jinja2 import Environment, StrictUndefined, select_autoescape

ROOT = Path(__file__).resolve().parents[2]


class RootlessApiComposition(unittest.TestCase):
    def test_dependent_roles_inherit_scope_aware_api_and_explicit_override(self):
        defaults = yaml.safe_load((ROOT / "roles/keycloak_deploy/defaults/main.yml").read_text())
        environment = Environment(
            undefined=StrictUndefined, autoescape=select_autoescape(default=False, default_for_string=False)
        )
        environment.filters["regex_replace"] = regex_replace
        for scope, override, expected in (
            ("user", "", "https://sso.example.invalid:9443"),
            ("system", "", "http://127.0.0.1:8080"),
            ("user", "https://explicit.example.invalid", "https://explicit.example.invalid"),
            ("system", "https://explicit.example.invalid", "https://explicit.example.invalid"),
        ):
            with self.subTest(scope=scope, override=override):
                values = defaults | {
                    "keycloak_deploy_systemd_scope": scope,
                    "keycloak_deploy_api_url": override,
                    "keycloak_deploy_hostname": "https://sso.example.invalid:9443/",
                }
                effective = environment.from_string(defaults["keycloak_deploy_api_url_effective"]).render(values)
                self.assertEqual(effective, expected)
                for role in ("keycloak_cac", "keycloak_validate"):
                    inherited = yaml.safe_load((ROOT / f"roles/{role}/defaults/main.yml").read_text())[f"{role}_url"]
                    self.assertEqual(
                        environment.from_string(inherited).render(keycloak_deploy_api_url_effective=effective), expected
                    )

    def test_unsupported_hardcoded_startup_settings_are_rejected_before_writes(self):
        rootless = yaml.safe_load((ROOT / "roles/keycloak_deploy/tasks/rootless.yml").read_text())
        initial = rootless[0]["ansible.builtin.assert"]["that"]
        for guard in (
            "keycloak_deploy_postgres_systemd_unit_name == keycloak_deploy_postgres_pod_name ~ '-pod'",
            "keycloak_deploy_start_command == 'start'",
            "keycloak_deploy_extra_start_args | length == 0",
            "keycloak_deploy_http_relative_path == ''",
            "keycloak_deploy_db_vendor == 'postgres'",
            "keycloak_deploy_db_port | int == 5432",
        ):
            self.assertIn(guard, initial)


if __name__ == "__main__":
    unittest.main()
