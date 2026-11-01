"""Reject unit injection and retain address changes behind unchanged upstream names."""

import importlib.util
import unittest
from pathlib import Path

from ansible.errors import AnsibleFilterError

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("rootless_edge", ROOT / "plugins/filter/rootless_edge.py")
FILTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FILTER)


class RootlessEdgeInputs(unittest.TestCase):
    def test_only_canonical_network_and_usable_unique_ipv4_members_are_accepted(self):
        valid = FILTER.rootless_network_valid
        self.assertTrue(valid("10.89.50.0/24", ["10.89.50.10", "10.89.50.20"]))
        for subnet in (
            "10.89.50.0/24\n[Service]\nExecStartPre=/usr/bin/true",
            "10.89.50.0/24\n",
            "10.89.50.1/24",
            "::/64",
            "bad",
            None,
        ):
            with self.subTest(subnet=subnet):
                self.assertFalse(valid(subnet, ["10.89.50.10", "10.89.50.20"]))
        for addresses in (["10.89.50.0"], ["10.89.50.255"], ["10.89.51.10"], ["10.89.50.10"] * 2):
            self.assertFalse(valid("10.89.50.0/24", addresses))

    def test_upstream_identity_changes_only_for_a_changed_address_set(self):
        resolve = FILTER.rootless_upstream_addresses
        original = resolve("10.89.50.10 STREAM keycloak\n10.89.50.10 DGRAM\n")
        self.assertEqual(original, resolve("10.89.50.10 RAW\n10.89.50.10 STREAM keycloak\n"))
        self.assertNotEqual(original, resolve("10.89.50.11 STREAM keycloak\n"))
        for invalid in ("", "not-an-address STREAM keycloak", "::1 STREAM keycloak"):
            with self.assertRaises(AnsibleFilterError):
                resolve(invalid)

    def test_guards_precede_managed_changes_and_resolution_is_bound_to_identity(self):
        keycloak = (ROOT / "roles/keycloak_deploy/tasks/rootless.yml").read_text()
        self.assertIn("keycloak_deploy_env_extra | length == 0", keycloak.split("- name: Resolve")[0])
        self.assertIn("lit.supplementary.rootless_network_valid", keycloak.split("- name: Resolve")[0])
        guards = (ROOT / "roles/nginx_deploy/tasks/rootless.yml").read_text().split("- name: Resolve")[0]
        for setting in (
            "not nginx_deploy_skip_config | bool",
            "not nginx_deploy_skip_validate | bool",
            "nginx_deploy_config_test | bool",
            "nginx_deploy_manage_default_site | bool",
            "nginx_deploy_default_server_extra_directives | length == 0",
            "nginx_deploy_http_extra_directives | length == 0",
        ):
            self.assertIn(setting, guards)
        nginx = (ROOT / "roles/nginx_deploy/tasks/rootless-reconcile.yml").read_text()
        self.assertIn("nginx_deploy_rootless_resolution.stdout | lit.supplementary.rootless_upstream_addresses", nginx)
        self.assertLess(nginx.index("getent ahostsv4"), nginx.index("Record only the successfully"))


if __name__ == "__main__":
    unittest.main()
