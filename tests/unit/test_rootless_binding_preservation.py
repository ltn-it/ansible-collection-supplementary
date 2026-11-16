"""Existing provider/CA bindings survive a complete rootless setup or stop safely."""

import copy
import importlib.util
import secrets
import unittest
from pathlib import Path

import yaml
from ansible.errors import AnsibleFilterError

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "plugins/filter" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MANIFEST = load("native_manifest")
EDGE = load("rootless_edge")


class BindingPreservation(unittest.TestCase):
    def setUp(self):
        self.old = {
            "kind": "Pod",
            "metadata": {"name": "keycloak"},
            "spec": {
                "containers": [
                    {
                        "name": "keycloak",
                        "command": ["/opt/keycloak/bin/kc.sh"],
                        "args": ["start"],
                        "env": [
                            {"name": "KC_DB_PASSWORD", "value": secrets.token_hex(16)},
                            {"name": "KC_FEATURES", "value": "scripts"},
                        ],
                        "volumeMounts": [
                            {"name": "providers", "mountPath": "/opt/keycloak/providers", "readOnly": True}
                        ],
                    }
                ],
                "volumes": [{"name": "providers", "hostPath": {"path": "/srv/providers", "type": "Directory"}}],
            },
        }

    def preserved(self, desired):
        return MANIFEST.rootless_keycloak_bindings_preserved(yaml.safe_dump(self.old), yaml.safe_dump(desired))

    def test_additive_ca_binding_and_explicit_managed_credential_change_are_allowed(self):
        desired = copy.deepcopy(self.old)
        desired["spec"]["containers"][0]["env"][0]["value"] = secrets.token_hex(16)
        desired["spec"]["volumes"].append({"name": "ca", "hostPath": {"path": "/srv/ca", "type": "Directory"}})
        desired["spec"]["containers"][0]["volumeMounts"].append(
            {"name": "ca", "mountPath": "/opt/keycloak/conf/truststores/ca", "readOnly": True}
        )
        self.assertTrue(self.preserved(desired))

    def test_provider_mount_source_mode_feature_and_start_removal_are_rejected(self):
        for field in ("volumes", "mounts", "path", "mode", "feature", "arguments"):
            with self.subTest(field=field):
                desired = copy.deepcopy(self.old)
                app = desired["spec"]["containers"][0]
                if field == "volumes":
                    desired["spec"]["volumes"] = []
                elif field == "mounts":
                    app["volumeMounts"] = []
                elif field == "path":
                    desired["spec"]["volumes"][0]["hostPath"]["path"] = "/srv/other"
                elif field == "mode":
                    app["volumeMounts"][0]["readOnly"] = False
                elif field == "feature":
                    app["env"] = app["env"][:1]
                else:
                    app["args"].append("--optimized")
                self.assertFalse(self.preserved(desired))

    def test_env_order_is_not_a_binding_change(self):
        desired = copy.deepcopy(self.old)
        desired["spec"]["containers"][0]["env"].reverse()
        self.assertTrue(self.preserved(desired))

    def test_malformed_or_ambiguous_input_fails_without_private_payload(self):
        for original in ("kind: Pod\nkind: List", "[]", "kind: Pod\nspec: null"):
            with self.subTest(original=original), self.assertRaises(AnsibleFilterError) as caught:
                MANIFEST.rootless_keycloak_bindings_preserved(original, yaml.safe_dump(self.old))
            self.assertEqual(str(caught.exception), "Rootless Keycloak binding comparison rejected")

    def test_only_implemented_public_environment_settings_are_allowed(self):
        self.assertTrue(EDGE.rootless_keycloak_env_valid({}))
        self.assertTrue(EDGE.rootless_keycloak_env_valid({"KC_FEATURES": "scripts"}))
        self.assertTrue(EDGE.rootless_keycloak_env_valid({"KC_TRUSTSTORE_PATHS": "/opt/keycloak/conf/truststores/ca"}))
        for value in (
            {"KC_HTTP_HOST": "192.0.2.1"},
            {"KC_DB_PASSWORD": secrets.token_hex(16)},
            {"JAVA_OPTS_APPEND": "x"},
            {"KC_FEATURES": "scripts\n"},
            {"KC_FEATURES": True},
            {"KC_FEATURES": ""},
            {"KC_TRUSTSTORE_PATHS": "/opt/keycloak/conf/truststores/../data"},
        ):
            with self.subTest(names=list(value)):
                self.assertFalse(EDGE.rootless_keycloak_env_valid(value))
