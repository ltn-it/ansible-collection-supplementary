"""Execute real CA update guards and partial-copy recovery tasks in isolation."""

import base64
import copy
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles/keycloak_deploy"
ANSIBLE = shutil.which("ansible-playbook")


@unittest.skipUnless(ANSIBLE, "requires the prescribed Ansible EE")
class TruststoreRecovery(unittest.TestCase):
    def run_play(self, root, tasks, variables, expected_rc, check_mode=False):
        config = root / "ansible.cfg"
        config.write_text("[defaults]\nstdout_callback=default\n")
        play = root / "play.yml"
        play.write_text(
            yaml.safe_dump(
                [dict(name="Isolated CA tasks", hosts="managed", gather_facts=False, vars=variables, tasks=tasks)],
                sort_keys=False,
            )
        )
        result = subprocess.run(  # noqa: S603 -- trusted EE executable and generated isolated task fixture.
            [ANSIBLE, "-i", "managed,", "-c", "local", str(play)] + (["--check"] if check_mode else []),
            env=os.environ
            | {
                "ANSIBLE_CONFIG": str(config),
                "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                "ANSIBLE_REMOTE_TEMP": str(root / "remote"),
                "ANSIBLE_COLLECTIONS_PATH": str(root / "collections"),
                "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "False",
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def guard_case(self, variant):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            collection = root / "collections/ansible_collections/lit/supplementary"
            collection.parent.mkdir(parents=True)
            collection.symlink_to(ROOT, target_is_directory=True)
            interpreter = root / "target-python"
            interpreter.write_text(f'#!/bin/sh\nexec "{sys.executable}" -S "$@"\n')
            interpreter.chmod(0o700)
            missing_yaml = subprocess.run(  # noqa: S603 -- own isolated interpreter wrapper.
                [str(interpreter), "-c", "import yaml"],
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(missing_yaml.returncode, 0)
            nonce = secrets.token_hex(16)
            original = {
                "kind": "Pod",
                "metadata": {"name": "fixture"},
                "spec": {
                    "containers": [
                        {
                            "name": "fixture",
                            "args": ["start"],
                            "env": [{"name": "KC_DB_PASSWORD", "value": nonce}],
                            "volumeMounts": [
                                {
                                    "name": "keycloak-truststores",
                                    "readOnly": True,
                                    "mountPath": "/opt/keycloak/conf/truststores/old",
                                }
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "keycloak-truststores", "hostPath": {"path": "/srv/old-ca", "type": "Directory"}}
                    ],
                },
            }
            desired = copy.deepcopy(original)
            if variant == "source":
                desired["spec"]["volumes"][0]["hostPath"]["path"] = "/srv/new-ca"
            elif variant == "mount":
                desired["spec"]["containers"][0]["volumeMounts"][0]["mountPath"] += "-new"
            elif variant == "mode":
                desired["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
            elif variant == "other":
                desired["spec"]["containers"][0]["env"][0]["value"] = secrets.token_hex(16)
            elif variant == "additive":
                original["spec"]["volumes"] = []
                original["spec"]["containers"][0]["volumeMounts"] = []
            all_tasks = yaml.safe_load((ROLE / "tasks/rootless-truststore-update.yml").read_text())
            tasks = [
                task
                for task in all_tasks
                if task["name"]
                in {
                    "Preserve all existing truststore and other native bindings",
                    "Require an exclusively additive truststore change",
                }
            ]
            self.assertEqual(len(tasks), 2)
            tasks.append({"name": "Report successful guard", "ansible.builtin.debug": {"msg": "CA_GUARD_PASS"}})
            output = self.run_play(
                root,
                tasks,
                {
                    "ansible_become": False,
                    "ansible_python_interpreter": str(interpreter),
                    "keycloak_deploy_truststore_original": {
                        "content": base64.b64encode(yaml.safe_dump(original).encode()).decode()
                    },
                    "keycloak_deploy_truststore_desired": yaml.safe_dump(desired),
                },
                0 if variant in {"same", "additive"} else 2,
            )
            self.assertNotIn(nonce, output)
            self.assertEqual("CA_GUARD_PASS" in output, variant in {"same", "additive"})

    def test_controller_comparison_needs_no_target_yaml_and_preserves_existing_bindings(self):
        for variant in ("same", "additive", "source", "mount", "mode", "other"):
            with self.subTest(variant=variant):
                self.guard_case(variant)

    def copy_case(self, partial_failure, link_variant=None, check_mode=False, invalidation_failure=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "sources"
            destination = root / "deployed"
            configuration = root / "config"
            for directory in (source, destination, configuration):
                directory.mkdir(mode=0o700)
            certificate = source / "added.pem"
            openssl = shutil.which("openssl")
            self.assertIsNotNone(openssl)
            generated = subprocess.run(  # noqa: S603 -- trusted EE OpenSSL, ephemeral synthetic key/certificate.
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=isolated-ca-test",
                    "-keyout",
                    str(root / "key.pem"),
                    "-out",
                    str(certificate),
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(generated.returncode, 0)
            preserved = destination / "existing.pem"
            preserved.write_bytes(certificate.read_bytes())
            marker = configuration / ".keycloak-last-applied"
            marker.write_text("APPLIED\n")
            marker.chmod(0o600)
            sources = [str(certificate)]
            if partial_failure:
                invalid = source / "invalid.pem"
                invalid.write_text("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n")
                sources.append(str(invalid))
            else:
                (destination / certificate.name).write_bytes(certificate.read_bytes())
            variables = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
            variables.update(
                ansible_become=False,
                keycloak_deploy_rootless_user=str(os.getuid()),
                keycloak_deploy_truststore_sources=sources,
                keycloak_deploy_truststore_dir=str(destination),
                keycloak_deploy_config_dir=str(configuration),
            )
            tasks = yaml.safe_load((ROLE / "tasks/rootless-truststores.yml").read_text())
            if link_variant:
                outside = root / "unrelated"
                outside.mkdir(mode=0o755)
                sentinel = outside / certificate.name
                sentinel.write_bytes(b"UNRELATED_SENTINEL")
                before = (sentinel.read_bytes(), sentinel.stat(), outside.stat())
                selected = destination / certificate.name
                if link_variant == "directory":
                    destination.rename(root / "retained")
                    destination.symlink_to(outside, target_is_directory=True)
                elif link_variant == "ancestor":
                    parent = root / "linked-parent"
                    parent.symlink_to(root, target_is_directory=True)
                    variables["keycloak_deploy_truststore_dir"] = str(parent / destination.name)
                elif link_variant == "file":
                    selected.unlink()
                    selected.symlink_to(sentinel)
                else:
                    selected.unlink()
                    os.link(sentinel, selected)
                    before = (sentinel.read_bytes(), sentinel.stat(), outside.stat())
                output = self.run_play(root, tasks, variables, 2)
                self.assertIn("ROOTLESS_CA_LINKED_PATH", output)
                self.assertEqual(before, (sentinel.read_bytes(), sentinel.stat(), outside.stat()))
                self.assertEqual(marker.read_text(), "APPLIED\n")
                return
            staging_before = {p.name for p in Path(tempfile.gettempdir()).glob("lit-keycloak-ca-*")}
            before = {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in destination.iterdir()}
            if invalidation_failure:
                self.assertNotEqual(os.getuid(), 0, "requires the prescribed non-root EE")
                configuration.chmod(0o500)
            try:
                output = self.run_play(root, tasks, variables, 2 if partial_failure else 0, check_mode=check_mode)
            finally:
                configuration.chmod(0o700)
            self.assertEqual(staging_before, {p.name for p in Path(tempfile.gettempdir()).glob("lit-keycloak-ca-*")})
            if invalidation_failure:
                self.assertIn("Permission denied", output)
                self.assertIn("Remove only this attempt's private certificate staging", output)
                self.assertEqual(marker.read_text(), "APPLIED\n")
                return
            if check_mode:
                after = {
                    p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in destination.iterdir()
                }
                self.assertEqual(before, after)
            self.assertEqual((destination / certificate.name).read_bytes(), certificate.read_bytes())
            self.assertEqual(preserved.read_bytes(), certificate.read_bytes())
            self.assertEqual(marker.exists(), not partial_failure)
            if partial_failure:
                variables["keycloak_deploy_truststore_sources"] = [str(certificate)]
                self.run_play(root, tasks, variables, 0)
                self.assertFalse(marker.exists(), "unchanged retry must retain pending reconciliation")

    def test_partial_copy_failure_invalidates_marker_even_before_an_unchanged_retry(self):
        self.copy_case(True)

    def test_marker_invalidation_failure_still_cleans_staging_and_propagates_failure(self):
        self.copy_case(True, invalidation_failure=True)

    def test_unchanged_successful_ca_copies_preserve_applied_marker(self):
        self.copy_case(False)

    def test_linked_ca_destinations_fail_before_modifying_unrelated_files(self):
        for variant in ("directory", "ancestor", "file", "hardlink"):
            with self.subTest(variant=variant):
                self.copy_case(False, variant)

    def test_check_mode_cleans_private_staging_without_publishing_or_invalidating_the_marker(self):
        self.copy_case(False, check_mode=True)
