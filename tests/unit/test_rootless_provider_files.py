"""Run actual Ansible provider integrity tasks on isolated files, without loading code."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "roles/keycloak_deploy/tasks/rootless-providers.yml"
ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook")


@unittest.skipUnless(ANSIBLE_PLAYBOOK, "requires the prescribed Ansible EE")
class ProviderFiles(unittest.TestCase):
    def run_case(self, variant):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "providers"
            directory.mkdir(mode=0o700)
            jar = directory / "fixture.jar"
            payload = b"fixture"
            jar.write_bytes(payload)
            jar.chmod(0o600)
            expected = hashlib.sha256(payload).hexdigest()
            selected_directory = str(directory)
            if variant == "invalid_path":
                selected_directory += "\n"
            elif variant == "invalid_checksum":
                expected += "\n"
            elif variant == "tampered":
                jar.write_bytes(b"changed")
            elif variant == "extra":
                (directory / "extra.jar").write_bytes(payload)
            elif variant == "missing":
                jar.unlink()
            elif variant == "symlink":
                target = root / "unrelated.bin"
                target.write_bytes(payload)
                jar.unlink()
                jar.symlink_to(target)
            elif variant == "hardlink":
                os.link(jar, root / "other.bin")
            before = {p.name: (p.lstat().st_ino, p.lstat().st_uid, p.lstat().st_mode) for p in directory.iterdir()}
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nstdout_callback=default\n")
            play = root / "provider.yml"
            play.write_text(
                yaml.safe_dump(
                    [
                        {
                            "name": "Check isolated prepared providers",
                            "hosts": "localhost",
                            "gather_facts": False,
                            "vars": {
                                "ansible_become": False,
                                "keycloak_deploy_rootless_user": "unused-fixture-user",
                                "keycloak_deploy_rootless_providers_dir": selected_directory,
                                "keycloak_deploy_rootless_provider_checksums": {jar.name: expected},
                            },
                            "tasks": yaml.safe_load(TASKS.read_text()),
                        }
                    ],
                    sort_keys=False,
                )
            )
            assert ANSIBLE_PLAYBOOK is not None
            result = subprocess.run(  # noqa: S603 -- resolved EE executable and isolated generated fixture; no shell.
                [ANSIBLE_PLAYBOOK, "-i", "localhost,", "-c", "local", str(play)],
                env=os.environ
                | {
                    "ANSIBLE_CONFIG": str(config),
                    "ANSIBLE_LOCAL_TEMP": str(root / "local"),
                    "ANSIBLE_REMOTE_TEMP": str(root / "remote"),
                    "ANSIBLE_NOCOLOR": "1",
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            after = {p.name: (p.lstat().st_ino, p.lstat().st_uid, p.lstat().st_mode) for p in directory.iterdir()}
            self.assertEqual(before, after)
            if variant == "valid":
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(jar.read_bytes(), payload)
            else:
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("ROOTLESS_PROVIDER_", result.stdout)
            return result

    def test_matching_regular_provider_is_accepted_without_mutation(self):
        self.run_case("valid")

    def test_changed_missing_extra_and_linked_providers_stop_before_deployment(self):
        for variant in ("tampered", "missing", "extra", "symlink", "hardlink", "invalid_path", "invalid_checksum"):
            with self.subTest(variant=variant):
                self.run_case(variant)
