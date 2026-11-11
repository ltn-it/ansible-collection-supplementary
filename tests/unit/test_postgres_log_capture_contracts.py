"""Execute actual Ansible policy assertions; native metadata/deployment is separate."""

import base64
import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = Path(os.environ.get("LIT_POSTGRES_LOG_ROLE", str(ROOT / "roles/postgres_backup_restore")))


class LogCaptureContractTests(unittest.TestCase):
    def setUp(self):
        tasks = yaml.safe_load((ROLE / "tasks/schedule_log_capture.yml").read_text())
        self.contract = tasks[-1]
        self.assertEqual(self.contract["name"], "Verify the log policy belongs to this prepared database runtime")
        self.policy = dict(
            version=1, user_uid=12000, container="example-pg", operational=True, directory="/srv/postgres/logs"
        )

    def run_policy(self, policy):
        executable = shutil.which("ansible-playbook")
        self.assertIsNotNone(executable, "Run inside pinned Devtools")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            playbook = [
                {
                    "name": "Exercise installed policy contract",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        "postgres_backup_restore_schedule_uid": 12000,
                        "postgres_backup_restore_container_name": "example-pg",
                        "postgres_backup_restore_backup_dir": "/srv/postgres/backups",
                        "postgres_backup_restore_schedule_pgdata_dir": "/srv/postgres/data",
                        "postgres_backup_restore_schedule_log_policy_raw": {
                            "content": base64.b64encode(json.dumps(policy).encode()).decode()
                        },
                    },
                    "tasks": [copy.deepcopy(self.contract)],
                }
            ]
            path = root / "contract.yml"
            path.write_text(yaml.safe_dump(playbook, sort_keys=False))
            config = root / "ansible.cfg"
            config.write_text("[defaults]\n")
            environment = dict(
                os.environ,
                ANSIBLE_LOCAL_TEMP=str(root / "ansible-tmp"),
                ANSIBLE_NOCOLOR="1",
                ANSIBLE_CONFIG=str(config),
            )
            return subprocess.run(  # noqa: S603 -- resolved Ansible executable and generated local fixture, no shell.
                [executable, "-i", "localhost,", str(path)], env=environment, capture_output=True, text=True, timeout=30
            )

    def test_same_database_identity_with_disjoint_log_path_is_accepted(self):
        result = self.run_policy(self.policy)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mismatched_identity_or_unbounded_operational_contract_is_rejected(self):
        for changed in (
            {"version": 2},
            {"user_uid": 12001},
            {"container": "another-pg"},
            {"operational": False},
            {"operational": "true"},
        ):
            with self.subTest(changed=changed):
                result = self.run_policy(dict(self.policy, **changed))
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(self.contract["name"], result.stdout)

    def test_backup_and_transaction_paths_cannot_be_used_as_log_stores(self):
        for directory in (
            "/srv/postgres/backups",
            "/srv/postgres/backups/logs",
            "/srv/postgres/data",
            "/srv/postgres/data/logs",
            "/srv/postgres",
            "/",
            "relative/logs",
            "/srv/postgres/logs/",
            "/srv/postgres/../logs",
            "/srv/./logs",
            "/srv//logs",
        ):
            with self.subTest(directory=directory):
                result = self.run_policy(dict(self.policy, directory=directory))
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(self.contract["name"], result.stdout)


if __name__ == "__main__":
    unittest.main()
