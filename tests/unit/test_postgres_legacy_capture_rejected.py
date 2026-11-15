"""Execute the real role assertion without configuring services or backups."""

import copy
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2] / "roles/postgres_backup_restore"


class LegacyCaptureTests(unittest.TestCase):
    def invoke(self, value, extra_variables=None):
        tasks = yaml.safe_load((ROLE / "tasks/assert.yml").read_text())
        task = next(
            t
            for t in tasks
            if t["name"] == getattr(self, "task_name", "Reject retired custom scheduled backup log capture")
        )
        with tempfile.TemporaryDirectory() as temporary:
            playbook = Path(temporary) / "test.yml"
            playbook.write_text(
                yaml.safe_dump(
                    [
                        dict(
                            name="Check retired capture input",
                            hosts="localhost",
                            connection="local",
                            gather_facts=False,
                            vars={
                                **dict(
                                    postgres_backup_restore_action="schedule",
                                    postgres_backup_restore_schedule_state="present",
                                    postgres_backup_restore_schedule_log_config=value,
                                    postgres_backup_restore_operations_log_file=value,
                                    postgres_backup_restore_schedule_instance="fixture",
                                    postgres_backup_restore_backup_dir="/srv/backups",
                                    postgres_backup_restore_schedule_pgdata_dir="/srv/data",
                                    postgres_backup_restore_file="/srv/backups/fixture.dump",
                                    postgres_backup_restore_restore_source="/srv/backups/fixture.dump",
                                    postgres_backup_restore_schedule_retention_days=14,
                                    postgres_backup_restore_schedule_min_free_percent=20,
                                    postgres_backup_restore_schedule_timeout_seconds=30,
                                    postgres_backup_restore_schedule_max_age_seconds=50400,
                                ),
                                **(extra_variables or {}),
                            },
                            tasks=[copy.deepcopy(task)],
                        )
                    ]
                )
            )
            executable = shutil.which("ansible-playbook")
            self.assertIsNotNone(executable, "Use the pinned development EE")
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(Path(temporary) / "local"))
            return subprocess.run(  # noqa: S603 - generated fixture and trusted EE executable
                [executable, "-i", "localhost,", str(playbook)],
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

    def test_direct_worker_configuration_accepts_empty_legacy_input(self):
        result = self.invoke("")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonempty_legacy_policy_is_rejected_before_services_are_configured(self):
        result = self.invoke("/etc/podman-component-logs/postgres.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Custom log capture is retired", result.stdout)


class StandardOutputTests(unittest.TestCase):
    task_name = "Validate optional PostgreSQL operations log file"
    invoke = LegacyCaptureTests.invoke

    def test_journal_and_explicit_instance_file_are_accepted(self):
        for value in ("", "/var/log/postgres-backup/fixture/operations.log"):
            with self.subTest(value=value):
                result = self.invoke(value)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_foreign_paths_and_control_characters_are_rejected(self):
        for value in (
            "/srv/backups/operations.log",
            "/var/log/postgres-backup/other/operations.log",
            "/var/log/postgres-backup/fixture/../operations.log",
            "/invalid/a\nStandardOutput=console",
        ):
            with self.subTest(value=value):
                result = self.invoke(value)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("Use the instance-specific operations.log", result.stdout)


class ScheduleNumericTests(unittest.TestCase):
    task_name = "Reject noninteger scheduled PostgreSQL numeric settings before conversion"
    invoke = LegacyCaptureTests.invoke
    fields = ("retention_days", "min_free_percent", "timeout_seconds", "max_age_seconds")

    def test_integer_and_decimal_integer_text_are_accepted(self):
        for value in (20, "20"):
            result = self.invoke("", {"postgres_backup_restore_schedule_" + field: value for field in self.fields})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_limit_rejects_malformed_text_boolean_and_fraction(self):
        for field in self.fields:
            for value in ("twenty", True, 20.5, "20\n"):
                with self.subTest(field=field, value=value):
                    result = self.invoke("", {"postgres_backup_restore_schedule_" + field: value})
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("Scheduled backup limits must be integers", result.stdout)
