"""Exercise shipped includes and pruning with real Ansible tag selection.

Privileged child effects use isolated untagged marker tasks. Actual database
commands and native scheduling are covered by separate integration tests.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2] / "roles/postgres_backup_restore"


class TaggedOperationTests(unittest.TestCase):
    def execute(self, action, tag, fail_operation=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "postgres-new.dump"
            older, newer = root / "postgres-old.dump", root / "postgres-current.dump"
            for number, path in enumerate((older, newer), 1):
                path.write_text("protected-old-backup")
                os.utime(path, (number, number))
            preparation, operation, schedule = (root / name for name in ("prepared", "operated", "scheduled"))
            children = {
                "schedule.yml": [
                    dict(
                        name="Isolated scheduler action",
                        **{"ansible.builtin.copy": dict(dest=str(schedule), content="configured", mode="0600")},
                    )
                ],
                "schedule_output.yml": [
                    dict(
                        name="Isolated protected output preparation",
                        **{"ansible.builtin.copy": dict(dest=str(preparation), content="prepared", mode="0600")},
                    )
                ],
                "logged_operation.yml": [
                    dict(
                        name="Require output preparation before the operation",
                        **{
                            "ansible.builtin.command": dict(argv=["test", "-f", str(preparation)]),
                            "changed_when": False,
                        },
                    ),
                    dict(
                        name="Isolated database operation",
                        **{
                            "ansible.builtin.copy": dict(
                                dest=str(backup if action == "backup" else operation),
                                content="replacement",
                                mode="0600",
                            )
                        },
                    ),
                ],
            }
            if fail_operation:
                children["logged_operation.yml"][1] = dict(
                    name="Fail the database fixture", **{"ansible.builtin.fail": dict(msg="OWNED_DATABASE_FAILURE")}
                )
            for filename, tasks in children.items():
                (root / filename).write_text(yaml.safe_dump(tasks))
            # Preserve shipped parameters, conditions and real pruning. The
            # replacement child effects deliberately have no tags.
            main = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
            tasks = [
                task
                for task in main
                if "ansible.builtin.include_tasks" in task or task["name"] == "Prune old PostgreSQL backups"
            ]
            values = dict(
                postgres_backup_restore_action=action,
                postgres_backup_restore_execute=True,
                postgres_backup_restore_operations_log_file="explicit-fixture-log",
                postgres_backup_restore_file=str(backup),
                postgres_backup_restore_backup_dir=str(root),
                postgres_backup_restore_retention_keep_last=2,
            )
            play = root / "test.yml"
            play.write_text(
                yaml.safe_dump(
                    [
                        dict(
                            name="Untagged invocation",
                            hosts="localhost",
                            connection="local",
                            gather_facts=False,
                            vars=values,
                            tasks=tasks,
                        )
                    ]
                )
            )
            executable = shutil.which("ansible-playbook")
            self.assertIsNotNone(executable)
            result = subprocess.run(  # noqa: S603 -- trusted Ansible and owned temporary fixture.
                [executable, "-i", "localhost,", str(play), "--tags", tag],
                capture_output=True,
                text=True,
                check=False,
                timeout=40,
                env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root / "local")),
            )
            self.assertEqual(result.returncode, 2 if fail_operation else 0, result.stdout + result.stderr)
            if action == "schedule":
                self.assertTrue(schedule.exists(), result.stdout)
                self.assertTrue(older.exists())
            else:
                self.assertTrue(preparation.exists(), result.stdout)
                if fail_operation:
                    self.assertFalse(backup.exists())
                    self.assertTrue(older.exists(), "Failed backup must not prune prior sets")
                elif action == "backup":
                    self.assertEqual(backup.read_text(), "replacement")
                    self.assertFalse(older.exists())
                else:
                    self.assertEqual(operation.read_text(), "replacement")
                    self.assertTrue(older.exists())
            self.assertEqual(newer.read_text(), "protected-old-backup")

    def test_schedule_children_inherit_each_public_schedule_tag(self):
        for tag in ("backup", "schedule"):
            with self.subTest(tag=tag):
                self.execute("schedule", tag)

    def test_logged_backup_prepares_output_and_creates_replacement_before_pruning(self):
        self.execute("backup", "backup")

    def test_logged_restore_prepares_output_and_runs_restore(self):
        self.execute("restore", "restore")

    def test_failed_tagged_backup_preserves_previous_sets(self):
        self.execute("backup", "backup", fail_operation=True)
