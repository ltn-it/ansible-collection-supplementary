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
    def execute(
        self, action, tag, fail_operation=False, selected=True, logged=True, existing_destination=False, skip_tag=None
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "unexpected-output" if not selected and action == "backup" else root
            if existing_destination:
                destination.mkdir(mode=0o755)
            backup = destination / "postgres-new.dump"
            oldest, older, newer = (
                root / name for name in ("postgres-oldest.dump", "postgres-old.dump", "postgres-current.dump")
            )
            for number, path in enumerate((oldest, older, newer)):
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
                if "ansible.builtin.include_tasks" in task
                or task["name"] in ["Prune old PostgreSQL backups", "Ensure PostgreSQL backup directory exists"]
            ]
            values = dict(
                postgres_backup_restore_action=action,
                postgres_backup_restore_execute=True,
                postgres_backup_restore_restore_confirm="YES_RESTORE",
                postgres_backup_restore_operations_log_file="explicit-fixture-log" if logged else "",
                postgres_backup_restore_schedule_uid=os.geteuid(),
                postgres_backup_restore_schedule_user=str(os.geteuid()),
                postgres_backup_restore_schedule_group=str(os.getegid()),
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
                [executable, "-i", "localhost,", str(play), "--tags", tag]
                + (["--skip-tags", skip_tag] if skip_tag else []),
                capture_output=True,
                text=True,
                check=False,
                timeout=40,
                env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root / "local")),
            )
            self.assertEqual(result.returncode, 2 if fail_operation else 0, result.stdout + result.stderr)
            if skip_tag and action == "backup":
                self.assertEqual(
                    dict(replacement_created=backup.exists(), oldest_preserved=oldest.exists()),
                    dict(replacement_created=True, oldest_preserved=False),
                    "Selected backup must create its replacement before retention, even when restore is excluded",
                )
            if not selected:
                observed = dict(
                    destination_exists=destination.exists() if destination != root else False,
                    destination_mode=(
                        (destination.stat().st_mode & 0o777) if destination != root and destination.exists() else None
                    ),
                    prepared=preparation.exists(),
                    confirmed_restore_executed=operation.exists(),
                    backup_executed=backup.exists(),
                    scheduler_changed=schedule.exists(),
                    old_backup_preserved=older.exists(),
                    oldest_backup_preserved=oldest.exists(),
                )
                self.assertEqual(
                    observed,
                    dict(
                        destination_exists=existing_destination,
                        destination_mode=0o755 if existing_destination else None,
                        prepared=False,
                        confirmed_restore_executed=False,
                        backup_executed=False,
                        scheduler_changed=False,
                        old_backup_preserved=True,
                        oldest_backup_preserved=True,
                    ),
                    "Wrong action selection must not prepare, execute or prune",
                )
            elif action == "schedule":
                self.assertTrue(schedule.exists(), result.stdout)
                self.assertTrue(older.exists())
            else:
                self.assertTrue(preparation.exists(), result.stdout)
                if fail_operation:
                    self.assertFalse(backup.exists())
                    self.assertTrue(older.exists(), "Failed backup must not prune prior sets")
                    self.assertTrue(oldest.exists(), "Failed backup must preserve the oldest set too")
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

    def test_backup_tag_does_not_execute_confirmed_logged_restore(self):
        self.execute("restore", "backup", selected=False)

    def test_restore_tag_does_not_execute_logged_backup_or_pruning(self):
        self.execute("backup", "restore", selected=False)

    def test_restore_tag_does_not_create_unlogged_backup_directory(self):
        self.execute("backup", "restore", selected=False, logged=False)

    def test_restore_tag_preserves_existing_backup_directory_mode(self):
        for logged in (True, False):
            with self.subTest(logged=logged):
                self.execute("backup", "restore", selected=False, logged=logged, existing_destination=True)

    def test_selected_backup_runs_before_pruning_when_restore_tag_is_excluded(self):
        self.execute("backup", "backup", skip_tag="restore")

    def test_selected_restore_runs_when_backup_tag_is_excluded(self):
        self.execute("restore", "restore", skip_tag="backup")
