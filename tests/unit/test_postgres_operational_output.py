"""Run actual Ansible command tasks against isolated fake database executables."""

import os
import secrets
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2] / "roles/postgres_backup_restore"


class OperationalOutputTests(unittest.TestCase):
    def execute(self, action, mode, fmt, rc=0, restore_args=None):
        nonce = secrets.token_hex(16)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            log = root / "operations.log"
            log.touch(mode=0o600)
            source = root / "source.dump"
            source.write_text("fixture-source")
            backup = root / "new.dump"
            fixture = f"""#!/bin/sh
[ "$PGPASSWORD" = "{nonce}" ] || exit 99
case "$0" in
  *psql) case " $* " in *" --set ON_ERROR_STOP=1 "*) ;; *) exit 96 ;; esac ;;
esac
printf '%s\\n' 'private-diagnostic-fixture' >&2
case "$0" in
  *pg_dump) printf '%s' 'fixture-dump' ;;
  *pg_restore)
     if [ "$PGTEST_FILE_MODE" = 1 ]; then
       for last do :; done
       [ "$last" = "$PGTEST_SOURCE" ] || exit 95
       [ -f "$last" ] && [ "$(cat "$last")" = 'fixture-source' ] || exit 98
       if [ "$PGTEST_REQUIRE_PARALLEL" = 1 ]; then
         case " $* " in *" --jobs=4 "*) ;; *) exit 94 ;; esac
       fi
     else
       [ "$(cat)" = 'fixture-source' ] || exit 98
     fi
     printf '%s\\n' 'fixture-restored' ;;
  *) [ "$(cat)" = 'fixture-source' ] || exit 98
     printf '%s\\n' 'fixture-restored' ;;
esac
exit "$PGTEST_RC"
"""
            for name in ("pg_dump", "pg_restore", "psql"):
                target = binary / name
                target.write_text(fixture)
                target.chmod(0o700)
            podman = binary / "podman"
            podman.write_text("""#!/bin/sh
[ "$1 $2 $3 $4 $5" = 'exec -i --env PGPASSWORD fixture-container' ] || exit 97
shift 5
exec "$@"
""")
            podman.chmod(0o700)
            variables = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
            variables.update(
                ansible_become=False,
                postgres_backup_restore_action=action,
                postgres_backup_restore_execution_mode=mode,
                postgres_backup_restore_format=fmt,
                postgres_backup_restore_db_name="fixture",
                postgres_backup_restore_extra_pg_restore_args=restore_args or [],
                postgres_backup_restore_db_user="fixture",
                postgres_backup_restore_db_host="/fixture-socket",
                postgres_backup_restore_db_port=5432,
                postgres_backup_restore_db_password=nonce,
                postgres_backup_restore_container_name="fixture-container",
                postgres_backup_restore_operations_log_file=str(log),
                postgres_backup_restore_file=str(backup),
                postgres_backup_restore_restore_source=str(source),
                postgres_backup_restore_schedule_user="unused-fixture-account",
                postgres_backup_restore_schedule_home=str(root),
                postgres_backup_restore_schedule_environment=dict(
                    PATH=str(binary) + ":" + os.environ["PATH"],
                    PGTEST_RC=str(rc),
                    PGTEST_FILE_MODE="1" if mode == "client" and fmt == "custom" else "0",
                    PGTEST_SOURCE=str(source),
                    PGTEST_REQUIRE_PARALLEL="1" if restore_args else "0",
                ),
            )
            tasks = yaml.safe_load((ROLE / "tasks/logged_operation.yml").read_text())
            play = root / "test.yml"
            play.write_text(
                yaml.safe_dump(
                    [
                        dict(
                            name="Run isolated operation command fixture",
                            hosts="localhost",
                            connection="local",
                            gather_facts=False,
                            vars=variables,
                            tasks=tasks,
                        )
                    ]
                )
            )
            executable = shutil.which("ansible-playbook")
            self.assertIsNotNone(executable)
            env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root / "local"))
            result = subprocess.run(  # noqa: S603 - generated fixture and trusted EE executable
                [executable, "-i", "localhost,", str(play)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
                timeout=40,
            )
            self.assertEqual(result.returncode, 0 if rc == 0 else 2, result.stdout + result.stderr)
            self.assertNotIn(nonce, result.stdout + result.stderr)
            self.assertNotIn("private-diagnostic-fixture", result.stdout + result.stderr)
            contents = log.read_text()
            self.assertIn("START " + action, contents)
            self.assertIn("END " + action + " rc=" + str(rc), contents)
            self.assertIn("private-diagnostic-fixture", contents)
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            if action == "backup":
                self.assertEqual(backup.read_text(), "fixture-dump")
                self.assertNotIn("fixture-dump", contents)
                self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            else:
                self.assertIn("fixture-restored", contents)
                self.assertEqual(source.read_text(), "fixture-source")

    def test_client_and_podman_output_without_dump_bytes_in_logs(self):
        for action in ("backup", "restore"):
            for mode in ("client", "podman"):
                for fmt in ("custom", "plain"):
                    with self.subTest(action=action, mode=mode, fmt=fmt):
                        self.execute(action, mode, fmt)

    def test_restore_failure_is_logged_and_not_reported_successful(self):
        for mode in ("client", "podman"):
            with self.subTest(mode=mode):
                self.execute("restore", mode, "custom", rc=7)

    def test_parallel_client_restore_keeps_a_regular_named_archive(self):
        self.execute("restore", "client", "custom", restore_args=["--jobs=4"])
