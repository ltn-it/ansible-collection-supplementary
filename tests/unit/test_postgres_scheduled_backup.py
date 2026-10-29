"""Filesystem and failure-path tests; real Podman/systemd acceptance is separate."""

import contextlib
import fcntl
import importlib.util
import io
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "roles/postgres_backup_restore/files/scheduled_backup.py"
SPEC = importlib.util.spec_from_file_location("scheduled_backup", SOURCE)
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


class ScheduledBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backups = self.root / "backups"
        self.backups.mkdir(mode=0o700)
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)
        self.config = {
            "instance": "postgres-test",
            "container": "postgres-test",
            "database": "app",
            "username": "app",
            "backup_dir": str(self.backups),
            "pgdata_dir": str(self.data),
            "pgdata_mount": "/var/lib/postgresql/data",
            "socket_dir": "/var/run/postgresql",
            "socket_port": 5432,
            "image": "registry.example.invalid/postgres@sha256:" + "a" * 64,
            "uid": os.geteuid(),
            "home": str(self.root),
            "retention_days": 14,
            "min_free_percent": 0,
            "timeout_seconds": 30,
            "max_age_seconds": 50400,
            "source_revision": "b" * 40,
            "podman_binary": "/usr/bin/podman",
        }
        test = self

        class FakeCommands:
            def __init__(self, config):
                self.config = config

            def inspect(self):
                return None

            def client(self, arguments, category, output=None, input_stream=None, stream_output=False):
                if category == "dump":
                    output.write(b"PGDMP-fixture-only")
                    return None
                if category == "archive":
                    test.assertIsNotNone(input_stream)
                    test.assertTrue(Path(input_stream.name).parent.name.endswith(".partial"))
                    return None
                if category == "version":
                    return b"pg_dump (PostgreSQL) 16.15\n"
                guard = b"before" if category == "roles_before" else b"after"
                return b"\\restrict " + guard + b"\nCREATE ROLE app;\n\\unrestrict " + guard + b"\n"

        self.fake = FakeCommands

    def run_backup(self, kind="scheduled"):
        with mock.patch.object(WORKER, "Commands", self.fake), contextlib.redirect_stdout(io.StringIO()):
            return WORKER.run_backup(self.config, kind)

    def completed(self):
        return [path for path in self.backups.iterdir() if WORKER.SET_ID.fullmatch(path.name)]

    def old_set(self, suffix, kind="scheduled"):
        name = "20200101T000000Z-" + suffix
        path = self.backups / name
        path.mkdir(mode=0o700)
        manifest = {
            "schema": WORKER.SCHEMA,
            "set_id": name,
            "instance": self.config["instance"],
            "database": self.config["database"],
            "kind": kind,
            "snapshot_utc": "2020-01-01T00:00:00Z",
        }
        WORKER.write_bytes(path / "database.dump", b"PGDMP-old-fixture")
        WORKER.write_bytes(path / "roles.sql", b"CREATE ROLE app;\n")
        WORKER.write_bytes(path / "manifest.json", json.dumps(manifest).encode())
        sums = "".join(
            WORKER.digest(path / item) + "  " + item + "\n" for item in ("database.dump", "roles.sql", "manifest.json")
        )
        WORKER.write_bytes(path / "SHA256SUMS", sums.encode())
        return path

    def test_complete_set_has_private_files_valid_checksums_and_status(self):
        self.assertEqual(self.run_backup(), 0)
        complete = self.completed()
        self.assertEqual(len(complete), 1)
        self.assertEqual({path.name for path in complete[0].iterdir()}, WORKER.FILES)
        self.assertEqual(stat.S_IMODE(complete[0].stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in complete[0].iterdir()))
        manifest = WORKER.verify_set(complete[0], self.config)
        self.assertEqual(manifest["kind"], "scheduled")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(WORKER.status_backup(self.config), 0)

    def test_role_changes_prevent_publication_and_preserve_previous_backups(self):
        old = self.old_set("a" * 12)
        original = self.fake.client

        def changed(commands, arguments, category, output=None, input_stream=None, stream_output=False):
            if category == "roles_after":
                return b"CREATE ROLE another_role;\n"
            if category == "archive":
                return None
            return original(commands, arguments, category, output, input_stream, stream_output)

        with mock.patch.object(self.fake, "client", changed):
            with self.assertRaises(WORKER.Failure):
                self.run_backup()
        self.assertTrue(old.is_dir())
        self.assertEqual(self.completed(), [old])
        self.assertTrue(any(path.name.endswith(".partial") for path in self.backups.iterdir()))
        self.assertFalse((self.backups / "last-success.json").exists())
        self.assertEqual(json.loads((self.backups / "last-run.json").read_text())["status"], "failed")

    def test_retention_preserves_manual_unknown_corrupt_and_symlinked_material(self):
        expired = self.old_set("a" * 12)
        manual = self.old_set("b" * 12, "manual")
        changed = self.old_set("c" * 12)
        (changed / "operator-note").write_text("keep")
        foreign = self.backups / "foreign"
        foreign.mkdir()
        linked = self.backups / ("20200101T000000Z-" + "d" * 12)
        linked.symlink_to(self.data, target_is_directory=True)
        removed = WORKER.prune(self.backups, self.config, WORKER.utc_now(), "")
        self.assertEqual(removed, 1)
        self.assertFalse(expired.exists())
        self.assertTrue(manual.is_dir() and changed.is_dir() and foreign.is_dir())
        self.assertTrue(linked.is_symlink() and self.data.is_dir())

    def test_held_lock_prevents_a_second_backup_without_touching_state(self):
        with (self.backups / ".lock").open("w") as stream:
            os.chmod(stream.name, 0o600)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_backup(), 75)
        self.assertEqual(self.completed(), [])
        self.assertFalse((self.backups / "last-run.json").exists())

    def test_altered_dump_fails_explicit_verification(self):
        old = self.old_set("a" * 12)
        (old / "database.dump").write_bytes(b"changed")
        with self.assertRaises(WORKER.Failure):
            WORKER.verify_set(old, self.config)

    def test_backup_root_symlink_and_pgdata_overlap_are_rejected(self):
        link = self.root / "linked"
        link.symlink_to(self.backups, target_is_directory=True)
        config = dict(self.config, backup_dir=str(link))
        with self.assertRaises(WORKER.Failure):
            WORKER.check_root(config)
        config = dict(self.config, backup_dir=str(self.data / "inside"), uid=max(1, os.geteuid()))
        with self.assertRaises(WORKER.Failure):
            WORKER.validate_config(config)

    def test_roles_comparison_preserves_sql_and_rejects_unpaired_guards(self):
        first = b"-- header\n\\restrict abc\nALTER ROLE app NOSUPERUSER;\n\\unrestrict abc\n"
        second = first.replace(b"abc", b"def")
        self.assertEqual(WORKER.normalized_roles(first), WORKER.normalized_roles(second))
        self.assertNotEqual(
            WORKER.normalized_roles(first), WORKER.normalized_roles(second.replace(b"NOSUPERUSER", b"SUPERUSER"))
        )
        with self.assertRaises(WORKER.Failure):
            WORKER.normalized_roles(first.replace(b"\\unrestrict abc\n", b""))

    def test_snapshot_age_not_completion_time_controls_health(self):
        old = self.old_set("a" * 12)
        WORKER.atomic_json(
            self.backups / "last-success.json",
            {
                "set_id": old.name,
                "snapshot_utc": "2020-01-01T00:00:00Z",
                "schema": WORKER.SCHEMA,
            },
        )
        WORKER.atomic_json(
            self.backups / "last-run.json",
            {
                "status": "ok",
                "finished_utc": WORKER.stamp(WORKER.utc_now()),
            },
        )
        with self.assertRaises(WORKER.Failure):
            WORKER.status_backup(self.config)

    def test_child_errors_and_ambient_credentials_are_never_forwarded(self):
        canary = secrets.token_urlsafe(24)
        response = types.SimpleNamespace(returncode=1, stdout=b"", stderr=canary.encode())
        with (
            mock.patch.dict(os.environ, {"PGPASSWORD": canary}),
            mock.patch.object(WORKER.subprocess, "run", return_value=response) as invoked,
        ):
            commands = WORKER.Commands(self.config)
            with self.assertRaises(WORKER.Failure) as error:
                commands.client(["pg_dump", "--version"], "fixture")
        self.assertTrue(canary not in str(error.exception), "Child diagnostics leaked.")
        self.assertTrue(canary not in json.dumps(invoked.call_args.kwargs["env"]), "Ambient credential forwarded.")
        self.assertTrue(all(canary not in value for value in invoked.call_args.args[0]), "Credential in argv.")

    def test_cli_failure_redacts_unexpected_secret_fields(self):
        canary = secrets.token_urlsafe(24)
        config_path = self.root / "config.json"
        WORKER.write_bytes(config_path, json.dumps(dict(self.config, password=canary)).encode())
        # Only this repository's fixed helper and a private fixture path are executed.
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(SOURCE), "--config", str(config_path), "--validate"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertTrue(canary not in result.stdout + result.stderr, "Configuration diagnostic leaked.")

    def test_client_unsets_service_variables_instead_of_selecting_an_empty_service(self):
        commands = WORKER.Commands(self.config)
        with mock.patch.object(commands, "run", return_value=b"") as invoked:
            commands.client(["pg_dump", "--version"], "version")
        arguments = invoked.call_args.args[0]
        index = arguments.index(self.config["container"])
        self.assertEqual(
            arguments[index + 1 :],
            ["env", "-u", "PGPASSWORD", "-u", "PGSERVICE", "-u", "PGSERVICEFILE", "pg_dump", "--version"],
        )
        self.assertIn("PGPASSFILE=/dev/null", arguments)

    def test_retention_preserves_a_set_with_modified_payload(self):
        old = self.old_set("c" * 12)
        (old / "database.dump").write_bytes(b"modified-payload")
        self.assertEqual(self.run_backup(), 0)
        self.assertTrue(old.exists())

    def test_manual_restore_point_does_not_trigger_automatic_pruning(self):
        old = self.old_set("a" * 12)
        original = self.fake.client

        def client(commands, arguments, category, output=None, input_stream=None, stream_output=False):
            if category == "archive":
                return None
            return original(commands, arguments, category, output, input_stream, stream_output)

        with mock.patch.object(self.fake, "client", client):
            self.assertEqual(self.run_backup("manual"), 0)
        self.assertTrue(old.is_dir())

    def test_streaming_dump_stops_before_the_filesystem_reserve_is_consumed(self):
        commands = WORKER.Commands(dict(self.config, podman_binary=sys.executable, min_free_percent=20))
        filesystem = types.SimpleNamespace(f_blocks=100000, f_bavail=20000, f_frsize=4096)
        output = io.BytesIO()
        with mock.patch.object(WORKER.os, "statvfs", return_value=filesystem):
            with self.assertRaises(WORKER.Failure):
                commands.stream_run(["-c", "import sys; sys.stdout.buffer.write(b'archive')"], "dump", output)
        self.assertEqual(output.getvalue(), b"")

    def test_archive_rejection_keeps_the_set_private_and_does_not_prune(self):
        old = self.old_set("a" * 12)
        original = self.fake.client

        def client(commands, arguments, category, output=None, input_stream=None, stream_output=False):
            if category == "archive":
                raise WORKER.Failure("archive")
            return original(commands, arguments, category, output, input_stream, stream_output)

        with mock.patch.object(self.fake, "client", client):
            with self.assertRaises(WORKER.Failure):
                self.run_backup()
        self.assertEqual(self.completed(), [old])
        self.assertTrue(any(path.name.endswith(".partial") for path in self.backups.iterdir()))

    def test_checksum_verification_runs_before_the_set_is_published(self):
        def reject(directory, config, expected_id=None):
            self.assertTrue(directory.name.endswith(".partial"))
            self.assertFalse((directory.parent / expected_id).exists())
            raise WORKER.Failure("checksum")

        with mock.patch.object(WORKER, "verify_set", side_effect=reject):
            with self.assertRaises(WORKER.Failure):
                self.run_backup()
        self.assertEqual(self.completed(), [])
        self.assertFalse((self.backups / "last-success.json").exists())


if __name__ == "__main__":
    unittest.main()
