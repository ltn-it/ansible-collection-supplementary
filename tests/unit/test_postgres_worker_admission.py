"""Run the real read-only admission preflight against isolated service fixtures."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles/postgres_backup_restore"
TASKS = ROLE / "tasks/schedule_worker_preflight.yml"


class WorkerAdmissionPreflightTests(unittest.TestCase):
    def invoke(self, extra):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            calls = root / "service-calls"
            systemctl = binary / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$*\" >> '{calls}'\n"
                'case "$*" in\n'
                " 'is-active fapolicyd.service') echo inactive; exit 3;;\n"
                " *) exit 44;;\n"
                "esac\n"
            )
            systemctl.chmod(0o700)
            values = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
            values.update(
                role_path=str(ROLE),
                postgres_backup_restore_schedule_worker="/usr/local/libexec/postgres-backup-admission-fixture.py",
            )
            values.update(extra)
            playbook = root / "preflight.yml"
            playbook.write_text(
                yaml.safe_dump(
                    [
                        dict(
                            name="Read-only fixture",
                            hosts="localhost",
                            gather_facts=False,
                            vars=values,
                            tasks=yaml.safe_load(TASKS.read_text()),
                        )
                    ],
                    sort_keys=False,
                )
            )
            executable = shutil.which("ansible-playbook")
            self.assertIsNotNone(executable, "Run in the pinned EE")
            result = subprocess.run(  # noqa: S603 -- resolved EE executable and isolated generated fixture; no shell.
                [executable, "-i", "localhost,", "-c", "local", str(playbook)],
                check=False,
                capture_output=True,
                text=True,
                timeout=40,
                env=os.environ
                | {"PATH": str(binary) + os.pathsep + os.environ["PATH"], "ANSIBLE_LOCAL_TEMP": str(root / "local")},
            )
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_inactive_unmanaged_service_needs_no_security_mutation(self):
        result, calls = self.invoke({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, ["is-active fapolicyd.service"])

    def test_approval_of_other_bytes_stops_before_service_observation(self):
        result, calls = self.invoke(
            {
                "postgres_backup_restore_schedule_fapolicyd_trust_file": "/etc/fapolicyd/trust.d/fixture",
                "postgres_backup_restore_schedule_fapolicyd_approved_sha256": hashlib.sha256(
                    b"other-payload"
                ).hexdigest(),
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("The approved digest does not identify", result.stdout)
        self.assertEqual(calls, [])

    def test_valid_payload_approval_does_not_enable_an_inactive_service(self):
        result, calls = self.invoke(
            {
                "postgres_backup_restore_schedule_fapolicyd_trust_file": "/etc/fapolicyd/trust.d/fixture",
                "postgres_backup_restore_schedule_fapolicyd_approved_sha256": hashlib.sha256(
                    (ROLE / "files/scheduled_backup.py").read_bytes()
                ).hexdigest(),
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Scoped admission requires the active existing service", result.stdout)
        self.assertEqual(calls, ["is-active fapolicyd.service"])

    def test_wildcard_or_traversal_trust_paths_stop_before_service_observation(self):
        digest = hashlib.sha256((ROLE / "files/scheduled_backup.py").read_bytes()).hexdigest()
        for path in (
            "/etc/fapolicyd/trust.d/*",
            "/etc/fapolicyd/trust.d/../global",
            "/etc/fapolicyd/trust.d/fixture\n",
        ):
            with self.subTest(path=path):
                result, calls = self.invoke(
                    {
                        "postgres_backup_restore_schedule_fapolicyd_trust_file": path,
                        "postgres_backup_restore_schedule_fapolicyd_approved_sha256": digest,
                    }
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
