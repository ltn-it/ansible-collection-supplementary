"""Exercise the actual Ansible task file against a local Vault protocol fixture."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]


class AppRoleRuntimeTests(unittest.TestCase):
    def run_role(self, *, existing=None, lookup=200, read_status=200, repeat=1, use_approle=False):
        state: dict[str, Any] = {
            "stored": existing,
            "version": 7,
            "generated": 0,
            "writes": 0,
            "lookups": 0,
            "logins": 0,
        }

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def authorized(self):
                expected = "scoped-fixture" if use_approle else "fixture-token"
                if self.headers.get("X-Vault-Token") != expected:
                    self.reply(403, {"errors": ["wrong auth token"]})
                    return False
                return True

            def do_GET(self):  # noqa: N802
                if not self.authorized():
                    return
                if self.path == "/v1/auth/custom-mount/role/test-role/role-id":
                    self.reply(200, {"data": {"role_id": "current-role-id"}})
                elif self.path == "/v1/kv/data/test/credentials":
                    if read_status != 200:
                        self.reply(read_status, {"errors": ["permission denied"]})
                    elif state["stored"] is None:
                        self.reply(404, {"errors": []})
                    else:
                        self.reply(200, {"data": {"data": state["stored"], "metadata": {"version": state["version"]}}})
                else:
                    self.reply(500, {"errors": ["unexpected path"]})

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/v1/auth/controller/login":
                    state["logins"] += 1
                    self.reply(200, {"auth": {"client_token": "scoped-fixture"}})
                    return
                if not self.authorized():
                    return
                if self.path.endswith("/secret-id/lookup"):
                    state["lookups"] += 1
                    status = 200 if body["secret_id"] == "new-secret-id" else lookup  # noqa: S105 - protocol fixture only
                    self.reply(status, {"data": {}, "errors": ["invalid secret id"] if status == 400 else []})
                elif self.path.endswith("/secret-id"):
                    state["generated"] += 1
                    self.reply(200, {"data": {"secret_id": "new-secret-id"}})
                elif self.path == "/v1/kv/data/test/credentials":
                    expected = state["version"] if state["stored"] is not None else 0
                    if body["options"]["cas"] != expected:
                        self.reply(400, {"errors": ["check-and-set failed"]})
                        return
                    state["writes"] += 1
                    state["stored"] = body["data"]
                    state["version"] += 1
                    self.reply(200, {"data": {"version": state["version"]}})
                else:
                    self.reply(500, {"errors": ["unexpected write"]})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                playbook = Path(directory) / "play.yml"
                playbook.write_text(
                    yaml.safe_dump(
                        [
                            {
                                "hosts": "localhost",
                                "gather_facts": False,
                                "vars": {
                                    "vault_config_api_url": f"http://127.0.0.1:{server.server_port}",
                                    "vault_config_api_delegate_to": "localhost",
                                    "vault_config_token": "fixture-token",
                                    "ansible_hashi_vault_mount_point": "controller",
                                    "ansible_hashi_vault_role_id": "controller-role" if use_approle else "",
                                    "ansible_hashi_vault_secret_id": "controller-secret" if use_approle else "",
                                    "vault_config_vault_validate_certs": False,
                                    "vault_config_engine_mount_point": "kv",
                                    "vault_config_auth_backends": [
                                        {"key": "global_approle", "type": "approle", "path": "custom-mount"}
                                    ],
                                    "vault_config_approle": {
                                        "role_name": "test-role",
                                        "credential_path": "test/credentials",
                                    },
                                },
                                "tasks": [
                                    {
                                        "ansible.builtin.include_tasks": str(
                                            ROOT / "roles/vault_config/tasks/approle.yml"
                                        )
                                    }
                                    for _ in range(repeat)
                                ],
                            }
                        ]
                    ),
                    encoding="utf-8",
                )
                result = subprocess.run(  # noqa: S603 - fixed local Ansible fixture
                    [shutil.which("ansible-playbook"), "-i", "localhost,", "-c", "local", str(playbook)],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(Path(directory) / "ansible-tmp")},
                )
                self.assertNotIn("new-secret-id", result.stdout)
                self.assertNotIn("fixture-token", result.stdout)
                return result, state
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_missing_credentials_created_once_then_reused(self):
        result, state = self.run_role(repeat=2)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["generated"], state["writes"], state["lookups"]), (1, 1, 1))

    def test_valid_secret_reused_and_role_id_repaired_preserving_other_fields(self):
        result, state = self.run_role(existing={"secret_id": "valid-secret-id", "role_id": "old", "extra": "retained"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["generated"], 0)
        self.assertEqual(
            state["stored"], {"secret_id": "valid-secret-id", "role_id": "current-role-id", "extra": "retained"}
        )

    def test_controller_approle_token_is_used_for_all_credential_calls(self):
        result, state = self.run_role(use_approle=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["logins"], state["generated"], state["writes"]), (1, 1, 1))

    def test_current_credentials_need_no_write(self):
        result, state = self.run_role(existing={"secret_id": "valid", "role_id": "current-role-id"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["generated"], state["writes"]), (0, 0))

    def test_expired_secret_replaced(self):
        result, state = self.run_role(existing={"secret_id": "expired"}, lookup=400)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["generated"], 1)

    def test_denied_read_does_not_create_credentials(self):
        result, state = self.run_role(read_status=403)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((state["generated"], state["writes"]), (0, 0))

    def test_denied_lookup_does_not_rotate_credentials(self):
        result, state = self.run_role(existing={"secret_id": "valid"}, lookup=403)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((state["generated"], state["writes"]), (0, 0))
