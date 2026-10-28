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
from urllib.parse import quote

import yaml

ROOT = Path(__file__).resolve().parents[2]


class AppRoleRuntimeTests(unittest.TestCase):
    def run_role(
        self,
        *,
        existing=None,
        lookup=200,
        read_status=200,
        repeat=1,
        use_approle=False,
        credential_path="test/credentials",
        target_namespace="",
        controller_namespace="",
        expiration="0001-01-01T00:00:00Z",
        soft_deleted=False,
    ):
        kv_url_path = "/v1/kv/data/" + quote(credential_path, safe="/")
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
                if (
                    self.headers.get("X-Vault-Token") != expected
                    or self.headers.get("X-Vault-Namespace", "") != target_namespace
                ):
                    self.reply(403, {"errors": ["wrong auth token"]})
                    return False
                return True

            def do_GET(self):  # noqa: N802
                if not self.authorized():
                    return
                if self.path == "/v1/auth/custom-mount/role/test-role/role-id":
                    self.reply(200, {"data": {"role_id": "current-role-id"}})
                elif self.path == kv_url_path:
                    if read_status != 200:
                        self.reply(read_status, {"errors": ["permission denied"]})
                    elif state["stored"] is None:
                        self.reply(
                            404,
                            {"data": {"data": None, "metadata": {"version": state["version"]}}}
                            if soft_deleted
                            else {"errors": []},
                        )
                    else:
                        self.reply(200, {"data": {"data": state["stored"], "metadata": {"version": state["version"]}}})
                else:
                    self.reply(500, {"errors": ["unexpected path"]})

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/v1/auth/controller/login":
                    if self.headers.get("X-Vault-Namespace", "") != controller_namespace:
                        self.reply(403, {"errors": ["wrong controller namespace"]})
                        return
                    state["logins"] += 1
                    self.reply(200, {"auth": {"client_token": "scoped-fixture"}})
                    return
                if not self.authorized():
                    return
                if self.path.endswith("/secret-id/lookup"):
                    state["lookups"] += 1
                    status = 200 if body["secret_id"] == "new-secret-id" else lookup  # noqa: S105 - protocol fixture only
                    effective_expiration = (
                        "0001-01-01T00:00:00Z" if body["secret_id"] == "new-secret-id" else expiration  # noqa: S105
                    )
                    self.reply(
                        status,
                        {
                            "data": {"expiration_time": effective_expiration},
                            "errors": ["invalid secret id"] if status == 400 else [],
                        },
                    )
                elif self.path.endswith("/secret-id"):
                    state["generated"] += 1
                    self.reply(200, {"data": {"secret_id": "new-secret-id"}})
                elif self.path == kv_url_path:
                    expected = state["version"] if state["stored"] is not None or soft_deleted else 0
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
                                    "vault_config_auth_namespace": controller_namespace,
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
                                        "credential_path": credential_path,
                                        "namespace": target_namespace,
                                    },
                                },
                                "tasks": [
                                    {
                                        "ansible.builtin.include_tasks": str(
                                            ROOT / "roles/vault_config/tasks/approle.yml"
                                        )
                                    }
                                    for _iteration in range(repeat)
                                ],
                            }
                        ]
                    ),
                    encoding="utf-8",
                )
                result = subprocess.run(  # noqa: S603 - fixed local Ansible fixture
                    [shutil.which("ansible-playbook"), "-i", "localhost,", "-c", "local", str(playbook)],
                    check=False,
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

    def test_reserved_characters_address_the_exact_kv_key(self):
        result, state = self.run_role(credential_path="team/ci#production?x=1%raw space", repeat=2)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["generated"], state["writes"]), (1, 1))

    def test_root_controller_can_manage_child_namespace(self):
        result, state = self.run_role(use_approle=True, target_namespace="child")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["logins"], state["writes"]), (1, 1))

    def test_controller_and_target_namespaces_are_independent(self):
        result, state = self.run_role(
            use_approle=True,
            controller_namespace="admin",
            target_namespace="admin/child",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["logins"], state["writes"]), (1, 1))

    def test_expired_successful_lookup_is_replaced_once(self):
        result, state = self.run_role(
            existing={"secret_id": "expired"},
            expiration="2000-01-01T00:00:00.123456789+05:30",
            repeat=2,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["generated"], state["writes"]), (1, 1))

    def test_future_expiration_with_nanoseconds_and_offset_is_reused(self):
        result, state = self.run_role(
            existing={"secret_id": "valid", "role_id": "current-role-id"},
            expiration="2999-01-01T00:00:00.123456789-05:30",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["generated"], state["writes"]), (0, 0))

    def test_malformed_expiration_fails_without_rotating(self):
        result, state = self.run_role(existing={"secret_id": "valid"}, expiration="malformed")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((state["generated"], state["writes"]), (0, 0))

    def test_soft_deleted_entry_retains_its_cas_version(self):
        result, state = self.run_role(soft_deleted=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((state["generated"], state["writes"], state["version"]), (1, 1, 8))

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
