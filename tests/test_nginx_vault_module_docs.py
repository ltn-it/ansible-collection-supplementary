"""Check installed Vault module contracts in the mandatory Devtools test gate.

Both the role-quality-python-tests hook and native policy unit job discover all
tests/ inside pinned Devtools, including its declared collection dependencies.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class NginxVaultModuleDocumentationTests(unittest.TestCase):
    def test_nginx_vault_options_match_installed_module_contracts(self) -> None:
        modules = (
            "community.hashi_vault.vault_kv2_get",
            "community.hashi_vault.vault_write",
            "community.hashi_vault.vault_kv2_write",
        )
        executable = shutil.which("ansible-doc")
        self.assertIsNotNone(executable, "Pinned Devtools Ansible is required")
        result = subprocess.run(  # noqa: S603 - installed documentation, no Vault calls
            [executable, "--json", *modules],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        documentation = json.loads(result.stdout)
        tasks = yaml.safe_load((ROOT / "roles/nginx_config/tasks/main.yml").read_text(encoding="utf-8"))
        for module in modules:
            with self.subTest(module=module):
                selected = [task for task in tasks if module in task]
                self.assertEqual(len(selected), 1)
                options = selected[0][module]
                supported = documentation[module]["doc"]["options"]
                self.assertIn("mount_point", supported)
                self.assertEqual(set(options) - set(supported), set())


if __name__ == "__main__":
    unittest.main()
