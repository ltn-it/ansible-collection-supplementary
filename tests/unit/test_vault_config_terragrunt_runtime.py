import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class VaultConfigTerragruntRuntimeTests(unittest.TestCase):
    def test_vault_config_forwards_guarded_terragrunt_runtime_inputs(self):
        defaults = yaml.safe_load((ROOT / "roles/vault_config/defaults/main.yml").read_text(encoding="utf-8"))
        tasks = (ROOT / "roles/vault_config/tasks/config.yml").read_text(encoding="utf-8")
        assertions = (ROOT / "roles/vault_config/tasks/assert.yml").read_text(encoding="utf-8")

        assert defaults["vault_config_terragrunt_import_strict"] is False
        assert defaults["vault_config_terragrunt_state_migration_strict"] is False
        assert defaults["vault_config_terragrunt_init_upgrade"] is False
        assert "terragrunt_import_strict: {{ vault_config_terragrunt_import_strict" in tasks
        assert "terragrunt_state_moves: {{ vault_config_terragrunt_state_moves" in tasks
        assert "terragrunt_state_removals: {{ vault_config_terragrunt_state_removals" in tasks
        assert "terragrunt_state_migration_strict: {{" in tasks
        assert "vault_config_terragrunt_state_migration_strict" in tasks
        assert "terragrunt_init_upgrade: {{ vault_config_terragrunt_init_upgrade" in tasks
        for variable in (
            "vault_config_terragrunt_import_strict",
            "vault_config_terragrunt_state_moves",
            "vault_config_terragrunt_state_removals",
            "vault_config_terragrunt_state_migration_strict",
            "vault_config_terragrunt_init_upgrade",
        ):
            assert variable in assertions

    def test_vault_config_local_state_fallback_guards_deploy_flavour(self):
        defaults_text = (ROOT / "roles/vault_config/defaults/main.yml").read_text(encoding="utf-8")

        assert "vault_deploy_flavour | default('vault', true)" in defaults_text
