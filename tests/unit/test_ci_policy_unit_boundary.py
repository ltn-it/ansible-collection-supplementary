"""Native policy-unit checks use the same complete pinned boundary as local gates."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PolicyUnitBoundaryTests(unittest.TestCase):
    def test_native_policy_and_compile_steps_use_the_canonical_offline_dispatcher(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-ci.yml").read_text())
        steps = {step.get("name"): step for step in workflow["jobs"]["lint-sanity"]["steps"]}
        self.assertNotIn("Install Vault task integration test collection", steps)
        policy = steps["Run policy and evidence unit tests"]
        self.assertEqual(
            policy["run"],
            "bash scripts/devtools-local-quality.sh python3 -m unittest discover -s tests -p 'test_*.py'",
        )
        self.assertNotIn("ANSIBLE_COLLECTIONS_PATH", policy.get("env", {}))
        compile_step = steps["Compile workflow-facing Python tools"]["run"]
        self.assertTrue(compile_step.startswith("bash scripts/devtools-local-quality.sh python3 -c"))
        self.assertIn('compile(Path(name).read_bytes(), name, "exec")', compile_step)

    def test_canonical_discovery_preserves_installed_plugin_and_vault_runtime_checks(self):
        suite = unittest.TestLoader().discover(str(ROOT / "tests"), pattern="test_*.py")

        def identifiers(cases):
            for case in cases:
                if isinstance(case, unittest.TestSuite):
                    yield from identifiers(case)
                else:
                    yield case.id()

        found = set(identifiers(suite))
        prefix = "unit.test_vault_config_terragrunt_runtime.VaultConfigTerragruntRuntimeTests."
        self.assertIn(prefix + "test_vault_config_forwards_guarded_terragrunt_runtime_inputs", found)
        self.assertIn(prefix + "test_vault_config_local_state_fallback_guards_deploy_flavour", found)
        self.assertIn(
            "unit.test_incus_tls_transport.LifecycleWiringTests."
            "test_installed_connection_plugin_uses_explicit_project_and_remote_for_guest_command",
            found,
        )
        # The canonical runner must never silently omit function-only pytest cases.
        for path in (ROOT / "tests").rglob("test_*.py"):
            tree = ast.parse(path.read_text())
            functions = [
                node.name
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
            ]
            self.assertEqual(functions, [], str(path.relative_to(ROOT)))
            classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
            if any(
                isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_")
                for cls in classes
                for method in cls.body
            ):
                prefix = ".".join(path.relative_to(ROOT / "tests").with_suffix("").parts) + "."
                self.assertTrue(any(name.startswith(prefix) for name in found), prefix)
