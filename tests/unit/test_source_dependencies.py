"""Regression tests for shipped source dependency completeness."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/source_dependencies.py"
SPEC = importlib.util.spec_from_file_location("source_dependencies_test", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"unable to import {SCRIPT}")
DEPENDENCIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPENDENCIES)


class SourceDependencyTests(unittest.TestCase):
    def _copy_source(self, destination: Path) -> None:
        for filename in ("galaxy.yml", ".pre-commit-config.yaml"):
            shutil.copy2(ROOT / filename, destination / filename)
        for directory in ("collections", "containerfiles", "examples", "manifests", "meta", "roles", "scripts"):
            shutil.copytree(ROOT / directory, destination / directory)

    def test_repository_inventory_is_complete(self) -> None:
        result = DEPENDENCIES.validate_source_dependencies(root=ROOT)
        self.assertEqual(result["container_count"], 30)
        self.assertEqual(result["derived_container_count"], 1)
        self.assertEqual(result["collection_count"], 14)
        self.assertEqual(result["external_product_count"], 1)

    def test_binary_shipped_payload_is_not_decoded_as_dependency_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_source(root)
            binary = root / "roles/aap/files/vendor-artifact.bin"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(bytes(range(256)))
            result = DEPENDENCIES.validate_source_dependencies(root=root)
            self.assertEqual(result["container_count"], 30)

    def test_renovate_updates_image_copies_but_excludes_entitlement_overlay(self) -> None:
        config = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))
        self.assertEqual(config.get("ignorePaths"), ["collections/requirements-rh.yml"])
        runtime_managers = [
            manager
            for manager in config.get("customManagers", [])
            if manager.get("description") == "Digest-pinned shipped role, test, and source-inventory images"
        ]
        self.assertEqual(len(runtime_managers), 1)
        patterns = runtime_managers[0].get("managerFilePatterns", [])
        self.assertTrue(any("containerfiles" in pattern for pattern in patterns))
        self.assertTrue(any("manifests" in pattern for pattern in patterns))
        self.assertTrue(any("roles/.*/defaults" in pattern for pattern in patterns))
        self.assertTrue(any("meta/source-dependencies" in pattern for pattern in patterns))

    def test_mutable_image_and_stale_inventory_are_rejected(self) -> None:
        for case in ("mutable-source", "stale-inventory"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._copy_source(root)
                default = root / "roles/alertmanager_deploy/defaults/main.yml"
                content = default.read_text(encoding="utf-8")
                if case == "mutable-source":
                    content = content.split("@sha256:", 1)[0] + "\n"
                    default.write_text(content, encoding="utf-8")
                    expected = "mutable shipped container image"
                else:
                    inventory_path = root / "meta/source-dependencies.yml"
                    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
                    inventory["container_images"] = [
                        image
                        for image in inventory["container_images"]
                        if not image["reference"].startswith("docker.io/prom/alertmanager:")
                    ]
                    inventory_path.write_text(yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8")
                    expected = "differs from shipped source"
                with self.assertRaisesRegex(DEPENDENCIES.SourceDependencyError, expected):
                    DEPENDENCIES.validate_source_dependencies(root=root)

    def test_collection_requirements_and_role_usage_are_fail_closed(self) -> None:
        for case in ("requirement", "unaccounted-use"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._copy_source(root)
                if case == "requirement":
                    requirements = root / "collections/requirements-rh.yml"
                    content = requirements.read_text(encoding="utf-8").replace('version: "4.8.2"', 'version: "9.9.9"')
                    requirements.write_text(content, encoding="utf-8")
                    expected = "differs from shipped requirements"
                else:
                    task = root / "roles/aap/tasks/unaccounted.yml"
                    task.parent.mkdir(parents=True, exist_ok=True)
                    task.write_text(
                        "---\n- name: Unsafe undeclared dependency\n  example.vendor.module:\n    value: true\n",
                        encoding="utf-8",
                    )
                    # Use a namespace that the scanner intentionally treats as a
                    # collection dependency rather than an arbitrary YAML key.
                    task.write_text(task.read_text().replace("example.vendor.module", "infra.unknown.module"))
                    expected = "unaccounted collections"
                with self.assertRaisesRegex(DEPENDENCIES.SourceDependencyError, expected):
                    DEPENDENCIES.validate_source_dependencies(root=root)

    def test_external_license_disposition_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_source(root)
            inventory_path = root / "meta/source-dependencies.yml"
            inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
            inventory["external_products"][0]["disposition"] = "verified"
            inventory_path.write_text(yaml.safe_dump(inventory, sort_keys=False), encoding="utf-8")
            with self.assertRaisesRegex(DEPENDENCIES.SourceDependencyError, "unsafe external product"):
                DEPENDENCIES.validate_source_dependencies(root=root)


if __name__ == "__main__":
    unittest.main()
