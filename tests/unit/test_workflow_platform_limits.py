"""Compile-time contracts that must hold before any GitHub job can start."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowPlatformLimitTests(unittest.TestCase):
    def test_release_and_collection_steps_fit_the_github_run_limit(self) -> None:
        for name in ("release-prepare.yml", "collection-ci.yml"):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
            for job, definition in workflow["jobs"].items():
                for step in definition.get("steps", []):
                    if "run" in step:
                        with self.subTest(workflow=name, job=job, step=step.get("name")):
                            self.assertLessEqual(len(step["run"]), 21_000)

    def test_quality_profiles_keep_the_existing_revision_under_the_current_owner(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-ci.yml").read_text())
        profiles = [job["uses"] for job in workflow["jobs"].values() if "uses" in job]
        self.assertEqual(2, len(profiles))
        self.assertEqual(
            {
                "ltn-it/modulix-validation/.github/workflows/collection-quality-profile.yml@"
                "154c99eb0d907b01edc10e9b39c94ef4912fd9dd"
            },
            set(profiles),
        )


if __name__ == "__main__":
    unittest.main()
