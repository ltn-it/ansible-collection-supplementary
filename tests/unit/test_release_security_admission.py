"""Exercise release admission and the final failure path without GitHub effects."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_admission", ROOT / "scripts/release_security_admission.py")
assert SPEC is not None and SPEC.loader is not None
ADMISSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADMISSION)
JOBS = yaml.safe_load((ROOT / ".github/workflows/collection-ci.yml").read_text())["jobs"]


class ReleaseSecurityAdmissionTests(unittest.TestCase):
    def needs(self) -> dict:
        return {name: {"result": "success"} for name in ADMISSION.MANDATORY}

    def test_every_unsatisfied_mandatory_result_denies_admission(self) -> None:
        for name in ADMISSION.MANDATORY:
            for result in ("failure", "cancelled", "skipped", "pending", "queued", "in_progress", "", "unknown"):
                with self.subTest(name=name, result=result):
                    needs = self.needs()
                    needs[name]["result"] = result
                    report = ADMISSION.prerequisites(needs)
                    expected = "pending" if result in ADMISSION.PENDING else "failed"
                    self.assertEqual(expected, report["state"])
                    self.assertEqual({name: result}, report["unsatisfied"])
        needs = self.needs()
        del needs["acceptance"]
        self.assertEqual("pending", ADMISSION.prerequisites(needs)["state"])
        needs["heavy"]["result"] = "failure"
        mixed = ADMISSION.prerequisites(needs)
        self.assertEqual("failed", mixed["state"])
        self.assertEqual({"acceptance": ""}, mixed["pending"])
        self.assertEqual({"heavy": "failure"}, mixed["failed"])

    def test_not_applicable_profile_cells_still_require_successful_aggregates(self) -> None:
        needs = self.needs()
        needs["quality-matrix"]["outputs"] = {"heavy_required": "false", "acceptance_required": "false"}
        self.assertEqual("prerequisites-satisfied", ADMISSION.prerequisites(needs)["state"])
        for job in ("heavy", "acceptance"):
            step = JOBS[job]["steps"][0]
            for required, result, succeeds in (
                ("false", "skipped", True),
                ("true", "success", True),
                ("true", "skipped", False),
                ("false", "failure", False),
            ):
                with self.subTest(job=job, required=required, result=result):
                    completed = subprocess.run(  # noqa: S603 -- checked-in shell with fixed environment.
                        ["/bin/bash", "-c", step["run"]],
                        env={**os.environ, "MATRIX_RESULT": "success", "REQUIRED": required, "PROFILE_RESULT": result},
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(succeeds, completed.returncode == 0)

    def test_exact_identity_rejects_each_stale_dimension_and_missing_evidence(self) -> None:
        expected = {
            "repository": "lightning-it/ansible-collection-supplementary",
            "commit_sha": "a" * 40,
            "workflow_run_id": "123",
            "workflow_attempt": "2",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "security").mkdir()
            for relative in ("manifest.json", "security/provenance.json"):
                (root / relative).write_text(json.dumps(expected))
            ADMISSION.verify_identity(root, expected)
            for relative in ("manifest.json", "security/provenance.json"):
                for field in expected:
                    with self.subTest(relative=relative, field=field):
                        (root / relative).write_text(json.dumps({**expected, field: "stale"}))
                        with self.assertRaisesRegex(ValueError, "stale"):
                            ADMISSION.verify_identity(root, expected)
                        (root / relative).write_text(json.dumps(expected))
            (root / "manifest.json").unlink()
            with self.assertRaises(FileNotFoundError):
                ADMISSION.verify_identity(root, expected)

    def test_failed_and_pending_classification_preserve_report_and_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            for result, state in (("failure", "failed"), ("in_progress", "pending")):
                needs = self.needs()
                needs["acceptance"]["result"] = result
                with (
                    patch.object(ADMISSION, "REPORT", report),
                    patch.object(sys, "argv", ["admit", "prerequisites"]),
                    patch.dict(os.environ, {"NEEDS_JSON": json.dumps(needs)}),
                ):
                    self.assertEqual(1, ADMISSION.main())
                    self.assertEqual(state, json.loads(report.read_text())["state"])

    def test_environment_depends_on_complete_read_only_admission(self) -> None:
        admission = JOBS["release-admission"]
        self.assertNotIn("environment", admission)
        self.assertEqual({"actions": "read", "contents": "read"}, admission["permissions"])
        self.assertEqual(set(ADMISSION.MANDATORY), set(admission["needs"]))
        text = json.dumps(admission)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("id-token", text)
        for step in admission["steps"]:
            if "download-artifact@" in step.get("uses", ""):
                self.assertNotIn("run-id", step["with"])
                self.assertNotIn("github-token", step["with"])
        release = JOBS["release-security"]
        self.assertIn("release-admission", release["needs"])
        self.assertIn("needs.release-admission.result == 'success'", release["if"])
        self.assertIn("needs.release-admission.outputs.admitted == 'true'", release["if"])
        self.assertEqual("always()", admission["steps"][-1]["if"])
        self.assertIn("steps.verify.outcome == 'success'", admission["outputs"]["admitted"])

    def test_real_cli_retains_stale_or_missing_artifact_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "artifacts/evidence"
            (evidence / "security").mkdir(parents=True)
            environment = {
                **os.environ,
                "NEEDS_JSON": json.dumps(self.needs()),
                "GITHUB_REPOSITORY": "lightning-it/ansible-collection-supplementary",
                "SOURCE_SHA": "a" * 40,
                "GITHUB_RUN_ID": "123",
                "GITHUB_RUN_ATTEMPT": "2",
            }

            def execute(mode: str) -> subprocess.CompletedProcess:
                return subprocess.run(  # noqa: S603 -- local stdlib-only admission, no service access.
                    [sys.executable, str(ROOT / "scripts/release_security_admission.py"), mode],
                    env=environment,
                    cwd=root,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(0, execute("prerequisites").returncode)
            payload = {
                "repository": environment["GITHUB_REPOSITORY"],
                "commit_sha": environment["SOURCE_SHA"],
                "workflow_run_id": "123",
                "workflow_attempt": "1",
            }
            for relative in ("manifest.json", "security/provenance.json"):
                (evidence / relative).write_text(json.dumps(payload))
            self.assertNotEqual(0, execute("artifacts").returncode)
            report = root / "artifacts/release-admission.json"
            self.assertEqual("stale", json.loads(report.read_text())["state"])
            self.assertNotEqual(0, execute("complete").returncode)
            self.assertEqual(0, execute("prerequisites").returncode)
            payload["workflow_attempt"] = "2"
            for relative in ("manifest.json", "security/provenance.json"):
                (evidence / relative).write_text(json.dumps(payload))
            self.assertEqual(0, execute("artifacts").returncode)
            self.assertEqual("identity-verified", json.loads(report.read_text())["state"])
            self.assertEqual(0, execute("complete").returncode)
            self.assertEqual("admitted", json.loads(report.read_text())["state"])
            self.assertEqual(0, execute("prerequisites").returncode)
            (evidence / "manifest.json").write_text("malformed")
            self.assertNotEqual(0, execute("artifacts").returncode)
            self.assertEqual("failed", json.loads(report.read_text())["state"])
            self.assertEqual(0, execute("prerequisites").returncode)
            (evidence / "manifest.json").unlink()
            self.assertNotEqual(0, execute("artifacts").returncode)
            self.assertEqual("failed", json.loads(report.read_text())["state"])

    def test_final_release_fails_when_admission_or_security_is_not_successful(self) -> None:
        final = JOBS["release-validation"]
        self.assertIn("always()", final["if"])
        step = next(step for step in final["steps"] if step.get("name") == "Enforce every mandatory aggregate")
        environment = {key: "success" for key in step["env"]}
        environment["IS_PROTECTED_MAIN_PUSH"] = "true"
        for key in ("RELEASE_ADMISSION_RESULT", "RELEASE_SECURITY_RESULT"):
            for result in ("success", "failure", "skipped", "cancelled", "pending"):
                with self.subTest(key=key, result=result):
                    completed = subprocess.run(  # noqa: S603 -- actual aggregate script with fixed fixture values.
                        ["/bin/bash", "-c", step["run"]],
                        env={**os.environ, **environment, key: result},
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result == "success", completed.returncode == 0)

    def test_unreachable_aliases_have_no_declared_entrypoint(self) -> None:
        self.assertFalse(any(name.startswith(("legacy-", "keycloak-legacy-")) for name in JOBS))
        workflow = (ROOT / ".github/workflows/collection-ci.yml").read_text()
        self.assertNotIn("nightly-develop", workflow)
        self.assertNotIn("workflow_call", workflow)


if __name__ == "__main__":
    unittest.main()
