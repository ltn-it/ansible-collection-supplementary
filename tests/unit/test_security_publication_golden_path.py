from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "collection-publish.yml"
MODULIX_WINDOW_PATH = ROOT / ".github" / "workflows" / "modulix-validation-window.yml"


class SecurityPublicationGoldenPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.workflow_text)
        cls.publish = cls.workflow["jobs"]["publish"]
        cls.steps = {step.get("name"): step for step in cls.publish["steps"]}
        cls.step_names = [step.get("name") for step in cls.publish["steps"]]
        cls.finalize = cls.workflow["jobs"]["publish-security-finalize"]
        cls.finalize_steps = {step.get("name"): step for step in cls.finalize["steps"]}
        cls.finalize_names = [step.get("name") for step in cls.finalize["steps"]]

    def test_security_classification_selects_exact_self_hosted_runner_labels(self) -> None:
        classification = self.workflow["jobs"]["security-classification"]
        self.assertEqual("${{ steps.runner.outputs.labels }}", classification["outputs"]["publish-runner"])
        runner = next(step for step in classification["steps"] if step.get("id") == "runner")
        self.assertIn('["self-hosted","linux","x64","incus"]', runner["run"])
        self.assertIn('["ubuntu-latest"]', runner["run"])
        self.assertEqual(
            "${{ fromJSON(needs.security-classification.outputs.publish-runner) }}",
            self.publish["runs-on"],
        )

    def test_normal_release_keeps_the_existing_approval_environment(self) -> None:
        environment = self.publish["environment"]["name"]
        self.assertIn("'mlx90-security-publish'", environment)
        self.assertIn("'ansible-collections'", environment)
        self.assertIn("lightning-it-release-automation[bot]", self.publish["if"])

    def test_release_validation_wait_covers_complete_ci_budget(self) -> None:
        environment = self.workflow["env"]
        self.assertFalse(
            {
                "RELEASE_VALIDATION_WINDOW_ATTEMPTS",
                "RELEASE_VALIDATION_FINAL_ATTEMPTS",
                "RELEASE_VALIDATION_POLL_SECONDS",
            }
            & environment.keys()
        )
        required = int(environment["RELEASE_VALIDATION_WORST_CASE_MINUTES"]) + int(
            environment["RELEASE_VALIDATION_QUEUE_ALLOWANCE_MINUTES"]
        )
        jobs = self.workflow["jobs"]
        reusable = yaml.safe_load((WORKFLOW_PATH.parent / "release-validation-window.yml").read_text())
        self.assertLessEqual(reusable["jobs"]["window"]["timeout-minutes"], 90)
        wait = reusable["jobs"]["window"]["steps"][0]["run"]
        intervals = re.findall(r"(?m)^\s*sleep ([1-9][0-9]*)\s*$", wait)
        self.assertEqual(["30"], intervals)
        poll_seconds = int(intervals[0])
        attempts = 0
        predecessor = "security-classification"
        for index in range(1, 9):
            job_name = (
                "release-validation"
                if index == 8
                else ("release-validation-window" if index == 1 else f"release-validation-window-{index}")
            )
            job = jobs[job_name]
            self.assertEqual(predecessor, job["needs"])
            self.assertEqual("./.github/workflows/release-validation-window.yml", job["uses"])
            self.assertEqual("${{ inputs.release_sha }}", job["with"]["release_sha"])
            self.assertEqual(140 if index == 8 else 160, job["with"]["attempts"])
            attempts += job["with"]["attempts"]
            self.assertEqual(index == 8, job["with"]["final_window"])
            if index > 1:
                for binding, output in (
                    ("prior_run_id", "ci-run-id"),
                    ("prior_run_attempt", "ci-run-attempt"),
                    ("prior_complete", "complete"),
                ):
                    self.assertEqual(f"${{{{ needs.{predecessor}.outputs.{output} }}}}", job["with"][binding])
            predecessor = job_name
        budget = attempts * poll_seconds // 60
        self.assertEqual(630, budget)
        self.assertGreaterEqual(budget, required)
        for exact_identity in (
            '.event == "push"',
            '.head_branch == "main"',
            ".head_sha == $sha",
        ):
            self.assertIn(exact_identity, wait)
        self.assertIn(".run_attempt == $run_attempt", wait)
        self.assertIn('test "$conclusion" = success', wait)
        self.assertIn('test "$gate_count" -eq 1', wait)
        self.assertEqual(["security-classification", "release-validation"], self.publish["needs"])
        self.assertNotIn("Wait for exact-SHA main Release Validation", self.step_names)
        download = self.steps["Download exact candidate and evidence from validated run"]
        self.assertEqual("${{ needs.release-validation.outputs.ci-run-id }}", download["env"]["CI_RUN_ID"])
        self.assertEqual("${{ needs.release-validation.outputs.ci-run-attempt }}", download["env"]["CI_RUN_ATTEMPT"])
        self.assertEqual(2, download["run"].count("scripts/verify-release-ci-run.sh"))
        validate = self.steps["Validate candidate, MANIFEST, evidence, and repository policy"]
        self.assertEqual("${{ needs.release-validation.outputs.ci-run-id }}", validate["env"]["CI_RUN_ID"])
        self.assertEqual("${{ needs.release-validation.outputs.ci-run-attempt }}", validate["env"]["CI_RUN_ATTEMPT"])
        for evidence in ("evidence_manifest", "publication", "security_receipt"):
            self.assertIn(f'{evidence}.get("workflow_attempt")', validate["run"])
        for name in (
            "Revalidate exact CI producer before external staging",
            "Revalidate exact CI producer before release publication",
            "Revalidate exact CI producer before Galaxy publication",
        ):
            self.assertIn(
                'scripts/verify-release-ci-run.sh "$RELEASE_SHA" "$CI_RUN_ID" "$CI_RUN_ATTEMPT"',
                self.steps[name]["run"],
            )

    def test_release_validation_window_rejects_changed_identity_and_failed_gate(self) -> None:
        reusable = yaml.safe_load((WORKFLOW_PATH.parent / "release-validation-window.yml").read_text())
        wait = reusable["jobs"]["window"]["steps"][0]["run"]
        stub = """#!/usr/bin/env python3
import json
import os
import sys

case = os.environ["STUB_CASE"]
sha = "a" * 40
run = {
    "id": 123, "run_attempt": 2 if case == "changed-attempt" else 1,
    "event": "push", "head_branch": "main",
    "head_sha": "b" * 40 if case == "changed-sha" else sha,
    "status": "completed", "conclusion": "success",
}
path = next(arg for arg in sys.argv[1:] if arg.startswith("repos/"))
if path.endswith("/jobs"):
    gate = {
        "name": "Collection / Release Validation", "run_attempt": 1,
        "status": "completed", "conclusion": "failure" if case == "failed-gate" else "success",
    }
    result = [{"jobs": [gate]}]
elif path.endswith("/runs"):
    matches = [run, {**run, "id": 124}] if case in {"ambiguous", "late-duplicate"} else [run]
    result = {"total_count": len(matches), "workflow_runs": matches}
else:
    result = run
print(json.dumps(result))
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text(stub, encoding="utf-8")
            gh.chmod(0o755)
            for case in ("success", "changed-attempt", "changed-sha", "failed-gate", "ambiguous", "late-duplicate"):
                with self.subTest(case=case):
                    output = root / f"{case}.output"
                    environment = {
                        **os.environ,
                        "PATH": f"{bin_dir}:{os.environ['PATH']}",
                        "STUB_CASE": case,
                        "GITHUB_REPOSITORY": "lightning-it/ansible-collection-supplementary",
                        "GITHUB_OUTPUT": str(output),
                        "GH_TOKEN": "fixture",
                        "RELEASE_SHA": "a" * 40,
                        "PRIOR_RUN_ID": "" if case == "ambiguous" else "123",
                        "PRIOR_RUN_ATTEMPT": "" if case == "ambiguous" else "1",
                        "PRIOR_COMPLETE": "false",
                        "ATTEMPTS": "1",
                        "FINAL_WINDOW": "true",
                    }
                    result = subprocess.run(  # noqa: S603 -- fixed checked-in workflow with a local gh stub.
                        ["/bin/bash", "-e", "-c", wait],
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if case == "success":
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertIn("ci-run-id=123", output.read_text(encoding="utf-8"))
                        self.assertIn("ci-run-attempt=1", output.read_text(encoding="utf-8"))
                        self.assertIn("complete=true", output.read_text(encoding="utf-8"))
                    else:
                        self.assertNotEqual(0, result.returncode, result.stdout)
                        self.assertFalse(output.exists())
                    publisher_check = subprocess.run(  # noqa: S603 -- fixed checked-in verifier with a local gh stub.
                        ["/bin/bash", str(ROOT / "scripts/verify-release-ci-run.sh"), "a" * 40, "123", "1"],
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if case == "success":
                        self.assertEqual(0, publisher_check.returncode, publisher_check.stderr)
                    else:
                        self.assertNotEqual(0, publisher_check.returncode, publisher_check.stdout)

    def test_final_window_queries_after_last_sleep_without_extending_budget(self) -> None:
        reusable = yaml.safe_load((WORKFLOW_PATH.parent / "release-validation-window.yml").read_text())
        wait = reusable["jobs"]["window"]["steps"][0]["run"]
        stub = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
clock = int(Path(os.environ['FIXTURE_CLOCK']).read_text())
case = os.environ['STUB_CASE']
terminal = clock >= 60
run = {'id': 123, 'run_attempt': 2 if terminal and case == 'changed-attempt' else 1,
       'event': 'push', 'head_branch': 'main', 'head_sha': 'a' * 40,
       'status': 'completed' if terminal and case != 'pending' else 'in_progress',
       'conclusion': ('failure' if case == 'failed' else 'success') if terminal else None}
path = next(arg for arg in sys.argv[1:] if arg.startswith('repos/'))
if path.endswith('/jobs'):
    value = [{'jobs': [{'name': 'Collection / Release Validation', 'run_attempt': 1,
                       'status': 'completed', 'conclusion': 'success'}]}]
elif path.endswith('/runs'):
    runs = [run, {**run, 'id': 124}] if terminal and case == 'duplicate' else [run]
    value = {'total_count': len(runs), 'workflow_runs': runs}
else:
    value = run
print(json.dumps(value))
"""
        sleeper = """#!/usr/bin/env python3
import os, sys
from pathlib import Path
clock = Path(os.environ['FIXTURE_CLOCK'])
clock.write_text(str(int(clock.read_text()) + int(sys.argv[1])))
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in (("gh", stub), ("sleep", sleeper)):
                executable = root / name
                executable.write_text(content, encoding="utf-8")
                executable.chmod(0o755)
            for case in ("success", "pending", "failed", "duplicate", "changed-attempt"):
                with self.subTest(case=case):
                    clock = root / "clock"
                    clock.write_text("0", encoding="utf-8")
                    output = root / f"{case}.output"
                    result = subprocess.run(  # noqa: S603 -- shipped workflow and local fixture binaries.
                        ["/bin/bash", "-e", "-c", wait],
                        env={
                            **os.environ,
                            "PATH": f"{root}:{os.environ['PATH']}",
                            "FIXTURE_CLOCK": str(clock),
                            "STUB_CASE": case,
                            "GITHUB_REPOSITORY": "lightning-it/ansible-collection-supplementary",
                            "GITHUB_OUTPUT": str(output),
                            "GH_TOKEN": "fixture",
                            "RELEASE_SHA": "a" * 40,
                            "PRIOR_RUN_ID": "123",
                            "PRIOR_RUN_ATTEMPT": "1",
                            "PRIOR_COMPLETE": "false",
                            "ATTEMPTS": "2",
                            "FINAL_WINDOW": "true",
                        },
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual("60", clock.read_text(encoding="utf-8"))
                    if case == "success":
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertIn("complete=true", output.read_text(encoding="utf-8"))
                    else:
                        self.assertNotEqual(0, result.returncode)
                        self.assertFalse(output.exists())

    def test_security_order_is_nexus_then_signed_modulix_then_galaxy(self) -> None:
        nexus = self.step_names.index("Stage exact Security candidate in native Nexus Galaxy v3")
        dispatch = self.step_names.index("Dispatch exact ModuLix validation request once")
        receipt = self.finalize_names.index("Reverify the same signed ModuLix receipt")
        finalize = self.finalize_names.index("Finalize immutable release attachments and notes")
        galaxy = self.finalize_names.index("Publish or verify validated artifact on Ansible Galaxy")
        self.assertLess(nexus, dispatch)
        self.assertLess(receipt, finalize)
        self.assertLess(finalize, galaxy)
        self.assertIn("modulix-validation-window-6", self.finalize["needs"])
        self.assertIn("needs.modulix-validation-window-6.outputs.complete == 'true'", self.finalize["if"])
        self.assertIn(
            "--phase window --final-window", self.finalize_steps["Reverify the same signed ModuLix receipt"]["run"]
        )

        for name in (
            "Stage exact Security candidate in native Nexus Galaxy v3",
            "Mint read-only release automation installation audit token",
            "Verify exact release automation installation and allowlist",
            "Mint exact ModuLix validation App token",
            "Dispatch exact ModuLix validation request once",
        ):
            self.assertEqual(
                "env.SECURITY_RELEASE == 'true' && env.GALAXY_REQUIRED == 'true'",
                self.steps[name]["if"],
            )
        self.assertNotIn(
            'test "$GALAXY_REQUIRED" = true',
            self.steps["Stage exact Security candidate in native Nexus Galaxy v3"]["run"],
        )

    def test_nexus_stage_is_native_v3_readback_and_fails_without_configuration(self) -> None:
        stage = self.steps["Stage exact Security candidate in native Nexus Galaxy v3"]
        self.assertEqual("${{ vars.NEXUS_GALAXY_REPOSITORY_URL }}", stage["env"]["NEXUS_GALAXY_REPOSITORY_URL"])
        self.assertEqual("${{ vars.NEXUS_GALAXY_REPOSITORY }}", stage["env"]["NEXUS_GALAXY_REPOSITORY"])
        self.assertEqual("${{ secrets.NEXUS_GALAXY_USERNAME }}", stage["env"]["NEXUS_GALAXY_USERNAME"])
        self.assertEqual("${{ secrets.NEXUS_GALAXY_PASSWORD }}", stage["env"]["NEXUS_GALAXY_PASSWORD"])
        self.assertIn("scripts/nexus-galaxy-v3-stage.py", stage["run"])
        self.assertNotIn("set -x", stage["run"])

        script = (ROOT / "scripts" / "nexus-galaxy-v3-stage.py").read_text(encoding="utf-8")
        self.assertIn("/api/v3/plugin/ansible/content/published/collections/artifacts/", script)
        self.assertIn("Nexus readback bytes differ", script)
        self.assertNotIn("print(password", script)

    def test_staged_release_handoff_is_bound_before_modulix_dispatch(self) -> None:
        stage = self.step_names.index("Stage exact Security candidate in native Nexus Galaxy v3")
        handoff = self.step_names.index("Create exact staged-release handoff")
        upload = self.step_names.index("Upload bound staged release")
        receipt = self.step_names.index("Dispatch exact ModuLix validation request once")
        self.assertLess(stage, handoff)
        self.assertLess(handoff, upload)
        self.assertLess(upload, receipt)
        step = self.steps["Create exact staged-release handoff"]
        self.assertEqual("env.SECURITY_RELEASE == 'true' && env.GALAXY_REQUIRED == 'true'", step["if"])
        for field in ("$GITHUB_RUN_ID", "$GITHUB_RUN_ATTEMPT", "$CI_RUN_ID", "$CI_RUN_ATTEMPT", "$RELEASE_SHA"):
            self.assertIn(field, step["run"])
        self.assertIn("scripts/release-stage-handoff.py create", step["run"])
        artifact = self.steps["Upload bound staged release"]
        self.assertEqual(step["if"], artifact["if"])
        self.assertIn("release-stage-handoff.json", artifact["with"]["path"])
        self.assertIn("dist/", artifact["with"]["path"])
        self.assertIn("incoming/", artifact["with"]["path"])
        self.assertEqual("error", artifact["with"]["if-no-files-found"])
        self.assertEqual("${{ steps.release-handoff.outputs.sha256 }}", self.publish["outputs"]["handoff-sha256"])

    def test_staged_handoff_preserves_portable_attestations_without_download_scratch(self) -> None:
        candidate = "lit-supplementary-3.2.4.tar.gz"
        portable = f"{candidate}.attestation.jsonl"
        raw = f"dist/attestation-download/{candidate}/sha256:{'c' * 64}.jsonl"
        files = {
            f"incoming/candidate/{candidate}": b"exact candidate",
            f"dist/release/{candidate}": b"exact candidate",
            f"dist/attestation-bundles/{portable}": b"verified attestation\n",
            f"dist/release/{portable}": b"verified attestation\n",
            "dist/validation/nexus-stage.json": b'{"staged":true}\n',
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, payload in {**files, raw: b"verified attestation\n"}.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            (root / "scripts").mkdir()
            (root / "scripts/release-stage-handoff.py").write_bytes(
                (ROOT / "scripts/release-stage-handoff.py").read_bytes()
            )
            environment = {
                **os.environ,
                "CANDIDATE_NAME": candidate,
                "CI_RUN_ATTEMPT": "1",
                "CI_RUN_ID": "456",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_RUN_ID": "123",
                "RELEASE_SHA": "a" * 40,
                "RELEASE_VERSION": "3.2.4",
                "SECURITY_EVIDENCE_ID": "MLX90-GHSA-VJJF-WC74-GP86-3.2.4",
                "RUNNER_TEMP": str(root),
                "GITHUB_OUTPUT": str(root / "output"),
            }
            result = subprocess.run(  # noqa: S603 -- fixed checked-in workflow on disposable fixture files.
                ["/bin/bash", "-c", self.steps["Create exact staged-release handoff"]["run"]],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            manifest_path = root / "release-stage-handoff.json"
            manifest = json.loads(manifest_path.read_bytes())
            rows = {row["path"]: row for row in manifest["files"]}
            self.assertEqual(set(files), set(rows))
            self.assertFalse((root / "dist/attestation-download").exists())
            for name, payload in files.items():
                self.assertNotRegex(name, r'[":<>|*?\\]')
                self.assertEqual(payload, (root / name).read_bytes())
                self.assertEqual(hashlib.sha256(payload).hexdigest(), rows[name]["sha256"])
            restored = subprocess.run(  # noqa: S603 -- fixed checked-in verifier on the generated fixture handoff.
                [
                    sys.executable,
                    "scripts/release-stage-handoff.py",
                    "verify",
                    "--root",
                    ".",
                    "--binding",
                    "release-stage-binding.json",
                    "--manifest",
                    "release-stage-handoff.json",
                    "--expected-sha256",
                    hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(0, restored.returncode, restored.stderr)

    def test_reusable_modulix_window_rechecks_handoff_and_never_dispatches(self) -> None:
        workflow = yaml.safe_load(MODULIX_WINDOW_PATH.read_text(encoding="utf-8"))
        window = workflow["jobs"]["window"]
        self.assertEqual(90, window["timeout-minutes"])
        self.assertEqual("mlx90-security-publish", window["environment"])
        self.assertIn("github.actor_id == '307565056'", window["if"])
        steps = {step["name"]: step for step in window["steps"]}
        self.assertIn("3.14", steps["Setup Python for bound validation"]["with"]["python-version"])
        verify = steps["Rebuild and verify exact staged-release handoff"]["run"]
        self.assertIn("scripts/release-stage-handoff.py verify", verify)
        self.assertIn('--expected-sha256 "$HANDOFF_SHA256"', verify)
        self.assertIn("$GITHUB_RUN_ATTEMPT", verify)
        self.assertIn("$CI_RUN_ATTEMPT", verify)
        self.assertIn("scripts/verify-release-ci-run.sh", verify)
        token = steps["Mint exact ModuLix validation App token"]
        self.assertEqual("modulix-validation", token["with"]["repositories"])
        self.assertEqual("read", token["with"]["permission-actions"])
        poll = steps["Poll only the bound ModuLix run"]["run"]
        self.assertIn("--phase window", poll)
        self.assertIn("--bound-run-attempt", poll)
        self.assertIn("--final-window", poll)
        self.assertNotIn("--phase dispatch", poll)

    def test_finalizer_fetches_reviewed_merge_parents_before_verification(self) -> None:
        checkout = self.finalize_steps["Checkout exact source for Security finalization"]
        self.assertEqual(0, checkout["with"]["fetch-depth"])
        self.assertFalse(checkout["with"]["persist-credentials"])
        self.assertEqual("${{ inputs.release_sha }}", checkout["with"]["ref"])
        self.assertLess(
            self.finalize_names.index(checkout["name"]),
            self.finalize_names.index("Re-prove protected release and reviewed merge"),
        )

    def test_only_initial_modulix_dispatch_token_can_write_actions(self) -> None:
        self.assertEqual(
            {
                "actions": "read",
                "attestations": "read",
                "contents": "write",
                "id-token": "write",
                "pull-requests": "read",
            },
            self.finalize["permissions"],
        )
        dispatch = self.steps["Mint exact ModuLix validation App token"]["with"]
        finalize = self.finalize_steps["Mint exact ModuLix App token for finalization"]["with"]
        for token in (dispatch, finalize):
            self.assertEqual("modulix-validation", token["repositories"])
            self.assertEqual("read", token["permission-contents"])
        self.assertEqual("write", dispatch["permission-actions"])
        self.assertEqual("read", finalize["permission-actions"])

    def test_polling_rejects_token_expiry_window_before_minting(self) -> None:
        reusable = yaml.safe_load(MODULIX_WINDOW_PATH.read_text(encoding="utf-8"))
        steps = reusable["jobs"]["window"]["steps"]
        names = [step["name"] for step in steps]
        guard = next(step for step in steps if step["name"] == "Validate token-safe polling bound")
        self.assertLess(names.index(guard["name"]), names.index("Mint exact ModuLix validation App token"))
        for value, expected in (("1", 0), ("2700", 0), ("2701", 1), ("4500", 1), ("0", 1), ("-1", 1), ("x", 1)):
            with self.subTest(wait_seconds=value):
                result = subprocess.run(  # noqa: S603 -- exact repository-owned guard with fixed input cases.
                    ["/bin/bash", "-c", guard["run"]],
                    env={**os.environ, "WAIT_SECONDS": value},
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(expected, result.returncode)

    def test_bound_windows_and_finalizer_preserve_one_release_identity(self) -> None:
        jobs = self.workflow["jobs"]
        for job in (self.publish, self.finalize):
            self.assertEqual("collection-release-${{ github.repository }}", job["concurrency"]["group"])
            self.assertEqual("max", job["concurrency"]["queue"])
            self.assertFalse(job["concurrency"]["cancel-in-progress"])
        previous = "publish"
        for index, wait_seconds in enumerate((2700,) * 6, start=1):
            job = jobs[f"modulix-validation-window-{index}"]
            self.assertEqual("./.github/workflows/modulix-validation-window.yml", job["uses"])
            self.assertIn(previous, job["needs"])
            self.assertEqual(wait_seconds, job["with"]["wait_seconds"])
            self.assertEqual(index == 6, job["with"]["final_window"])
            self.assertEqual("${{ inputs.release_sha }}", job["with"]["release_sha"])
            self.assertEqual("${{ needs.publish.outputs.handoff-sha256 }}", job["with"]["handoff_sha256"])
            self.assertEqual("${{ needs.publish.outputs.controller-sha }}", job["with"]["controller_sha"])
            self.assertEqual("${{ needs.publish.outputs.request-id }}", job["with"]["request_id"])
            if index > 1:
                self.assertEqual(f"${{{{ needs.{previous}.outputs.controller-run-id }}}}", job["with"]["prior_run_id"])
                self.assertEqual(
                    f"${{{{ needs.{previous}.outputs.controller-run-attempt }}}}",
                    job["with"]["prior_run_attempt"],
                )
            previous = f"modulix-validation-window-{index}"
        self.assertEqual(
            16_200,
            sum(
                job["with"]["wait_seconds"]
                for name, job in jobs.items()
                if name.startswith("modulix-validation-window-")
            ),
        )
        self.assertIn(previous, self.finalize["needs"])
        self.assertIn(f"needs.{previous}.outputs.complete == 'true'", self.finalize["if"])
        self.assertEqual(
            "${{ needs.publish.outputs.handoff-sha256 }}",
            self.finalize_steps["Verify the bound staged release before finalization"]["env"]["HANDOFF_SHA256"],
        )
        receipt = self.finalize_steps["Reverify the same signed ModuLix receipt"]
        self.assertEqual(f"${{{{ needs.{previous}.outputs.controller-run-id }}}}", receipt["env"]["BOUND_RUN_ID"])
        self.assertEqual(
            f"${{{{ needs.{previous}.outputs.controller-run-attempt }}}}", receipt["env"]["BOUND_RUN_ATTEMPT"]
        )
        self.assertEqual("${{ needs.publish.outputs.request-id }}", receipt["env"]["REQUEST_ID"])
        self.assertEqual("${{ needs.publish.outputs.controller-sha }}", receipt["env"]["CONTROLLER_SHA"])

        completion_names = [
            "Prepare completed normal publication evidence",
            "Attest completed normal publication",
            "Publish and verify completed normal publication evidence",
        ]
        for name in completion_names:
            self.assertIn("env.NORMAL_TWO_STAGE == 'true'", self.steps[name]["if"])
            self.assertNotIn(name, self.finalize_names)
        self.assertIn(
            "env.NORMAL_TWO_STAGE != 'true'", self.steps["Attach signed post-publication verification receipt"]["if"]
        )
        deferred_names = [
            name
            for name in self.step_names[self.step_names.index("Finalize immutable release attachments and notes") :]
            if name not in completion_names
        ]
        final_names = self.finalize_names[
            self.finalize_names.index("Finalize immutable release attachments and notes") :
        ]
        self.assertEqual(deferred_names, final_names)
        # Historical normal rechecks cannot create missing publication proof.
        # Remove only these exact normal-only guards; every shared Security
        # line and environment field must still compare exactly below.
        normal_legacy_guards = {
            "Finalize immutable release attachments and notes": (
                '  if [ "${LEGACY_NORMAL_RECHECK:-false}" = true ]; then\n'
                "    echo 'Legacy normal recheck requires the existing signed checksum pair.' >&2\n"
                "    exit 1\n"
                "  fi\n"
            ),
            "Create or verify GitHub Release and immutable assets": (
                '    if [ "${LEGACY_NORMAL_RECHECK:-false}" = true ]; then\n'
                "      echo 'Legacy normal recheck cannot add missing GitHub Release assets.' >&2\n"
                "      exit 1\n"
                "    fi\n"
            ),
            "Attach signed post-publication verification receipt": (
                '  if [ "${LEGACY_NORMAL_RECHECK:-false}" = true ]; then\n'
                "    echo 'Legacy normal recheck requires the existing signed post-release receipt pair.' >&2\n"
                "    exit 1\n"
                "  fi\n"
            ),
        }
        self.assertTrue(normal_legacy_guards.keys() <= set(deferred_names))
        for name in deferred_names:
            stage = {key: value for key, value in self.steps[name].items() if key != "if"}
            final = {key: value for key, value in self.finalize_steps[name].items() if key != "if"}
            if name in normal_legacy_guards:
                legacy_guard = normal_legacy_guards[name]
                self.assertEqual(1, stage["run"].count(legacy_guard), name)
                self.assertNotIn(legacy_guard, final["run"], name)
                stage["run"] = stage["run"].replace(legacy_guard, "", 1)
                self.assertNotIn(legacy_guard, stage["run"], name)
            if name == "Verify GitHub Release download, install, and smoke":
                # Only normal publication has this archive. Preserve exact
                # equality of every shared Security verification line and env.
                archive_guard = (
                    'if [ "${NORMAL_TWO_STAGE:-false}" = true ]; then\n'
                    "  python scripts/normal_release_archive.py \\\n"
                    '    --snapshot "$verify_root/normal-release-native-evidence.json" \\\n'
                    '    --bundle "$verify_root/normal-release-native-evidence.sigstore.json" \\\n'
                    '    --repository "$GITHUB_REPOSITORY" --repository-id "$REPOSITORY_ID" --release "$RELEASE_SHA"\n'
                    "fi\n"
                )
                self.assertEqual(1, stage["run"].count(archive_guard))
                self.assertNotIn("normal_release_archive.py", final["run"])
                self.assertEqual("${{ github.repository_id }}", stage["env"]["REPOSITORY_ID"])
                stage["env"] = {key: value for key, value in stage["env"].items() if key != "REPOSITORY_ID"}
                stage["run"] = stage["run"].replace(archive_guard, "", 1)
            self.assertEqual(stage, final, name)
            if name != "Upload exact release attachment set":
                self.assertIn("env.SECURITY_RELEASE != 'true'", self.steps[name]["if"])
        self.assertIn("failure()", self.steps["Upload exact release attachment set"]["if"])
        self.assertIn("env.GALAXY_REQUIRED != 'true'", self.steps["Upload exact release attachment set"]["if"])

    def test_queue_extension_is_manifest_bound_and_fails_on_mutation(self) -> None:
        config = yaml.safe_load((ROOT / ".github/actionlint.yaml").read_text(encoding="utf-8"))
        ignored = {"ignore": ['unexpected key "queue" for "concurrency" section']}
        self.assertEqual(
            {
                ".github/workflows/collection-publish.yml": ignored,
                ".github/workflows/release-back-sync.yml": ignored,
                ".github/workflows/release-prepare.yml": ignored,
            },
            config["paths"],
        )
        policy = (ROOT / ".github/workflow-queue-policy.json").read_text(encoding="utf-8")
        validator = ROOT / "scripts/validate-actionlint-queue-policy.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (root / ".github/workflow-queue-policy.json").write_text(policy, encoding="utf-8")
            workflow = workflows / "collection-publish.yml"
            for filename in ("release-back-sync.yml", "release-prepare.yml"):
                (workflows / filename).write_bytes((WORKFLOW_PATH.parent / filename).read_bytes())

            def check() -> subprocess.CompletedProcess[str]:
                return subprocess.run(  # noqa: S603 -- fixed checked-in validator and isolated temporary fixture.
                    [sys.executable, str(validator), "--root", str(root)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

            workflow.write_text(self.workflow_text, encoding="utf-8")
            self.assertEqual(0, check().returncode)
            workflow.write_text(self.workflow_text.replace("queue: max", "queue: single", 1), encoding="utf-8")
            self.assertNotEqual(0, check().returncode)
            workflow.write_text(self.workflow_text, encoding="utf-8")
            workflow.write_text(self.workflow_text.replace("      queue: max\n", "", 1), encoding="utf-8")
            self.assertNotEqual(0, check().returncode)
            workflow.write_text(self.workflow_text, encoding="utf-8")
            (workflows / "extra.yml").write_text(
                "jobs:\n  extra:\n    concurrency:\n      group: extra\n"
                "      queue: max\n      cancel-in-progress: false\n",
                encoding="utf-8",
            )
            self.assertNotEqual(0, check().returncode)
            (workflows / "extra.yml").unlink()
            prepare = workflows / "release-prepare.yml"
            prepare.write_text(prepare.read_text(encoding="utf-8").replace("  queue: max\n", "", 1), encoding="utf-8")
            self.assertNotEqual(0, check().returncode)

    def test_repository_local_release_jobs_have_bounded_class_limits(self) -> None:
        selected = {
            "changelog.yml": {"changelog": 30},
            "openssf-scorecard.yml": {"scorecard": 60, "upload-sarif": 10},
            "collection-ci.yml": {
                "quality-matrix": 10,
                "tiny": 10,
                "fast": 10,
                "heavy": 10,
                "acceptance": 10,
                "release-admission": 10,
            },
            "release-back-sync.yml": {"back-sync": 60},
            "release-prepare.yml": {"prepare": 60},
        }
        for filename, additions in selected.items():
            jobs = yaml.safe_load((WORKFLOW_PATH.parent / filename).read_text(encoding="utf-8"))["jobs"]
            for name, minutes in additions.items():
                self.assertEqual(minutes, jobs[name]["timeout-minutes"], f"{filename}:{name}")
            for name, job in jobs.items():
                if "uses" not in job:
                    limit = job.get("timeout-minutes")
                    self.assertIs(type(limit), int, f"{filename}:{name}")
                    self.assertLessEqual(limit, 90, f"{filename}:{name}")
        for filename in ("release-back-sync.yml", "release-prepare.yml"):
            concurrency = yaml.safe_load((WORKFLOW_PATH.parent / filename).read_text(encoding="utf-8"))["concurrency"]
            self.assertEqual("max", concurrency["queue"])
            self.assertFalse(concurrency["cancel-in-progress"])

    def test_modulix_dispatch_is_exact_app_scoped_and_receipt_gated(self) -> None:
        audit_token = self.steps["Mint read-only release automation installation audit token"]
        self.assertEqual("read", audit_token["with"]["permission-actions"])
        self.assertNotIn("repositories", audit_token["with"])
        audit = self.steps["Verify exact release automation installation and allowlist"]["run"]
        self.assertIn(".id == 148019054", audit)
        self.assertIn('"checks": "read"', audit)
        self.assertIn('"pull_requests": "write"', audit)
        self.assertIn("lightning-it/shared-assets-lit", audit)
        self.assertIn("lightning-it/modulix-validation", audit)
        token = self.steps["Mint exact ModuLix validation App token"]
        self.assertEqual("modulix-validation", token["with"]["repositories"])
        self.assertEqual("write", token["with"]["permission-actions"])
        self.assertEqual("read", token["with"]["permission-contents"])
        self.assertNotIn("permission-administration", token["with"])
        self.assertNotIn("permission-environments", token["with"])
        self.assertNotIn("permission-secrets", token["with"])

        gate = self.steps["Dispatch exact ModuLix validation request once"]["run"]
        self.assertIn('test "$APP_INSTALLATION_ID" = 148019054', gate)
        self.assertIn("scripts/modulix-validation-receipt.py", gate)
        self.assertIn("--phase dispatch", gate)
        self.assertIn('--source-run-attempt "$GITHUB_RUN_ATTEMPT"', gate)
        self.assertNotIn("set -x", gate)
        self.assertIn(
            "--phase window --final-window", self.finalize_steps["Reverify the same signed ModuLix receipt"]["run"]
        )

    def test_security_path_binds_both_app_login_and_numeric_actor_id(self) -> None:
        self.assertIn("github.actor == 'lightning-it-release-automation[bot]'", self.publish["if"])
        self.assertIn("github.actor_id == '307565056'", self.publish["if"])
        self.assertIn("github.actor_id == '307565056'", self.publish["environment"]["name"])

    def test_galaxy_cannot_publish_security_candidate_without_exact_receipt(self) -> None:
        galaxy = self.finalize_steps["Publish or verify validated artifact on Ansible Galaxy"]["run"]
        receipt_check = galaxy.index("MODULIX_VALIDATION_RECEIPT_SHA256")
        publish = galaxy.index("ansible-galaxy collection publish")
        readback = galaxy.index("galaxy_download_url")
        self.assertLess(receipt_check, publish)
        self.assertLess(publish, readback)
        self.assertIn(".decision.galaxyPublicationAuthorized == true", galaxy)
        self.assertIn(".request.candidate.sha256 == $digest", galaxy)

    def test_transition_noop_and_galaxy_first_path_are_absent(self) -> None:
        self.assertNotIn("Dispatch transitional central validation", self.step_names)
        self.assertNotIn("scripts/dispatch-transition-validation.py", self.workflow_text)
        self.assertNotIn("transition-noop", self.workflow_text)


if __name__ == "__main__":
    unittest.main()
