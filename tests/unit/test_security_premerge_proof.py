"""Native data packet and funding-withdrawal boundaries for Security producers."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

from tests.unit import test_security_main_promotion as FIXTURE

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "security_premerge_emitter_tested", ROOT / "scripts/security_premerge_proof.py"
)
EMIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EMIT)


class SecurityPremergeProofTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FIXTURE.SecurityMainPromotionTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.source = self.fixture.base_sha
        self.fixture.receipt["controller"]["runId"] = "222"
        self.head = self.fixture._materialize_head()

    def context(self, kind):
        _unused, workflow, job = EMIT.PRODUCERS[kind]
        actor = dict(zip(("login", "id", "type"), EMIT.APP, strict=True))
        event = "workflow_dispatch" if kind == "intake" else "push"
        run = {
            "id": 222,
            "workflow_id": 444,
            "run_attempt": 1,
            "repository": {"full_name": EMIT.C.PRODUCER_REPOSITORY, "id": int(EMIT.C.PRODUCER_REPOSITORY_ID)},
            "head_repository": {"full_name": EMIT.C.PRODUCER_REPOSITORY, "id": int(EMIT.C.PRODUCER_REPOSITORY_ID)},
            "head_sha": self.source,
            "head_branch": "main",
            "path": workflow,
            "event": event,
            "actor": actor,
            "triggering_actor": actor,
            "status": "in_progress",
            "conclusion": None,
        }
        jobs = {
            "total_count": 1,
            "jobs": [
                {"id": 333, "name": job, "run_id": 222, "run_attempt": 1, "status": "in_progress", "conclusion": None}
            ],
        }
        env = {
            "GITHUB_REPOSITORY": EMIT.C.PRODUCER_REPOSITORY,
            "GITHUB_REPOSITORY_ID": EMIT.C.PRODUCER_REPOSITORY_ID,
            "GITHUB_SHA": self.source,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": f"{EMIT.C.PRODUCER_REPOSITORY}/{workflow}@refs/heads/main",
            "GITHUB_ACTOR": EMIT.APP[0],
            "GITHUB_TRIGGERING_ACTOR": EMIT.APP[0],
            "GITHUB_EVENT_NAME": event,
            "GITHUB_RUN_ID": "222",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_JOB": "materialize" if kind == "intake" else "prepare",
        }
        head_ref = f"security-release/{FIXTURE.EVIDENCE_ID}" if kind == "intake" else f"release/v{FIXTURE.VERSION}"
        pull = {
            "number": 111,
            "state": "open",
            "draft": True,
            "auto_merge": None,
            "body": EMIT.locator(kind, 222, 1),
            "user": actor,
            "base": {"ref": "main", "sha": self.source, "repo": {"full_name": EMIT.C.PRODUCER_REPOSITORY}},
            "head": {"ref": head_ref, "sha": self.head, "repo": {"full_name": EMIT.C.PRODUCER_REPOSITORY}},
        }
        return pull, run, jobs, env

    def packet(self, kind="intake", context=None):
        return EMIT.emit(self.root, kind, self.source, *(context or self.context(kind)), checked_at=FIXTURE.CHECKED_AT)

    def prepare(self):
        self.source = self.head
        module = EMIT.GIT.load_release_version_module(ROOT)
        resolution = module.resolve_version(
            self.root / "galaxy.yml",
            self.root / "changelogs/fragments",
            security_target=FIXTURE.VERSION,
            root=self.root,
            checked_at=FIXTURE.CHECKED_AT,
        )
        receipt = module.build_preparation_receipt(
            resolution,
            repository=EMIT.C.PRODUCER_REPOSITORY,
            repository_id=EMIT.C.PRODUCER_REPOSITORY_ID,
            base_sha=self.source,
            workflow_run_id="222",
            workflow_attempt="1",
            workflow_ref=f"{EMIT.C.PRODUCER_REPOSITORY}/.github/workflows/release-prepare.yml@refs/heads/main",
            workflow_event="push",
            workflow_actor=EMIT.APP[0],
            root=self.root,
            checked_at=FIXTURE.CHECKED_AT,
        )
        (self.root / "changelogs/release-preparation.json").write_bytes(EMIT.C.canonical_document_bytes(receipt))
        (self.root / "galaxy.yml").write_text(f"---\nversion: {FIXTURE.VERSION}\n")
        (self.root / "CHANGELOG.rst").write_text("Generated Security release\n")
        (self.root / "changelogs/fragments/keycloak-security.yml").unlink()
        FIXTURE.git(self.root, "add", ".")
        FIXTURE.git(self.root, "commit", "-q", "-m", f"chore(release): prepare v{FIXTURE.VERSION}")
        self.head = FIXTURE.git(self.root, "rev-parse", "HEAD")

    def test_real_intake_packet_exact_contract_and_git_materials(self):
        packet = self.packet()
        self.assertEqual(
            {
                "version",
                "profile",
                "kind",
                "repository",
                "repository_id",
                "binding",
                "integration_tree",
                "diff_sha256",
                "chain_id",
                "evidence_id",
                "fixed_version",
                "acceptance_profile",
                "issued_at",
                "expires_at",
                "revoked",
                "producer",
                "materials",
            },
            set(packet),
        )
        self.assertEqual(EMIT.PROFILE, packet["profile"])
        self.assertEqual(
            {"number", "base", "head", "base_ref", "head_ref", "head_repository", "author"}, set(packet["binding"])
        )
        self.assertEqual({"id", "run", "attempt", "job", "source_sha"}, set(packet["producer"]))
        self.assertEqual(333, packet["producer"]["job"])
        self.assertEqual({"receipt", "metadata", "fragment"}, {item["role"] for item in packet["materials"]})
        raw = EMIT.GIT.git_bytes(
            self.root,
            "diff",
            "--binary",
            "--full-index",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            f"{self.source}^{{tree}}",
            packet["integration_tree"],
        )
        self.assertEqual(hashlib.sha256(raw).hexdigest(), packet["diff_sha256"])
        for material in packet["materials"]:
            self.assertEqual({"role", "at", "path", "sha256"}, set(material))
            raw = EMIT.blob(self.root, self.head, material["path"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), material["sha256"])
        wire = EMIT.canonical(packet)
        self.assertLessEqual(len(wire), 262144)
        self.assertEqual(packet, json.loads(wire))
        self.assertFalse(wire.endswith(b"\n"))

    def test_real_preparation_packet_binds_base_intake_and_deleted_fragments(self):
        self.prepare()
        packet = self.packet("preparation")
        self.assertEqual({"receipt", "metadata", "intake", "fragment"}, {item["role"] for item in packet["materials"]})
        for item in packet["materials"]:
            expected_at = "base" if item["role"] in {"intake", "fragment"} else "head"
            self.assertEqual(expected_at, item["at"])
            revision = self.source if expected_at == "base" else self.head
            self.assertEqual(hashlib.sha256(EMIT.blob(self.root, revision, item["path"])).hexdigest(), item["sha256"])
        self.assertEqual(self.fixture.request["chainId"], packet["chain_id"])

    def test_target_digest_locator_and_native_context_drift_fail_closed(self):
        context = self.context("intake")
        for label, change in (
            ("target", lambda p, r, j, e: p["base"].__setitem__("ref", "develop")),
            ("fork", lambda p, r, j, e: p["head"]["repo"].__setitem__("full_name", "other/repo")),
            ("duplicate-locator", lambda p, r, j, e: p.__setitem__("body", p["body"] * 2)),
            ("ready-old-head", lambda p, r, j, e: p.__setitem__("draft", False)),
            ("auto-merge-enabled", lambda p, r, j, e: p.__setitem__("auto_merge", {"merge_method": "merge"})),
            ("auto-merge-unknown", lambda p, r, j, e: p.pop("auto_merge")),
            ("run-source", lambda p, r, j, e: r.__setitem__("head_sha", "a" * 40)),
            ("attempt", lambda p, r, j, e: e.__setitem__("GITHUB_RUN_ATTEMPT", "2")),
            ("actor", lambda p, r, j, e: e.__setitem__("GITHUB_ACTOR", "litroc")),
            ("job-attempt", lambda p, r, j, e: j["jobs"][0].__setitem__("run_attempt", 2)),
            ("duplicate-job", lambda p, r, j, e: j.update({"total_count": 2, "jobs": j["jobs"] * 2})),
            ("boolean-job-attempt", lambda p, r, j, e: j["jobs"][0].__setitem__("run_attempt", True)),
            ("wrong-job-context", lambda p, r, j, e: e.__setitem__("GITHUB_JOB", "classify")),
            ("boolean-workflow", lambda p, r, j, e: r.__setitem__("workflow_id", True)),
        ):
            with self.subTest(case=label):
                changed = copy.deepcopy(context)
                change(*changed)
                with self.assertRaises(ValueError):
                    self.packet(context=changed)
        # A real changed Git material cannot retain the original intake digest.
        (self.root / "roles/keycloak_deploy/defaults/main.yml").write_text("---\nimage: altered\n")
        FIXTURE.git(self.root, "add", ".")
        tree = FIXTURE.git(self.root, "write-tree")
        self.head = FIXTURE.git(
            self.root, "commit-tree", tree, "-p", self.source, "-m", f"fix(security): {FIXTURE.EVIDENCE_ID}"
        )
        with self.assertRaisesRegex(ValueError, "candidate-digest"):
            self.packet()

    def test_material_symlinks_traversal_and_size_are_rejected(self):
        (self.root / "unsafe").symlink_to("galaxy.yml")
        (self.root / "large").write_bytes(b"x" * (EMIT.MAX_MATERIAL + 1))
        FIXTURE.git(self.root, "add", "unsafe", "large")
        FIXTURE.git(self.root, "commit", "-q", "-m", "unsafe material fixture")
        revision = FIXTURE.git(self.root, "rev-parse", "HEAD")
        for path in ("unsafe", "large", "../galaxy.yml", "roles//file", "/absolute"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                EMIT.blob(self.root, revision, path)
        with self.assertRaises(ValueError):
            EMIT.parse(b'{"x":1,"x":2}', "duplicate")

    def test_protected_selector_only_withdraws_legacy_funding(self):
        for selector, expected in (
            ("absent", "legacy"),
            (EMIT.PROFILE, "producer-only"),
            (None, None),
            (True, None),
            ("unknown", None),
        ):
            with self.subTest(selector=selector):
                policy = {"version": 1, "repository": EMIT.C.PRODUCER_REPOSITORY}
                if selector != "absent":
                    policy["security_profile"] = selector
                path = self.root / ".lit/workflow-control.json"
                path.write_bytes(EMIT.canonical(policy))
                FIXTURE.git(self.root, "add", str(path))
                FIXTURE.git(self.root, "commit", "-q", "-m", f"protected selector {selector}")
                source = FIXTURE.git(self.root, "rev-parse", "HEAD")
                if expected:
                    self.assertEqual(expected, EMIT.route(self.root, source))
                else:
                    with self.assertRaisesRegex(ValueError, "unknown-security-profile"):
                        EMIT.route(self.root, source)

    def readiness(self, kind, route, *, defect=None, after_ready=False, existing_ready=False):
        workflow_name, job, start = {
            "intake": (
                "security-release-intake.yml",
                "materialize",
                "Ready fresh Security PR after native data upload",
            ),
            "preparation": ("release-prepare.yml", "prepare", "Finalize Security readiness after native data upload"),
        }[kind]
        steps = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text())["jobs"][job]["steps"]
        start_index = next(i for i, step in enumerate(steps) if step["name"] == start)
        pull, _unused, _unused, _unused = self.context(kind)
        if existing_ready:
            pull["draft"] = False
        path = self.root / "native-pull.json"
        path.write_text(json.dumps(pull))
        changed = copy.deepcopy(pull)
        if defect == "auto":
            changed["auto_merge"] = {"merge_method": "merge"}
        elif defect == "missing-auto":
            changed.pop("auto_merge")
        elif defect == "base":
            changed["base"]["sha"] = "a" * 40
        elif defect == "head":
            changed["head"]["sha"] = "b" * 40
        elif defect == "branch":
            changed["head"]["ref"] = "release/vwrong"
        elif defect == "owner":
            changed["user"]["id"] = 1
        if not after_ready:
            path.write_text(json.dumps(changed))
        changed["draft"] = False
        readback = self.root / "readback-pull.json"
        readback.write_text(json.dumps(changed))
        calls = self.root / "native-calls"
        calls.write_text("")
        executable = shutil.which("bash")
        assert executable
        stub = r"""gh() {
          printf '%s\n' "$*" >>"$NATIVE_CALLS"
          if [ "$1" = api ]; then cat "$PULL_FILE";
          elif [ "$1 $2" = 'pr ready' ]; then cp "$READBACK_FILE" "$PULL_FILE";
          elif [ "$1 $2" = 'pr merge' ]; then
            jq '.auto_merge={merge_method:"merge",enabled_by:.user}' "$PULL_FILE" >"$PULL_FILE.next"
            mv "$PULL_FILE.next" "$PULL_FILE"
          fi
        }
        git() {
          case "$*" in *'rev-parse origin/main') printf '%s\n' "$BASE_SHA" ;; esac
        }
        """
        outputs = {
            "steps.pull.outputs.emit_premerge": "false" if existing_ready else "true",
            "steps.security-route.outputs.mode": route,
            "needs.security-classification.outputs.security-release": "true",
        }
        results = []
        for step in steps[start_index:]:
            condition = re.fullmatch(r"([\w.-]+) == '([^']+)'", step["if"])
            self.assertIsNotNone(condition, "The harness must understand every actual readiness condition")
            if outputs[condition[1]] != condition[2]:
                continue
            result = subprocess.run(  # noqa: S603 -- actual protected shell, isolated native stubs.
                [executable, "-c", stub + step["run"]],
                cwd=self.root,
                env={
                    **os.environ,
                    "REVIEW_ROUTE": route,
                    "GITHUB_ACTOR": EMIT.APP[0],
                    "GITHUB_REPOSITORY": EMIT.C.PRODUCER_REPOSITORY,
                    "GITHUB_SHA": self.source,
                    "BASE_SHA": self.source,
                    "HEAD_SHA": self.head,
                    "HEAD_REF": pull["head"]["ref"],
                    "PR_NUMBER": "111",
                    "PR_URL": "https://github.com/lightning-it/ansible-collection-supplementary/pull/111",
                    "REQUEST_EVENT": "mlx90-security-release",
                    "SECURITY_VERSION": FIXTURE.VERSION,
                    "APP_TOKEN": "fixture-only",
                    "PULL_FILE": str(path),
                    "READBACK_FILE": str(readback),
                    "NATIVE_CALLS": str(calls),
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            results.append(result)
            if result.returncode:
                break
        return results, calls.read_text().splitlines(), json.loads(path.read_text())

    def test_actual_readiness_paths_use_native_review_and_preserve_producer_only_no_merge(self):
        for kind in ("intake", "preparation"):
            for route in ("legacy", "producer-only"):
                with self.subTest(kind=kind, route=route):
                    results, operations, pull = self.readiness(kind, route)
                    self.assertTrue(results)
                    for result in results:
                        self.assertEqual(0, result.returncode, result.stderr)
                    self.assertFalse(pull["draft"])
                    self.assertEqual(1, sum(item.startswith("pr ready ") for item in operations))
                    self.assertEqual(
                        0,
                        sum(item.startswith("workflow run release-bot-exact-head-review.yml ") for item in operations),
                    )
                    self.assertEqual(
                        1 if route == "legacy" else 0, sum("--auto --merge" in item for item in operations)
                    )
                    if route == "producer-only":
                        self.assertIsNone(pull["auto_merge"])

    def test_actual_producer_readiness_rejects_auto_merge_and_subject_drift_before_and_after_ready(self):
        for kind in ("intake", "preparation"):
            for defect in ("auto", "missing-auto", "base", "head", "branch", "owner"):
                for after_ready in (False, True):
                    with self.subTest(kind=kind, defect=defect, after_ready=after_ready):
                        results, operations, _unused = self.readiness(
                            kind, "producer-only", defect=defect, after_ready=after_ready
                        )
                        self.assertNotEqual(0, results[-1].returncode)
                        self.assertFalse(any(item.startswith(("workflow run ", "pr merge ")) for item in operations))
                        self.assertEqual(int(after_ready), sum(item.startswith("pr ready ") for item in operations))

    def test_actual_existing_ready_legacy_heads_still_request_auto_merge(self):
        for kind in ("intake", "preparation"):
            with self.subTest(kind=kind):
                results, operations, _unused = self.readiness(kind, "legacy", existing_ready=True)
                self.assertTrue(results)
                for result in results:
                    self.assertEqual(0, result.returncode, result.stderr)
                self.assertFalse(any(item.startswith("pr ready ") for item in operations))
                self.assertEqual(1, sum("--auto --merge" in item for item in operations))

    def test_preparation_duplicate_or_false_material_digest_is_rejected(self):
        self.prepare()
        original = json.loads((self.root / "changelogs/release-preparation.json").read_text())
        for label, change in (
            ("duplicate", lambda value: value["fragments"].append(value["fragments"][0])),
            ("digest", lambda value: value["fragments"][0].__setitem__("sha256", "0" * 64)),
            ("old-controller", lambda value: value["workflow"].__setitem__("run_id", "221")),
        ):
            with self.subTest(case=label):
                changed = copy.deepcopy(original)
                change(changed)
                (self.root / "changelogs/release-preparation.json").write_bytes(
                    EMIT.C.canonical_document_bytes(changed)
                )
                FIXTURE.git(self.root, "add", "changelogs/release-preparation.json")
                tree = FIXTURE.git(self.root, "write-tree")
                self.head = FIXTURE.git(
                    self.root,
                    "commit-tree",
                    tree,
                    "-p",
                    self.source,
                    "-m",
                    f"chore(release): prepare v{FIXTURE.VERSION}",
                )
                with self.assertRaises(ValueError):
                    self.packet("preparation")

    def test_workflows_upload_before_ready_and_gate_legacy_dispatch(self):
        for workflow, job, emit_name, upload_name, ready_name in (
            (
                "security-release-intake.yml",
                "materialize",
                "Emit exact native Security intake data packet",
                "Upload pre-merge Security intake producer data",
                "Ready fresh Security PR after native data upload",
            ),
            (
                "release-prepare.yml",
                "prepare",
                "Emit exact native Security preparation data packet",
                "Upload pre-merge Security preparation producer data",
                "Finalize Security readiness after native data upload",
            ),
        ):
            with self.subTest(workflow=workflow):
                steps = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())["jobs"][job]["steps"]
                names = [step["name"] for step in steps]
                self.assertLess(names.index(emit_name), names.index(upload_name))
                self.assertLess(names.index(upload_name), names.index(ready_name))
                upload = steps[names.index(upload_name)]
                self.assertEqual("security-premerge-${{ github.run_attempt }}", upload["with"]["name"])
                self.assertIn("security-premerge-proof.json", upload["with"]["path"])
                route = next(i for i, step in enumerate(steps) if step.get("id") == "security-route")
                mint = next(i for i, step in enumerate(steps) if "Mint" in step["name"])
                self.assertLess(route, mint)
        ready = steps[names.index(ready_name)]["run"]
        self.assertIn('if [ "$REVIEW_ROUTE" = legacy ]; then', ready)
        self.assertIn('test "$REVIEW_ROUTE" = producer-only', ready)
        self.assertNotIn("while", ready)


if __name__ == "__main__":
    unittest.main()
