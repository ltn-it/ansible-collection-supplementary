from __future__ import annotations

import contextlib
import io
import json
import os
import runpy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
ENGINE = runpy.run_path(str(ROOT / "scripts" / "lit-push-ready.py"), run_name="lit_push_ready_engine_test")
GIT = shutil.which("git") or "git"


def run_git(repository: Path, *args: str, environment: dict[str, str]) -> None:
    if args[0] == "init":
        repository.mkdir()
    subprocess.run([GIT, "-C", repository, *args], check=True, env=environment)  # noqa: S603


class PushReadyEngineTests(unittest.TestCase):
    def test_check_environment_provides_private_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            alias = Path(parent) / "alias"
            alias.symlink_to(Path(parent), target_is_directory=True)
            previous_umask = os.umask(0o777)
            try:
                state_root = alias / "state"
                state_root.mkdir(mode=0o700)
                environment = ENGINE["minimal_check_environment"](state_root)
            finally:
                os.umask(previous_umask)
            runner_temp = Path(environment["RUNNER_TEMP"])

            self.assertEqual(0o700, state_root.stat().st_mode & 0o777)
            self.assertTrue(runner_temp.is_dir())
            self.assertEqual(0o700, runner_temp.stat().st_mode & 0o777)
            self.assertTrue(runner_temp.is_relative_to(state_root.resolve()))
            self.assertEqual(0o700, Path(environment["HOME"]).stat().st_mode & 0o777)
            self.assertEqual(0o700, Path(environment["TMPDIR"]).stat().st_mode & 0o777)

    def test_repository_quality_check_has_full_profile_timeout_budget(self) -> None:
        self.assertEqual(3_600, ENGINE["CHECK_TIMEOUT_SECONDS"])
        self.assertLessEqual(ENGINE["CHECK_TIMEOUT_SECONDS"], ENGINE["MAX_TIMEOUT_SECONDS"])

    def test_planned_diff_is_full_index_without_expanded_context(self) -> None:
        source = (ROOT / "scripts" / "lit-push-ready.py").read_text(encoding="utf-8")
        planned_change = source.split("def planned_change(", 1)[1].split("def config_at_commit(", 1)[0]
        self.assertIn('"--binary",', planned_change)
        self.assertIn('"--full-index",', planned_change)
        self.assertNotIn('"--unified=40",', planned_change)

    def test_trusted_policy_covers_executable_quality_scripts(self) -> None:
        trusted_paths = set(ENGINE["TRUSTED_CHECK_POLICY_PATHS"])

        self.assertIn(".pre-commit-config.yaml", trusted_paths)
        self.assertIn(".lit/ltn399-push-ready-origin-adoption.json", trusted_paths)
        self.assertIn("scripts/devtools-local-quality.sh", trusted_paths)
        self.assertIn("scripts/lit-repository-quality.py", trusted_paths)
        self.assertIn("scripts/lit-trust-root-base-verifier.py", trusted_paths)
        self.assertIn("scripts/validate-embedded-code.py", trusted_paths)

    def test_governed_origin_preserves_actual_owner_after_organization_rename(self) -> None:
        parse = ENGINE["governed_push_remote_from_url"]
        for owner in ("ltn-it", "lightning-it"):
            for url in (
                f"https://github.com/{owner}/ansible-collection-supplementary.git",
                f"ssh://git@github.com/{owner}/ansible-collection-supplementary.git",
                f"git@github.com:{owner}/ansible-collection-supplementary.git",
            ):
                with self.subTest(url=url):
                    self.assertEqual(f"{owner}/ansible-collection-supplementary", parse("origin", url)["repository"])
        for name, url in (
            ("upstream", "https://github.com/ltn-it/ansible-collection-supplementary.git"),
            ("origin", "https://github.com/untrusted/ansible-collection-supplementary.git"),
            ("origin", "https://github.com/ltn-it/ansible-collection-supplementary/extra.git"),
            ("origin", "https://github.com/ltn-it/ansible-collection-supplementary.git\n"),
        ):
            with self.subTest(name=name, url=url), self.assertRaises(RuntimeError):
                parse(name, url)

    def test_local_quality_dispatcher_changes_require_trust_root_review(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "c" * 64)
        policy = ENGINE["require_trusted_check_policy"]
        dispatcher = "scripts/devtools-local-quality.sh"
        for base_entry, head_entry in (("old", "new"), ("", "new"), ("old", "")):
            with self.subTest(base=base_entry, head=head_entry):

                def entries(commit: str, path: str, base: str = base_entry, head: str = head_entry) -> str:
                    if path == dispatcher:
                        return base if commit == change.base_tip else head
                    return "stable"

                with (
                    mock.patch.dict(policy.__globals__, {"git_tree_entry": entries}),
                    self.assertRaisesRegex(
                        RuntimeError, r"policy differs from base: scripts/devtools-local-quality\.sh"
                    ),
                ):
                    policy(change)
        with mock.patch.dict(policy.__globals__, {"git_tree_entry": lambda _commit, _path: "stable"}):
            policy(change)

    def test_policy_gate_precedes_checks(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "c" * 64)
        checks = mock.Mock(side_effect=AssertionError("untrusted checks executed"))
        function_globals = ENGINE["produce_evidence"].__globals__

        def entries(commit: str, path: str) -> str:
            return commit if path == ".pre-commit-config.yaml" else "stable"

        with (
            mock.patch.dict(function_globals, {"git_tree_entry": entries}),
            self.assertRaisesRegex(RuntimeError, r"policy differs from base: \.pre-commit-config\.yaml"),
        ):
            ENGINE["require_trusted_check_policy"](change)
        with (
            mock.patch.dict(
                function_globals,
                {
                    "require_trusted_review_policy": mock.Mock(side_effect=RuntimeError("policy differs from base")),
                    "execute_integration_checks": checks,
                },
            ),
            self.assertRaisesRegex(RuntimeError, "policy differs from base"),
        ):
            ENGINE["produce_evidence"]({}, change, fixture_manifest_bootstrap=False)
        checks.assert_not_called()
        source = (ROOT / "scripts" / "lit-push-ready.py").read_text(encoding="utf-8")
        validate = source.split('if args.command == "validate":', 1)[1].split('if args.command == "review":', 1)[0]
        self.assertLess(validate.index("classify_review_profile"), validate.index("execute_integration_checks"))
        self.assertIn('if classification.profile == "standard":', validate)
        self.assertLess(validate.index("require_trusted_check_policy"), validate.index("execute_integration_checks"))
        self.assertNotIn("run_agent_reviews", validate)
        self.assertNotIn("produce_evidence", validate)

    def test_trust_root_bootstrap_skips_base_policy_comparison(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "c" * 64)
        function_globals = ENGINE["require_trusted_review_policy"].__globals__
        trusted_policy = mock.Mock()
        with mock.patch.dict(
            function_globals,
            {
                "require_review_bootstrap_contract": mock.Mock(return_value=True),
                "require_trusted_check_policy": trusted_policy,
            },
        ):
            self.assertTrue(ENGINE["require_trusted_review_policy"](change))
        trusted_policy.assert_not_called()

        with mock.patch.dict(
            function_globals,
            {
                "require_review_bootstrap_contract": mock.Mock(return_value=False),
                "require_trusted_check_policy": trusted_policy,
            },
        ):
            self.assertFalse(ENGINE["require_trusted_review_policy"](change))
        trusted_policy.assert_called_once_with(change, allow_fixture_manifest_bootstrap=False)

    def test_profile_uses_isolated_pre_commit_home(self) -> None:
        profile = (ROOT / "scripts" / "lit-ci-profile.sh").read_text(encoding="utf-8")
        home_export = 'export HOME="$pre_commit_venv/home"'
        export = 'export PRE_COMMIT_HOME="$pre_commit_venv/home"'
        self.assertIn(home_export, profile)
        self.assertIn(export, profile)
        self.assertLess(profile.index(home_export), profile.index('python3 "$pre_commit_zipapp" run --all-files'))
        self.assertLess(profile.index(export), profile.index('python3 "$pre_commit_zipapp" run --all-files'))

    def test_review_cli_produces_push_evidence(self) -> None:
        config: dict[str, object] = {}
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "c" * 64)
        produced = mock.Mock()
        replacements = {
            "check_instruction_contract": mock.Mock(),
            "load_config": mock.Mock(return_value=config),
            "require_clean_head": mock.Mock(),
            "refresh_authoritative_base": mock.Mock(),
            "planned_change": mock.Mock(return_value=change),
            "report_review_size": mock.Mock(),
            "require_review_bootstrap_contract": mock.Mock(),
            "produce_evidence": produced,
        }
        function_globals = ENGINE["main"].__globals__
        with (
            mock.patch.dict(function_globals, replacements),
            mock.patch.object(function_globals["sys"], "argv", ["lit-push-ready.py", "review"]),
        ):
            self.assertEqual(0, ENGINE["main"]())
        produced.assert_called_once_with(config, change, fixture_manifest_bootstrap=False)

    def test_trust_root_update_cannot_self_certify_evidence(self) -> None:
        source = (ROOT / "scripts" / "lit-push-ready.py").read_text(encoding="utf-8")
        producer = source.split("def produce_evidence(", 1)[1].split("def main()", 1)[0]
        self.assertNotIn("trust_root_update", producer)
        verifier = source.split("def verify_evidence(", 1)[1].split("def verify_pre_push_updates(", 1)[0]
        self.assertNotIn("trust_root_update", verifier)
        mode = source.split("if args.trust_root_update:", 1)[1].split("elif args.base:", 1)[0]
        self.assertIn("run_agent_reviews", mode)
        self.assertNotIn("produce_evidence", mode)

    def test_validate_runs_deterministic_gates_without_agent_review(self) -> None:
        config: dict[str, object] = {}
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "patch", (), {}, "c" * 64)
        checked = mock.Mock()
        agent_review = mock.Mock(side_effect=AssertionError("validate invoked an external reviewer"))
        replacements = {
            "check_instruction_contract": mock.Mock(),
            "load_config": mock.Mock(return_value=config),
            "require_clean_head": mock.Mock(),
            "refresh_authoritative_base": mock.Mock(),
            "planned_change": mock.Mock(return_value=change),
            "report_review_size": mock.Mock(),
            "require_review_bootstrap_contract": mock.Mock(),
            "require_trusted_check_policy": mock.Mock(),
            "execute_integration_checks": checked,
            "run_agent_reviews": agent_review,
        }
        function_globals = ENGINE["main"].__globals__
        with (
            mock.patch.dict(function_globals, replacements),
            mock.patch.object(function_globals["sys"], "argv", ["lit-push-ready.py", "validate"]),
        ):
            self.assertEqual(0, ENGINE["main"]())
        checked.assert_called_once_with(config, change)
        agent_review.assert_not_called()

    def test_pre_push_hook_rejects_stale_head(self) -> None:
        config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertNotIn("stages: [pre-push]", config)
        profile = (ROOT / "scripts" / "lit-ci-profile.sh").read_text(encoding="utf-8")
        self.assertIn('python3 "$pre_commit_zipapp" run --all-files', profile)
        self.assertNotIn("SKIP=molecule-light", profile)
        self.assertRegex(profile, r'readonly PRE_COMMIT_SHA256="[0-9a-f]{64}"')
        self.assertNotIn("pip install", profile)
        branch, stale, expected = "refs/heads/test", "b" * 40, "a" * 40
        payload = {
            "push_remote": ENGINE["governed_push_remote_from_url"](
                "origin", "https://github.com/lightning-it/ansible-collection-supplementary.git"
            ),
            "head_commit": expected,
            "local_branch_ref": branch,
        }
        function_globals = ENGINE["verify_pre_push_updates"].__globals__
        with (
            mock.patch.dict(function_globals, {"git_output": lambda *_args: stale}),
            self.assertRaisesRegex(RuntimeError, "not bound"),
        ):
            ENGINE["verify_pre_push_updates"](
                payload,
                f"{branch} {stale} {branch} {'0' * 40}\n",
                remote_name="origin",
                remote_url="https://github.com/lightning-it/ansible-collection-supplementary.git",
            )

    def test_native_pre_push_hook_preserves_git_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            hooks = Path(temporary_directory)
            function_globals = ENGINE["install_pre_push_hook"].__globals__
            with mock.patch.dict(
                function_globals,
                {"git_output": mock.Mock(return_value=str(hooks))},
            ):
                ENGINE["install_pre_push_hook"]()
                hook = hooks / "pre-push"
                self.assertTrue(hook.stat().st_mode & 0o111)
                self.assertIn('--remote-name "$1" --remote-url "$2"', hook.read_text())
                ENGINE["install_pre_push_hook"]()
                hook.write_text("different\n", encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "hook differs"):
                    ENGINE["install_pre_push_hook"]()

        updates = "refs/heads/a " + "a" * 40 + " refs/heads/a " + "b" * 40 + "\n"
        verify = mock.Mock()
        main_globals = ENGINE["main"].__globals__
        replacements = {
            "check_instruction_contract": mock.Mock(),
            "reject_hidden_index_entries": mock.Mock(),
            "load_config": mock.Mock(return_value={}),
            "require_clean_head": mock.Mock(),
            "refresh_authoritative_base": mock.Mock(),
            "verify_evidence": mock.Mock(return_value={}),
            "verify_pre_push_updates": verify,
            "evidence_path": mock.Mock(return_value=Path("fixture-evidence.json")),
        }
        with (
            mock.patch.dict(main_globals, replacements),
            mock.patch.object(
                main_globals["sys"],
                "argv",
                ["lit-push-ready.py", "pre-push", "--remote-name", "origin", "--remote-url", "url"],
            ),
            mock.patch.object(main_globals["sys"], "stdin", io.StringIO(updates)),
        ):
            self.assertEqual(0, ENGINE["main"]())
        verify.assert_called_once_with({}, updates, remote_name="origin", remote_url="url")

    def test_container_engine_fallback(self) -> None:
        function_globals = ENGINE["copilot_container_command"].__globals__
        with tempfile.TemporaryDirectory() as runtime:
            runtime = str(Path(runtime).resolve())
            host = f"unix://{runtime}/docker.sock"
            probe = mock.Mock(side_effect=[subprocess.CompletedProcess([], code, "") for code in (1, 0)])
            with (
                mock.patch.object(function_globals["shutil"], "which", side_effect=("/docker", "/podman")),
                mock.patch.dict(function_globals, {"run": probe, "existing_unix_socket": lambda _value: host[7:]}),
                mock.patch.dict(os.environ, {"DOCKER_HOST": host, "XDG_RUNTIME_DIR": runtime}, clear=True),
            ):
                environment = {
                    **ENGINE["COPILOT_PROMPT_MODE_BOUNDARY"],
                    "COPILOT_GITHUB_TOKEN": "secret",
                }
                command = ENGINE["copilot_container_command"](environment, ROOT)
            self.assertNotIn("HOME", probe.call_args_list[0].kwargs["env"])
            self.assertEqual(host, probe.call_args_list[0].kwargs["env"]["DOCKER_HOST"])
            self.assertEqual(runtime, probe.call_args_list[1].kwargs["env"]["XDG_RUNTIME_DIR"])
            for call in probe.call_args_list:
                self.assertTrue(all(name not in call.kwargs["env"] for name in ENGINE["COPILOT_TOKEN_NAMES"]))
            self.assertEqual("secret", environment["COPILOT_GITHUB_TOKEN"])
        self.assertEqual("/podman", command[0])
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            mock.patch.dict(os.environ, {name: "token" for name in ENGINE["COPILOT_TOKEN_NAMES"]}, clear=True),
            mock.patch.object(function_globals["shutil"], "which", return_value=None),
        ):
            environment = ENGINE["minimal_agent_environment"](state_root=Path(temporary_directory), agent="copilot")
        forwarded = [name for name in ENGINE["COPILOT_TOKEN_NAMES"] if name in environment]
        self.assertEqual(["COPILOT_GITHUB_TOKEN"], forwarded)
        with (
            mock.patch.object(function_globals["shutil"], "which", return_value="/podman"),
            mock.patch.dict(function_globals, {"run": mock.Mock(return_value=subprocess.CompletedProcess([], 0, ""))}),
        ):
            version_command = ENGINE["copilot_container_command"](environment, ROOT, include_credentials=False)
        self.assertTrue(all(name not in version_command for name in ENGINE["COPILOT_TOKEN_NAMES"]))

    def test_bootstrap_config(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "c" * 64)
        function_globals = ENGINE["require_review_bootstrap_contract"].__globals__
        original = function_globals["git_tree_entry"]
        try:
            function_globals["git_tree_entry"] = lambda commit, _path: "entry" if commit == "b" * 40 else ""
            self.assertTrue(ENGINE["require_review_bootstrap_contract"](change))
            function_globals["git_tree_entry"] = lambda commit, path: (
                "entry" if commit == "b" * 40 or path == ".lit/push-ready.json" else ""
            )
            with self.assertRaisesRegex(RuntimeError, "bootstrap is incomplete"):
                ENGINE["require_review_bootstrap_contract"](change)
            function_globals["git_tree_entry"] = lambda commit, path: (
                "" if commit == "b" * 40 and path == ".lit/push-ready.json" else "entry"
            )
            with self.assertRaisesRegex(RuntimeError, "lacks policy"):
                ENGINE["require_review_bootstrap_contract"](change)
        finally:
            function_globals["git_tree_entry"] = original

        with tempfile.TemporaryDirectory() as temporary_directory:
            config = json.loads((ROOT / ".lit" / "push-ready.json").read_text(encoding="utf-8"))
            config["checks"] = []
            path = Path(temporary_directory) / "push-ready.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            function_globals = ENGINE["load_config"].__globals__
            original = function_globals["CONFIG"]
            function_globals["CONFIG"] = path
            try:
                with (
                    mock.patch.dict(function_globals, reject_hidden_index_entries=mock.Mock()),
                    self.assertRaisesRegex(RuntimeError, "define checks"),
                ):
                    ENGINE["load_config"]()
            finally:
                function_globals["CONFIG"] = original

    def test_history_free_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            repository = root / "repository"
            environment = ENGINE["isolated_git_environment"]({"PATH": os.environ["PATH"]})
            run_git(repository, "init", "-q", environment=environment)
            (repository / "safe.txt").write_text("safe\n", encoding="utf-8")
            run_git(repository, "add", "safe.txt", environment=environment)
            run_git(
                repository,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@invalid",
                "commit",
                "-q",
                "-m",
                "root",
                environment=environment,
            )
            self.assertRegex(
                ENGINE["require_history_free_review_workspace"](repository, source_commits=("f" * 40,)),
                r"^[0-9a-f]{40}$",
            )

    def test_sanitized_checkout_uses_exact_detached_commit_without_branch_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            destination = root / "destination"
            hooks = root / "hooks"
            hooks.mkdir()
            environment = ENGINE["isolated_git_environment"]({"PATH": os.environ["PATH"]})
            run_git(source, "init", "-q", environment=environment)
            (source / "safe.txt").write_text("safe\n", encoding="utf-8")
            run_git(source, "add", "safe.txt", environment=environment)
            run_git(
                source,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@invalid",
                "commit",
                "-q",
                "-m",
                "root",
                environment=environment,
            )
            commit = subprocess.check_output(  # noqa: S603
                [GIT, "-C", source, "rev-parse", "HEAD"],
                env=environment,
                text=True,
            ).strip()
            destination.mkdir()
            ENGINE["checkout_sanitized_commit"](source, commit, destination, hooks)
            self.assertEqual(
                commit,
                subprocess.check_output(  # noqa: S603
                    [GIT, "-C", destination, "rev-parse", "HEAD"],
                    env=environment,
                    text=True,
                ).strip(),
            )
            self.assertEqual(
                "HEAD",
                subprocess.check_output(  # noqa: S603
                    [GIT, "-C", destination, "rev-parse", "--abbrev-ref", "HEAD"],
                    env=environment,
                    text=True,
                ).strip(),
            )

    def test_review_workspace_rejects_non_utf8_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp).resolve() / "repository"
            environment = ENGINE["isolated_git_environment"]({"PATH": os.environ["PATH"]})
            run_git(repository, "init", "-q", environment=environment)
            (repository / "invalid.bin").write_bytes(b"invalid\xff")
            run_git(repository, "add", "invalid.bin", environment=environment)
            with self.assertRaisesRegex(RuntimeError, "sanitized review file is not UTF-8: invalid.bin"):
                ENGINE["ensure_workspace_review_safe"](repository)

    def test_review_workspace_rejects_secret_paths_and_secret_like_content(self) -> None:
        cases = (
            (".env", "harmless fixture text\n", "secret-like tracked paths"),
            ("settings.yml", "api_" + "key: " + "abcdefghijklmnop\n", "secret-like review content"),
        )
        for name, content, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                repository = Path(temporary_directory).resolve() / "repository"
                environment = ENGINE["isolated_git_environment"]({"PATH": os.environ["PATH"]})
                run_git(repository, "init", "-q", environment=environment)
                (repository / name).write_text(content, encoding="utf-8")
                run_git(repository, "add", name, environment=environment)
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    ENGINE["ensure_workspace_review_safe"](repository)

    def test_evidence_contains_bindings_but_not_the_private_diff(self) -> None:
        private_diff = "PRIVATE_DIFF_SENTINEL"
        change = ENGINE["PlannedChange"](
            "refs/remotes/origin/develop",
            "a" * 40,
            "a" * 40,
            "b" * 40,
            private_diff,
            ("roles/example/tasks/main.yml",),
            {},
            "c" * 64,
        )
        classification = ENGINE["ReviewClassification"]("standard", (), "d" * 64, "test")
        captured = mock.Mock()
        replacements = {
            "tree_fingerprint": mock.Mock(return_value=change.tree_fingerprint),
            "config_sha256": mock.Mock(return_value="e" * 64),
            "instruction_file_hashes": mock.Mock(return_value={"AGENTS.md": "f" * 64}),
            "platform_evidence": mock.Mock(return_value={}),
            "runtime_versions": mock.Mock(return_value={}),
            "governed_push_remote": mock.Mock(return_value={}),
            "review_execution_evidence": mock.Mock(return_value={}),
            "execution_metrics": mock.Mock(return_value={}),
            "require_review_bootstrap_contract": mock.Mock(return_value=False),
            "current_branch_ref": mock.Mock(return_value="refs/heads/test"),
            "write_evidence_text": captured,
        }
        config = {
            "review": {"max_diff_bytes": 200_000},
            "remote_only_checks": [],
        }
        with mock.patch.dict(ENGINE["write_evidence"].__globals__, replacements):
            ENGINE["write_evidence"](
                config,
                [],
                [],
                change,
                started_at="2026-01-01T00:00:00Z",
                started_monotonic=0.0,
                integration_tree="1" * 40,
                integration_commit="2" * 40,
                integration_fingerprint="3" * 64,
                classification=classification,
            )
        serialized = captured.call_args.args[0]
        self.assertNotIn(private_diff, serialized)
        self.assertIn(change.diff_sha256, serialized)
        self.assertIn(change.head_commit, serialized)

    def test_integration_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory).resolve() / "repository"
            environment = ENGINE["isolated_git_environment"]({"PATH": os.environ["PATH"]})
            run_git(repository, "init", "-q", environment=environment)
            commits = []
            for message in ("base", "head"):
                (repository / "value.txt").write_text(message + "\n", encoding="utf-8")
                run_git(repository, "add", "value.txt", environment=environment)
                run_git(
                    repository,
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@invalid",
                    "commit",
                    "-q",
                    "-m",
                    message,
                    environment=environment,
                )
                commits.append(
                    subprocess.check_output(  # noqa: S603
                        [GIT, "-C", repository, "rev-parse", "HEAD"], env=environment, text=True
                    ).strip()
                )
            function_globals = ENGINE["execute_integration_checks"].__globals__
            original = function_globals["ROOT"]
            function_globals["ROOT"] = repository
            try:
                change = ENGINE["PlannedChange"]("base", commits[0], commits[0], commits[1], "", (), {}, "f" * 64)
                result = ENGINE["execute_integration_checks"](
                    {"checks": [{"name": "true", "command": ["true"]}]}, change
                )
            finally:
                function_globals["ROOT"] = original
            self.assertEqual(0, result[0][0]["exit_code"])
            self.assertRegex("".join(result[1:]), r"^[0-9a-f]{144}$")

    def test_markdown_validators(self) -> None:
        quality = runpy.run_path(str(ROOT / "scripts" / "lit-repository-quality.py"))
        validator = runpy.run_path(
            str(ROOT / "scripts" / "validate-embedded-code.py"),
            run_name="embedded_code_contract_test",
        )
        runtime = __import__("sys")
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            repository = root / "repository"
            environment = ENGINE["isolated_git_environment"]({"PATH": os.environ["PATH"]})
            run_git(repository, "init", "-q", environment=environment)
            run_git(
                repository,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "root",
                environment=environment,
            )
            (repository / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts" / "validate-embedded-code.py", repository / "scripts")
            (repository / "staged.MD").write_text("~~~yaml\ninvalid: [\n~~~\n", encoding="utf-8")
            run_git(repository, "add", "staged.MD", environment=environment)
            run_git(repository, "update-ref", "refs/remotes/origin/develop", "HEAD", environment=environment)
            quality["check_embedded_code"].__globals__["ROOT"] = repository
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(subprocess.CalledProcessError):
                    quality["check_embedded_code"]()
            canary = root / "filter-canary"
            run_git(repository, "config", "filter.review.clean", f"touch {canary}", environment=environment)
            with self.assertRaisesRegex(AssertionError, "unsafe local Git configuration"):
                quality["check_embedded_code"]()
            self.assertFalse(canary.exists())
            with self.assertRaises(subprocess.CalledProcessError):
                quality["check_embedded_code"](["staged.MD"])

            quality["assert_file"].__globals__["ROOT"] = repository
            outside = root / "outside.md"
            outside.write_text("outside\n", encoding="utf-8")
            linked_document = repository / "linked.md"
            linked_document.symlink_to(outside)
            with self.assertRaisesRegex(AssertionError, "non-symlink regular file"):
                quality["assert_file"](linked_document)
            directory = repository / "directory.md"
            directory.mkdir()
            with self.assertRaisesRegex(AssertionError, "non-symlink regular file"):
                quality["assert_file"](directory)

            markdown = root / "markdown"
            markdown.mkdir()
            validator["main"].__globals__["ROOT"] = markdown
            for language in ("yaml", "shell"):
                self.assertEqual(
                    "safe\n```\nunsafe\n",
                    validator["fenced_blocks"](f"````{language}\nsafe\n```\nunsafe\n````\n")[0][1],
                )
            original_argv, original_which = runtime.argv, shutil.which
            try:
                shutil.which = lambda _name: None
                for name, language in (("A.MD", "ansible"), ("s.md", "sh")):
                    fence = "~~~" if name == "s.md" else "```"
                    (markdown / name).write_text(f"{fence}{language}\n[]\n{fence}\n", encoding="utf-8")
                    runtime.argv = ["validate-embedded-code.py", name]
                    self.assertEqual(1, validator["main"]())
            finally:
                runtime.argv, shutil.which = original_argv, original_which

    def test_evidence_intervals(self) -> None:
        prefix = "2026-01-01T"
        bounds = tuple(ENGINE["parse_timestamp"](prefix + value, "test") for value in ("00:01:00Z", "00:10:00Z"))
        cases = (
            ("00:05:00Z", "00:04:00Z", 0),
            ("00:02:00Z", "00:03:00Z", 1),
            ("00:00:00Z", "00:02:00Z", 120),
            ("00:09:00Z", "00:11:00Z", 120),
        )
        for started, completed, duration in cases:
            with self.assertRaisesRegex(RuntimeError, "invalid timing"):
                ENGINE["evidence_interval"](
                    {
                        "started_at": prefix + started,
                        "completed_at": prefix + completed,
                        "duration_seconds": duration,
                    },
                    "test",
                    bounds,
                )

    def test_trust_root_profile_scans_snapshot_without_external_ai(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "f" * 64)
        classification = ENGINE["ReviewClassification"]("trust-root", (), "a" * 64, "test")
        function_globals = ENGINE["run_agent_reviews"].__globals__

        @contextlib.contextmanager
        def isolated_workspace(*_args, **_kwargs):
            with tempfile.TemporaryDirectory() as temporary_directory:
                workspace = Path(temporary_directory)
                yield workspace, workspace, type("Topology", (), {"integration_tree": "d" * 40})()

        codex = mock.Mock(side_effect=AssertionError("local scan invoked Codex"))
        copilot = mock.Mock(side_effect=AssertionError("local scan invoked Copilot"))
        replacements = {
            "tree_fingerprint": lambda: "f" * 64,
            "expected_integration_tree": lambda _change: "d" * 40,
            "sanitized_review_workspace": isolated_workspace,
            "integration_worktree_fingerprint": lambda *_args, **_kwargs: "stable",
            "copilot_review": copilot,
            "codex_review": codex,
        }
        original = {name: function_globals[name] for name in replacements}
        try:
            function_globals.update(replacements)
            reviews = ENGINE["run_agent_reviews"](
                {
                    "agents": {
                        "codex": {"enabled": False, "required": False},
                        "copilot": {"enabled": False, "required": False},
                    }
                },
                change,
                classification=classification,
            )
        finally:
            function_globals.update(original)
        self.assertEqual([], reviews)
        codex.assert_not_called()
        copilot.assert_not_called()

    def test_nonempty_local_ai_profile_is_fail_closed(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "f" * 64)
        function_globals = ENGINE["run_agent_reviews"].__globals__
        classification = ENGINE["ReviewClassification"]("trust-root", ("codex",), "a" * 64, "test")
        with mock.patch.dict(function_globals, {"tree_fingerprint": lambda: "f" * 64}):
            with self.assertRaisesRegex(RuntimeError, "local external AI reviewers are prohibited"):
                ENGINE["run_agent_reviews"](
                    {
                        "agents": {
                            "codex": {"enabled": False, "required": False},
                            "copilot": {"enabled": False, "required": False},
                        }
                    },
                    change,
                    classification=classification,
                )

    def test_review_size_is_advisory_and_legacy_limit_does_not_block(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "x" * 500001, (), {}, "f" * 64)
        for review, threshold, warned in (
            ({"max_diff_bytes": 10}, 500000, True),
            ({"warn_diff_bytes": 600000}, 600000, False),
            ({"warn_diff_bytes": None}, None, False),
        ):
            with self.subTest(review=review):
                result = ENGINE["review_size_evidence"]({"review": review}, change)
                self.assertEqual(500001, result["bytes"])
                self.assertEqual(threshold, result["warning_bytes"])
                self.assertEqual(warned, result["warning_exceeded"])
                self.assertEqual("advisory/v1", result["profile"])
        for invalid in (True, 0, -1, "500000"):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                ENGINE["review_warning_bytes"]({"warn_diff_bytes": invalid})

    def test_review_evidence_and_metrics_record_no_local_ai_egress(self) -> None:
        classification = ENGINE["ReviewClassification"]("trust-root", (), "a" * 64, "test")
        evidence = ENGINE["review_execution_evidence"](classification, [])
        self.assertEqual("deterministic-only", evidence["mode"])
        self.assertEqual([], evidence["reviewers"])
        self.assertIsNone(evidence["input_sha256"])
        metrics = ENGINE["execution_metrics"]([], [])
        self.assertEqual(0, metrics["local_external_review_invocations"])
        self.assertEqual(0, metrics["local_codex_review_invocations"])
        self.assertEqual(0, metrics["local_copilot_review_invocations"])
        with self.assertRaisesRegex(RuntimeError, "evidence is prohibited"):
            ENGINE["review_execution_evidence"](classification, [{"agent": "codex"}])
        with self.assertRaisesRegex(RuntimeError, "metrics are prohibited"):
            ENGINE["execution_metrics"]([], [{"agent": "codex"}])

    def test_review_profile_classification_is_base_policy_bound_and_fail_closed(self) -> None:
        base_config = json.loads((ROOT / ".lit" / "push-ready.json").read_text(encoding="utf-8"))

        def classify(*paths: str, diff: str = "benign implementation change"):
            change = ENGINE["PlannedChange"](
                "base",
                "a" * 40,
                "a" * 40,
                "b" * 40,
                diff,
                paths,
                {},
                "f" * 64,
            )
            function_globals = ENGINE["classify_review_profile"].__globals__
            with mock.patch.dict(function_globals, {"config_at_commit": mock.Mock(return_value=base_config)}):
                return ENGINE["classify_review_profile"](change)

        standard = classify("roles/example/tasks/main.yml")
        self.assertEqual("standard", standard.profile)
        self.assertEqual((), standard.agents)
        standard = classify("tests/unit/test_example.py", "README.md")
        self.assertEqual("standard", standard.profile)
        self.assertEqual((), standard.agents)
        for path in (
            "roles/vault_bootstrap/tasks/main.yml",
            "roles/aap_tls/tasks/main.yml",
            "roles/keycloak_config/tasks/main.yml",
            "roles/forgejo_cac/tasks/main.yml",
            "docs/security-boundary.md",
        ):
            with self.subTest(path=path):
                classification = classify(path)
                self.assertEqual("trust-root", classification.profile)
                self.assertEqual((), classification.agents)
        semantic_risk = classify("roles/example/tasks/main.yml", diff="+ api_token: protected")
        self.assertEqual("trust-root", semantic_risk.profile)
        self.assertEqual((), semantic_risk.agents)
        self.assertEqual("trust-root-term:token", semantic_risk.reason)
        self.assertEqual("trust-root", classify("scripts/lit-push-ready.py").profile)
        self.assertEqual("trust-root", classify(".lit/push-ready.json").profile)
        self.assertEqual("trust-root", classify("unknown/new-surface.txt").profile)

        change = ENGINE["PlannedChange"](
            "base", "a" * 40, "a" * 40, "b" * 40, "patch", ("roles/example/tasks/main.yml",), {}, "f" * 64
        )
        function_globals = ENGINE["classify_review_profile"].__globals__
        with mock.patch.dict(function_globals, {"config_at_commit": mock.Mock(return_value=None)}):
            classification = ENGINE["classify_review_profile"](change)
        self.assertEqual("trust-root", classification.profile)
        self.assertEqual("base-policy-unavailable", classification.reason)

    def test_review_policy_rejects_untrusted_or_unsorted_risk_terms(self) -> None:
        policy = json.loads((ROOT / ".lit" / "push-ready.json").read_text(encoding="utf-8"))["review"]
        ENGINE["validate_review_policy"](policy)
        for terms in (("token", "secret"), ("token", "unsafe/secret"), ("token", "token")):
            with self.subTest(terms=terms):
                malformed = json.loads(json.dumps(policy))
                malformed["classification"]["trust_root_terms"] = list(terms)
                with self.assertRaisesRegex(RuntimeError, "trust_root_terms"):
                    ENGINE["validate_review_policy"](malformed)

    def test_review_binding_changes_with_profile_and_exact_head(self) -> None:
        standard = ENGINE["ReviewClassification"]("standard", (), "a" * 64, "all-paths-standard")
        trust_root = ENGINE["ReviewClassification"]("trust-root", (), "a" * 64, "unknown-or-trust-root-path")
        first = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "patch", (), {}, "f" * 64)
        second = first._replace(head_commit="c" * 40)
        instructions = {"AGENTS.md": "d" * 64}
        standard_binding = ENGINE["review_input_sha256"](first, "e" * 40, instructions, standard)
        self.assertNotEqual(
            standard_binding,
            ENGINE["review_input_sha256"](first, "e" * 40, instructions, trust_root),
        )
        self.assertNotEqual(
            standard_binding,
            ENGINE["review_input_sha256"](second, "e" * 40, instructions, standard),
        )

    def test_enabled_local_ai_configuration_is_fail_closed(self) -> None:
        change = ENGINE["PlannedChange"]("base", "a" * 40, "a" * 40, "b" * 40, "", (), {}, "f" * 64)
        classification = ENGINE["ReviewClassification"]("standard", (), "a" * 64, "test")
        function_globals = ENGINE["run_agent_reviews"].__globals__
        with mock.patch.dict(function_globals, {"tree_fingerprint": lambda: "f" * 64}):
            with self.assertRaisesRegex(RuntimeError, "must remain disabled"):
                ENGINE["run_agent_reviews"](
                    {
                        "agents": {
                            "codex": {"enabled": True, "required": False},
                            "copilot": {"enabled": False, "required": False},
                        }
                    },
                    change,
                    classification=classification,
                )
