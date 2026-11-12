"""Security contracts for the containerized forward proxy role."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined, Template

ROOT = Path(__file__).resolve().parents[2]
ASSERTS = ROOT / "roles" / "forward_proxy" / "tasks" / "assert.yml"
MAIN = ROOT / "roles" / "forward_proxy" / "tasks" / "main.yml"
TRANSITION = ROOT / "roles" / "forward_proxy" / "tasks" / "transition.yml"
ENSURE_DIRECTORY = ROOT / "roles" / "forward_proxy" / "tasks" / "ensure_directory.yml"
ENABLED = ROOT / "roles" / "forward_proxy" / "tasks" / "enabled.yml"
ENABLED_APPLY = ROOT / "roles" / "forward_proxy" / "tasks" / "enabled_apply.yml"
READINESS = ROOT / "roles" / "forward_proxy" / "tasks" / "verify_runtime_ready.yml"
POD_TEMPLATE = ROOT / "roles" / "forward_proxy" / "templates" / "squid-pod.yml.j2"
SQUID_TEMPLATE = ROOT / "roles" / "forward_proxy" / "templates" / "squid.conf.j2"
RESTORE = ROOT / "roles" / "forward_proxy" / "tasks" / "restore_managed_file.yml"
README = ROOT / "roles" / "forward_proxy" / "README.md"
VERIFY = ROOT / "molecule" / "forward-proxy-tiny" / "verify.yml"
CONVERGE = ROOT / "molecule" / "forward-proxy-tiny" / "converge.yml"
CLEANUP = ROOT / "molecule" / "forward-proxy-tiny" / "cleanup.yml"
RELEASE_ELIGIBILITY = ROOT / "molecule" / "forward-proxy-tiny" / "tasks" / "release_eligibility.yml"


class ForwardProxyContractTests(unittest.TestCase):
    def test_source_bound_domains_do_not_render_a_shared_allow_rule(self) -> None:
        # This renders a Squid configuration, not HTML; match Ansible's template behavior.
        environment = Environment(undefined=StrictUndefined, autoescape=False)  # noqa: S701
        rendered = environment.from_string(SQUID_TEMPLATE.read_text()).render(
            forward_proxy_listen_addresses=["127.0.0.1"],
            forward_proxy_port=3128,
            forward_proxy_allowed_clients=["127.0.0.1/32", "10.89.10.3/32"],
            forward_proxy_allowed_destination_ports=[80, 443],
            forward_proxy_allowed_destination_domains=[".ubuntu.com", "lightning-it.okta.com"],
            forward_proxy_destination_domains_by_client={
                "127.0.0.1/32": [".ubuntu.com"],
                "10.89.10.3/32": ["lightning-it.okta.com"],
            },
            forward_proxy_upstream_enabled=False,
        )
        self.assertIn("acl lit_client_0 src 10.89.10.3/32", rendered)
        self.assertIn("acl lit_domains_0 dstdomain -n lightning-it.okta.com", rendered)
        self.assertIn("acl lit_client_1 src 127.0.0.1/32", rendered)
        self.assertIn("acl lit_domains_1 dstdomain -n .ubuntu.com", rendered)
        self.assertIn("http_access allow lit_client_0 lit_domains_0", rendered)
        self.assertIn("http_access allow lit_client_1 lit_domains_1", rendered)
        self.assertNotIn("http_access allow lit_clients lit_allowed_domains", rendered)

    def test_runtime_liveness_probe_uses_only_pinned_image_primitives(self) -> None:
        pod_template = POD_TEMPLATE.read_text(encoding="utf-8")

        liveness_block = pod_template.split("livenessProbe:", maxsplit=1)[1].split("initialDelaySeconds:", maxsplit=1)[
            0
        ]

        self.assertIn("exec:", liveness_block)
        self.assertIn("- /bin/bash", liveness_block)
        self.assertIn("exec 3<>/dev/tcp/127.0.0.1/{{ forward_proxy_port }}", liveness_block)
        self.assertIn("GET http://health.invalid/ HTTP/1.0", liveness_block)
        self.assertIn('[[ "${status}" == HTTP/* ]]', liveness_block)
        self.assertNotIn("tcpSocket:", liveness_block)
        self.assertNotIn(" nc ", liveness_block)

    def test_runtime_image_capability_is_verified_before_managed_state_mutation(self) -> None:
        transition = TRANSITION.read_text(encoding="utf-8")

        image_exists = transition.index("Verify the pinned Squid image before any enabled-state mutation")
        bash_capability = transition.index(
            "Validate the pinned Squid image Bash capability before any enabled-state mutation"
        )
        first_managed_state_step = transition.index("Initialize the check-mode forward proxy directory plan")
        capability_block = transition[bash_capability:first_managed_state_step]

        self.assertLess(image_exists, bash_capability)
        self.assertLess(bash_capability, first_managed_state_step)
        for required_argument in (
            "- --pull=never",
            "- --network=none",
            "- --read-only",
            "- --cap-drop=ALL",
            "- no-new-privileges",
            "- /bin/bash",
            "[[ -x /bin/bash && $(type -t printf) == builtin ]]",
        ):
            with self.subTest(required_argument=required_argument):
                self.assertIn(required_argument, capability_block)
        self.assertIn("changed_when: false", capability_block)
        self.assertIn("check_mode: false", capability_block)
        self.assertIn("- forward_proxy_enabled | bool", capability_block)
        self.assertIn("- forward_proxy_manage_runtime | bool", capability_block)

    def test_integer_boundaries_reject_yaml_booleans(self) -> None:
        asserts = ASSERTS.read_text(encoding="utf-8")

        for variable in (
            "forward_proxy_lock_timeout",
            "forward_proxy_port",
            "forward_proxy_readiness_timeout",
            "forward_proxy_upstream_port",
        ):
            with self.subTest(variable=variable):
                self.assertIn(f"{variable} is integer", asserts)
                self.assertIn(f"{variable} is not boolean", asserts)

    def test_numeric_file_identities_match_the_atomic_module_boundary(self) -> None:
        asserts = ASSERTS.read_text(encoding="utf-8")

        for variable in ("forward_proxy_file_owner", "forward_proxy_file_group"):
            with self.subTest(variable=variable):
                self.assertIn(f"{variable} is not match('^[0-9]+\\Z')", asserts)
                self.assertIn(f"{variable} | int < 4294967295", asserts)

    def test_rollback_uses_the_nested_stat_item_path(self) -> None:
        restore = RESTORE.read_text(encoding="utf-8")
        self.assertEqual(3, restore.count("forward_proxy_restore_entry.0.item.item.0.0"))
        self.assertNotIn("forward_proxy_restore_entry.0.item.0.0", restore)

    def test_tiny_rollback_decodes_slurped_content_exactly_once_in_role(self) -> None:
        verify = VERIFY.read_text(encoding="utf-8")
        restore = RESTORE.read_text(encoding="utf-8")

        self.assertIn(
            'forward_proxy_restore_entry:\n              - content: "{{ forward_proxy_squid_config.content }}"',
            verify,
        )
        self.assertNotIn(
            "forward_proxy_restore_entry:\n"
            '              - content: "{{ forward_proxy_squid_config.content | b64decode }}"',
            verify,
        )
        self.assertEqual(
            1,
            restore.count("forward_proxy_restore_entry.0.content | b64decode"),
        )

    def test_readme_example_is_an_explicit_runnable_opt_in(self) -> None:
        readme = README.read_text(encoding="utf-8")
        self.assertIn("`lit.foundational` 1.35.0 or newer", readme)
        self.assertIn("`podman_systemd`", readme)
        self.assertIn("forward_proxy_enabled: true", readme)
        self.assertIn("forward_proxy_experimental_runtime_acceptance: true", readme)
        self.assertIn("forward_proxy_allowed_destination_domains:", readme)
        self.assertIn("pull policy is Never", readme)

    def test_disabled_unowned_invocation_skips_the_lock_boundary(self) -> None:
        main = MAIN.read_text(encoding="utf-8")
        converge = CONVERGE.read_text(encoding="utf-8")

        self.assertIn("Inspect forward proxy state before entering the mutation boundary", main)
        self.assertIn("Inspect a concurrent forward proxy transition without creating a lock", main)
        self.assertIn("Reinspect forward proxy state after the concurrent-lock observation", main)
        self.assertIn("forward_proxy_transition_scope_internal.required | bool", main)
        self.assertLess(
            main.index("Inspect forward proxy state before entering the mutation boundary"),
            main.index("Inspect a concurrent forward proxy transition without creating a lock"),
        )
        self.assertLess(
            main.index("Inspect a concurrent forward proxy transition without creating a lock"),
            main.index("Reinspect forward proxy state after the concurrent-lock observation"),
        )
        self.assertLess(
            main.index("Reinspect forward proxy state after the concurrent-lock observation"),
            main.index("Inspect the required forward proxy lock parent"),
        )
        self.assertIn("forward_proxy_invocation_lock.stat.exists", main)
        self.assertIn("forward_proxy_invocation_state_marker_after_lock.stat.exists", main)
        self.assertIn("forward_proxy_transition_initialized_internal: false", main)
        self.assertIn("Exercise a disabled unowned invocation without a lock parent", converge)
        self.assertIn("disabled unowned invocation to remain mutation-free", converge)

    def test_check_mode_reports_each_planned_directory_creation(self) -> None:
        ensure_directory = ENSURE_DIRECTORY.read_text(encoding="utf-8")

        planned = ensure_directory.index("Carry the planned forward proxy directory through check mode")
        following = ensure_directory.index("Reinspect the trusted proxy directory before privileged writes")
        self.assertIn("changed_when: true", ensure_directory[planned:following])

    def test_disabled_runtime_fails_closed_without_owned_quadlet_evidence(self) -> None:
        transition = TRANSITION.read_text(encoding="utf-8")

        missing = transition.index("Fail closed when runtime-managed Quadlet evidence is missing")
        capture = transition.index("Capture the existing runtime identity before any runtime mutation")
        revalidate = transition.index("Revalidate the existing runtime at the disabled-state removal boundary")
        remove = transition.index("Remove a previously managed forward proxy runtime when disabled")
        absent = transition.index("Prove the disabled runtime is absent before deleting owned state")
        self.assertLess(missing, capture)
        self.assertLess(capture, revalidate)
        self.assertLess(revalidate, remove)
        self.assertLess(remove, absent)
        self.assertIn("forward_proxy_previous_quadlet_stat.stat.exists", transition[missing:capture])
        self.assertNotIn(
            "or forward_proxy_previous_quadlet_stat.stat.exists",
            transition[capture:revalidate],
        )

    def test_check_mode_reports_the_owned_disable_transition(self) -> None:
        transition = TRANSITION.read_text(encoding="utf-8")

        planned = transition.index("Report the planned owned forward proxy disable transition in check mode")
        capture = transition.index("Capture the existing runtime identity before any runtime mutation")
        section = transition[planned:capture]
        self.assertIn("changed_when: true", section)
        self.assertIn("ansible_check_mode", section)
        self.assertIn("not forward_proxy_enabled | bool", section)
        self.assertIn("forward_proxy_state_marker.stat.exists", section)

    def test_check_mode_reports_render_only_runtime_removal(self) -> None:
        enabled_apply = ENABLED_APPLY.read_text(encoding="utf-8")

        planned = enabled_apply.index("Report the planned runtime removal for render-only mode in check mode")
        removal = enabled_apply.index("Remove the previous runtime when switching to render-only mode")
        section = enabled_apply[planned:removal]
        self.assertIn("changed_when: true", section)
        self.assertIn("ansible_check_mode", section)
        self.assertIn("forward_proxy_previous_state_manifest.runtime_managed | bool", section)
        self.assertIn("not forward_proxy_manage_runtime | bool", section)

    def test_check_mode_reports_runtime_activation_or_restart(self) -> None:
        enabled_apply = ENABLED_APPLY.read_text(encoding="utf-8")

        planned = enabled_apply.index("Report the planned runtime activation or restart in check mode")
        mutation = enabled_apply.index("Manage the persistent Squid container service")
        section = enabled_apply[planned:mutation]
        self.assertIn("changed_when: true", section)
        self.assertIn("ansible_check_mode", section)
        self.assertIn("not forward_proxy_state_marker.stat.exists", section)
        self.assertIn("forward_proxy_config_path | dirname in forward_proxy_planned_directories_internal", section)
        self.assertIn(
            "forward_proxy_pod_manifest_path | dirname in forward_proxy_planned_directories_internal", section
        )
        self.assertIn("forward_proxy_squid_config_result.changed | default(false) | bool", section)
        self.assertIn("forward_proxy_pod_manifest_result.changed | default(false) | bool", section)

    def test_disabled_runtime_checkpoints_absence_before_file_unlinks(self) -> None:
        transition = TRANSITION.read_text(encoding="utf-8")

        runtime_absent = transition.index("Prove the disabled runtime is absent before deleting owned state")
        checkpoint = transition.index("Persist the resumable runtime-absent ownership checkpoint")
        bind = transition.index("Bind the runtime-absent checkpoint for resumable file deletion")
        unlink = transition.index("Remove each managed file at its exact disabled-state mutation boundary")
        self.assertLess(runtime_absent, checkpoint)
        self.assertLess(checkpoint, bind)
        self.assertLess(bind, unlink)
        section = transition[checkpoint:bind]
        self.assertIn("lit.supplementary.atomic_path", section)
        self.assertIn("allow_absent: false", section)
        self.assertIn("expected_checksum", section)
        self.assertIn("forward_proxy_pre_checkpoint_state_marker.stat.checksum", section)
        self.assertIn("'runtime_managed': false", transition[runtime_absent:checkpoint])
        self.assertIn("'quadlet_checksum': ''", transition[runtime_absent:checkpoint])

    def test_readiness_uses_protocol_evidence_and_revalidates_runtime(self) -> None:
        readiness = READINESS.read_text(encoding="utf-8")

        self.assertIn("Require a Squid protocol response", readiness)
        self.assertIn("Resolve the target Python interpreter", readiness)
        self.assertIn('"{{ forward_proxy_probe_interpreter_internal }}"', readiness)
        self.assertNotIn("- /usr/bin/python3", readiness)
        self.assertIn("x-squid-error", readiness)
        self.assertIn('while b"\\r\\n\\r\\n" not in response', readiness)
        self.assertIn('has_complete_headers = b"\\r\\n\\r\\n" in response', readiness)
        self.assertIn("if has_complete_headers and response.startswith", readiness)
        self.assertIn("len(response) > 65536", readiness)
        self.assertIn("Reinspect the Pod identity after the Squid protocol probe", readiness)
        self.assertIn("Require the same captured runtime after the Squid protocol probe", readiness)

    def test_readiness_interpreter_resolution_supports_explicit_and_discovered_modes(self) -> None:
        tasks = yaml.safe_load(READINESS.read_text(encoding="utf-8"))
        resolve_task = next(
            task for task in tasks if task["name"] == "Resolve the target Python interpreter for the protocol probe"
        )
        expression = resolve_task["ansible.builtin.set_fact"]["forward_proxy_probe_interpreter_internal"]
        template = Environment(undefined=StrictUndefined, autoescape=True).from_string(expression)

        self.assertEqual(
            "/opt/managed/python",
            template.render(ansible_python_interpreter="/opt/managed/python", ansible_facts={}).strip(),
        )
        self.assertEqual(
            "/usr/libexec/platform-python",
            template.render(
                ansible_python_interpreter="auto_silent",
                ansible_facts={"discovered_interpreter_python": "/usr/libexec/platform-python"},
            ).strip(),
        )
        self.assertEqual(
            "/usr/bin/python3",
            template.render(ansible_facts={"discovered_interpreter_python": "/usr/bin/python3"}).strip(),
        )
        self.assertEqual("", template.render(ansible_facts={}).strip())

    def test_readiness_protocol_probe_accepts_only_complete_squid_headers(self) -> None:
        tasks = yaml.safe_load(READINESS.read_text(encoding="utf-8"))
        probe_task = next(
            task for task in tasks if task["name"] == "Require a Squid protocol response from the configured proxy port"
        )
        probe = probe_task["ansible.builtin.command"]["argv"][2]

        def run_probe(response: bytes) -> subprocess.CompletedProcess[str]:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            def serve_once() -> None:
                try:
                    connection, _address = listener.accept()
                    with connection:
                        connection.recv(4096)
                        connection.sendall(response)
                finally:
                    listener.close()

            server = threading.Thread(target=serve_once, daemon=True)
            server.start()
            result = subprocess.run(  # noqa: S603 - fixed interpreter and test-owned arguments
                [sys.executable, "-c", probe, "127.0.0.1", str(port)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            server.join(timeout=2)
            return result

        self.assertEqual(
            0,
            run_probe(b"HTTP/1.1 403 Forbidden\r\nServer: squid/6.10\r\nContent-Length: 0\r\n\r\n").returncode,
        )
        self.assertNotEqual(
            0,
            run_probe(b"HTTP/1.1 403 Forbidden\r\nServer: squid/6.10\r\n").returncode,
        )
        self.assertNotEqual(
            0,
            run_probe(b"HTTP/1.1 403 Forbidden\r\nServer: other/1.0\r\n\r\n").returncode,
        )

    def test_runtime_image_preflight_precedes_every_enabled_state_mutation(self) -> None:
        transition = TRANSITION.read_text(encoding="utf-8")
        enabled = ENABLED.read_text(encoding="utf-8")
        enabled_apply = ENABLED_APPLY.read_text(encoding="utf-8")

        preflight = "Verify the pinned Squid image before any enabled-state mutation"
        first_directory_mutation = "Create and revalidate every trusted forward proxy parent boundary"
        enabled_transition = "Apply the enabled forward proxy state"

        self.assertIn(preflight, transition)
        self.assertIn("forward_proxy_enabled | bool", transition)
        self.assertIn("forward_proxy_manage_runtime | bool", transition)
        self.assertIn(first_directory_mutation, transition)
        self.assertIn(enabled_transition, transition)
        self.assertLess(transition.index(preflight), transition.index(first_directory_mutation))
        self.assertLess(transition.index(preflight), transition.index(enabled_transition))
        self.assertNotIn("Verify the pinned Squid image was preloaded", enabled)
        self.assertNotIn("forward_proxy_transition_initialized_internal: true", transition)
        self.assertEqual(2, enabled_apply.count("forward_proxy_transition_initialized_internal: true"))
        self.assertLess(
            enabled_apply.index("Refuse a foreign same-named runtime before any managed-file write"),
            enabled_apply.index("Enter the rollback boundary before writing the Squid policy"),
        )
        self.assertLess(
            enabled_apply.index("Enter the rollback boundary before writing the Squid policy"),
            enabled_apply.index("Render the Squid policy with an atomic no-follow write"),
        )
        self.assertLess(
            enabled_apply.index("Enter the rollback boundary before writing the Squid policy"),
            enabled_apply.index("Render the digest-pinned Squid Pod manifest with an atomic no-follow write"),
        )
        self.assertLess(
            enabled_apply.index("Enter the rollback boundary before writing the Squid policy"),
            enabled_apply.index("Manage the persistent Squid container service"),
        )
        self.assertLess(
            enabled_apply.index("Enter the rollback boundary before removing the previous runtime"),
            enabled_apply.index("Remove the previous runtime when switching to render-only mode"),
        )
        self.assertIn("No rollback was attempted", enabled)
        self.assertEqual(
            3,
            enabled.count("forward_proxy_transition_initialized_internal | default(false) | bool"),
        )

    def test_first_install_accepts_systemd_no_match_without_weakening_foreign_runtime_guard(self) -> None:
        runtime_absent_path = ROOT / "roles" / "forward_proxy" / "tasks" / "verify_runtime_absent.yml"
        restart_boundary_path = ROOT / "roles" / "forward_proxy" / "tasks" / "verify_runtime_restart_boundary.yml"
        enabled_apply = ENABLED_APPLY.read_text(encoding="utf-8")
        runtime_absent = runtime_absent_path.read_text(encoding="utf-8")
        restart_boundary = restart_boundary_path.read_text(encoding="utf-8")

        self.assertIn("forward_proxy_first_run_systemd_unit_files.stdout_lines | length == 0", enabled_apply)
        self.assertIn("forward_proxy_runtime_systemd_unit_files.stdout_lines | length == 0", runtime_absent)
        self.assertIn("forward_proxy_restart_boundary_unit_files.stdout_lines | length == 0", restart_boundary)

        probes = (
            (
                ENABLED_APPLY,
                "Inspect a same-named installed unit file before any first activation writes",
                "forward_proxy_first_run_systemd_unit_files",
            ),
            (
                runtime_absent_path,
                "Inspect installed forward proxy systemd unit files",
                "forward_proxy_runtime_systemd_unit_files",
            ),
            (
                restart_boundary_path,
                "Reinspect installed unit files before restarting an absent runtime",
                "forward_proxy_restart_boundary_unit_files",
            ),
        )
        environment = Environment(undefined=StrictUndefined, autoescape=True)

        def is_failure(
            template: Template,
            register: str,
            rc: int,
            stdout: str = "",
            stderr: str = "",
        ) -> bool:
            result = type("CommandResult", (), {"rc": rc, "stdout": stdout, "stderr": stderr})()
            return template.render(**{register: result}).strip() == "True"

        for path, task_name, register in probes:
            with self.subTest(path=path.name):
                tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
                task = next(item for item in tasks if item["name"] == task_name)
                expression = task["failed_when"]
                template = environment.from_string("{{ " + expression + " }}")

                self.assertFalse(is_failure(template, register, 0))
                self.assertFalse(is_failure(template, register, 1))
                self.assertTrue(is_failure(template, register, 1, stderr="Failed to connect to bus"))
                self.assertTrue(is_failure(template, register, 1, stdout="unexpected diagnostic"))
                self.assertTrue(is_failure(template, register, 2))
                self.assertIn(f"{register}.stderr | trim | length > 0", expression)

    def test_tiny_evidence_is_per_contract_and_disposition_bound(self) -> None:
        converge = CONVERGE.read_text(encoding="utf-8")
        verify = VERIFY.read_text(encoding="utf-8")
        cleanup = CLEANUP.read_text(encoding="utf-8")
        release_eligibility = RELEASE_ELIGIBILITY.read_text(encoding="utf-8")
        self.assertIn("forward_proxy_contract_results", verify)
        self.assertIn("Write provisional fail-closed forward proxy JUnit result before convergence", converge)
        self.assertIn("forward proxy Tiny convergence or verification did not complete", converge)
        self.assertIn('errors="1"', converge)
        self.assertIn(
            '<error message="forward proxy Tiny convergence or verification did not complete"/>',
            converge,
        )
        self.assertLess(
            converge.index("Write provisional fail-closed forward proxy JUnit result before convergence"),
            converge.index("Remove only the scenario-owned stale forward proxy lock"),
        )
        self.assertLess(
            verify.index("Read rendered Squid policy"),
            verify.index("Write final per-contract forward proxy JUnit result"),
        )
        self.assertIn("Keep every dynamic boolean inside one native expression", verify)
        self.assertIn("{% for contract in forward_proxy_contract_results %}", verify)
        self.assertIn("forward_proxy_failed_contracts", verify)
        self.assertIn("tasks_from: restore_managed_file.yml", verify)
        self.assertIn("Require exact rollback of the transaction candidate", verify)
        self.assertIn("managed-file-rollback", verify)
        self.assertIn("rollback-fixture-restored", verify)
        self.assertIn("Restore the original policy through the bound atomic path", verify)
        self.assertIn("lit.supplementary.atomic_path", verify)
        self.assertIn("Require a canonical controller-owned rollback parent", verify)
        self.assertLess(
            verify.index("Require exact rollback of the transaction candidate"),
            verify.index("Write final per-contract forward proxy JUnit result"),
        )
        self.assertIn("meta/role-coverage.yml", cleanup)
        self.assertIn("forward_proxy_junit_passed", cleanup)
        self.assertIn("tasks/release_eligibility.yml", cleanup)
        self.assertIn("forward_proxy_release_gate_junit_passed | bool", release_eligibility)
        self.assertIn("== 'supported'", release_eligibility)
        self.assertIn("failed JUnit result against a supported profile", verify)
        self.assertIn("passed JUnit against the authoritative experimental profile", verify)
        self.assertIn("experimental profile to remain ineligible for release", verify)
        self.assertIn("passed JUnit result against a supported profile", verify)
        self.assertIn('forward_proxy_release_gate_junit_passed: "False"', verify)
        self.assertIn('forward_proxy_release_gate_junit_passed: "True"', verify)
        self.assertIn("forward_proxy_junit_passed | bool", cleanup)
        self.assertNotIn("release_eligible: false", cleanup)


if __name__ == "__main__":
    unittest.main()
