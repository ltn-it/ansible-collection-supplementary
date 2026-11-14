"""Regression tests for exact-owned Incus network and instance lifecycle policy."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import yaml

from scripts import prune_stale_incus_resources

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / "molecule" / "shared" / "incus"
PARTIAL_RUNTIME_SCENARIOS = (
    "atlas-observability-incus_heavy",
    "rsyslog-lifecycle-incus_heavy",
    "samba-lifecycle-incus_heavy",
)


def load_play_tasks(name: str) -> list[dict[str, Any]]:
    payload = yaml.safe_load((SHARED / name).read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise AssertionError(f"{name} is not an Ansible playbook")
    tasks = payload[0].get("tasks")
    if not isinstance(tasks, list):
        raise AssertionError(f"{name} has no task list")
    return tasks


def task_named(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    matches = [task for task in tasks if task.get("name") == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one task named {name!r}, got {len(matches)}")
    return matches[0]


class IncusLifecycleTests(unittest.TestCase):
    def test_actual_configuration_task_keeps_container_idmaps_out_of_vm_commands(self) -> None:
        task = task_named(load_play_tasks("create.yml"), "Apply requested Incus instance configuration")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = root / "record.py"
            calls = root / "calls.jsonl"
            recorder.write_text(
                "import json,os,sys\n"
                "with open(os.environ['INCUS_CONFIG_CALLS'],'a') as f:"
                "f.write(json.dumps(sys.argv[1:])+'\\n')\n"
            )
            # Replace only the executable with an inert recorder. The real
            # task's loop, condition and argv templating run inside Ansible.
            command = task["ansible.builtin.command"]["argv"]
            task["ansible.builtin.command"]["argv"] = [sys.executable, str(recorder), *command[1:]]
            task["environment"] = {"INCUS_CONFIG_CALLS": str(calls)}
            common = [{"key": "security.nesting", "value": "true"}, {"key": "security.idmap.isolated", "value": "true"}]
            platforms = [
                {"name": "vm", "type": "vm", "config": common},
                {"name": "container", "type": "container", "config": common},
                {"name": "legacy", "config": common},
            ]
            play = root / "configuration.yml"
            play.write_text(
                yaml.safe_dump(
                    [
                        {
                            "name": "Inert typed configuration fixture",
                            "hosts": "localhost",
                            "connection": "local",
                            "gather_facts": False,
                            "vars": {"molecule_incus_instances": platforms},
                            "tasks": [task],
                        }
                    ]
                )
            )
            environment = dict(
                os.environ, ANSIBLE_HOME=str(root / "home"), ANSIBLE_LOCAL_TEMP=str(root / "ansible-tmp")
            )
            environment.pop("ANSIBLE_CONFIG", None)
            ansible = shutil.which("ansible-playbook")
            self.assertIsNotNone(ansible)
            # Exact EE executable and generated inert fixture; no shell or external input.
            result = subprocess.run(  # noqa: S603
                [ansible, "-i", "localhost,", str(play)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            observed = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertCountEqual(
                [
                    ["config", "set", "vm", "security.nesting=true"],
                    ["config", "set", "container", "security.nesting=true"],
                    ["config", "set", "container", "security.idmap.isolated=true"],
                    ["config", "set", "legacy", "security.nesting=true"],
                    ["config", "set", "legacy", "security.idmap.isolated=true"],
                ],
                observed,
            )

    def test_legacy_pruner_never_accesses_incus_for_any_run_order(self) -> None:
        # A newer run must not kill an older run; an attempt shares its run ID.
        for run_id in ("41", "42", "35703209227"):
            with (
                self.subTest(run_id=run_id),
                mock.patch("sys.argv", ["pruner", "--repository", "lightning-it/example", "--current-run-id", run_id]),
                mock.patch("subprocess.run") as execute,
                mock.patch("subprocess.Popen") as spawn,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(0, prune_stale_incus_resources.main())
                self.assertIn("Cross-run Incus pruning disabled", output.getvalue())
                execute.assert_not_called()
                spawn.assert_not_called()

    def test_legacy_pruner_retains_input_validation_without_mutation(self) -> None:
        for repository, run_id in (
            ("bad/owner/name", "42"),
            ("lightning-it/example", "0"),
            ("lightning-it/example", "bad"),
        ):
            with (
                self.subTest(repository=repository, run_id=run_id),
                mock.patch("sys.argv", ["pruner", "--repository", repository, "--current-run-id", run_id]),
                mock.patch("subprocess.run") as execute,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as failure:
                    prune_stale_incus_resources.main()
                self.assertEqual(2, failure.exception.code)
                execute.assert_not_called()

    def test_nested_containers_use_isolated_idmaps(self) -> None:
        for molecule_file in sorted((ROOT / "molecule").glob("*/molecule.yml")):
            config = yaml.safe_load(molecule_file.read_text(encoding="utf-8"))
            for platform in config.get("platforms", []):
                instance_config = {item["key"]: item["value"] for item in platform.get("config", [])}
                if instance_config.get("security.nesting") != "true":
                    continue
                with self.subTest(scenario=molecule_file.parent.name):
                    self.assertEqual(
                        "true",
                        instance_config.get("security.idmap.isolated"),
                        "nested Incus containers must not share per-UID kernel quotas",
                    )

    def test_network_and_instance_ownership_is_atomic(self) -> None:
        tasks = load_play_tasks("create.yml")
        network_create = task_named(tasks, "Create the managed network with atomic exact-owner labels")
        network_argv = str(network_create["ansible.builtin.command"]["argv"])
        self.assertIn("'incus', 'network', 'create'", network_argv)
        self.assertIn("user.lit-molecule-owner=", network_argv)
        self.assertEqual("{{ 0 if molecule_incus_is_remote else 3 }}", network_create["retries"])
        self.assertEqual(10, network_create["delay"])
        self.assertEqual("molecule_incus_network_create.rc == 0", network_create["until"])

        instance_init = task_named(
            tasks,
            "Initialize missing Incus instances with atomic owner labels and network attachment",
        )
        instance_argv = str(instance_init["ansible.builtin.command"]["argv"])
        self.assertIn("['incus', 'init'", instance_argv)
        self.assertIn("['--network', molecule_incus_network_effective]", instance_argv)
        self.assertIn("user.lit-molecule-owner=", instance_argv)
        self.assertIn("user.lit-molecule-repository=", instance_argv)

    def test_every_attachment_is_verified_before_any_start(self) -> None:
        tasks = load_play_tasks("create.yml")
        names = [str(task.get("name", "")) for task in tasks]
        verify_index = names.index("Verify every instance is attached to the exact-owned network before start")
        start_index = names.index("Start Incus instances")
        self.assertLess(verify_index, start_index)
        self.assertIn("molecule_incus_network_attachments.stdout", str(tasks[verify_index]))

    def test_destroy_is_owner_filtered_and_has_a_fail_closed_postcondition(
        self,
    ) -> None:
        tasks = load_play_tasks("destroy.yml")
        delete_instances = task_named(tasks, "Delete only Incus instances owned by this exact test run")
        self.assertEqual(
            "{{ molecule_incus_instance_owners_at_delete.results }}",
            delete_instances["loop"],
        )
        revalidate_instances = task_named(tasks, "Revalidate ownership immediately before instance deletion")
        self.assertEqual(
            "{{ molecule_incus_exact_owned_instance_names }}",
            revalidate_instances["loop"],
        )
        self.assertIn("molecule_incus_owner_effective", str(delete_instances["when"]))
        delete_network = task_named(tasks, "Delete only the network owned by this exact test run")
        self.assertIn("molecule_incus_network_owner_at_delete.stdout", str(delete_network["when"]))

        postcondition = task_named(tasks, "Fail closed when exact-owned Incus resources remain")
        assertions = postcondition["ansible.builtin.assert"]["that"]
        self.assertIn("molecule_incus_remaining_exact_owned_instances | length == 0", assertions)
        self.assertIn("molecule_incus_remaining_exact_owned_networks | length == 0", str(assertions))
        self.assertIn("molecule_incus_remaining_network_owner", str(assertions))

    def test_network_lifecycle_evidence_is_recorded_in_every_phase(self) -> None:
        create = (SHARED / "create.yml").read_text(encoding="utf-8")
        cleanup = (SHARED / "cleanup.yml").read_text(encoding="utf-8")
        destroy = (SHARED / "destroy.yml").read_text(encoding="utf-8")
        self.assertIn("-network-ready.json", create)
        self.assertIn("attachment_verified_before_start", create)
        self.assertIn("-network.json", cleanup)
        self.assertIn('"firewall_controller"', cleanup)
        self.assertIn('"firewalld_runtime_zone"', cleanup)
        self.assertIn("-network-destroy.json", destroy)
        self.assertIn("exact_owned_network_remaining", destroy)

    def test_container_inventory_is_json_and_failed_optional_logs_are_not_written(
        self,
    ) -> None:
        collection = (SHARED / "collect-evidence.yml").read_text(encoding="utf-8")
        tasks = yaml.safe_load(collection)
        inventory = task_named(tasks, "Read exact in-target container image identities and digests")
        argv = inventory["ansible.builtin.command"]["argv"]
        dependency_inventory = task_named(tasks, "Record exact sanitized image dependency identities")
        refreshed_inventory = task_named(
            tasks,
            "Refresh the dependency inventory from the populated Podman evidence stream",
        )

        self.assertEqual(["sh", "-c"], argv[-3:-1])
        self.assertIn("e3tqc29uIC59fQ==", argv[-1])
        self.assertIn('podman images --all --format "$format"', argv[-1])
        self.assertNotIn("{{json", argv[-1])
        self.assertIn("item.molecule_incus_evidence_command.name == 'podman-inventory'", collection)
        self.assertIn("when: item.rc == 0", collection)
        self.assertNotIn("--format=json", argv)
        for task in (dependency_inventory, refreshed_inventory):
            conditions = task["when"]
            self.assertIn("molecule_incus_evidence_base_image.rc == 0", conditions)
            self.assertTrue(
                any("is match('^[0-9a-f]{64}$')" in str(condition) for condition in conditions),
                conditions,
            )

    def test_firewalld_binding_is_runtime_scoped_and_destroyed_first(self) -> None:
        create_tasks = load_play_tasks("create.yml")
        create_names = [str(task.get("name", "")) for task in create_tasks]
        inspect = task_named(create_tasks, "Inspect any existing runtime firewalld bridge binding")
        bind = task_named(
            create_tasks,
            "Bind only the exact-owned bridge to the runtime firewalld zone",
        )
        verify = task_named(create_tasks, "Verify the exact runtime firewalld bridge binding")
        for task in (inspect, bind, verify):
            self.assertTrue(task["become"])
            rendered = str(task)
            self.assertIn("molecule_incus_network_effective", rendered)
            self.assertNotIn("--permanent", rendered)
        self.assertLess(
            create_names.index("Refuse a conflicting runtime firewalld bridge binding"),
            create_names.index("Bind only the exact-owned bridge to the runtime firewalld zone"),
        )
        network_create = task_named(create_tasks, "Create the managed network with atomic exact-owner labels")
        network_argv = str(network_create["ansible.builtin.command"]["argv"])
        self.assertIn("ipv4.firewall=", network_argv)
        self.assertIn("user.lit-molecule-firewalld-zone=", network_argv)

        destroy_tasks = load_play_tasks("destroy.yml")
        destroy_names = [str(task.get("name", "")) for task in destroy_tasks]
        removal = task_named(destroy_tasks, "Remove only the exact bridge runtime firewalld binding")
        self.assertTrue(removal["become"])
        self.assertNotIn("--permanent", str(removal))
        self.assertIn("molecule_incus_owner_effective", str(removal["when"]))
        self.assertLess(
            destroy_names.index("Verify the runtime firewalld binding is absent before network deletion"),
            destroy_names.index("Delete only the network owned by this exact test run"),
        )

    def test_network_readiness_proves_lease_route_and_dns(self) -> None:
        tasks = load_play_tasks("create.yml")
        names = [str(task.get("name", "")) for task in tasks]
        start = names.index("Start Incus instances")
        lease = names.index("Wait for an Incus-managed IPv4 lease")
        route = names.index("Verify a guest default IPv4 route")
        dns = names.index("Verify guest DNS through the exact-owned bridge")
        evidence = names.index("Record exact-owned network creation and attachment evidence")
        self.assertLess(start, lease)
        self.assertLess(lease, route)
        self.assertLess(route, dns)
        self.assertLess(dns, evidence)
        create = (SHARED / "create.yml").read_text(encoding="utf-8")
        self.assertIn('"ipv4_leases"', create)
        self.assertIn('"default_routes"', create)
        self.assertIn('"dns_verified": true', create)

    def test_local_identity_is_persisted_across_phases_and_cleared_after_destroy(
        self,
    ) -> None:
        for name in ("create.yml", "cleanup.yml", "destroy.yml"):
            with self.subTest(playbook=name):
                text = (SHARED / name).read_text(encoding="utf-8")
                self.assertIn("MOLECULE_EPHEMERAL_DIRECTORY", text)
                self.assertIn("['--state-file', molecule_incus_local_state_file]", text)

        destroy_tasks = load_play_tasks("destroy.yml")
        names = [str(task.get("name", "")) for task in destroy_tasks]
        self.assertGreater(
            names.index("Remove persisted local identity only after successful cleanup"),
            names.index("Fail closed when exact-owned Incus resources remain"),
        )

    def test_partial_static_networking_is_retired_and_ci_names_are_per_run(
        self,
    ) -> None:
        for scenario in PARTIAL_RUNTIME_SCENARIOS:
            with self.subTest(scenario=scenario):
                root = ROOT / "molecule" / scenario
                config = yaml.safe_load((root / "molecule.yml").read_text(encoding="utf-8"))
                platform = config["platforms"][0]
                self.assertNotIn("ipv4_address", platform)
                self.assertNotIn("ipv4_gateway", platform)
                self.assertNotIn("dns_servers", platform)
                self.assertIn("${MOLECULE_TEST_INSTANCE:-", platform["name"])
                self.assertIn(
                    "../shared/incus/create.yml",
                    (root / "create.yml").read_text(encoding="utf-8"),
                )

        action = (ROOT / ".github" / "actions" / "run-quality-profile" / "action.yml").read_text(encoding="utf-8")
        self.assertIn('echo "MOLECULE_TEST_INSTANCE=$instance"', action)
        self.assertIn('echo "MOLECULE_TEST_IMAGE=$TEST_IMAGE"', action)
        self.assertIn("dependencies.mkdir(parents=True, exist_ok=True)", action)
        self.assertIn('"${candidates[0]}"', action)
        self.assertIn("--no-deps", action)
        self.assertIn("runtime-collections.tar.gz", action)
        self.assertIn("missing declared runtime collections", action)

    def test_quality_action_does_not_prune_other_runs(self) -> None:
        action = (ROOT / ".github" / "actions" / "run-quality-profile" / "action.yml").read_text(encoding="utf-8")
        self.assertNotIn("scripts/prune_stale_incus_resources.py", action)
        self.assertIn('molecule cleanup -s "$QUALITY_SCENARIO"', action)
        self.assertIn('molecule destroy -s "$QUALITY_SCENARIO"', action)

        cleanup = (SHARED / "cleanup.yml").read_text(encoding="utf-8")
        network_show = cleanup.split(
            "- name: Read exact-owned managed-network state for lifecycle evidence",
            maxsplit=1,
        )[1].split("- name:", maxsplit=1)[0]
        self.assertIn("failed_when: false", network_show)

    def test_legacy_static_entrypoint_fails_before_create(self) -> None:
        payload = yaml.safe_load((SHARED / "create-static-network.yml").read_text(encoding="utf-8"))
        self.assertEqual(
            "Reject the retired after-start static-network lifecycle",
            payload[0]["name"],
        )
        self.assertIn("ansible.builtin.assert", payload[0]["tasks"][0])
        self.assertIn("ansible.builtin.import_playbook", payload[1])


if __name__ == "__main__":
    unittest.main()
