"""Validate PostgreSQL legacy-to-Quadlet transition contracts."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles" / "postgres_deploy"


class PostgresSystemdPreservationTests(unittest.TestCase):
    def test_real_lifecycle_tasks_cover_accepted_and_rejected_states(self) -> None:
        block = yaml.safe_load((ROLE / "tasks/systemd.yml").read_text(encoding="utf-8"))[0]["block"]
        task_map = {task["name"]: task for task in block}
        validation = task_map["Refuse unknown PostgreSQL lifecycle states"]["ansible.builtin.assert"]["that"]
        collision_task = task_map["Refuse unmanaged PostgreSQL pod; remove it first"]
        collision = collision_task["failed_when"]
        self.assertEqual(collision_task["ansible.builtin.command"]["argv"][:3], ["podman", "pod", "exists"])
        self.assertIn("postgres_deploy_native_systemd_active", collision)
        self.assertFalse((ROLE / "templates/podman-kube@.service.j2").exists())
        lifecycle_contract = str(validation)
        for contract in ("legacy_systemd_active", "native_systemd_active"):
            self.assertIn(contract, lifecycle_contract)
        for unsupported in ("activating", "static", "indirect", "transient", "linked"):
            self.assertNotIn(unsupported, lifecycle_contract)
        self.assertIn("postgres_deploy_legacy_systemd_active.stdout | trim != 'failed'", validation)
        self.assertIn("postgres_deploy_native_systemd_active.stdout | trim != 'failed'", validation)
        ownership = task_map["Refuse unproven drift in an existing native PostgreSQL Quadlet"]
        ownership_contract = "\n".join(str(item) for item in ownership["ansible.builtin.assert"]["that"])
        for contract in (
            "isreg",
            "islnk",
            "mode",
            "pw_name",
            "native_drop_in_paths",
            "service\\.d",
            "Description=",
            "Yaml=",
            "native_systemd_enabled",
            "/run/systemd/generator",
        ):
            self.assertIn(contract, ownership_contract)
        transaction = task_map["Cut over to native PostgreSQL Quadlet with rollback"]
        transaction_map = {task["name"]: task for task in transaction["block"]}
        transaction_names = [task["name"] for task in transaction["block"]]
        self.assertIn("Require the staged native PostgreSQL Quadlet provenance boundary", transaction_names)
        staging_condition = "not (postgres_deploy_native_quadlet_file.stat.exists | default(false))"
        for name in (
            "Stage the native PostgreSQL Quadlet before lifecycle mutation",
            "Reinspect the staged native PostgreSQL Quadlet",
            "Resolve the staged native PostgreSQL unit fragment",
            "Resolve staged native PostgreSQL unit drop-ins",
            "Require the staged native PostgreSQL Quadlet provenance boundary",
        ):
            self.assertEqual(transaction_map[name]["when"], staging_condition)
        staged_provenance = "\n".join(
            transaction_map["Require the staged native PostgreSQL Quadlet provenance boundary"][
                "ansible.builtin.assert"
            ]["that"]
        )
        self.assertIn("service\\.d", staged_provenance)
        legacy_stop = "Stop and disable the exact legacy PostgreSQL unit before Quadlet takeover"
        native_stop = "Stop the exact active native PostgreSQL unit before manifest replacement"
        preview = "Preview transactional PostgreSQL Pod manifest drift"
        render = "Render the transactional PostgreSQL Pod manifest"
        manage = "Manage the native PostgreSQL Quadlet service"
        self.assertLess(transaction_names.index(legacy_stop), transaction_names.index(render))
        self.assertLess(transaction_names.index(preview), transaction_names.index(native_stop))
        self.assertLess(transaction_names.index(native_stop), transaction_names.index(render))
        self.assertLess(transaction_names.index(render), transaction_names.index(manage))
        self.assertEqual((transaction_map[preview]["check_mode"], transaction_map[preview]["diff"]), (True, False))
        self.assertIs(transaction_map[preview]["no_log"], True)
        self.assertIn("postgres_deploy_manifest_preview.changed", "\n".join(transaction_map[native_stop]["when"]))
        self.assertIn("/run/systemd/system/service\\.d/zzz-lxc-service\\.conf", ownership_contract)
        self.assertLess(
            transaction_names.index(manage),
            transaction_names.index("Wait for PostgreSQL readiness before committing native takeover"),
        )
        rescue_source = "\n".join(str(task) for task in transaction["rescue"])
        for contract in (
            "exact pre-transaction PostgreSQL Pod manifest",
            "transaction-created PostgreSQL Pod manifest",
            "generated native PostgreSQL service",
            "native PostgreSQL inactivity",
            "exact legacy PostgreSQL service",
        ):
            self.assertIn(contract, rescue_source)
        pod_tasks = yaml.safe_load((ROLE / "tasks/deploy_pod.yml").read_text(encoding="utf-8"))
        manifest_render = next(task for task in pod_tasks if task["name"].startswith("Render PostgreSQL Pod manifest"))
        self.assertIn("not postgres_deploy_manage_systemd", manifest_render["when"])
        self.assertEqual(manifest_render["ansible.builtin.template"]["owner"], "root")
        self.assertEqual(manifest_render["ansible.builtin.template"]["group"], "root")
        self.assertEqual(manifest_render["ansible.builtin.template"]["mode"], "0600")

    def test_failed_fresh_cleanup_detects_a_running_native_pod(self) -> None:
        executable = shutil.which("ansible-playbook")
        self.assertIsNotNone(executable, "Pinned Devtools Ansible is required")

        with tempfile.TemporaryDirectory(prefix="postgres-rollback-") as temporary:
            root = Path(temporary)
            collection = root / "collections/ansible_collections/lit/supplementary"
            fixture_role = collection / "roles/postgres_deploy"
            fixture_role.parent.mkdir(parents=True)
            shutil.copytree(ROLE, fixture_role)
            fixture_filters = collection / "plugins/filter"
            fixture_filters.mkdir(parents=True)
            shutil.copy2(ROLE.parents[1] / "plugins/filter/native_manifest.py", fixture_filters / "native_manifest.py")
            fixture_foundational_tasks = (
                root / "collections/ansible_collections/lit/foundational/roles/podman_systemd/tasks"
            )
            fixture_foundational_tasks.mkdir(parents=True)
            (fixture_foundational_tasks / "main.yml").write_text(
                """---
- name: Ensure fixture Quadlet directory exists
  ansible.builtin.file:
    path: "{{ podman_systemd_quadlet_dir }}"
    state: directory
    mode: '0755'

- name: Materialize fixture Quadlet
  ansible.builtin.copy:
    dest: "{{ podman_systemd_quadlet_dir }}/{{ podman_systemd_unit_name }}.kube"
    content: "[Kube]\nYaml={{ podman_systemd_manifest_path }}\n"
    mode: '0644'
  when: podman_systemd_action not in ['absent', 'stopped']

- name: Apply fixture service action
  ansible.builtin.command:
    argv:
      - systemctl
      - >-
        {{
          'restart'
          if podman_systemd_action == 'restarted'
          else ('stop' if podman_systemd_action == 'stopped' else 'start')
        }}
      - "{{ podman_systemd_unit_name }}.service"
  changed_when: true
  when: podman_systemd_action != 'absent'

- name: Apply fixture enabled state
  ansible.builtin.command:
    argv:
      - systemctl
      - "{{ 'enable' if podman_systemd_enabled | bool else 'disable' }}"
      - "{{ podman_systemd_unit_name }}.service"
  changed_when: true
  when: podman_systemd_action != 'absent'

- name: Stop fixture service before removal
  ansible.builtin.command:
    argv: [systemctl, stop, "{{ podman_systemd_unit_name }}.service"]
  changed_when: true
  failed_when: false
  when: podman_systemd_action == 'absent'

- name: Remove fixture Quadlet
  ansible.builtin.file:
    path: "{{ podman_systemd_quadlet_dir }}/{{ podman_systemd_unit_name }}.kube"
    state: absent
  when: podman_systemd_action == 'absent'
""",
                encoding="utf-8",
            )
            fixture_systemd = fixture_role / "tasks/systemd.yml"
            production_systemd = fixture_systemd.read_text(encoding="utf-8")
            privileged_render = """            owner: root
            group: root
            mode: '0600'
"""
            self.assertEqual(production_systemd.count(privileged_render), 2)
            fixture_systemd.write_text(
                production_systemd.replace(
                    privileged_render,
                    f"""            owner: {os.geteuid()}
            group: {os.getegid()}
            mode: '0600'
""",
                )
                .replace(
                    "            owner: root\n            group: root\n            mode: '0644'\n",
                    f"            owner: {os.geteuid()}\n            group: {os.getegid()}\n            mode: '0644'\n",
                )
                .replace(
                    "postgres_deploy_staged_quadlet_file.stat.pw_name | default('') == 'root'",
                    f"postgres_deploy_staged_quadlet_file.stat.uid | int == {os.geteuid()}",
                )
                .replace(
                    "postgres_deploy_staged_quadlet_file.stat.gr_name | default('') == 'root'",
                    f"postgres_deploy_staged_quadlet_file.stat.gid | int == {os.getegid()}",
                ),
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            state = root / "systemd-state"
            state.mkdir()
            native_state = "postgres-pod_service"
            (state / f"{native_state}.active").write_text("inactive", encoding="utf-8")
            log = root / "systemctl.log"
            manifest = root / "postgres.yml"
            original = b"kind: Pod\nmetadata: {name: original-postgres}\nspec: {containers: []}\n"
            manifest.write_bytes(original)
            manifest.chmod(0o640)
            quadlet_dir = root / "quadlets"
            quadlet_dir.mkdir()

            systemd_escape = fake_bin / "systemd-escape"
            systemd_escape.write_text("#!/bin/sh\nprintf '%s\\n' 'etc-podman-pods-postgres.yml'\n", encoding="utf-8")
            systemd_escape.chmod(0o755)

            systemctl = fake_bin / "systemctl"
            systemctl.write_text(
                """#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
command_name="${1:-}"
case "$command_name" in
  --user) shift; command_name="${1:-}" ;;
esac
shift || true
unit="${1:-}"
safe_unit=$(printf '%s' "$unit" | tr '/@.' '___')
active_file="$FAKE_SYSTEMD_STATE/$safe_unit.active"
enabled_file="$FAKE_SYSTEMD_STATE/$safe_unit.enabled"
case "$unit" in
  podman-kube@*) default_active=unknown; default_enabled=not-found ;;
  *) default_active=inactive; default_enabled=not-found ;;
esac
active=$(cat "$active_file" 2>/dev/null || printf '%s' "$default_active")
enabled=$(cat "$enabled_file" 2>/dev/null || printf '%s' "$default_enabled")
case "$command_name" in
  show)
    case "$*" in
      *--property=DropInPaths*) printf '\n' ;;
      *--property=FragmentPath*) printf '/run/systemd/generator/%s\\n' "$unit" ;;
      *) printf 'LoadState=loaded\\nActiveState=%s\\nSubState=%s\\nUnitFileState=%s\\n' \
           "$active" "$active" "$enabled" ;;
    esac
    ;;
  is-active)
    printf '%s\\n' "$active"
    if [ "$active" = active ]; then exit 0; fi
    exit 3
    ;;
  is-enabled)
    printf '%s\\n' "$enabled"
    test "$enabled" = enabled
    ;;
  enable)
    printf enabled > "$enabled_file"
    ;;
  disable)
    printf disabled > "$enabled_file"
    ;;
  start|restart)
    printf active > "$active_file"
    ;;
  stop)
    if [ "$unit" = postgres-pod.service ] && [ "$active" = active ]; then exit 42; fi
    printf inactive > "$active_file"
    ;;
  daemon-reload)
    ;;
  list-unit-files)
    printf '%s enabled\\n' "$unit"
    ;;
  *)
    ;;
esac
""",
                encoding="utf-8",
            )
            systemctl.chmod(0o755)

            podman = fake_bin / "podman"
            podman.write_text(
                """#!/bin/sh
set -eu
if [ "${1:-}" = pod ] && [ "${2:-}" = exists ]; then
  [ "$(cat "$FAKE_NATIVE_ACTIVE_FILE" 2>/dev/null || true)" = active ] && exit 0
  exit 1
fi
if [ "${1:-}" = exec ]; then
  exit 1
fi
exit 0
""",
                encoding="utf-8",
            )
            podman.chmod(0o755)

            playbook = root / "rollback.yml"
            playbook.write_text(
                yaml.safe_dump(
                    [
                        {
                            "hosts": "localhost",
                            "gather_facts": False,
                            "vars": {
                                "ansible_service_mgr": "systemd",
                                "postgres_deploy_pod_manifest_path": str(manifest),
                                "postgres_deploy_quadlet_dir": str(quadlet_dir),
                                "postgres_deploy_host_data_dir": str(root / "data"),
                                "postgres_deploy_db_password_effective": "OFFLINE_TEST_ONLY",
                                "postgres_deploy_readiness_retries": 1,
                                "postgres_deploy_readiness_delay": 0,
                            },
                            "tasks": [
                                {
                                    "name": "Execute the real PostgreSQL systemd transaction",
                                    "ansible.builtin.include_role": {
                                        "name": "lit.supplementary.postgres_deploy",
                                        "tasks_from": "systemd",
                                    },
                                }
                            ],
                        }
                    ],
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nstdout_callback=default\n", encoding="utf-8")
            environment = {
                **os.environ,
                "ANSIBLE_CONFIG": str(config),
                "ANSIBLE_COLLECTIONS_PATH": f"{root / 'collections'}:/usr/share/ansible/collections",
                "ANSIBLE_LOCAL_TEMP": str(root / "ansible-tmp"),
                "ANSIBLE_NOCOLOR": "1",
                "FAKE_SYSTEMCTL_LOG": str(log),
                "FAKE_SYSTEMD_STATE": str(state),
                "FAKE_NATIVE_ACTIVE_FILE": str(state / f"{native_state}.active"),
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
            }
            result = subprocess.run(  # noqa: S603
                [executable, "-i", "localhost,", "-c", "local", str(playbook)],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

            output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn("Native PostgreSQL Quadlet takeover failed", output)
            self.assertEqual(manifest.read_bytes(), original)
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o640)
            self.assertFalse((quadlet_dir / "postgres-pod.kube").exists())
            service_log = log.read_text(encoding="utf-8")
            evidence = f"{output}\nSYSTEMCTL LOG:\n{service_log}"
            self.assertIn("start postgres-pod.service", service_log, evidence)
            self.assertIn("stop postgres-pod.service", service_log, evidence)
            self.assertIn("Native quiescence failure", output)
            self.assertEqual((state / f"{native_state}.active").read_text(encoding="utf-8"), "active")

    def test_active_native_rollback_restarts_the_restored_manifest(self) -> None:
        tasks = yaml.safe_load((ROLE / "tasks/systemd.yml").read_text(encoding="utf-8"))[0]["block"]
        transaction = next(
            task for task in tasks if task["name"] == "Cut over to native PostgreSQL Quadlet with rollback"
        )
        restoration = next(
            task
            for task in transaction["rescue"]
            if task["name"] == "Attempt pre-existing native PostgreSQL service-state restoration"
        )
        for task in restoration["block"]:
            state_expression = task["ansible.builtin.systemd"]["state"]
            self.assertIn("'restarted'", state_expression)
            self.assertIn("'active'", state_expression)
            self.assertIn("'stopped'", state_expression)

    def test_existing_quadlet_is_read_with_supported_slurp_argument(self) -> None:
        block = yaml.safe_load((ROLE / "tasks/systemd.yml").read_text(encoding="utf-8"))[0]["block"]
        task = next(task for task in block if task["name"] == "Read the desired native PostgreSQL Quadlet file")
        self.assertEqual(set(task["ansible.builtin.slurp"]), {"src"})


if __name__ == "__main__":
    unittest.main()
