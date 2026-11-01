"""Contract tests for Keycloak role interfaces and portable service identities."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from jinja2 import Environment

ROOT = Path(__file__).parents[2]


class KeycloakRoleContractTests(unittest.TestCase):
    def _role_defaults(self, role: str) -> dict[str, object]:
        path = ROOT / "roles" / role / "defaults" / "main.yml"
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertIsInstance(loaded, dict)
        return loaded

    def _role_options(self, role: str) -> dict[str, dict[str, object]]:
        path = ROOT / "roles" / role / "meta" / "argument_specs.yml"
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        options = loaded["argument_specs"]["main"]["options"]
        self.assertIsInstance(options, dict)
        return options

    def _assert_documented_options(self, options: dict[str, dict[str, object]]) -> None:
        for name, option in options.items():
            with self.subTest(option=name):
                self.assertIn("type", option)
                self.assertIsInstance(option.get("description"), str)
                self.assertTrue(str(option["description"]).strip())
                nested = option.get("options")
                if nested is not None:
                    self.assertIsInstance(nested, dict)
                    self._assert_documented_options(nested)

    def test_every_keycloak_default_has_a_typed_described_argument(self) -> None:
        for role in ("keycloak_deploy", "keycloak_cac"):
            with self.subTest(role=role):
                defaults = self._role_defaults(role)
                options = self._role_options(role)
                self.assertEqual(set(defaults), set(options))
                self._assert_documented_options(options)

    def test_secret_bearing_arguments_are_suppressed_from_logs(self) -> None:
        deploy = self._role_options("keycloak_deploy")
        deploy_secrets = {
            "keycloak_deploy_db_password",
            "keycloak_deploy_admin_password",
            "keycloak_deploy_env_extra",
            "keycloak_deploy_vault_token",
            "keycloak_deploy_vault_role_id",
            "keycloak_deploy_vault_secret_id",
            "keycloak_deploy_vault_auth_token",
            "keycloak_deploy_vault_auth_role_id",
            "keycloak_deploy_vault_auth_secret_id",
        }
        for name in deploy_secrets:
            with self.subTest(option=name):
                self.assertIs(deploy[name].get("no_log"), True)

        cac = self._role_options("keycloak_cac")
        cac_secrets = {
            "keycloak_cac_admin_password",
            "keycloak_cac_realms",
            "keycloak_cac_clients",
            "keycloak_cac_users",
            "keycloak_cac_groups",
            "keycloak_cac_roles",
            "keycloak_cac_user_role_mappings",
            "keycloak_cac_samba_ldap_provider",
            "keycloak_cac_ldap_providers",
        }
        for name in cac_secrets:
            with self.subTest(option=name):
                self.assertIs(cac[name].get("no_log"), True)

        ldap_options = cac["keycloak_cac_samba_ldap_provider"]["options"]
        self.assertIs(ldap_options["bind_credential"].get("no_log"), True)

    def _assert_portable_group_expression(self, expression: object) -> None:
        self.assertIsInstance(expression, str)
        template = Environment(autoescape=False).from_string(expression)  # noqa: S701

        self.assertEqual(template.render(ansible_facts={"os_family": "Debian"}).strip(), "nogroup")
        self.assertEqual(template.render(ansible_facts={"os_family": "RedHat"}).strip(), "nobody")
        self.assertEqual(template.render(ansible_facts={"os_family": "Suse"}).strip(), "")
        self.assertEqual(template.render().strip(), "")

    def test_service_group_defaults_are_portable_and_fail_closed(self) -> None:
        samba_expression = self._role_defaults("samba_deploy")["samba_deploy_share_group"]
        self._assert_portable_group_expression(samba_expression)

        acceptance_path = ROOT / "molecule" / "keycloak-application-acceptance" / "converge.yml"
        acceptance_source = acceptance_path.read_text(encoding="utf-8")
        acceptance_plays = yaml.safe_load(acceptance_source)
        acceptance_expression = acceptance_plays[1]["vars"]["keycloak_acceptance_service_group"]
        self._assert_portable_group_expression(acceptance_expression)
        self.assertIn("User={{ keycloak_acceptance_service_user }}", acceptance_source)
        self.assertIn("Group={{ keycloak_acceptance_service_group }}", acceptance_source)

    def test_samba_bind_identity_matches_keycloak_ldap_provider(self) -> None:
        samba_defaults = self._role_defaults("samba_deploy")
        expected_cn = " ".join(
            (
                str(samba_defaults["samba_deploy_ad_dc_keycloak_bind_given_name"]),
                str(samba_defaults["samba_deploy_ad_dc_keycloak_bind_surname"]),
            )
        )

        cac_defaults = self._role_defaults("keycloak_cac")
        default_bind_dn = cac_defaults["keycloak_cac_samba_ldap_provider"]["bind_dn"]
        self.assertEqual(default_bind_dn, f"CN={expected_cn},CN=Users,DC=corp,DC=example,DC=com")

        heavy_path = ROOT / "molecule" / "keycloak-heavy" / "converge.yml"
        heavy_plays = yaml.safe_load(heavy_path.read_text(encoding="utf-8"))
        heavy_provider = heavy_plays[1]["vars"]["keycloak_cac_samba_ldap_provider"]
        self.assertEqual(
            heavy_provider["bind_dn"],
            f"CN={expected_cn},CN=Users,DC=keycloak,DC=test",
        )

    def test_postgres_manifest_with_password_is_owner_only(self) -> None:
        tasks_path = ROOT / "roles" / "postgres_deploy" / "tasks" / "deploy_pod.yml"
        tasks = yaml.safe_load(tasks_path.read_text(encoding="utf-8"))
        render_task = next(task for task in tasks if task.get("name", "").startswith("Render PostgreSQL Pod manifest"))

        self.assertEqual(render_task["ansible.builtin.template"]["mode"], "0600")
        self.assertIs(render_task["no_log"], True)

        systemd_block = yaml.safe_load(
            (ROOT / "roles" / "postgres_deploy" / "tasks" / "systemd.yml").read_text(encoding="utf-8")
        )[0]["block"]
        transaction = next(
            task for task in systemd_block if task["name"] == "Cut over to native PostgreSQL Quadlet with rollback"
        )
        transactional_render = next(
            task for task in transaction["block"] if task["name"] == "Render the transactional PostgreSQL Pod manifest"
        )
        self.assertEqual(transactional_render["ansible.builtin.template"]["mode"], "0600")
        self.assertIs(transactional_render["no_log"], True)

        template_path = ROOT / "roles" / "postgres_deploy" / "templates" / "postgres-pod.yml.j2"
        self.assertIn("POSTGRES_PASSWORD", template_path.read_text(encoding="utf-8"))

    def test_keycloak_lifecycle_has_one_controller_and_verifies_runtime(self) -> None:
        pod_tasks_path = ROOT / "roles" / "keycloak_deploy" / "tasks" / "deploy_pod.yml"
        pod_tasks = yaml.safe_load(pod_tasks_path.read_text(encoding="utf-8"))
        pod_task_map = {task["name"]: task for task in pod_tasks}
        recreate = pod_task_map["Recreate Keycloak pod from the desired manifest"]
        self.assertEqual(recreate["vars"]["kubeplay_action"], "recreate")
        self.assertIn("not keycloak_deploy_manage_systemd | bool", recreate["when"])
        systemd_block = yaml.safe_load((ROOT / "roles/keycloak_deploy/tasks/systemd.yml").read_text(encoding="utf-8"))[
            0
        ]["block"]
        systemd_map = {task["name"]: task for task in systemd_block}
        transaction = systemd_map["Cut over to native Keycloak Quadlet with rollback"]
        transaction_map = {task["name"]: task for task in transaction["block"]}
        quadlet = transaction_map["Manage the native Keycloak Quadlet service"]
        self.assertEqual(quadlet["ansible.builtin.include_role"]["name"], "lit.foundational.podman_systemd")
        for contract in (
            "keycloak_deploy_pod_manifest_path",
            "keycloak_deploy_quadlet_dir",
            "keycloak_deploy_networks",
        ):
            self.assertIn(contract, str(quadlet["vars"]))
        stage = transaction_map["Stage the native Keycloak Quadlet before lifecycle mutation"]
        names = [task["name"] for task in systemd_block]
        validation_index = names.index("Refuse unknown Keycloak lifecycle states")
        collision_index = next(index for index, name in enumerate(names) if "Refuse unmanaged Keycloak" in name)
        collision = systemd_block[collision_index]
        self.assertEqual(collision["ansible.builtin.command"]["argv"][:3], ["podman", "pod", "exists"])
        self.assertIn("keycloak_deploy_native_systemd_active", collision["failed_when"])
        ownership = systemd_map["Refuse unproven drift in an existing native Keycloak Quadlet"]
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
        self.assertIn("Require the staged native Keycloak Quadlet provenance boundary", transaction_map)
        staging_condition = "not (keycloak_deploy_native_quadlet_file.stat.exists | default(false))"
        for name in (
            "Stage the native Keycloak Quadlet before lifecycle mutation",
            "Reinspect the staged native Keycloak Quadlet",
            "Resolve the staged native Keycloak unit fragment",
            "Resolve staged native Keycloak unit drop-ins",
            "Require the staged native Keycloak Quadlet provenance boundary",
        ):
            self.assertEqual(transaction_map[name]["when"], staging_condition)
        lifecycle_contract = str(systemd_block[validation_index]["ansible.builtin.assert"]["that"])
        for unsupported in ("activating", "reloading", "deactivating", "static", "indirect", "transient", "linked"):
            self.assertNotIn(unsupported, lifecycle_contract)
        legacy_stop = transaction_map["Stop and disable the exact legacy Keycloak unit before Quadlet takeover"]
        native_stop = transaction_map["Stop the exact active native Keycloak unit before manifest replacement"]
        manifest_preview = transaction_map["Preview transactional Keycloak Pod manifest drift"]
        manifest_render = transaction_map["Render the transactional Keycloak Pod manifest"]
        manage = transaction_map["Manage the native Keycloak Quadlet service"]
        transaction_index = systemd_block.index(transaction)
        self.assertTrue(validation_index < collision_index < transaction_index)
        self.assertLess(systemd_block.index(ownership), collision_index)
        self.assertLess(transaction["block"].index(stage), transaction["block"].index(legacy_stop))
        self.assertLess(transaction["block"].index(manifest_preview), transaction["block"].index(native_stop))
        self.assertLess(transaction["block"].index(legacy_stop), transaction["block"].index(manifest_render))
        self.assertLess(transaction["block"].index(native_stop), transaction["block"].index(manifest_render))
        self.assertLess(transaction["block"].index(manifest_render), transaction["block"].index(manage))
        self.assertEqual((manifest_preview["check_mode"], manifest_preview["diff"]), (True, False))
        self.assertIs(manifest_preview["no_log"], True)
        self.assertIn("keycloak_deploy_manifest_preview.changed", "\n".join(native_stop["when"]))
        self.assertIn(
            "service\\.d",
            "\n".join(
                transaction_map["Require the staged native Keycloak Quadlet provenance boundary"][
                    "ansible.builtin.assert"
                ]["that"]
            ),
        )
        self.assertIn("/run/systemd/system/service\\.d/zzz-lxc-service\\.conf", ownership_contract)
        self.assertEqual(
            (legacy_stop["ansible.builtin.systemd"]["state"], legacy_stop["ansible.builtin.systemd"]["enabled"]),
            ("stopped", False),
        )
        rescue_source = "\n".join(str(task) for task in transaction["rescue"])
        for contract in (
            "exact pre-transaction Keycloak Pod manifest",
            "transaction-created Keycloak Pod manifest",
            "generated native Keycloak service",
            "native Keycloak inactivity",
            "exact legacy Keycloak service",
        ):
            self.assertIn(contract, rescue_source)
        native_restoration = next(
            task
            for task in transaction["rescue"]
            if task["name"] == "Attempt pre-existing native Keycloak service-state restoration"
        )
        for task in native_restoration["block"]:
            state_expression = task["ansible.builtin.systemd"]["state"]
            self.assertIn("'restarted'", state_expression)
            self.assertIn("'active'", state_expression)
            self.assertIn("'stopped'", state_expression)
        self.assertIn("Inspect the transactional Keycloak database endpoint", str(transaction["block"]))
        self.assertIn(
            "Require the desired database endpoint before committing Keycloak takeover",
            str(transaction["block"]),
        )
        manifest_render = next(task for task in pod_tasks if task["name"].startswith("Render Keycloak Pod manifest"))
        self.assertIn("not keycloak_deploy_manage_systemd", manifest_render["when"])
        runtime_block = yaml.safe_load((ROOT / "roles/keycloak_deploy/tasks/deploy.yml").read_text(encoding="utf-8"))[
            2
        ]["block"]
        runtime_map = {task["name"]: task for task in runtime_block}
        inspect = runtime_map["Inspect the effective Keycloak environment"]
        self.assertEqual(
            (inspect["no_log"], inspect["ansible.builtin.command"]["argv"][:3]),
            (True, ["podman", "container", "inspect"]),
        )
        self.assertIn("not keycloak_deploy_manage_systemd", inspect["when"])
        verify = runtime_map["Require the desired database endpoint in the active Keycloak pod"]
        self.assertIs(verify["no_log"], True)
        self.assertIn("KC_DB_URL_HOST=", str(verify))
        self.assertIn("KC_DB_URL_PORT=", str(verify))
        source = pod_tasks_path.read_text(encoding="utf-8")
        self.assertNotIn("Ignore kubeplay remove failure", source)
        self.assertNotIn("Ignore kubeplay run failure", source)

    def test_existing_native_quadlets_skip_mutating_staging(self) -> None:
        executable = shutil.which("ansible-playbook")
        self.assertIsNotNone(executable, "Pinned Devtools Ansible is required")
        selected_tasks = []
        existing_vars: dict[str, object] = {}
        cases = (
            (
                "keycloak_deploy",
                "Cut over to native Keycloak Quadlet with rollback",
                "Stage the native Keycloak Quadlet before lifecycle mutation",
                "keycloak_deploy_native_quadlet_file",
            ),
            (
                "postgres_deploy",
                "Cut over to native PostgreSQL Quadlet with rollback",
                "Stage the native PostgreSQL Quadlet before lifecycle mutation",
                "postgres_deploy_native_quadlet_file",
            ),
        )
        for role, transaction_name, stage_name, fact_name in cases:
            block = yaml.safe_load((ROOT / f"roles/{role}/tasks/systemd.yml").read_text(encoding="utf-8"))[0]["block"]
            transaction = next(task for task in block if task["name"] == transaction_name)
            selected_tasks.append(next(task for task in transaction["block"] if task["name"] == stage_name))
            existing_vars[fact_name] = {"stat": {"exists": True}}

        with tempfile.TemporaryDirectory(prefix="native-steady-state-") as temporary:
            root = Path(temporary)
            fixture_tasks = root / "collections/ansible_collections/lit/foundational/roles/podman_systemd/tasks"
            fixture_tasks.mkdir(parents=True)
            (fixture_tasks / "main.yml").write_text(
                """---
- name: Reject mutating staging during a verified native steady-state run
  ansible.builtin.fail:
    msg: mutating Quadlet staging was executed
""",
                encoding="utf-8",
            )
            playbook = root / "steady-state.yml"
            playbook.write_text(
                yaml.safe_dump(
                    [
                        {
                            "hosts": "localhost",
                            "gather_facts": False,
                            "vars": existing_vars,
                            "tasks": selected_tasks,
                        }
                    ],
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            config = root / "ansible.cfg"
            config.write_text("[defaults]\nstdout_callback=default\n", encoding="utf-8")
            result = subprocess.run(  # noqa: S603
                [executable, "-i", "localhost,", "-c", "local", str(playbook)],
                env={
                    **os.environ,
                    "ANSIBLE_CONFIG": str(config),
                    "ANSIBLE_COLLECTIONS_PATH": str(root / "collections"),
                    "ANSIBLE_LOCAL_TEMP": str(root / "ansible-tmp"),
                    "ANSIBLE_NOCOLOR": "1",
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertEqual(output.count("skipping: [localhost]"), 2, output)
        self.assertNotIn("mutating Quadlet staging was executed", output)

    def test_mixed_legacy_enablement_and_active_native_state_is_rejected(self) -> None:
        for role, task_name in (
            ("keycloak_deploy", "Refuse unknown Keycloak lifecycle states"),
            ("postgres_deploy", "Refuse unknown PostgreSQL lifecycle states"),
        ):
            block = yaml.safe_load((ROOT / f"roles/{role}/tasks/systemd.yml").read_text(encoding="utf-8"))[0]["block"]
            contract = "\n".join(
                next(task for task in block if task["name"] == task_name)["ansible.builtin.assert"]["that"]
            )
            with self.subTest(role=role):
                self.assertIn(f"{role}_legacy_systemd_enabled.stdout | trim == 'enabled'", contract)
                self.assertIn(f"{role}_native_systemd_active.stdout | trim == 'active'", contract)

    def test_failed_fresh_keycloak_cleanup_detects_a_running_native_pod(self) -> None:
        executable = shutil.which("ansible-playbook")
        self.assertIsNotNone(executable, "Pinned Devtools Ansible is required")
        role = ROOT / "roles" / "keycloak_deploy"

        with tempfile.TemporaryDirectory(prefix="keycloak-rollback-") as temporary:
            root = Path(temporary)
            collection = root / "collections/ansible_collections/lit/supplementary"
            fixture_role = collection / "roles/keycloak_deploy"
            fixture_role.parent.mkdir(parents=True)
            shutil.copytree(role, fixture_role)
            fixture_filters = collection / "plugins/filter"
            fixture_filters.mkdir(parents=True)
            shutil.copy2(ROOT / "plugins/filter/native_manifest.py", fixture_filters / "native_manifest.py")
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
  when: podman_systemd_action != 'absent'

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
                    "keycloak_deploy_staged_quadlet_file.stat.pw_name | default('') == 'root'",
                    f"keycloak_deploy_staged_quadlet_file.stat.uid | int == {os.geteuid()}",
                )
                .replace(
                    "keycloak_deploy_staged_quadlet_file.stat.gr_name | default('') == 'root'",
                    f"keycloak_deploy_staged_quadlet_file.stat.gid | int == {os.getegid()}",
                )
                .replace(
                    "          retries: 30\n          delay: 5",
                    "          retries: 1\n          delay: 0",
                    2,
                ),
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            state = root / "systemd-state"
            state.mkdir()
            native_state = "keycloak-pod_service"
            (state / f"{native_state}.active").write_text("inactive", encoding="utf-8")
            log = root / "systemctl.log"
            manifest = root / "keycloak.yml"
            original = b"kind: Pod\nmetadata: {name: original-keycloak}\nspec: {containers: []}\n"
            manifest.write_bytes(original)
            manifest.chmod(0o640)
            quadlet_dir = root / "quadlets"
            quadlet_dir.mkdir()

            systemd_escape = fake_bin / "systemd-escape"
            systemd_escape.write_text("#!/bin/sh\nprintf '%s\\n' 'etc-podman-pods-keycloak.yml'\n", encoding="utf-8")
            systemd_escape.chmod(0o755)
            systemctl = fake_bin / "systemctl"
            systemctl.write_text(
                """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
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
      *--property=FragmentPath*) printf '/run/systemd/generator/%s\n' "$unit" ;;
      *) printf 'LoadState=loaded\nActiveState=%s\nSubState=%s\nUnitFileState=%s\n' \
           "$active" "$active" "$enabled" ;;
    esac
    ;;
  is-active)
    printf '%s\n' "$active"
    if [ "$active" = active ]; then exit 0; fi
    exit 3
    ;;
  is-enabled)
    printf '%s\n' "$enabled"
    test "$enabled" = enabled
    ;;
  enable) printf enabled > "$enabled_file" ;;
  disable) printf disabled > "$enabled_file" ;;
  start|restart) printf active > "$active_file" ;;
  stop)
    if [ "$unit" = keycloak-pod.service ] && [ "$active" = active ]; then exit 42; fi
    printf inactive > "$active_file"
    ;;
  *) ;;
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
                                "keycloak_deploy_pod_manifest_path": str(manifest),
                                "keycloak_deploy_quadlet_dir": str(quadlet_dir),
                                "keycloak_deploy_host_data_dir": str(root / "data"),
                                "keycloak_deploy_db_password_effective": "OFFLINE_DB_TEST_ONLY",
                                "keycloak_deploy_admin_password_effective": "OFFLINE_ADMIN_TEST_ONLY",
                                "keycloak_deploy_health_url_effective": "http://127.0.0.1:9/health/ready",
                                "keycloak_deploy_liveness_url_effective": "http://127.0.0.1:9/health/live",
                            },
                            "tasks": [
                                {
                                    "name": "Execute the real Keycloak systemd transaction",
                                    "ansible.builtin.include_role": {
                                        "name": "lit.supplementary.keycloak_deploy",
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
            self.assertIn("Native Keycloak Quadlet takeover failed", output)
            self.assertNotIn("OFFLINE_DB_TEST_ONLY", output)
            self.assertNotIn("OFFLINE_ADMIN_TEST_ONLY", output)
            self.assertEqual(manifest.read_bytes(), original)
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o640)
            self.assertEqual((manifest.stat().st_uid, manifest.stat().st_gid), (os.geteuid(), os.getegid()))
            self.assertFalse((quadlet_dir / "keycloak-pod.kube").exists())
            service_log = log.read_text(encoding="utf-8")
            self.assertIn("Native quiescence failure", output)
            self.assertEqual(
                (state / f"{native_state}.active").read_text(encoding="utf-8"),
                "active",
                output,
            )
            self.assertIn("stop keycloak-pod.service", service_log)
            self.assertNotIn("start podman-kube@etc-podman-pods-keycloak.yml.service", service_log)

    def test_edge_proxy_contract_restricts_forwarded_identity(self) -> None:
        defaults = self._role_defaults("keycloak_deploy")
        self.assertEqual(defaults["keycloak_deploy_proxy_trusted_addresses"], [])
        self.assertEqual(defaults["keycloak_deploy_host_ip"], "127.0.0.1")
        self.assertEqual(defaults["keycloak_deploy_networks"], [])
        self.assertIn("keycloak_deploy_networks", defaults["keycloak_deploy_postgres_networks"])

        template = (ROOT / "roles" / "keycloak_deploy" / "templates" / "keycloak-pod.yml.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("KC_PROXY_TRUSTED_ADDRESSES", template)
        self.assertIn("keycloak_deploy_proxy_trusted_addresses | join(',')", template)
        tasks = yaml.safe_load(
            (ROOT / "roles" / "keycloak_deploy" / "tasks" / "assert.yml").read_text(encoding="utf-8")
        )
        core_contract = "\n".join(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("keycloak_deploy_extra_start_args | select('string')", core_contract)
        for protected_option in ("db", "proxy", "hostname", "http", "health-enabled", "bootstrap-admin"):
            self.assertIn(protected_option, core_contract)
        validation = next(task for task in tasks if task["name"] == "Validate trusted Keycloak proxy address syntax")
        command = validation["ansible.builtin.command"]["argv"]
        self.assertIn("ipaddress.ip_network(sys.argv[1], strict=False)", command[2])
        self.assertEqual(
            (command[3], validation["loop"]), ("{{ item }}", "{{ keycloak_deploy_proxy_trusted_addresses }}")
        )
        self.assertEqual((validation["check_mode"], validation["changed_when"]), (False, False))

    def test_systemd_management_fails_closed_without_systemd_facts(self) -> None:
        for role in ("keycloak_deploy", "postgres_deploy"):
            assertions = (ROOT / "roles" / role / "tasks" / "assert.yml").read_text(encoding="utf-8")
            for contract in (
                f"not {role}_manage_systemd | bool",
                f"{role}_skip_runtime | bool",
                f"{role}_skip_deploy | bool",
            ):
                self.assertIn(contract, assertions)
            with self.subTest(role=role):
                self.assertIn("ansible_facts.get('service_mgr', '')", assertions)

    def test_system_quadlet_interfaces_reject_injection(self) -> None:
        for role in ("keycloak_deploy", "postgres_deploy"):
            tasks = yaml.safe_load((ROOT / "roles" / role / "tasks" / "assert.yml").read_text(encoding="utf-8"))
            contract = "\n".join(tasks[0]["ansible.builtin.assert"]["that"])
            prefix = role
            with self.subTest(role=role):
                self.assertIn(f"{prefix}_systemd_unit_name is string", contract)
                self.assertIn("^[A-Za-z0-9][A-Za-z0-9_.-]*$", contract)
                self.assertIn(f"'\\n' not in {prefix}_systemd_description", contract)
                self.assertIn(f"'\\r' not in {prefix}_systemd_description", contract)
                self.assertIn(f"{prefix}_systemd_scope == 'system'", contract)
                self.assertIn(f"{prefix}_quadlet_dir == '/etc/containers/systemd'", contract)

        keycloak_options = self._role_options("keycloak_deploy")
        self.assertEqual(keycloak_options["keycloak_deploy_systemd_scope"]["choices"], ["system", "user"])

    def test_quadlet_networks_use_exact_grammar_and_ipv4_validation(self) -> None:
        for role, variable in (
            ("keycloak_deploy", "keycloak_deploy_networks"),
            ("postgres_deploy", "postgres_deploy_networks"),
        ):
            tasks = yaml.safe_load((ROOT / "roles" / role / "tasks" / "assert.yml").read_text(encoding="utf-8"))
            core = "\n".join(tasks[0]["ansible.builtin.assert"]["that"])
            validator = next(task for task in tasks if "static IPv4 addresses" in task["name"])
            with self.subTest(role=role):
                self.assertIn(variable, core)
                self.assertIn("(?::ip=[0-9]{1,3}", core)
                self.assertIn("ipaddress.ip_address", validator["ansible.builtin.command"]["argv"][2])
                self.assertEqual(validator["when"], "':ip=' in item")

    def test_ordinary_keycloak_deploy_proves_database_dns_at_runtime(self) -> None:
        pod_template = (ROOT / "roles" / "keycloak_deploy" / "templates" / "keycloak-pod.yml.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("hostAliases:", pod_template)
        self.assertIn("keycloak_deploy_database_private_address | default({})", pod_template)
        self.assertIn("keycloak_deploy_db_host | to_json", pod_template)

        pod_tasks = yaml.safe_load(
            (ROOT / "roles" / "keycloak_deploy" / "tasks" / "deploy_pod.yml").read_text(encoding="utf-8")
        )
        address = next(
            task
            for task in pod_tasks
            if task["name"] == "Resolve the unique private address for the managed database name"
        )
        self.assertIn("ipaddress.IPv4Address", address["ansible.builtin.command"]["argv"][2])
        self.assertEqual(address["register"], "keycloak_deploy_database_private_address")

        validation_path = ROOT / "roles" / "keycloak_deploy" / "tasks" / "validate_database_dns.yml"
        validation = yaml.safe_load(validation_path.read_text(encoding="utf-8"))
        self.assertEqual(
            validation[0]["ansible.builtin.command"]["argv"],
            [
                "podman",
                "exec",
                "{{ keycloak_deploy_database_dns_probe_container }}",
                "getent",
                "ahostsv4",
                "{{ keycloak_deploy_db_host }}",
            ],
        )
        resolution_contract = "\n".join(validation[1]["ansible.builtin.assert"]["that"])
        self.assertIn("lit.supplementary.keycloak_database_resolution_valid", resolution_contract)
        for binding in (
            "keycloak_deploy_networks",
            "keycloak_deploy_postgres_networks",
            "keycloak_deploy_postgres_pod_name",
            "keycloak_deploy_postgres_container_name",
        ):
            self.assertIn(binding, resolution_contract)

        systemd = yaml.safe_load(
            (ROOT / "roles" / "keycloak_deploy" / "tasks" / "systemd.yml").read_text(encoding="utf-8")
        )[0]["block"]
        transaction = next(
            task for task in systemd if task["name"] == "Cut over to native Keycloak Quadlet with rollback"
        )
        transaction_names = [task["name"] for task in transaction["block"]]
        self.assertLess(
            transaction_names.index("Manage the native Keycloak Quadlet service"),
            transaction_names.index("Validate managed database DNS from the native Keycloak container"),
        )
        self.assertLess(
            transaction_names.index("Validate managed database DNS from the native Keycloak container"),
            transaction_names.index("Wait until Keycloak health endpoint is reachable"),
        )
        rescue_names = [task["name"] for task in transaction["rescue"]]
        self.assertIn("Capture safe native Keycloak service failure properties", rescue_names)

        deploy = yaml.safe_load(
            (ROOT / "roles" / "keycloak_deploy" / "tasks" / "deploy.yml").read_text(encoding="utf-8")
        )[2]["block"]
        deploy_names = [task["name"] for task in deploy]
        self.assertLess(
            deploy_names.index("Require the desired database endpoint in the active Keycloak pod"),
            deploy_names.index("Validate managed database DNS from the non-systemd Keycloak container"),
        )
        self.assertLess(
            deploy_names.index("Validate managed database DNS from the non-systemd Keycloak container"),
            deploy_names.index("Wait until Keycloak health endpoint is reachable (non-systemd)"),
        )
        non_systemd_validation = next(
            task
            for task in deploy
            if task["name"] == "Validate managed database DNS from the non-systemd Keycloak container"
        )
        self.assertEqual(non_systemd_validation["ansible.builtin.include_tasks"], "validate_database_dns.yml")

    def test_managed_bridge_database_requires_a_shared_normalized_network(self) -> None:
        assertions = (ROOT / "roles" / "keycloak_deploy" / "tasks" / "assert.yml").read_text(encoding="utf-8")
        defaults = self._role_defaults("keycloak_deploy")
        self.assertEqual(
            (defaults["keycloak_deploy_postgres_port"], defaults["keycloak_deploy_postgres_container_port"]),
            (5432, 5432),
        )
        self.assertGreaterEqual(assertions.count("map('regex_replace', ':.*$', '')"), 2)
        for contract in (
            "not (keycloak_deploy_host_network | bool)",
            "| intersect(",
            "or keycloak_deploy_manage_systemd | bool",
        ):
            self.assertIn(contract, assertions)
        tasks = yaml.safe_load(assertions)
        validation = next(task for task in tasks if task["name"] == "Validate the managed private PostgreSQL endpoint")
        endpoint_contract = "\n".join(validation["ansible.builtin.assert"]["that"])
        for binding in (
            "lit.supplementary.keycloak_private_database_endpoint_valid",
            "keycloak_deploy_db_host",
            "keycloak_deploy_networks",
            "keycloak_deploy_postgres_networks",
            "keycloak_deploy_postgres_pod_name",
        ):
            self.assertIn(binding, endpoint_contract)
        self.assertEqual(
            validation["when"],
            [
                "keycloak_deploy_manage_postgres | bool",
                "not keycloak_deploy_host_network | bool",
                "not keycloak_deploy_postgres_host_network | bool",
            ],
        )

    def test_managed_bridge_database_requires_native_quadlet_network_handoff(self) -> None:
        tasks = yaml.safe_load(
            (ROOT / "roles" / "keycloak_deploy" / "tasks" / "assert.yml").read_text(encoding="utf-8")
        )
        core = tasks[0]["ansible.builtin.assert"]["that"]
        contract = next(
            item
            for item in core
            if isinstance(item, str)
            and "not keycloak_deploy_manage_postgres" in item
            and "keycloak_deploy_manage_systemd" in item
        )
        self.assertIn("keycloak_deploy_host_network", contract)
        self.assertIn("keycloak_deploy_postgres_host_network", contract)

    def test_managed_postgres_quadlet_is_always_enabled(self) -> None:
        keycloak_tasks = yaml.safe_load(
            (ROOT / "roles" / "keycloak_deploy" / "tasks" / "assert.yml").read_text(encoding="utf-8")
        )
        keycloak_contract = "\n".join(keycloak_tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("keycloak_deploy_manage_postgres", keycloak_contract)
        self.assertIn("or keycloak_deploy_systemd_enabled | bool", keycloak_contract)
        tasks = yaml.safe_load(
            (ROOT / "roles" / "postgres_deploy" / "tasks" / "assert.yml").read_text(encoding="utf-8")
        )
        core = tasks[0]["ansible.builtin.assert"]["that"]
        self.assertIn(
            "not postgres_deploy_manage_systemd | bool or postgres_deploy_systemd_enabled | bool",
            core,
        )

    def test_quadlet_destroy_fails_closed_until_li220(self) -> None:
        for role, deploy_role in (("keycloak_destroy", "keycloak_deploy"), ("postgres_destroy", "postgres_deploy")):
            defaults = self._role_defaults(role)
            assertions = (ROOT / "roles" / role / "tasks" / "assert.yml").read_text(encoding="utf-8")
            self.assertEqual(
                defaults[f"{role}_manage_systemd"], f"{{{{ {deploy_role}_manage_systemd | default(true) }}}}"
            )
            self.assertIn(f"not ({role}_manage_systemd | bool)", assertions)
            self.assertIn("currently unsupported Quadlet teardown", assertions)


if __name__ == "__main__":
    unittest.main()
