"""Rootless kube manifests retain listener and proxy security boundaries."""

import json
import unittest
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined, select_autoescape

ROOT = Path(__file__).resolve().parents[2]


class RootlessEdgeTemplates(unittest.TestCase):
    def render(self, role, name, **values):
        source = (ROOT / "roles" / role / "templates" / name).read_text()
        environment = Environment(
            undefined=StrictUndefined,
            autoescape=select_autoescape(default=False, default_for_string=False),
        )
        environment.filters["to_json"] = json.dumps
        environment.filters["bool"] = lambda value: str(value).lower() in {"true", "yes", "on", "1"}
        return environment.from_string(source).render(**values)

    def keycloak(self, enabled, port=19000):
        return yaml.safe_load(
            self.render(
                "keycloak_deploy",
                "rootless-keycloak-pod.yml.j2",
                keycloak_deploy_pod_name="keycloak",
                keycloak_deploy_container_name="keycloak",
                keycloak_deploy_image="example/keycloak@sha256:abc",
                keycloak_deploy_run_user_uid="1000",
                keycloak_deploy_run_user_gid="1000",
                keycloak_deploy_management_port=port,
                keycloak_deploy_rootless_publish_management=enabled,
                keycloak_deploy_host_data_dir="/srv/data",
                keycloak_deploy_rootless_postgres_ip="10.89.50.20",
                keycloak_deploy_db_name="keycloak",
                keycloak_deploy_db_user="keycloak",
                keycloak_deploy_db_password=self.id(),
                keycloak_deploy_admin_user="admin",
                keycloak_deploy_admin_password=self.id(),
                keycloak_deploy_hostname="https://sso.example.invalid",
                keycloak_deploy_proxy_headers="xforwarded",
                keycloak_deploy_proxy_trusted_addresses=["10.89.50.30"],
            )
        )

    def test_only_configured_management_port_is_host_published(self):
        manifest = self.keycloak(True)
        container = manifest["spec"]["containers"][0]
        self.assertEqual(container["ports"], [{"containerPort": 9000, "hostPort": 19000, "hostIP": "127.0.0.1"}])
        self.assertEqual(
            manifest["metadata"]["annotations"]["io.podman.annotations.userns"], "keep-id:uid=1000,gid=1000"
        )
        self.assertNotIn("ports", self.keycloak(False)["spec"]["containers"][0])
        self.assertNotIn("ports", self.keycloak("false")["spec"]["containers"][0])
        self.assertIn("ports", self.keycloak("true")["spec"]["containers"][0])
        self.assertEqual(self.keycloak(True, 9000)["spec"]["containers"][0]["ports"][0]["hostPort"], 9000)

    def test_postgres_has_no_host_listener(self):
        manifest = yaml.safe_load(
            self.render(
                "keycloak_deploy",
                "rootless-postgres-pod.yml.j2",
                keycloak_deploy_postgres_pod_name="keycloak-postgres",
                keycloak_deploy_postgres_container_name="postgres",
                keycloak_deploy_postgres_image="example/postgres@sha256:abc",
                keycloak_deploy_postgres_data_dir="/srv/pgdata",
                keycloak_deploy_db_name="keycloak",
                keycloak_deploy_db_user="keycloak",
                keycloak_deploy_db_password=self.id(),
            )
        )
        self.assertNotIn("ports", manifest["spec"]["containers"][0])
        self.assertNotIn("hostNetwork", manifest["spec"])
        self.assertEqual(manifest["spec"]["volumes"][0]["hostPath"], {"path": "/srv/pgdata", "type": "Directory"})

    def test_proxy_replaces_untrusted_headers_and_blocks_management(self):
        rendered = self.render(
            "nginx_deploy",
            "rootless-nginx.conf.j2",
            nginx_deploy_server_name="sso.example.invalid",
            nginx_deploy_rootless_upstream="http://keycloak:8080",
            nginx_deploy_tls_host_port=443,
        )
        boundary = yaml.safe_load((ROOT / "roles/nginx_config/defaults/main.yml").read_text())[
            "nginx_config_proxy_required_directives"
        ]
        for directive in boundary:
            self.assertIn(directive + ";", rendered)
        self.assertNotIn("$host;", rendered)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", rendered)
        self.assertNotIn("$proxy_add_x_forwarded_for", rendered)
        self.assertIn('proxy_set_header Forwarded "";', rendered)
        self.assertIn("location /health { return 404; }", rendered)
        self.assertIn("location /metrics { return 404; }", rendered)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", rendered)


if __name__ == "__main__":
    unittest.main()
