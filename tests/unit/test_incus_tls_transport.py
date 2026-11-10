"""TLS transport boundaries and real loopback TLS; not a live Incus/VM grant."""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "molecule/shared/incus/helpers/tls_transport.py"
spec = importlib.util.spec_from_file_location("incus_tls_transport", HELPER)
transport = importlib.util.module_from_spec(spec)
# dataclasses resolves module annotations through sys.modules.
sys.modules[spec.name] = transport
spec.loader.exec_module(transport)
NOW = dt.datetime.now(dt.UTC)
GIB = 1024**3
OWNER = "example/repository:501:1:fixture:vm"
NETWORK = "lit" + hashlib.sha256(OWNER.encode()).hexdigest()[:12]


def runtime():
    return {
        "firewall_controller": "incus",
        "storage_pool": "fixture-pool",
        "bridge": {
            "name": NETWORK,
            "project": "default",
            "owner": OWNER,
            "ipv4_address": "10.20.30.1/24",
            "dns_domain": "fixture.invalid",
            "dhcp": True,
            "nat": True,
            "firewall": True,
            "ipv6_address": "none",
        },
    }


class FixtureClient:
    project = "fixture-lease"

    def __init__(self, responses):
        self.responses = responses
        self.paths = []

    def get(self, path, *, expected=dict):
        self.paths.append(path)
        if path not in self.responses:
            raise transport.Refused("fixture-resource-missing")
        value = copy.deepcopy(self.responses[path])
        if type(value) is not expected:  # pylint: disable=unidiomatic-typecheck
            # Match the client's exact built-in schema, including bool/int separation.
            raise AssertionError("fixture response type differs from requested API schema")
        return value


def responses():
    return {
        "/1.0": {
            "auth": "trusted",
            "api_extensions": ["resources", "projects", "project_usage"],
            "environment": {
                "project": "fixture-lease",
                "server": "incus",
                "driver": "qemu | lxc",
                "server_version": "7.6",
                "firewall": "nftables",
            },
        },
        "/1.0/projects/fixture-lease": {
            "name": "fixture-lease",
            "config": {
                "restricted": "true",
                "features.networks": "false",
                "restricted.devices.nic": "managed",
                "restricted.devices.disk": "managed",
                "restricted.networks.access": NETWORK,
                "restricted.storage-pools.access": "fixture-pool",
            },
        },
        "/1.0/networks/" + NETWORK: {
            "name": NETWORK,
            "managed": True,
            "type": "bridge",
            "used_by": [],
            "config": {
                "user.lit-molecule-owner": OWNER,
                "ipv4.address": "10.20.30.1/24",
                "ipv4.dhcp": "true",
                "ipv4.nat": "true",
                "ipv4.firewall": "true",
                "ipv6.address": "none",
                "dns.domain": "fixture.invalid",
                "dns.mode": "managed",
                "user.lit-molecule-firewall-controller": "incus",
                "user.lit-molecule-firewalld-zone": "none",
            },
        },
        "/1.0/resources": {"cpu": {"total": 8}, "memory": {"total": 64 * GIB, "used": 8 * GIB}},
        "/1.0/projects/fixture-lease/state": {
            "resources": {
                "cpu": {"Limit": 4, "Usage": 0},
                "memory": {"Limit": 12 * GIB, "Usage": 0},
                "disk": {"Limit": 24 * GIB, "Usage": 0},
            }
        },
        "/1.0/profiles/default": {"devices": {"root": {"type": "disk", "path": "/", "pool": "fixture-pool"}}},
        "/1.0/storage-pools/fixture-pool/resources": {"space": {"total": 100 * GIB, "used": 60 * GIB}},
        "/1.0/instances": [],
    }


class CapacityTests(unittest.TestCase):
    @staticmethod
    def owned_data(kind, status, free_memory):
        data = responses()
        data["/1.0/resources"]["memory"]["used"] = 64 * GIB - free_memory
        data["/1.0/instances"] = ["/1.0/instances/vm1"]
        data["/1.0/instances/vm1"] = {
            "name": "vm1",
            "type": "virtual-machine" if kind == "vm" else "container",
            "expanded_config": {"user.lit-molecule-owner": OWNER, "limits.cpu": "4", "limits.memory": "12GiB"},
            "expanded_devices": {"root": {"type": "disk", "path": "/", "size": "24GiB"}},
        }
        if status is not None:
            data["/1.0/instances/vm1"]["status"] = status
        for row in data["/1.0/projects/fixture-lease/state"]["resources"].values():
            row["Usage"] = row["Limit"]
        return data

    def test_owned_instance_ram_is_never_added_to_observed_physical_headroom(self):
        for kind in ("vm", "container"):
            for status in ("Stopped", "Running", "Frozen", "Error", "Unknown", None):
                with self.subTest(kind=kind, status=status):
                    data = self.owned_data(kind, status, 8 * GIB)
                    facts = transport.server_facts(
                        FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": kind}
                    )
                    self.assertEqual(8 * GIB, facts["available"]["memory"])
                    self.assertEqual(12 * GIB, facts["own_existing_allocations"]["memory"])

    def test_real_create_preflight_enforces_free_ram_for_vm_and_container_restart_plans(self):
        tasks = yaml.safe_load((ROOT / "molecule/shared/incus/create.yml").read_text())[0]["tasks"]
        named = {task["name"]: task for task in tasks if "name" in task}
        plays = []
        for kind in ("vm", "container"):
            for mode in ("tls", "local"):
                for status in ("Stopped", "Running", "Frozen", "Unknown", None, "missing"):
                    for free_gib in (8, 12):
                        data = self.owned_data(kind, status, free_gib * GIB)
                        if status == "missing":
                            data["/1.0/instances"] = []
                            for row in data["/1.0/projects/fixture-lease/state"]["resources"].values():
                                row["Usage"] = 0
                        facts = transport.server_facts(
                            FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": kind}
                        )
                        gate_name = (
                            "Enforce authenticated remote resource observations and hard project quota headroom"
                            if mode == "tls"
                            else "Enforce Incus host resource prerequisites"
                        )
                        gate = copy.deepcopy(named[gate_name])
                        # Only the fixture observes both expected denials and
                        # successes. The production assertion remains unchanged.
                        gate.update(register="capacity_gate", ignore_errors=True)
                        plays.append(
                            {
                                "name": f"{mode} {kind} {status} free={free_gib}GiB",
                                "hosts": "localhost",
                                "connection": "local",
                                "gather_facts": False,
                                "vars": {
                                    "molecule_incus_is_remote": mode == "tls",
                                    "molecule_incus_instances": [
                                        {
                                            "name": "vm1",
                                            "type": kind,
                                            "resources": {"cpu": 4, "memory": "12GiB", "disk": "24GiB"},
                                        }
                                    ],
                                    "molecule_incus_transport_facts": facts,
                                    "molecule_incus_available_cpu": {"stdout": "4"},
                                    "molecule_incus_available_memory": {"stdout": str(free_gib * GIB)},
                                    "molecule_incus_available_disk": {"stdout_lines": ["Available", str(24 * GIB)]},
                                    "expected_denied": free_gib < 12,
                                },
                                "tasks": [
                                    copy.deepcopy(named["Initialize requested resource totals"]),
                                    copy.deepcopy(named["Calculate requested resource totals"]),
                                    gate,
                                    {
                                        "name": "Verify actual preflight result",
                                        "ansible.builtin.assert": {
                                            "that": [
                                                "not capacity_gate.skipped | default(false)",
                                                "capacity_gate.failed | default(false) == expected_denied",
                                                "molecule_incus_requested_memory_total | int == 12884901888",
                                            ]
                                        },
                                    },
                                ],
                            }
                        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            playbook = root / "memory-preflight.yml"
            playbook.write_text(yaml.safe_dump(plays))
            environment = dict(os.environ, ANSIBLE_HOME=str(root / "home"), ANSIBLE_LOCAL_TEMP=str(root / "tmp"))
            environment.pop("ANSIBLE_CONFIG", None)
            ansible = shutil.which("ansible-playbook")
            self.assertIsNotNone(ansible)
            # Exact installed EE executable; only inert production assertions run.
            result = subprocess.run(  # noqa: S603
                [ansible, "-i", "localhost,", str(playbook)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_actual_server_shapes_bound_physical_observations_by_finite_quotas(self):
        client = FixtureClient(responses())
        facts = transport.server_facts(client, capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": "vm"})
        self.assertEqual(facts["available"], {"cpu": 4, "memory": 12 * GIB, "disk": 24 * GIB})
        self.assertTrue(facts["declares_vm_driver"])
        self.assertFalse(facts["capacity_is_reservation"])
        self.assertNotIn("admission_verified", facts)
        self.assertIn("/1.0/storage-pools/fixture-pool/resources", client.paths)

    def test_default_unlimited_project_or_missing_hard_quota_denies_before_creation(self):
        for value in (-1, 0, True, 1.5):
            data = responses()
            data["/1.0/projects/fixture-lease/state"]["resources"]["cpu"]["Limit"] = value
            with self.subTest(value=value), self.assertRaises(transport.Refused):
                transport.server_facts(FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER)
        data = responses()
        data["/1.0"]["environment"]["project"] = "default"
        with self.assertRaises(transport.Refused):
            transport.server_facts(FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER)

    def test_capture_and_destroy_do_not_require_unused_capacity(self):
        data = responses()
        data.pop("/1.0/resources")
        client = FixtureClient(data)
        self.assertEqual(
            transport.server_facts(client, capacity=False, runtime=runtime(), owner=OWNER)["project"], "fixture-lease"
        )
        self.assertNotIn("/1.0/resources", client.paths)
        self.assertIn("/1.0/networks/" + NETWORK, client.paths)

    def test_exact_owned_existing_allocations_allow_idempotent_same_vm_rerun(self):
        data = responses()
        data["/1.0/instances"] = ["/1.0/instances/vm1?project=fixture-lease"]
        data["/1.0/instances/vm1"] = {
            "name": "vm1",
            "type": "virtual-machine",
            "expanded_config": {"user.lit-molecule-owner": OWNER, "limits.cpu": "4", "limits.memory": "12GiB"},
            "expanded_devices": {"root": {"type": "disk", "path": "/", "size": "24GiB"}},
        }
        for row in data["/1.0/projects/fixture-lease/state"]["resources"].values():
            row["Usage"] = row["Limit"]
        facts = transport.server_facts(
            FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": "vm"}
        )
        self.assertEqual(facts["available"], {"cpu": 4, "memory": 12 * GIB, "disk": 24 * GIB})
        self.assertEqual(facts["own_existing_allocations"]["memory"], 12 * GIB)
        data["/1.0/instances/vm1"]["type"] = "container"
        with self.assertRaisesRegex(transport.Refused, "owned-instance-type-mismatch"):
            transport.server_facts(
                FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": "vm"}
            )

    def test_foreign_instance_or_owner_gets_no_allocation_credit(self):
        data = responses()
        data["/1.0/instances"] = ["/1.0/instances/foreign?project=fixture-lease"]
        with self.assertRaisesRegex(transport.Refused, "foreign-instance-in-project"):
            transport.server_facts(
                FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": "vm"}
            )
        data["/1.0/instances"] = ["/1.0/instances/vm1"]
        data["/1.0/instances/vm1"] = {
            "name": "vm1",
            "type": "virtual-machine",
            "expanded_config": {"user.lit-molecule-owner": "foreign-owner"},
        }
        with self.assertRaisesRegex(transport.Refused, "foreign-instance-in-project"):
            transport.server_facts(
                FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": "vm"}
            )

    def test_foreign_project_url_lowercase_or_malformed_resource_schema_denies(self):
        data = responses()
        data["/1.0/instances"] = ["/1.0/instances/vm1?project=foreign"]
        with self.assertRaises(transport.Refused):
            transport.server_facts(
                FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER, platforms={"vm1": "vm"}
            )
        data = responses()
        data["/1.0/projects/fixture-lease/state"]["resources"]["cpu"] = {"limit": 4, "usage": 0}
        with self.assertRaises(transport.Refused):
            transport.server_facts(FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER)
        data = responses()
        data["/1.0/resources"]["memory"]["used"] = 65 * GIB
        with self.assertRaises(transport.Refused):
            transport.server_facts(FixtureClient(data), capacity=True, runtime=runtime(), owner=OWNER)


class ContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "explicit-pin-fixture.invalid")])
        cls.certificate = (
            x509.CertificateBuilder()
            .subject_name(cls.subject)
            .issuer_name(cls.subject)
            .public_key(cls.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(cls.key.public_key()), critical=False)
            .sign(cls.key, hashes.SHA256())
        )

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "servercerts").mkdir(mode=0o700)
        pem = self.certificate.public_bytes(serialization.Encoding.PEM)
        key = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        self.binding = {
            "schema": 2,
            "repository": "example/repository",
            "run_id": "501",
            "run_attempt": "1",
            "server": "https://127.0.0.1:8443",
            "project": "fixture-lease",
            "expires_at": (NOW + dt.timedelta(minutes=30)).isoformat(),
            "runtime": runtime(),
            "admission": "syntactic.not.authority",
        }
        self.config = {
            "default-remote": "quality",
            "remotes": {
                "quality": {
                    "addr": self.binding["server"],
                    "auth_type": "tls",
                    "project": "fixture-lease",
                    "protocol": "incus",
                    "public": False,
                },
                "images": {"addr": "https://images.linuxcontainers.org", "protocol": "simplestreams", "public": True},
            },
        }
        for name, raw in (("client.crt", pem), ("client.key", key), ("servercerts/quality.crt", pem)):
            self.write(name, raw)
        self.refresh()

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)

    def refresh(self):
        self.write("binding.json", json.dumps(self.binding).encode())
        self.write("config.yml", yaml.safe_dump(self.config).encode())

    def load(self):
        return transport.load_context(self.root, repository="example/repository", run_id="501", attempt="1", now=NOW)

    def test_private_context_matches_current_tuple_and_uses_explicit_leaf_pin(self):
        binding, tls, digest = self.load()
        self.assertEqual(binding, self.binding)
        self.assertEqual(tls.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(tls.context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertFalse(tls.context.check_hostname)
        self.assertEqual(
            tls.peer_sha256, hashlib.sha256(self.certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
        )
        self.assertEqual(digest, hashlib.sha256((self.root / "binding.json").read_bytes()).hexdigest())

    def test_encrypted_client_key_fails_without_password_prompt_or_key_disclosure(self):
        encrypted = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(os.urandom(24)),
        )
        self.write("client.key", encrypted)
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(ssl.SSLError):
            self.load()
        self.assertEqual(error.getvalue(), "")

    def test_schema_one_foreign_tuple_default_project_expiry_and_firewall_deny(self):
        original = copy.deepcopy(self.binding)
        changes = {
            "schema": 1,
            "repository": "foreign/repository",
            "run_id": "500",
            "run_attempt": "2",
            "project": "default",
            "expires_at": (NOW - dt.timedelta(seconds=1)).isoformat(),
            "runtime": {"firewall_controller": "firewalld-runtime"},
            "admission": "unsigned",
        }
        for key, value in changes.items():
            self.binding = dict(original, **{key: value})
            self.refresh()
            with self.subTest(key=key), self.assertRaises(transport.Refused):
                self.load()

    def test_client_default_project_or_public_boolean_override_deny(self):
        original = copy.deepcopy(self.config)
        self.config["default-remote"] = "local"
        self.refresh()
        with self.assertRaises(transport.Refused):
            self.load()
        for key, value in (("project", "foreign"), ("public", 0), ("addr", "https://foreign.invalid")):
            self.config = copy.deepcopy(original)
            self.config["remotes"]["quality"][key] = value
            self.refresh()
            with self.subTest(key=key), self.assertRaises(transport.Refused):
                self.load()

    def test_private_mode_hardlink_symlink_extra_and_duplicate_fields_deny(self):
        path = self.root / "binding.json"
        path.chmod(0o644)
        with self.assertRaises(transport.Refused):
            self.load()
        path.chmod(0o600)
        link = self.root.parent / (self.root.name + "-outside-hardlink")
        self.addCleanup(lambda: link.unlink(missing_ok=True))
        os.link(path, link)
        with self.assertRaises(transport.Refused):
            self.load()
        link.unlink()
        self.write("binding.json", b'{"schema":2,"schema":2}')
        with self.assertRaises(transport.Refused):
            self.load()
        self.refresh()
        target = self.root / "client.crt"
        target.unlink()
        target.symlink_to(self.root / "servercerts/quality.crt")
        with self.assertRaises((OSError, transport.Refused)):
            self.load()

    def test_entry_rejects_plugin_binding_mismatch_before_server_access(self):
        arguments = [
            "tls_transport",
            "--repository",
            "example/repository",
            "--run-id",
            "501",
            "--attempt",
            "1",
            "--owner",
            OWNER,
            "--platforms",
            '[["vm1","vm"]]',
        ]
        for remote, project in (("local", "fixture-lease"), ("quality", "foreign-project")):
            error = io.StringIO()
            with (
                mock.patch.object(transport, "CONTEXT", self.root),
                mock.patch.object(sys, "argv", arguments),
                mock.patch.dict(
                    os.environ,
                    {"INCUS_CONF": str(self.root), "MOLECULE_INCUS_REMOTE": remote, "MOLECULE_INCUS_PROJECT": project},
                    clear=True,
                ),
                mock.patch.object(transport, "Client") as client,
                contextlib.redirect_stderr(error),
            ):
                self.assertEqual(transport.main(), 2)
            client.assert_not_called()
            self.assertIn("ansible-connection-binding-required", error.getvalue())
            self.assertNotIn(self.binding["admission"], error.getvalue())

    def test_root_runtime_has_closed_shape_real_booleans_and_canonical_subnet(self):
        variants = []
        for field, value in (
            ("dhcp", 1),
            ("nat", "true"),
            ("firewall", False),
            ("ipv4_address", "999.1.1.1/24"),
            ("ipv4_address", "10.20.30.0/24"),
            ("name", "litffffffffffff"),
            ("project", "foreign"),
        ):
            changed = runtime()
            changed["bridge"][field] = value
            variants.append(changed)
        changed = runtime()
        changed["bridge"]["approved"] = True
        variants.append(changed)
        changed = runtime()
        del changed["bridge"]["owner"]
        variants.append(changed)
        variants.append({"firewall_controller": "incus"})
        for changed in variants:
            self.binding["runtime"] = changed
            self.refresh()
            with self.subTest(runtime=changed), self.assertRaises(transport.Refused):
                self.load()

    def test_redacted_bridge_requires_matching_root_owner_network_and_selected_pool(self):
        data = responses()
        data["/1.0/networks/" + NETWORK]["config"] = {}
        for field in ("owner", "storage_pool"):
            changed = runtime()
            if field == "owner":
                changed["bridge"]["owner"] = "foreign-owner"
                changed["bridge"]["name"] = "lit" + hashlib.sha256(b"foreign-owner").hexdigest()[:12]
            else:
                changed[field] = "foreign-pool"
            with self.subTest(field=field), self.assertRaises(transport.Refused):
                transport.server_facts(
                    FixtureClient(data), capacity=False, runtime=changed, owner=OWNER, platforms={"vm1": "vm"}
                )

    def test_entry_reads_only_root_precreated_bridge_and_exact_project_restrictions(self):
        arguments = [
            "tls_transport",
            "--repository",
            "example/repository",
            "--run-id",
            "501",
            "--attempt",
            "1",
            "--owner",
            OWNER,
            "--platforms",
            '[["vm1","vm"]]',
            "--capacity",
        ]
        base = responses()
        base["/1.0/networks/" + NETWORK]["used_by"] = ["/1.0/instances/vm1?project=fixture-lease"]
        redacted = copy.deepcopy(base)
        redacted["/1.0/networks/" + NETWORK]["config"] = {}
        redacted["/1.0/networks/" + NETWORK].update(project="default", status="Created", locations=["fixture"])
        cases = [("valid-visible", base, 0), ("valid-redacted", redacted, 0)]
        for config in (None, [], "", {"ipv4.nat": "true"}):
            data = copy.deepcopy(base)
            data["/1.0/networks/" + NETWORK]["config"] = config
            cases.append(("malformed-or-incomplete-config", data, 2))
        data = copy.deepcopy(base)
        del data["/1.0/networks/" + NETWORK]["config"]
        cases.append(("missing-config", data, 2))
        for key, value in (
            ("ipv4.address", "10.99.1.1/24"),
            ("dns.domain", "foreign.invalid"),
            ("ipv4.nat", "false"),
            ("ipv4.firewall", "false"),
        ):
            data = copy.deepcopy(base)
            data["/1.0/networks/" + NETWORK]["config"][key] = value
            cases.append(("visible-conflict-" + key, data, 2))
        for key, value in (
            ("used_by", ["/1.0/instances/vm1?project=foreign"]),
            ("used_by", None),
            ("name", "foreign"),
            ("managed", False),
            ("type", "ovn"),
        ):
            data = copy.deepcopy(redacted)
            data["/1.0/networks/" + NETWORK][key] = value
            cases.append(("redacted-conflict-" + key, data, 2))
        for key, value in (
            ("features.networks", "true"),
            ("restricted.devices.nic", "allow"),
            ("restricted.networks.access", NETWORK + ",foreign"),
            ("restricted.storage-pools.access", "foreign"),
            ("restricted.storage-pools.access", ""),
        ):
            data = copy.deepcopy(base)
            data["/1.0/projects/fixture-lease"]["config"][key] = value
            cases.append((key + value, data, 2))
        for key, value in (("type", "ovn"), ("managed", False), ("name", "foreign")):
            data = copy.deepcopy(base)
            data["/1.0/networks/" + NETWORK][key] = value
            cases.append((key, data, 2))
        data = copy.deepcopy(base)
        data["/1.0/networks/" + NETWORK]["config"]["user.lit-molecule-owner"] = "foreign"
        cases.append(("foreign-owner", data, 2))
        data = copy.deepcopy(base)
        del data["/1.0/networks/" + NETWORK]
        cases.append(("missing-bridge", data, 2))
        for url in (
            "/1.0/instances/vm1?project=foreign",
            "/1.0/instances/vm1",
            "/1.0/profiles/vm1?project=fixture-lease",
            "/1.0/instances/vm1?project=fixture-lease&x=1",
            "https://foreign/1.0/instances/vm1?project=fixture-lease",
            "/1.0/instances/%76m1?project=fixture-lease",
        ):
            data = copy.deepcopy(base)
            data["/1.0/networks/" + NETWORK]["used_by"] = [url]
            cases.append((url, data, 2))
        for label, data, expected in cases:
            client = FixtureClient(data)
            output, error = io.StringIO(), io.StringIO()
            with (
                self.subTest(label=label),
                mock.patch.object(transport, "CONTEXT", self.root),
                mock.patch.object(sys, "argv", arguments),
                mock.patch.dict(
                    os.environ,
                    {
                        "INCUS_CONF": str(self.root),
                        "MOLECULE_INCUS_REMOTE": "quality",
                        "MOLECULE_INCUS_PROJECT": "fixture-lease",
                    },
                    clear=True,
                ),
                mock.patch.object(transport, "Client", return_value=client),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(error),
            ):
                self.assertEqual(transport.main(), expected)
                if expected == 0:
                    facts = json.loads(output.getvalue())
                    self.assertEqual(facts["network"], NETWORK)
                    self.assertEqual(facts["storage_pool"], "fixture-pool")
                    self.assertEqual(facts["network_cleanup"], "deferred-root")
                    self.assertEqual(
                        facts["network_config_visibility"],
                        "redacted" if data["/1.0/networks/" + NETWORK]["config"] == {} else "visible",
                    )
                    self.assertEqual(facts["network_used_by_visibility"], "lease-visible")
                    self.assertEqual(facts["network_config"]["ipv4.address"], runtime()["bridge"]["ipv4_address"])
                    self.assertEqual(facts["network_config"]["user.lit-molecule-owner"], OWNER)
                    self.assertNotIn("global_foreign_users_absent", facts)
                else:
                    self.assertEqual(output.getvalue(), "")
                self.assertNotIn(self.binding["admission"], error.getvalue())

    def serve(self, *, certificate=None, server_key=None, redirect=False):
        class Handler(http.server.BaseHTTPRequestHandler):
            requests = []

            def do_GET(self):
                self.requests.append(self.path)
                if redirect:
                    self.send_response(302)
                    self.send_header("Location", "https://foreign.invalid/")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"type": "sync", "status_code": 200, "metadata": {"project": "fixture-lease"}}).encode()
                )

            def log_message(self, *_):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if certificate is not None:
            self.write("alternate.crt", certificate.public_bytes(serialization.Encoding.PEM))
            self.write(
                "alternate.key",
                server_key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                ),
            )
            ctx.load_cert_chain(str(self.root / "alternate.crt"), str(self.root / "alternate.key"))
        else:
            ctx.load_cert_chain(str(self.root / "servercerts/quality.crt"), str(self.root / "client.key"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(self.root / "client.crt"))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

        self.addCleanup(cleanup)
        return server, Handler

    def test_real_mutual_tls_ignores_proxy_and_requires_exact_peer_leaf_before_http(self):
        _binding, tls, _root = self.load()
        server, handler = self.serve()
        binding = dict(self.binding, server="https://127.0.0.1:" + str(server.server_port))
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1"}):
            client = transport.Client(binding, tls)
            self.assertEqual(client.get("/1.0"), {"project": "fixture-lease"})
        self.assertEqual(handler.requests, ["/1.0?project=fixture-lease"])
        with self.assertRaises(transport.Refused):
            client.get("/1.0?project=foreign")

    def test_valid_ca_but_different_peer_leaf_fails_before_http(self):
        _binding, tls, _root = self.load()
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alternate-server.invalid")])
        alternate = (
            x509.CertificateBuilder()
            .subject_name(server_subject)
            .issuer_name(self.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        server, handler = self.serve(certificate=alternate, server_key=server_key)
        binding = dict(self.binding, server="https://127.0.0.1:" + str(server.server_port))
        # Prove that chain verification accepts this distinct, CA-signed leaf;
        # the following refusal must come from the stronger exact-leaf pin.
        correct_pin = hashlib.sha256(alternate.public_bytes(serialization.Encoding.DER)).hexdigest()
        alternate_tls = transport.TLSConfig(tls.context, correct_pin)
        self.assertEqual(transport.Client(binding, alternate_tls).get("/1.0"), {"project": "fixture-lease"})
        self.assertEqual(len(handler.requests), 1)
        handler.requests.clear()
        with self.assertRaisesRegex(transport.Refused, "server-leaf-pin-mismatch"):
            transport.Client(binding, tls).get("/1.0")
        self.assertEqual(handler.requests, [])

    def test_real_tls_redirect_is_not_followed(self):
        _binding, tls, _root = self.load()
        server, handler = self.serve(redirect=True)
        binding = dict(self.binding, server="https://127.0.0.1:" + str(server.server_port))
        with self.assertRaisesRegex(transport.Refused, "redirect-refused"):
            transport.Client(binding, tls).get("/1.0")
        self.assertEqual(len(handler.requests), 1)


class LifecycleWiringTests(unittest.TestCase):
    def tasks(self, name):
        return yaml.safe_load((ROOT / "molecule/shared/incus" / name).read_text())[0]["tasks"]

    def named(self, tasks, name):
        return next(task for task in tasks if task.get("name") == name)

    def test_create_capture_destroy_qualify_transport_before_first_incus_command(self):
        for file in ("create.yml", "cleanup.yml", "destroy.yml"):
            tasks = self.tasks(file)
            gate = next(
                i
                for i, task in enumerate(tasks)
                if task.get("name") == "Qualify the explicit Incus transport before lifecycle access"
            )
            incus = next(
                i
                for i, task in enumerate(tasks)
                if (task.get("ansible.builtin.command", {}).get("argv") or [None])[0] == "incus"
            )
            self.assertLess(gate, incus, file)

    def test_remote_path_skips_controller_resources_kvm_and_local_firewall_detection(self):
        tasks = self.tasks("create.yml")
        for name in (
            "Read available controller CPUs",
            "Read available controller memory",
            "Read available controller workspace storage",
            "Enforce Incus host resource prerequisites",
            "Detect an active host firewalld service",
        ):
            self.assertEqual(self.named(tasks, name)["when"], "not molecule_incus_is_remote | bool")
        for name in (
            "Verify KVM is readable for VM scenarios",
            "Verify KVM is writable for VM scenarios",
            "Require usable KVM for VM scenarios",
        ):
            self.assertIn("not molecule_incus_is_remote | bool", self.named(tasks, name)["when"])
        remote = self.named(tasks, "Enforce authenticated remote resource observations and hard project quota headroom")
        self.assertEqual(remote["when"], "molecule_incus_is_remote | bool")

    def test_remote_keeps_vm_init_start_agent_and_guest_network_checks(self):
        tasks = self.tasks("create.yml")
        initialization = self.named(
            tasks, "Initialize missing Incus instances with atomic owner labels and network attachment"
        )
        self.assertIn("['--vm']", initialization["ansible.builtin.command"]["argv"])
        names = [task.get("name") for task in tasks]
        for name in (
            "Start Incus instances",
            "Wait for Incus execution readiness",
            "Verify guest IPv4 after DHCP or deterministic fallback",
            "Verify guest DNS through the exact-owned bridge",
        ):
            self.assertIn(name, names)
        readiness = self.named(tasks, "Wait for Incus execution readiness")["ansible.builtin.command"]["argv"]
        self.assertEqual(readiness[:2], ["/bin/sh", "-c"])
        self.assertIn("'' if molecule_incus_is_remote", readiness[2])
        self.assertIn("incus exec", readiness[2])

    def test_remote_write_not_blindly_retried_and_destroy_enumerates_names_only(self):
        tasks = self.tasks("create.yml")
        create = self.named(tasks, "Create the managed network with atomic exact-owner labels")
        self.assertEqual(create["retries"], "{{ 0 if molecule_incus_is_remote else 3 }}")
        destroy = self.tasks("destroy.yml")
        names = self.named(destroy, "List all Incus instance names for exact-owner cleanup")
        self.assertEqual(names["ansible.builtin.command"]["argv"], ["incus", "list", "--format", "csv", "-c", "n"])
        owner = self.named(destroy, "Delete only Incus instances owned by this exact test run")
        self.assertIn("molecule_incus_owner_effective", str(owner["when"]))

    def test_tls_never_writes_networks_and_defers_only_exact_bridge_cleanup(self):
        create = self.tasks("create.yml")
        for name in (
            "Create the managed network with atomic exact-owner labels",
            "Reconcile configuration only on the exact-owned managed network",
        ):
            self.assertIn("not molecule_incus_is_remote | bool", str(self.named(create, name)["when"]))
        destroy = self.tasks("destroy.yml")
        deletion = self.named(destroy, "Delete only the network owned by this exact test run")
        self.assertIn("not molecule_incus_is_remote | bool", deletion["when"])
        evidence = self.named(destroy, "Record network and exact-owner cleanup completion evidence")
        self.assertIn('"network_cleanup_deferred"', evidence["ansible.builtin.copy"]["content"])
        self.assertIn("not molecule_incus_is_remote", evidence["ansible.builtin.copy"]["content"])
        assertions = self.named(destroy, "Fail closed when exact-owned Incus resources remain")[
            "ansible.builtin.assert"
        ]["that"]
        self.assertIn("difference([molecule_incus_network_effective])", str(assertions))
        self.assertIn("molecule_incus_remaining_exact_owned_instances | length == 0", assertions)

    def test_redacted_tls_keeps_full_static_fallback_dns_and_scoped_evidence(self):
        tasks = self.tasks("create.yml")
        visibility = self.named(tasks, "Resolve managed-network observation visibility")["ansible.builtin.set_fact"]
        self.assertIn("molecule_incus_transport_facts.network_config", visibility["molecule_incus_network_config"])
        checks = self.named(tasks, "Validate every visible managed-network configuration field")
        self.assertEqual(checks["when"], "not molecule_incus_network_config_redacted | bool")
        compare = self.named(tasks, "Compare every visible TLS bridge field with the Root-signed projection")
        self.assertIn("not molecule_incus_network_config_redacted | bool", compare["when"])
        fallback = self.named(tasks, "Assign a deterministic isolated IPv4 address when guest DHCP is unavailable")
        self.assertEqual(fallback["when"], "item.stdout | default('') | trim | length == 0")
        self.assertIn("molecule_incus_network_config['ipv4.address']", str(fallback["ansible.builtin.command"]["argv"]))
        dns = self.named(tasks, "Bind guest DNS directly to the exact-owned managed bridge")
        self.assertIn("molecule_incus_network_config['ipv4.address']", dns["ansible.builtin.command"]["stdin"])
        self.assertNotIn("stdout.split()", dns["ansible.builtin.command"]["stdin"])
        for name in (
            "Record exact-owned managed-network readiness evidence",
            "Record exact-owned network creation and attachment evidence",
        ):
            evidence = self.named(tasks, name)["ansible.builtin.copy"]["content"]
            self.assertIn('"used_by_visibility"', evidence)
            self.assertIn("none if molecule_incus_network_config_redacted else true", evidence)
            self.assertIn("root-signed-runtime", evidence)

    def test_every_existing_incus_connection_explicitly_maps_remote_and_project(self):
        count = 0

        def inspect(value):
            nonlocal count
            if isinstance(value, dict):
                if value.get("ansible_connection") == "community.general.incus":
                    count += 1
                    self.assertEqual(value.get("ansible_incus_remote"), "${MOLECULE_INCUS_REMOTE:-local}")
                    self.assertEqual(value.get("ansible_incus_project"), "${MOLECULE_INCUS_PROJECT:-default}")
                for child in value.values():
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)

        for path in sorted((ROOT / "molecule").glob("*/molecule.yml")):
            inspect(yaml.safe_load(path.read_text()))
        self.assertGreater(count, 0)

    def test_installed_connection_plugin_uses_explicit_project_and_remote_for_guest_command(self):
        # Load the actual installed collection entry point, rather than a copy
        # of its command builder. Only binary discovery is replaced; no CLI is
        # executed and no protected runtime is needed for this option contract.
        from ansible.playbook.play_context import PlayContext
        from ansible.plugins.loader import connection_loader, init_plugin_loader

        init_plugin_loader()
        cls = connection_loader.get("community.general.incus", class_only=True)
        self.assertIsNotNone(cls, "Pinned EE must contain the declared community.general.incus dependency")
        module = sys.modules[cls.__module__]
        self.assertIn("community/general/plugins/connection/incus.py", str(Path(module.__file__)))
        with mock.patch.object(module, "get_bin_path", return_value="/usr/bin/incus"):
            plugin = cls(PlayContext(), None)
        plugin.set_options(
            var_options={
                "ansible_incus_remote": "quality",
                "ansible_incus_project": "fixture-lease",
                "ansible_incus_host": "vm1",
                "ansible_user": "root",
            }
        )
        self.assertEqual(plugin.get_option("remote"), "quality")
        self.assertEqual(plugin.get_option("project"), "fixture-lease")
        self.assertEqual(
            plugin._build_command("id"),
            ["/usr/bin/incus", "--project", "fixture-lease", "exec", "quality:vm1", "--", "/bin/sh", "-c", "id"],
        )


if __name__ == "__main__":
    unittest.main()
