"""Read the admitted TLS cell context or plan local Incus resources.

This client is not an issuer or an admission verifier. The root launcher must
verify the compact admission JWS and its binding digest before starting the
cell. Merely parsing that field here never establishes authorization. Resource
figures are current observations bounded by hard project quotas, not host-wide
reservations. Real VM start, agent readiness and functional assertions remain
mandatory. The TLS path has no alternate endpoint, redirect, proxy or retry.
"""

# The closed JSON contract requires exact built-in types (not bool-as-int or
# user-defined subclasses); isinstance would broaden this trust boundary.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

CONTEXT = Path("/incus")
MAX_FILE = 65536
MAX_REPLY = 4 * 1024 * 1024
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")


class Refused(Exception):
    """Fixed-category failure without certificate/key/JWS/response disclosure."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-field")
        result[key] = value
    return result


def reject_nonfinite(_value):
    raise Refused("nonfinite-number")


def json_object(raw):
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_nonfinite)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Refused("invalid-json") from None
    require(type(value) is dict, "invalid-json-object")
    return value


class UniqueLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node):
    return unique(loader.construct_pairs(node, deep=True))


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def private_directory(path):
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
        "unsafe-context-directory",
    )


def private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= MAX_FILE,
            "unsafe-context-file",
        )
        raw = os.read(fd, MAX_FILE + 1)
        after = os.fstat(fd)

        def stamp(item):
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_nlink,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        require(len(raw) == info.st_size and stamp(after) == stamp(info), "context-file-changed")
        return raw
    finally:
        os.close(fd)


def runtime_facts(value):
    """Validate the closed Root-signed projection, never mint its authority."""
    require(
        type(value) is dict
        and set(value) == {"firewall_controller", "bridge", "storage_pool"}
        and value["firewall_controller"] == "incus",
        "remote-firewall-policy",
    )
    bridge = value["bridge"]
    require(
        type(bridge) is dict
        and set(bridge)
        == {"name", "project", "owner", "ipv4_address", "dns_domain", "dhcp", "nat", "firewall", "ipv6_address"},
        "root-bridge-facts-schema",
    )
    require(
        type(bridge["owner"]) is str
        and re.fullmatch(r"[A-Za-z0-9._/:-]{1,1024}", bridge["owner"])
        and bridge["name"] == "lit" + hashlib.sha256(bridge["owner"].encode()).hexdigest()[:12]
        and bridge["project"] == "default"
        and all(bridge[key] is True for key in ("dhcp", "nat", "firewall"))
        and bridge["ipv6_address"] == "none"
        and type(bridge["dns_domain"]) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]", bridge["dns_domain"])
        and type(value["storage_pool"]) is str
        and NAME.fullmatch(value["storage_pool"]),
        "root-bridge-facts-schema",
    )
    try:
        address = ipaddress.IPv4Interface(bridge["ipv4_address"])
        require(
            str(address) == bridge["ipv4_address"]
            and 8 <= address.network.prefixlen <= 30
            and address.ip not in (address.network.network_address, address.network.broadcast_address),
            "root-bridge-facts-address",
        )
    except (ValueError, TypeError):
        raise Refused("root-bridge-facts-address") from None
    return bridge


def load_context(root, *, repository, run_id, attempt, now):
    """Internal reader; production main fixes root=/incus and INCUS_CONF=/incus."""
    private_directory(root)
    private_directory(root / "servercerts")
    require(
        {p.name for p in root.iterdir()} == {"binding.json", "config.yml", "client.crt", "client.key", "servercerts"},
        "context-inventory",
    )
    require({p.name for p in (root / "servercerts").iterdir()} == {"quality.crt"}, "context-inventory")
    raw = {
        name: private_file(root / name)
        for name in ("binding.json", "config.yml", "client.crt", "client.key", "servercerts/quality.crt")
    }
    binding = json_object(raw["binding.json"])
    require(
        set(binding)
        == {"schema", "repository", "run_id", "run_attempt", "server", "project", "expires_at", "runtime", "admission"}
        and type(binding["schema"]) is int
        and binding["schema"] == 2,
        "legacy-binding-schema",
    )
    require(
        binding["repository"] == repository and binding["run_id"] == run_id and binding["run_attempt"] == attempt,
        "binding-invocation",
    )
    require(
        type(binding["project"]) is str and NAME.fullmatch(binding["project"]) and binding["project"] != "default",
        "binding-project",
    )
    runtime_facts(binding["runtime"])
    require(
        type(binding["admission"]) is str
        and len(binding["admission"]) <= 16384
        and re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", binding["admission"]),
        "missing-upstream-admission",
    )
    require(type(binding["expires_at"]) is str, "binding-expiry")
    try:
        expiry = dt.datetime.fromisoformat(binding["expires_at"].replace("Z", "+00:00"))
        remaining = (expiry - now).total_seconds()
    except (ValueError, TypeError):
        raise Refused("binding-expiry") from None
    require(expiry.tzinfo is not None and 0 < remaining <= 5400, "binding-expiry")
    require(type(binding["server"]) is str, "binding-server")
    url = urllib.parse.urlsplit(binding["server"])
    require(
        url.scheme == "https"
        and url.hostname
        and not url.username
        and not url.password
        and url.path in ("", "/")
        and not url.query
        and not url.fragment,
        "binding-server",
    )
    try:
        loader = UniqueLoader(raw["config.yml"])
        try:
            config = loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError:
        raise Refused("invalid-client-config") from None
    require(
        type(config) is dict
        and set(config) == {"default-remote", "remotes"}
        and config["default-remote"] == "quality"
        and type(config["remotes"]) is dict
        and set(config["remotes"]) == {"quality", "images"},
        "client-remote-set",
    )
    require(
        config["remotes"]["quality"]
        == {
            "addr": binding["server"],
            "auth_type": "tls",
            "project": binding["project"],
            "protocol": "incus",
            "public": False,
        },
        "client-remote-binding",
    )
    require(config["remotes"]["quality"]["public"] is False, "client-remote-binding")
    require(
        config["remotes"]["images"]
        == {"addr": "https://images.linuxcontainers.org", "protocol": "simplestreams", "public": True},
        "client-image-remote",
    )
    require(config["remotes"]["images"]["public"] is True, "client-image-remote")
    # Legacy TLS2 deliberately uses Incus's exact pinned-leaf identity. The
    # pre-admission signature also binds these context-file digests. This is
    # not a caller-selectable hostname-verification exception or insecure mode.
    certificate = raw["servercerts/quality.crt"].decode("ascii")
    require(
        certificate.count("-----BEGIN CERTIFICATE-----") == 1
        and certificate.strip().startswith("-----BEGIN CERTIFICATE-----")
        and certificate.strip().endswith("-----END CERTIFICATE-----"),
        "server-leaf-required",
    )
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=certificate)
    # Issued cell keys are unencrypted private files. An encrypted or malformed
    # key must fail immediately, never enter OpenSSL's interactive password UI.
    context.load_cert_chain(str(root / "client.crt"), str(root / "client.key"), password=lambda: "")
    return binding, TLSConfig(context, pin), hashlib.sha256(raw["binding.json"]).hexdigest()


@dataclass(frozen=True)
class TLSConfig:
    context: ssl.SSLContext
    peer_sha256: str


class PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, peer_sha256, **kwargs):
        self.peer_sha256 = peer_sha256
        super().__init__(host, **kwargs)

    def connect(self):
        super().connect()
        require(
            hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest() == self.peer_sha256,
            "server-leaf-pin-mismatch",
        )


class PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self, tls):
        self.tls = tls
        super().__init__(context=tls.context, check_hostname=False)

    def https_open(self, req):
        def connection(host, **kwargs):
            return PinnedConnection(host, peer_sha256=self.tls.peer_sha256, **kwargs)

        return self.do_open(connection, req, context=self.tls.context, check_hostname=False)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise Refused("redirect-refused")


class Client:
    def __init__(self, binding, tls):
        self.origin = binding["server"].rstrip("/")
        self.project = binding["project"]
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), PinnedHandler(tls))

    def get(self, path, *, expected=dict):
        require(path.startswith("/1.0") and "?" not in path and "#" not in path, "invalid-api-path")
        url = self.origin + path + "?" + urllib.parse.urlencode({"project": self.project})
        try:
            # The origin is HTTPS-only; proxy and redirect handlers are disabled.
            request = urllib.request.Request(url, method="GET")  # noqa: S310
            with self.opener.open(request, timeout=10) as reply:
                require(reply.status == 200, "remote-api-failed")
                raw = reply.read(MAX_REPLY + 1)
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                if path == "/1.0/resources":
                    raise Refused("remote-host-resource-read-required") from None
                if path.startswith("/1.0/storage-pools/"):
                    raise Refused("remote-storage-resource-read-required") from None
                if path.startswith("/1.0/projects/"):
                    raise Refused("remote-project-state-read-required") from None
                raise Refused("remote-scope-read-required") from None
            raise Refused("remote-api-unavailable") from None
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError):
            raise Refused("remote-api-unavailable") from None
        require(len(raw) <= MAX_REPLY, "remote-api-limit")
        value = json_object(raw)
        require(
            value.get("type") == "sync" and value.get("status_code") == 200 and type(value.get("metadata")) is expected,
            "remote-api-envelope",
        )
        return value["metadata"]


def integer(value, reason):
    require(type(value) is int and 0 <= value <= 2**63 - 1, reason)
    return value


def quota_headroom(row):
    require(type(row) is dict and set(row) == {"Limit", "Usage"}, "project-quota-schema")
    limit = integer(row["Limit"], "project-hard-quota-required")
    usage = integer(row["Usage"], "project-quota-usage")
    require(limit > 0 and usage <= limit, "project-hard-quota-required")
    return limit - usage


def byte_size(value):
    require(type(value) is str, "owned-allocation-schema")
    match = re.fullmatch(r"([1-9][0-9]{0,18})(KiB|MiB|GiB|TiB|kB|MB|GB|TB|B)?", value)
    require(match is not None, "owned-allocation-schema")
    powers = {
        None: 1,
        "B": 1,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "TiB": 1024**4,
        "kB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
    }
    return integer(int(match[1]) * powers[match[2]], "owned-allocation-schema")


VM_STATE_DEFAULT = "500MiB"  # Incus v7.6 project VM block filesystem default.


def owned_allocations(client, *, owner, platforms, inventory=None, local=False):
    """Credit exact-owned logical quota allocations, never physical guest RAM.

    This is not ownership authority for a privileged root executor. The shared
    lifecycle independently rechecks owners immediately before mutation/delete.
    """
    urls = client.get("/1.0/instances", expected=list)
    require(
        len(urls) <= 1000 and all(type(url) is str for url in urls) and len(urls) == len(set(urls)),
        "project-instance-inventory",
    )
    total = {"cpu": 0, "memory": 0, "disk": 0}
    for url in urls:
        require(type(url) is str, "project-instance-inventory")
        parsed = urllib.parse.urlsplit(url)
        require(
            not parsed.scheme
            and not parsed.netloc
            and not parsed.fragment
            and parsed.path.startswith("/1.0/instances/"),
            "project-instance-inventory",
        )
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True) if parsed.query else {}
        require(query in ({}, {"project": [client.project]}), "project-instance-inventory")
        name = urllib.parse.unquote(parsed.path.removeprefix("/1.0/instances/"))
        if local and name not in platforms:
            continue
        require(name in platforms and "/" not in name, "foreign-instance-in-project")
        instance = client.get("/1.0/instances/" + urllib.parse.quote(name, safe=""))
        config, devices = instance.get("expanded_config"), instance.get("expanded_devices")
        require(
            type(config) is dict and config.get("user.lit-molecule-owner") == owner and instance.get("name") == name,
            "foreign-instance-in-project",
        )
        require(
            instance.get("type") == ("virtual-machine" if platforms[name] == "vm" else "container"),
            "owned-instance-type-mismatch",
        )
        require(
            type(config.get("limits.cpu")) is str and re.fullmatch(r"[1-9][0-9]{0,9}", config["limits.cpu"]),
            "owned-allocation-schema",
        )
        require(
            type(devices) is dict
            and type(devices.get("root")) is dict
            and devices["root"].get("type") == "disk"
            and devices["root"].get("path") == "/",
            "owned-allocation-schema",
        )
        root = devices["root"]
        allocation = {
            "cpu": integer(int(config["limits.cpu"]), "owned-allocation-schema"),
            "memory": byte_size(config.get("limits.memory")),
            "disk": byte_size(root.get("size")),
        }
        state = byte_size(root.get("size.state", VM_STATE_DEFAULT)) if platforms[name] == "vm" else 0
        if inventory is not None:
            inventory[name] = (allocation, state, root.get("pool"), "size.state" in root)
        for key, value in allocation.items():
            total[key] += value
        total["disk"] += state
    return total


def inherited_bridge(client, *, owner, platforms, runtime):
    """Read the Root-owned default bridge through the restricted lease project.

    Names are locators derived from the existing native cell tuple, never a
    replacement for admission. This consumer has no network write authority.
    """
    require(type(owner) is str and 0 < len(owner) <= 1024, "network-owner-required")
    network = "lit" + hashlib.sha256(owner.encode()).hexdigest()[:12]
    facts = runtime_facts(runtime)
    require(facts["owner"] == owner and facts["name"] == network, "root-bridge-facts-binding")
    project = client.get("/1.0/projects/" + urllib.parse.quote(client.project, safe=""))
    config = project.get("config")
    require(
        project.get("name") == client.project
        and type(config) is dict
        and config.get("restricted") == "true"
        and config.get("features.networks") == "false"
        and config.get("restricted.devices.nic") == "managed"
        and config.get("restricted.networks.access") == network
        and config.get("restricted.devices.disk") == "managed",
        "restricted-project-network-required",
    )
    profile = client.get("/1.0/profiles/default")
    devices = profile.get("devices")
    require(
        type(devices) is dict
        and type(devices.get("root")) is dict
        and devices["root"].get("type") == "disk"
        and devices["root"].get("path") == "/",
        "remote-root-storage-required",
    )
    pool = devices["root"].get("pool")
    require(
        type(pool) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", pool)
        and config.get("restricted.storage-pools.access") == pool
        and pool == runtime["storage_pool"],
        "restricted-storage-pool-required",
    )
    bridge = client.get("/1.0/networks/" + network)
    settings = bridge.get("config")
    require(
        bridge.get("name") == network
        and bridge.get("managed") is True
        and bridge.get("type") == "bridge"
        and type(settings) is dict,
        "root-precreated-bridge-required",
    )
    # Incus7.6 redacts inherited default-network config for lease-only TLS
    # CanView. Root's signed handoff follows its full ownership/config readback;
    # this consumer cannot attest hidden fields or global absence of users.
    # A nonempty visible config must still satisfy the complete existing check.
    effective = {
        "user.lit-molecule-owner": facts["owner"],
        "ipv4.address": facts["ipv4_address"],
        "ipv4.dhcp": "true",
        "ipv4.nat": "true",
        "ipv4.firewall": "true",
        "ipv6.address": "none",
        "dns.domain": facts["dns_domain"],
        "dns.mode": "managed",
        "user.lit-molecule-firewall-controller": "incus",
        "user.lit-molecule-firewalld-zone": "none",
    }
    require(
        not settings
        or (
            settings.get("user.lit-molecule-owner") == owner
            and settings.get("ipv4.dhcp") == "true"
            and settings.get("ipv4.nat") == "true"
            and settings.get("ipv4.firewall") == "true"
            and settings.get("ipv6.address") == "none"
            and settings.get("user.lit-molecule-firewall-controller") == "incus"
            and settings.get("user.lit-molecule-firewalld-zone") == "none"
            and type(settings.get("ipv4.address")) is str
            and all(settings.get(key) == value for key, value in effective.items())
        ),
        "root-precreated-bridge-required",
    )
    users = bridge.get("used_by")
    allowed = {
        "/1.0/instances/"
        + urllib.parse.quote(name, safe="")
        + "?project="
        + urllib.parse.quote(client.project, safe="")
        for name in platforms
    }
    require(
        type(users) is list
        and all(type(url) is str and url in allowed for url in users)
        and len(users) == len(set(users)),
        "foreign-network-user",
    )
    return network, pool, not settings, effective, devices["root"]


def server_facts(client, *, capacity, runtime, owner="", platforms=None, requests=None):
    server = client.get("/1.0")
    environment = server.get("environment")
    require(
        server.get("auth") == "trusted"
        and type(environment) is dict
        and environment.get("project") == client.project
        and environment.get("server") == "incus",
        "remote-server-binding",
    )
    require(type(environment.get("driver")) is str, "remote-driver-schema")
    result = {
        "mode": "tls",
        "project": client.project,
        "server_version": environment.get("server_version", ""),
        "declares_vm_driver": "qemu" in environment["driver"].split(" | "),
        "firewall_controller": "incus",
    }
    network, pool, redacted, effective, root = inherited_bridge(
        client, owner=owner, platforms=platforms or {}, runtime=runtime
    )
    result.update(
        network=network,
        storage_pool=pool,
        network_cleanup="deferred-root",
        network_config_visibility="redacted" if redacted else "visible",
        network_used_by_visibility="lease-visible",
        network_config=effective,
        network_config_source="root-signed-runtime" if redacted else "visible-api-matches-root-runtime",
    )
    if not capacity:
        return result
    extensions = server.get("api_extensions")
    require(
        type(extensions) is list and {"resources", "project_usage", "projects"} <= set(extensions),
        "remote-resource-api-required",
    )
    plan = capacity_plan(client, owner=owner, platforms=platforms or {}, requests=requests, root=root)
    result["plan"] = plan["instances"]
    result["requested"] = plan["requested"]
    result["available"] = plan["available"]
    result["capacity_is_reservation"] = False
    return result


def valid_pool(pool):
    return type(pool) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", pool)


def capacity_plan(client, *, owner, platforms, requests, root, local=False):
    """Plan only positive quota changes; configured capacity is never physical credit."""
    require(type(requests) is dict and requests.keys() == platforms.keys(), "requested-resources-schema")
    require(type(root) is dict and root.get("type") == "disk" and root.get("path") == "/", "root-storage-required")
    pool = root.get("pool")
    require(valid_pool(pool), "root-storage-required")
    inventory = {}
    allocations = owned_allocations(client, owner=owner, platforms=platforms, inventory=inventory, local=local)
    quotas = client.get("/1.0/projects/" + urllib.parse.quote(client.project, safe="") + "/state").get("resources")
    require(type(quotas) is dict, "project-quota-schema")
    headroom = {}
    for key in ("cpu", "memory", "disk"):
        row = quotas.get(key)
        if local and (row is None or (type(row) is dict and row.get("Limit") == -1)):
            continue
        headroom[key] = quota_headroom(row)
        require(allocations[key] <= row["Usage"], "owned-allocation-exceeds-project-usage")

    changes = dict.fromkeys(("cpu", "memory", "disk"), 0)
    requested = dict.fromkeys(changes, 0)
    by_pool = {}
    instances = {}
    for name, kind in platforms.items():
        req = requests[name]
        require(type(req) is dict and set(req) == {"cpu", "memory", "disk"}, "requested-resources-schema")
        require(type(req["cpu"]) is str and re.fullmatch(r"[1-9][0-9]{0,9}", req["cpu"]), "requested-resources-schema")
        limits = {"cpu": int(req["cpu"]), "memory": byte_size(req["memory"]), "disk": byte_size(req["disk"])}
        old, old_state, target_pool, explicit_state = inventory.get(name, ({}, 0, pool, False))
        require(valid_pool(target_pool) and (local or target_pool == pool), "owned-root-storage-mismatch")
        state = None
        if kind == "vm":
            if old:
                require(limits["disk"] >= old["disk"], "vm-root-shrink-refused")
                # Incus reapplies the state quota when resizing a VM root.
                # For legacy implicit state the physical filesystem may have
                # a volume-specific size which the expanded device cannot prove.
                require(limits["disk"] == old["disk"] or explicit_state, "vm-root-resize-state-unproven")
            else:
                state = root.get("size.state", root.get("initial.size.state", VM_STATE_DEFAULT))
                byte_size(state)
        state_bytes = byte_size(state) if state is not None else 0
        requested["disk"] += state_bytes + old_state
        changes["disk"] += state_bytes
        for key, value in limits.items():
            requested[key] += value
            changes[key] += max(0, value - old.get(key, 0))
        by_pool[target_pool] = by_pool.get(target_pool, 0) + state_bytes + max(0, limits["disk"] - old.get("disk", 0))
        instances[name] = {
            "present": bool(old),
            "resize_root": bool(old) and old["disk"] != limits["disk"],
            "state": state,
            **req,
        }
    require(all(changes[key] <= free for key, free in headroom.items()), "insufficient-project-quota")
    for target_pool, growth in by_pool.items():
        quota_key = "disk." + target_pool
        if quota_key in quotas:
            free = quota_headroom(quotas[quota_key])
            observed = sum(old["disk"] + state for old, state, p, _ in inventory.values() if p == target_pool)
            require(observed <= quotas[quota_key]["Usage"], "owned-allocation-exceeds-pool-usage")
            require(growth <= free, "insufficient-pool-project-quota")
        storage = client.get("/1.0/storage-pools/" + urllib.parse.quote(target_pool, safe="") + "/resources")
        space = storage.get("space")
        require(type(space) is dict, "storage-pool-resource-schema")
        total = integer(space.get("total"), "storage-pool-resource-schema")
        used = integer(space.get("used"), "storage-pool-resource-schema")
        require(used <= total and growth <= total - used, "insufficient-storage-pool-space")

    available = {}
    if not local:
        resources = client.get("/1.0/resources")
        cpu, memory = resources.get("cpu"), resources.get("memory")
        require(type(cpu) is dict and type(memory) is dict, "remote-resource-schema")
        total = integer(memory.get("total"), "remote-memory-schema")
        used = integer(memory.get("used"), "remote-memory-schema")
        require(used <= total, "remote-memory-schema")
        available = {"cpu": integer(cpu.get("total"), "remote-cpu-schema"), "memory": total - used}
    return {"instances": instances, "requested": requested, "available": available}


class LocalClient:
    """Read the same CLI-selected project used by local lifecycle commands."""

    def __init__(self):
        require(self._run("remote", "get-default").strip() == b"local", "local-remote-binding")
        self.project = self._run("project", "get-current").decode("ascii").strip()
        require(valid_pool(self.project), "local-project-binding")
        server = self.get("/1.0")
        environment = server.get("environment")
        require(
            server.get("auth") == "trusted"
            and type(environment) is dict
            and environment.get("server") == "incus"
            and environment.get("project") == self.project,
            "local-server-binding",
        )

    @staticmethod
    def _run(*args):
        try:
            # Fixed read-only CLI operations; no shell.
            proc = subprocess.run(  # noqa: S603
                ["incus", *args],  # noqa: S607
                capture_output=True,
                timeout=15,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise Refused("local-resource-api-unavailable") from None
        require(len(proc.stdout) <= MAX_REPLY, "local-resource-response-size")
        return proc.stdout

    def get(self, path, *, expected=dict):
        # The raw query CLI does not attach the CLI-selected project.
        raw = self._run("query", path + "?" + urllib.parse.urlencode({"project": self.project}))
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_nonfinite)
        require(type(value) is expected, "local-resource-response-type")
        return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository")
    parser.add_argument("--run-id")
    parser.add_argument("--attempt")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--platforms", required=True)
    parser.add_argument("--capacity", action="store_true")
    parser.add_argument("--requests")
    parser.add_argument("--local", action="store_true")
    args = parser.parse_args()
    try:
        if args.local:
            require(args.requests is not None, "requested-resources-schema")
            platforms = json_object(args.platforms)
            require(
                0 < len(platforms) <= 1000
                and all(
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", name) and kind in ("vm", "container")
                    for name, kind in platforms.items()
                ),
                "invalid-declared-platforms",
            )
            client = LocalClient()
            devices = client.get("/1.0/profiles/default").get("devices")
            require(type(devices) is dict, "root-storage-required")
            root = devices.get("root")
            plan = capacity_plan(
                client,
                owner=args.owner,
                platforms=platforms,
                requests=json_object(args.requests),
                root=root,
                local=True,
            )
            print(json.dumps({"plan": plan["instances"], "requested": plan["requested"]}))
            return 0
        require(all((args.repository, args.run_id, args.attempt)), "missing-tls-identity")
        require(args.capacity == (args.requests is not None), "requested-resources-schema")
        require(os.environ.get("INCUS_CONF") == str(CONTEXT), "fixed-incus-context-required")
        require(
            not any(os.environ.get(name) for name in ("INCUS_REMOTE", "INCUS_PROJECT", "INCUS_SOCKET")),
            "incus-context-override-refused",
        )
        platforms = json.loads(args.platforms)
        require(
            type(platforms) is list
            and 0 < len(platforms) <= 1000
            and all(
                type(row) is list
                and len(row) == 2
                and type(row[0]) is str
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", row[0])
                and row[1] in ("vm", "container")
                for row in platforms
            )
            and len(dict(platforms)) == len(platforms),
            "invalid-declared-platforms",
        )
        binding, context, digest = load_context(
            CONTEXT, repository=args.repository, run_id=args.run_id, attempt=args.attempt, now=dt.datetime.now(dt.UTC)
        )
        require(
            os.environ.get("MOLECULE_INCUS_REMOTE") == "quality"
            and os.environ.get("MOLECULE_INCUS_PROJECT") == binding["project"],
            "ansible-connection-binding-required",
        )
        result = server_facts(
            Client(binding, context),
            capacity=args.capacity,
            runtime=binding["runtime"],
            owner=args.owner,
            platforms=dict(platforms),
            requests=json_object(args.requests) if args.requests else None,
        )
        result["binding_sha256"] = digest
        result["expires_at"] = binding["expires_at"]
        print(json.dumps(result, sort_keys=True))
    except Refused as error:
        mode = "local" if args.local else "TLS"
        print(
            f"Incus {mode} lifecycle preflight refused ({error}); no automatic fallback or retry.",
            file=sys.stderr,
        )
        return 2
    except (OSError, ssl.SSLError, ValueError, TypeError):
        print("Incus TLS lifecycle preflight refused; no automatic fallback or retry.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
