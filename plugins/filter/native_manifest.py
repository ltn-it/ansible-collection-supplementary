"""Private, type-aware comparison of complete native Pod manifests."""

import json

import yaml
from ansible.errors import AnsibleFilterError


class UniqueMappingLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate keys instead of silently keeping the last."""


def unique_mapping(loader, node):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result:
            raise ValueError("ambiguous manifest mapping")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


UniqueMappingLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def native_manifest_equal(original, desired):
    """Ignore presentation only; preserve scalar types and sequence ordering."""
    try:
        normalized = []
        for content in (original, desired):
            if not isinstance(content, str) or not content or len(content) > 1_048_576:
                raise ValueError("invalid manifest input")
            # SafeLoader subclass additionally rejects ambiguous mapping keys.
            loader = UniqueMappingLoader(content)
            try:
                document = loader.get_single_data()
            finally:
                loader.dispose()
            if not isinstance(document, dict) or document.get("kind") != "Pod":
                raise ValueError("complete Pod manifest required")
            normalized.append(json.dumps(document, sort_keys=True, allow_nan=False, separators=(",", ":")))
        return normalized[0] == normalized[1]
    except (ValueError, TypeError, RecursionError, yaml.YAMLError):
        raise AnsibleFilterError("Native manifest comparison rejected") from None


KEYCLOAK_MANAGED_ENV = frozenset(
    {
        "KC_DB",
        "KC_DB_URL_HOST",
        "KC_DB_URL_PORT",
        "KC_DB_URL_DATABASE",
        "KC_DB_USERNAME",
        "KC_DB_PASSWORD",
        "KC_BOOTSTRAP_ADMIN_USERNAME",
        "KC_BOOTSTRAP_ADMIN_PASSWORD",
        "KC_HTTP_ENABLED",
        "KC_HTTP_PORT",
        "KC_HEALTH_ENABLED",
        "KC_METRICS_ENABLED",
        "KC_HOSTNAME",
        "KC_PROXY_HEADERS",
        "KC_PROXY_TRUSTED_ADDRESSES",
    }
)


def rootless_keycloak_bindings_preserved(original, desired):
    """Refuse silent removal of existing mounts, extra environment or start arguments."""
    try:
        documents = []
        for content in (original, desired):
            if not isinstance(content, str) or not content or len(content) > 1_048_576:
                raise ValueError("invalid manifest input")
            loader = UniqueMappingLoader(content)
            try:
                document = loader.get_single_data()
            finally:
                loader.dispose()
            if not isinstance(document, dict) or document.get("kind") != "Pod":
                raise ValueError("complete Pod manifest required")
            documents.append(document)
        before, after = documents
        if before["metadata"]["name"] != after["metadata"]["name"]:
            return False
        old_apps, new_apps = before["spec"]["containers"], after["spec"]["containers"]
        if len(old_apps) != 1 or len(new_apps) != 1:
            return False
        old, new = old_apps[0], new_apps[0]
        if old["name"] != new["name"] or any(old.get(k) != new.get(k) for k in ("command", "args")):
            return False

        def named(entries):
            if not isinstance(entries, list) or any(not isinstance(x, dict) for x in entries):
                raise ValueError("invalid binding list")
            names = [x["name"] for x in entries]
            if any(not isinstance(x, str) or not x for x in names) or len(set(names)) != len(names):
                raise ValueError("ambiguous bindings")
            return dict(zip(names, entries, strict=True))

        def canonical(value):
            return json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":"))

        for key, old_parent, new_parent in (
            ("volumes", before["spec"], after["spec"]),
            ("volumeMounts", old, new),
        ):
            old_bindings = named(old_parent.get(key, []))
            new_bindings = named(new_parent.get(key, []))
            for name, binding in old_bindings.items():
                wanted = new_bindings.get(name)
                if wanted is None:
                    return False
                a, b = dict(binding), dict(wanted)
                if key == "volumeMounts":
                    for mount in (a, b):
                        if "readOnly" in mount and not isinstance(mount["readOnly"], bool):
                            raise ValueError("invalid mount mode")
                        if mount.get("readOnly") is False:
                            mount.pop("readOnly")
                if canonical(a) != canonical(b):
                    return False
        old_env, new_env = named(old.get("env", [])), named(new.get("env", []))
        for name, binding in old_env.items():
            wanted = new_env.get(name)
            if wanted is None:
                return False
            if (name not in KEYCLOAK_MANAGED_ENV or "valueFrom" in binding) and canonical(binding) != canonical(wanted):
                return False
        return True
    except (ValueError, TypeError, KeyError, IndexError, RecursionError, yaml.YAMLError):
        raise AnsibleFilterError("Rootless Keycloak binding comparison rejected") from None


class FilterModule:
    def filters(self):
        return {
            "native_manifest_equal": native_manifest_equal,
            "rootless_keycloak_bindings_preserved": rootless_keycloak_bindings_preserved,
        }
