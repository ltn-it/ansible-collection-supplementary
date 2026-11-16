"""Strict single-line network inputs and stable rootless upstream identities."""

import ipaddress
import re
from collections.abc import Mapping

from ansible.errors import AnsibleFilterError


def rootless_network_valid(subnet, addresses):
    """Require one canonical IPv4 subnet and distinct usable member addresses."""
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
        if not isinstance(subnet, str) or str(network) != subnet:
            return False
        parsed = [ipaddress.IPv4Address(value) for value in addresses]
        return (
            bool(parsed)
            and len(set(parsed)) == len(parsed)
            and all(
                str(address) == value
                and address in network
                and address not in (network.network_address, network.broadcast_address)
                for address, value in zip(parsed, addresses, strict=True)
            )
        )
    except (ValueError, TypeError):
        return False


def rootless_upstream_addresses(output):
    """Bind getent's duplicate socket records to a sorted IPv4 address set."""
    try:
        addresses = sorted({str(ipaddress.IPv4Address(line.split()[0])) for line in output.splitlines() if line})
        if not addresses:
            raise ValueError("empty resolution")
        return addresses
    except (ValueError, TypeError, AttributeError, IndexError):
        raise AnsibleFilterError("Rootless upstream IPv4 resolution rejected") from None


def rootless_keycloak_env_valid(values):
    """Allow only implemented public feature/trust settings, never protected connection overrides."""
    if not isinstance(values, Mapping):
        return False
    allowed = {"KC_FEATURES", "KC_FEATURES_DISABLED", "KC_TRUSTSTORE_PATHS"}
    feature = r"[a-z][a-z0-9-]*(?::v[1-9][0-9]*)?"
    for name, value in values.items():
        if name not in allowed or not isinstance(value, str) or not value or len(value) > 4096:
            return False
        if name == "KC_TRUSTSTORE_PATHS":
            if any(
                not re.fullmatch(r"/opt/keycloak/conf/truststores/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path)
                or any(part in (".", "..") for part in path.split("/"))
                for path in value.split(",")
            ):
                return False
        elif not re.fullmatch(feature + r"(?:," + feature + r")*", value):
            return False
    return True


class FilterModule:
    def filters(self):
        return {
            "rootless_network_valid": rootless_network_valid,
            "rootless_keycloak_env_valid": rootless_keycloak_env_valid,
            "rootless_upstream_addresses": rootless_upstream_addresses,
        }
