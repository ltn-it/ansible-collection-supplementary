"""Strict single-line network inputs and stable rootless upstream identities."""

import ipaddress

from ansible.errors import AnsibleFilterError


def rootless_network_valid(subnet, addresses):
    """Require one canonical IPv4 subnet and distinct usable member addresses."""
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
        if not isinstance(subnet, str) or str(network) != subnet:
            return False
        parsed = [ipaddress.IPv4Address(value) for value in addresses]
        return bool(parsed) and len(set(parsed)) == len(parsed) and all(
            str(address) == value
            and address in network
            and address not in (network.network_address, network.broadcast_address)
            for address, value in zip(parsed, addresses, strict=True)
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


class FilterModule:
    def filters(self):
        return {
            "rootless_network_valid": rootless_network_valid,
            "rootless_upstream_addresses": rootless_upstream_addresses,
        }
