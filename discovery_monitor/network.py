from ipaddress import IPv4Network

import netifaces

from . import config
from .helpers import save_json_atomic


def _gateway_for_iface(iface: str):
    gws = netifaces.gateways()
    for tup in gws.get(netifaces.AF_INET, []) or []:
        if len(tup) >= 2 and tup[1] == iface:
            return tup[0]
    default = gws.get("default", {}).get(netifaces.AF_INET)
    return default[0] if default else None


def get_network_info():
    networks = []

    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)

        if netifaces.AF_INET not in addrs:
            continue

        ipv4 = addrs[netifaces.AF_INET][0]
        ip = ipv4.get("addr")
        mask = ipv4.get("netmask")

        if not ip or not mask:
            continue

        net = IPv4Network(f"{ip}/{mask}", strict=False)
        networks.append(
            {
                "interface": iface,
                "ip": ip,
                "netmask": mask,
                "cidr": str(net),
                "totalHosts": net.num_addresses - 2,
                "gateway": _gateway_for_iface(iface),
                "broadcastId": str(net.broadcast_address),
            }
        )

    save_json_atomic(config.NETWORK_JSON, networks)
    return networks


def select_primary_network(networks: list) -> dict | None:
    """Prefer default-route interface, then first non-loopback IPv4."""
    if not networks:
        return None

    gws = netifaces.gateways()
    default = gws.get("default", {}).get(netifaces.AF_INET)
    if default and len(default) >= 2:
        iface_name = default[1]
        for n in networks:
            if n["interface"] == iface_name:
                return n

    for n in networks:
        if not str(n.get("ip", "")).startswith("127."):
            return n

    return networks[0]
