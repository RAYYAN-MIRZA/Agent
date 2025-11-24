# network_info.py
import json
import os
from dotenv import load_dotenv
import netifaces
from ipaddress import IPv4Network
from helpers import save_json_atomic

load_dotenv()

AGENT_HUB_URL = os.getenv("AGENT_HUB_URL")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 20))
PING_WORKERS = int(os.getenv("PING_WORKERS", 50))

NETWORK_FILE = "data/network_info.json"

def get_network_info():
    networks = []

    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)

        if netifaces.AF_INET not in addrs:
            continue

        ipv4 = addrs[netifaces.AF_INET][0]
        ip = ipv4.get("addr")
        mask = ipv4.get("netmask")
        gateway = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, [None])[0]

        if not ip or not mask:
            continue

        # Calculate CIDR + network details
        net = IPv4Network(f"{ip}/{mask}", strict=False)
        networks.append({
            "interface": iface,
            "ip": ip,
            "netmask": mask,
            "cidr": str(net),
            "totalHosts": net.num_addresses - 2,
            "gateway": gateway,
            "broadcastId": str(net.broadcast_address)
        })

    save_json_atomic(NETWORK_FILE, networks)
    return networks
