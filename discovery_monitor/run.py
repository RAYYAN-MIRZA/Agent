"""
Run LAN discovery (ARP + Nmap) and online/offline monitoring.

Loads settings from discovery_monitor/.env (see .env.example).
Writes JSON under discovery_monitor/data/ unless LAN_AGENT_DATA_DIR is set:
  network_info.json, ip_mac.json, nmap_results.json, statuses.json

Usage:
  python -m discovery_monitor
  python -m discovery_monitor.run
"""
import asyncio

from . import config
from .discovery import run_discovery_loop
from .monitor import run_monitor_loop
from .network import get_network_info, select_primary_network


async def main():
    networks = get_network_info()
    net = select_primary_network(networks)
    if not net:
        print("[discovery_monitor] No usable IPv4 network found.")
        return

    cidr = net["cidr"]
    iface = net["interface"]
    print(f"[discovery_monitor] Using {cidr} on {iface}")
    print(f"[discovery_monitor] Data directory: {config.DATA_DIR}")

    asyncio.create_task(run_monitor_loop(iface=iface))
    await run_discovery_loop(cidr=cidr, iface=iface)


if __name__ == "__main__":
    asyncio.run(main())
