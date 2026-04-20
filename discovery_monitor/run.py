"""
Run LAN discovery (ARP + optional Nmap) and online/offline monitoring.

Loads settings from discovery_monitor/.env (see .env.example).
Writes JSON under discovery_monitor/data/ unless LAN_AGENT_DATA_DIR is set:
  network_info.json, devices.json (MAC-keyed inventory), nmap_results.json,
  statuses.json (hysteresis + reachability).

Legacy ip_mac.json is migrated once to devices.json on first run if present.

Usage:
  python -m discovery_monitor
  python -m discovery_monitor.run
"""
import asyncio
import logging
import signal
import sys

from . import config
from .discovery import run_discovery_loop
from .identity import migrate_legacy_inventory
from .monitor import run_monitor_loop
from .network import get_network_info, select_primary_network

logger = logging.getLogger(__name__)


async def _runner(stop_event: asyncio.Event):
    migrate_legacy_inventory(config.DEVICES_JSON, config.IP_MAC_JSON)

    networks = get_network_info()
    net = select_primary_network(networks)
    if not net:
        logger.error("No usable IPv4 network found.")
        return

    cidr = net["cidr"]
    iface = net["interface"]
    logger.info("Using %s on %s", cidr, iface)
    logger.info("Data directory: %s", config.DATA_DIR)

    await asyncio.gather(
        run_monitor_loop(iface=iface, stop_event=stop_event),
        run_discovery_loop(cidr=cidr, iface=iface, stop_event=stop_event),
    )


def _install_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            continue


async def amain() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    stop_event = asyncio.Event()
    _install_signal_handlers(stop_event)
    try:
        await _runner(stop_event)
    finally:
        logger.info("Shutdown complete.")


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)


if __name__ == "__main__":
    main()
