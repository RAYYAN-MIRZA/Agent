"""Lightweight network discovery for the connected agent.

Runs ARP sweeps over the agent's local subnet at a configurable interval
and pushes discovered devices to the backend via the SignalR hub
(``ReportDiscovery`` method). Works on Linux (Scapy) with fallback to
``arp -a`` parsing on Windows/macOS where raw sockets aren't available.

This module is designed to run in a background thread alongside the main
hub_client connection loop.
"""
from __future__ import annotations

import logging
import ipaddress
import platform
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredDevice:
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    status: str = "up"


@dataclass
class DiscoveryConfig:
    enabled: bool = True
    scan_interval_seconds: int = 20
    network_cidr: Optional[str] = None  # auto-detect if None


def _normalize_mac(raw: str) -> str:
    cleaned = raw.strip().replace("-", ":").upper()
    return cleaned


def _detect_local_cidr() -> Optional[str]:
    """Best-effort CIDR detection using platform commands."""
    system = platform.system().lower()
    try:
        if system == "linux":
            result = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"dev\s+(\S+)", result.stdout)
            if match:
                iface = match.group(1)
                addr_result = subprocess.run(
                    ["ip", "-4", "addr", "show", iface],
                    capture_output=True, text=True, timeout=5,
                )
                cidr_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", addr_result.stdout)
                if cidr_match:
                    return cidr_match.group(1)
        elif system == "windows":
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).InterfaceIndex | "
                 "ForEach-Object { (Get-NetIPAddress -InterfaceIndex $_ -AddressFamily IPv4).IPAddress + '/' + "
                 "(Get-NetIPAddress -InterfaceIndex $_ -AddressFamily IPv4).PrefixLength }"],
                capture_output=True, text=True, timeout=10,
            )
            cidr = result.stdout.strip()
            if re.match(r"\d+\.\d+\.\d+\.\d+/\d+", cidr):
                return cidr
        elif system == "darwin":
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", line)
                if match and not match.group(1).startswith("127."):
                    ip = match.group(1)
                    mask_hex = match.group(2)
                    prefix = bin(int(mask_hex, 16)).count("1")
                    return f"{ip}/{prefix}"
    except Exception as e:
        logger.debug("CIDR auto-detection failed: %s", e)
    return None


def _arp_scan_scapy(cidr: str) -> list[DiscoveredDevice]:
    """Use Scapy for ARP sweep (requires root/admin on Linux)."""
    try:
        from scapy.all import ARP, Ether, srp
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        ans, _ = srp(pkt, timeout=2, retry=0, verbose=0)
        devices = []
        for _, rcv in ans:
            devices.append(DiscoveredDevice(
                ip=rcv.psrc,
                mac=_normalize_mac(rcv.hwsrc),
            ))
        return devices
    except ImportError:
        logger.debug("Scapy not available, falling back to arp command")
        return []
    except Exception as e:
        logger.warning("Scapy ARP scan failed: %s", e)
        return []


def _arp_scan_command(cidr: str) -> list[DiscoveredDevice]:
    """Fallback: parse ``arp -a`` output (works without raw sockets)."""
    system = platform.system().lower()
    devices = []
    try:
        if system == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                match = re.match(
                    r"\s*(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:-]+)\s+",
                    line,
                )
                if match:
                    ip, mac = match.group(1), _normalize_mac(match.group(2))
                    if mac and mac != "FF:FF:FF:FF:FF:FF":
                        devices.append(DiscoveredDevice(ip=ip, mac=mac))
        else:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.splitlines():
                match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-fA-F:]+)", line)
                if match:
                    ip, mac = match.group(1), _normalize_mac(match.group(2))
                    if mac and mac != "FF:FF:FF:FF:FF:FF":
                        devices.append(DiscoveredDevice(ip=ip, mac=mac))
    except Exception as e:
        logger.warning("ARP command scan failed: %s", e)
    return devices


def run_discovery_scan(cidr: str) -> list[DiscoveredDevice]:
    """Run a single ARP discovery sweep over the given CIDR."""
    raw_devices = _arp_scan_scapy(cidr)
    if not raw_devices:
        raw_devices = _arp_scan_command(cidr)

    try:
        target_network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        logger.warning("Invalid discovery CIDR '%s' — skipping scan batch", cidr)
        return []

    filtered: list[DiscoveredDevice] = []
    dropped_ips: list[str] = []

    for device in raw_devices:
        try:
            ip = ipaddress.ip_address(device.ip)
        except ValueError:
            dropped_ips.append(device.ip)
            continue

        if ip in target_network:
            filtered.append(device)
        else:
            dropped_ips.append(device.ip)

    if dropped_ips:
        sample = ", ".join(dropped_ips[:5])
        logger.info(
            "Discovery dropped %d devices outside %s (sample: %s)",
            len(dropped_ips),
            target_network.with_prefixlen,
            sample,
        )

    logger.info(
        "Discovery scan found %d devices on %s (raw=%d, kept=%d)",
        len(filtered),
        target_network.with_prefixlen,
        len(raw_devices),
        len(filtered),
    )
    return filtered


class DiscoveryRunner:
    """Background thread that runs periodic discovery and pushes to the hub."""

    def __init__(
        self,
        hub_invoke,
        network_id: str,
        config: DiscoveryConfig,
    ):
        self._hub_invoke = hub_invoke
        self._network_id = network_id
        self._config = config
        self._stopping = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not self._config.enabled:
            logger.info("Discovery disabled by config")
            return

        cidr = self._config.network_cidr or _detect_local_cidr()
        if not cidr:
            logger.warning("Could not determine network CIDR — discovery disabled")
            return

        logger.info("Starting discovery loop for %s (interval=%ds)",
                    cidr, self._config.scan_interval_seconds)

        self._thread = threading.Thread(
            target=self._loop,
            args=(cidr,),
            daemon=True,
            name="discovery-runner",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self, cidr: str) -> None:
        while not self._stopping.is_set():
            try:
                devices = run_discovery_scan(cidr)
                if devices:
                    self._push_batch(devices)
            except Exception:
                logger.exception("Discovery loop error")

            self._stopping.wait(timeout=self._config.scan_interval_seconds)

    def _push_batch(self, devices: list[DiscoveredDevice]) -> None:
        payload = {
            "networkId": self._network_id,
            "devices": [
                {
                    "ip": d.ip,
                    "mac": d.mac,
                    "hostName": d.hostname,
                    "vendor": d.vendor,
                    "os": None,
                    "deviceType": None,
                    "openPorts": None,
                    "status": d.status,
                }
                for d in devices
            ],
        }
        try:
            self._hub_invoke("ReportDiscovery", payload)
            logger.debug("Pushed %d devices to backend", len(devices))
        except Exception:
            logger.exception("Failed to push discovery batch")
