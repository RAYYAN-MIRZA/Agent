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
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

from .network_util import get_local_host_on_cidr

logger = logging.getLogger(__name__)

# Subnets larger than this skip ICMP ping sweeps (ARP-only).
_MAX_PING_SWEEP_HOSTS = 512


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


def _resolve_scan_iface(cidr: str) -> Optional[str]:
    """Pick the local interface that owns the target CIDR.

    Critical on multi-homed agents (e.g. the lab agent attached to both
    backend-net and lab-net). Without this, Scapy's ``srp`` defaults to
    ``conf.iface`` — typically the default-route NIC — and ARP requests
    never leave the wrong subnet, so only the gateway ever responds.
    We pick the iface whose own routed subnet contains the target.
    """
    try:
        target = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None

    try:
        from scapy.all import conf  # type: ignore[import-not-found]
    except ImportError:
        return None

    try:
        # conf.route.routes is a list of tuples; the schema is stable across
        # scapy versions: (network_int, netmask_int, gw, iface, addr, metric).
        for entry in conf.route.routes:
            try:
                net_int, mask_int, _gw, iface, _addr, *_ = entry
            except (TypeError, ValueError):
                continue
            if not iface or iface == "lo":
                continue
            if mask_int == 0:
                continue
            try:
                route_net = ipaddress.IPv4Network(
                    f"{ipaddress.IPv4Address(net_int)}/{bin(mask_int).count('1')}",
                    strict=False,
                )
            except (ipaddress.AddressValueError, ValueError):
                continue
            if route_net.subnet_of(target) or target.subnet_of(route_net):
                return iface
    except Exception:  # pragma: no cover — never crash discovery on a route lookup
        logger.debug("scapy route lookup failed", exc_info=True)
    return None


def _arp_scan_scapy(cidr: str) -> list[DiscoveredDevice]:
    """Use Scapy for ARP sweep (requires root/admin on Linux)."""
    try:
        from scapy.all import ARP, Ether, srp
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        iface = _resolve_scan_iface(cidr)
        if iface:
            logger.debug("ARP sweep using iface=%s for %s", iface, cidr)
            ans, _ = srp(pkt, timeout=4, retry=1, verbose=0, iface=iface)
        else:
            ans, _ = srp(pkt, timeout=4, retry=1, verbose=0)
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


def _merge_devices(*groups: list[DiscoveredDevice]) -> list[DiscoveredDevice]:
    """Merge device lists; prefer entries that include a MAC address."""
    by_ip: dict[str, DiscoveredDevice] = {}
    for group in groups:
        for device in group:
            existing = by_ip.get(device.ip)
            if existing is None:
                by_ip[device.ip] = device
            elif not existing.mac and device.mac:
                by_ip[device.ip] = device
    return list(by_ip.values())


def _local_device(cidr: str) -> Optional[DiscoveredDevice]:
    """Include the scanning agent's own host on the discovery subnet."""
    local = get_local_host_on_cidr(cidr)
    if not local:
        return None
    ip, mac = local
    hostname: Optional[str]
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = None
    return DiscoveredDevice(
        ip=ip,
        mac=mac or "",
        hostname=hostname,
        status="up",
    )


def _ping_responding_hosts(cidr: str) -> set[str]:
    """ICMP ping sweep; returns IPs that replied (live hosts only)."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return set()

    if network.version != 4:
        return set()

    hosts = list(network.hosts())
    if len(hosts) > _MAX_PING_SWEEP_HOSTS:
        logger.debug(
            "Skipping ping sweep for %s (%d hosts > %d)",
            network.with_prefixlen,
            len(hosts),
            _MAX_PING_SWEEP_HOSTS,
        )
        return set()

    system = platform.system().lower()
    responded: set[str] = set()
    lock = threading.Lock()

    def ping_one(target: str) -> None:
        try:
            if system == "windows":
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "200", target],
                    capture_output=True,
                    timeout=3,
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", target],
                    capture_output=True,
                    timeout=3,
                )
            if result.returncode == 0:
                with lock:
                    responded.add(target)
        except (OSError, subprocess.SubprocessError):
            pass

    logger.debug("Ping sweep on %s (%d hosts)", network.with_prefixlen, len(hosts))
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(ping_one, [str(h) for h in hosts]))
    return responded


def _filter_command_arp_to_live(
    devices: list[DiscoveredDevice],
    ping_ok: set[str],
) -> list[DiscoveredDevice]:
    """Drop passive ARP cache entries for hosts that did not answer ping this sweep."""
    if not ping_ok:
        return devices
    live = [d for d in devices if d.ip in ping_ok]
    dropped = len(devices) - len(live)
    if dropped:
        logger.debug(
            "Filtered %d stale ARP cache entries (no ping reply this sweep)",
            dropped,
        )
    return live


def _needs_proactive_neighbor_scan(devices: list[DiscoveredDevice], cidr: str) -> bool:
    """True when ARP results look sparse (typical when only the gateway responded)."""
    if not devices:
        return True
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    # /24 and smaller: expect multiple LAN hosts when peers exist.
    if network.num_addresses <= 256 and len(devices) <= 2:
        return True
    return False


def run_discovery_scan(cidr: str) -> list[DiscoveredDevice]:
    """Run a single discovery sweep over the given CIDR (ARP + proactive ping)."""
    try:
        target_network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        logger.warning("Invalid discovery CIDR '%s' — skipping scan batch", cidr)
        return []

    scapy_devices = _arp_scan_scapy(cidr)
    raw_devices = list(scapy_devices)

    if _needs_proactive_neighbor_scan(scapy_devices, cidr):
        logger.info(
            "Sparse ARP on %s (%d devices) — running ping sweep to populate neighbor tables",
            target_network.with_prefixlen,
            len(scapy_devices),
        )
        ping_ok = _ping_responding_hosts(cidr)
        retry_scapy = _arp_scan_scapy(cidr)
        if len(retry_scapy) > len(raw_devices):
            raw_devices = retry_scapy
        retry_cmd = _filter_command_arp_to_live(_arp_scan_command(cidr), ping_ok)
        raw_devices = _merge_devices(raw_devices, retry_cmd)
    elif not raw_devices:
        ping_ok = _ping_responding_hosts(cidr)
        raw_devices = _filter_command_arp_to_live(_arp_scan_command(cidr), ping_ok)
    # When Scapy returned a healthy set, trust active ARP only — do not merge
    # passive `arp -a` cache entries that would keep WiFi-off hosts "Online".

    local = _local_device(cidr)
    merged = _merge_devices(raw_devices, [local] if local else [])

    filtered: list[DiscoveredDevice] = []
    dropped_ips: list[str] = []

    for device in merged:
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
        len(merged),
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
                else:
                    logger.debug("Discovery sweep returned no devices for %s", cidr)
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
