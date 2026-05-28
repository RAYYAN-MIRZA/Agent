"""Network helpers for Metasploit callback (LHOST) and discovery."""
from __future__ import annotations

import ipaddress
import logging
import os
import platform
import re
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


def resolve_callback_ipv4(discovery_cidr: Optional[str] = None) -> Optional[str]:
    """Return the routable IPv4 address targets should use for reverse shells (LHOST).

    Priority:
      1. FYP_AGENT_LAB_CALLBACK_IPV4 / FYP_AGENT_CALLBACK_IPV4 (lab or operator override)
      2. IPv4 on the interface that owns discovery_cidr (multi-homed agents)
      3. First non-loopback global IPv4
    """
    for key in ("FYP_AGENT_LAB_CALLBACK_IPV4", "FYP_AGENT_CALLBACK_IPV4"):
        explicit = os.environ.get(key, "").strip()
        if explicit and _is_ipv4(explicit):
            return explicit

    if discovery_cidr:
        bound = _ipv4_on_cidr_interface(discovery_cidr)
        if bound:
            return bound
        if platform.system().lower() == "windows":
            bound = resolve_callback_ipv4_windows(discovery_cidr)
            if bound:
                return bound

    return _first_global_ipv4()


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _ipv4_on_cidr_interface(cidr: str) -> Optional[str]:
    try:
        target_net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None

    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    for line in result.stdout.splitlines():
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not match:
            continue
        ip = match.group(1)
        prefix = int(match.group(2))
        try:
            iface_net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            continue
        if ipaddress.IPv4Address(ip) in target_net or iface_net.overlaps(target_net):
            return ip

    return None


def _first_global_ipv4() -> Optional[str]:
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    for line in result.stdout.splitlines():
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", line)
        if match:
            ip = match.group(1)
            if not ip.startswith("127."):
                return ip
    return None


def resolve_callback_ipv4_windows(cidr: Optional[str] = None) -> Optional[str]:
    """Windows-friendly callback IP when the ``ip`` CLI is unavailable."""
    if not cidr:
        return None
    try:
        target_net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    try:
        result = subprocess.run(
            [
                "powershell",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object { $_.IPAddress -notlike '127.*' } | "
                "ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }",
            ],
            capture_output=True,
            text=True,
            timeout=12,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if "/" not in line:
                continue
            ip_str, prefix_str = line.split("/", 1)
            try:
                iface_net = ipaddress.IPv4Network(f"{ip_str}/{prefix_str}", strict=False)
            except ValueError:
                continue
            if ipaddress.IPv4Address(ip_str) in target_net or iface_net.overlaps(target_net):
                return ip_str
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def get_local_host_on_cidr(cidr: str) -> Optional[tuple[str, Optional[str]]]:
    """Return (ipv4, mac) for this machine on the discovery subnet, if bound."""
    ip = resolve_callback_ipv4(cidr)
    if not ip:
        return None
    mac = resolve_mac_for_ip(ip) or _mac_for_local_interface(cidr, ip)
    return ip, mac


def resolve_mac_for_ip(ip: str) -> Optional[str]:
    """Best-effort MAC lookup for an IPv4 address (neighbor/ARP table)."""
    if not _is_ipv4(ip):
        return None

    system = platform.system().lower()
    try:
        if system == "windows":
            subprocess.run(
                ["ping", "-n", "1", "-w", "400", ip],
                capture_output=True,
                timeout=4,
            )
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(
                r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}",
                result.stdout,
                re.IGNORECASE,
            )
            if match:
                return _normalize_mac(match.group(0))
        else:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                timeout=4,
            )
            result = subprocess.run(
                ["ip", "neigh", "show", ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(
                r"([\da-fA-F]{2}:){5}[\da-fA-F]{2}",
                result.stdout,
                re.IGNORECASE,
            )
            if match:
                return _normalize_mac(match.group(0))
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _normalize_mac(raw: str) -> str:
    return raw.strip().replace("-", ":").upper()


def _mac_for_local_interface(cidr: str, ip: str) -> Optional[str]:
    """Read MAC from the OS interface that owns ``ip`` on ``cidr``."""
    system = platform.system().lower()
    try:
        if system == "linux":
            addr = subprocess.run(
                ["ip", "-4", "-o", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            iface = None
            for line in addr.stdout.splitlines():
                if f"inet {ip}/" in line or f"inet {ip} " in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        iface = parts[1].rstrip(":")
                        break
            if not iface:
                return None
            link = subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(r"link/ether\s+([\da-f:]+)", link.stdout, re.IGNORECASE)
            if match:
                return _normalize_mac(match.group(1))
        elif system == "windows":
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    f"(Get-NetIPAddress -IPAddress '{ip}' -ErrorAction SilentlyContinue | "
                    "Select-Object -First 1).InterfaceIndex | ForEach-Object { "
                    "(Get-NetAdapter -InterfaceIndex $_).MacAddress }",
                ],
                capture_output=True,
                text=True,
                timeout=12,
            )
            mac = result.stdout.strip().replace("-", ":").upper()
            if re.match(r"([\dA-F]{2}:){5}[\dA-F]{2}$", mac):
                return mac
        elif system == "darwin":
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for block in result.stdout.split("\n\n"):
                if f"inet {ip} " in block:
                    match = re.search(r"ether\s+([\da-f:]+)", block, re.IGNORECASE)
                    if match:
                        return _normalize_mac(match.group(1))
    except (OSError, subprocess.SubprocessError):
        logger.debug("Local interface MAC lookup failed for %s", ip, exc_info=True)
    return None
