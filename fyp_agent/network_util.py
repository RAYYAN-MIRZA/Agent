"""Network helpers for Metasploit callback (LHOST) discovery."""
from __future__ import annotations

import ipaddress
import logging
import os
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
