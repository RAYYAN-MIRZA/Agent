"""Stable LAN identity: normalized MAC as device_id; legacy JSON migration."""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

from .helpers import save_json_atomic

logger = logging.getLogger(__name__)

# EUI-48 / common randomized formats (colon or hyphen separated octets).
_MAC_RE = re.compile(
    r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]"
    r"([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$"
)
_MAC_COMPACT_RE = re.compile(r"^([0-9A-Fa-f]{12})$")


def normalize_mac(mac: str | None) -> str | None:
    """Return lowercase `aa:bb:cc:dd:ee:ff` or None if invalid."""
    if not mac or not isinstance(mac, str):
        return None
    s = mac.strip()
    m = _MAC_RE.match(s)
    if m:
        return ":".join(x.lower() for x in m.groups())
    m2 = _MAC_COMPACT_RE.match(s.replace(":", "").replace("-", ""))
    if m2:
        h = m2.group(1).lower()
        return ":".join(h[i : i + 2] for i in range(0, 12, 2))
    return None


def device_id_from_mac(mac: str | None) -> str | None:
    """Primary key for a NIC on the LAN (same as normalized MAC)."""
    return normalize_mac(mac)


def migrate_legacy_inventory(devices_path: Path, legacy_ip_mac_path: Path) -> None:
    """
    If devices.json is missing but ip_mac.json exists, merge legacy rows by MAC
    and write devices.json. Does not delete the legacy file.
    """
    if devices_path.exists():
        return
    if not legacy_ip_mac_path.exists():
        save_json_atomic(devices_path, [])
        return
    try:
        with open(legacy_ip_mac_path, encoding="utf-8") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Could not read legacy %s: %s", legacy_ip_mac_path, e)
        save_json_atomic(devices_path, [])
        return

    if not isinstance(raw, list):
        save_json_atomic(devices_path, [])
        return

    now = time.time()
    by_mac: dict[str, dict] = {}
    for row in raw:
        if not isinstance(row, dict):
            continue
        mac = normalize_mac(row.get("mac"))
        if not mac:
            continue
        ip = row.get("ip")
        if not ip:
            continue
        disc = float(row.get("discoveredOn", now))
        mid = mac
        if mid not in by_mac:
            by_mac[mid] = {
                "device_id": mac,
                "mac": mac,
                "current_ip": str(ip).strip(),
                "first_seen": disc,
                "last_seen": disc,
                "_last_disc": disc,
            }
        else:
            ex = by_mac[mid]
            ex["first_seen"] = min(ex["first_seen"], disc)
            ex["last_seen"] = max(ex["last_seen"], disc)
            if disc >= ex["_last_disc"]:
                ex["_last_disc"] = disc
                ex["current_ip"] = str(ip).strip()
    for ex in by_mac.values():
        ex.pop("_last_disc", None)

    out = sorted(by_mac.values(), key=lambda x: x["device_id"])
    save_json_atomic(devices_path, out)
    logger.info(
        "Migrated %s legacy rows -> %s devices in %s",
        len(raw),
        len(out),
        devices_path,
    )
