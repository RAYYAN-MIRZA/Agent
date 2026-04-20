"""Paths and tunables for LAN discovery + status monitoring."""
import os
from pathlib import Path

from dotenv import load_dotenv

PACKAGE_DIR = Path(__file__).resolve().parent
load_dotenv(PACKAGE_DIR / ".env", override=False)
PACKAGE_DATA_DIR = PACKAGE_DIR / "data"
DATA_DIR = Path(os.environ.get("LAN_AGENT_DATA_DIR", str(PACKAGE_DATA_DIR))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

NETWORK_JSON = DATA_DIR / "network_info.json"
# Canonical inventory (MAC-keyed). Legacy ip_mac.json is migrated once at startup.
DEVICES_JSON = DATA_DIR / "devices.json"
IP_MAC_JSON = DATA_DIR / "ip_mac.json"
NMAP_JSON = DATA_DIR / "nmap_results.json"
STATUSES_JSON = DATA_DIR / "statuses.json"

SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "20"))
PING_INTERVAL = int(os.environ.get("PING_INTERVAL", "10"))
PING_WORKERS = int(os.environ.get("PING_WORKERS", "50"))
ARP_CONCURRENCY = int(os.environ.get("ARP_CONCURRENCY", "50"))
DISCOVERY_WORKERS = int(os.environ.get("DISCOVERY_WORKERS", "3"))
NMAP_PARALLEL = int(os.environ.get("NMAP_PARALLEL", "3"))

# ICMP timeout (ms); Wi‑Fi may need 600–1500.
PING_TIMEOUT_MS = int(os.environ.get("PING_TIMEOUT_MS", "750"))
# Scapy ARP probe timeout (seconds) for monitor fallback.
ARP_FALLBACK_TIMEOUT = float(os.environ.get("ARP_FALLBACK_TIMEOUT", "0.6"))
# Discovery ARP sweep per-host timeout (seconds).
ARP_SCAN_TIMEOUT = float(os.environ.get("ARP_SCAN_TIMEOUT", "1.0"))

# Hysteresis: require N consecutive failures before "offline", M successes before "online".
OFFLINE_AFTER_FAILS = max(1, int(os.environ.get("OFFLINE_AFTER_FAILS", "3")))
ONLINE_AFTER_OK = max(1, int(os.environ.get("ONLINE_AFTER_OK", "1")))

# Remove inventory rows not seen in this many seconds (0 = disabled).
DEVICE_STALE_SECONDS = int(os.environ.get("DEVICE_STALE_SECONDS", "0"))

# Optional: skip Nmap entirely for fast discovery-only runs.
NMAP_ENABLED = os.environ.get("NMAP_ENABLED", "true").strip().lower() in (
    "1",
    "true",
    "yes",
)
