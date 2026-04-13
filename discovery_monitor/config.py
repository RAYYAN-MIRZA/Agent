"""Paths and tunables for LAN discovery + status monitoring."""
import os
from pathlib import Path

from dotenv import load_dotenv

PACKAGE_DIR = Path(__file__).resolve().parent
# This package's own config (not the parent repo's .env).
load_dotenv(PACKAGE_DIR / ".env", override=False)
# All JSON output lives under this package's data/ unless overridden.
PACKAGE_DATA_DIR = PACKAGE_DIR / "data"
DATA_DIR = Path(os.environ.get("LAN_AGENT_DATA_DIR", str(PACKAGE_DATA_DIR))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

NETWORK_JSON = DATA_DIR / "network_info.json"
IP_MAC_JSON = DATA_DIR / "ip_mac.json"
NMAP_JSON = DATA_DIR / "nmap_results.json"
STATUSES_JSON = DATA_DIR / "statuses.json"

SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "20"))
PING_INTERVAL = int(os.environ.get("PING_INTERVAL", "10"))
PING_WORKERS = int(os.environ.get("PING_WORKERS", "50"))
ARP_CONCURRENCY = int(os.environ.get("ARP_CONCURRENCY", "50"))
DISCOVERY_WORKERS = int(os.environ.get("DISCOVERY_WORKERS", "3"))
NMAP_PARALLEL = int(os.environ.get("NMAP_PARALLEL", "3"))
