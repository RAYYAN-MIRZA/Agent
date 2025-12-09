# job1.py
import asyncio
import os

from dotenv import load_dotenv
from network_info import get_network_info
from device_discovery import start_discovery



load_dotenv()

AGENT_HUB_URL = os.getenv("AGENT_HUB_URL")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 20))
PING_WORKERS = int(os.getenv("PING_WORKERS", 50))
PING_INTERVAL = int(os.getenv("PING_INTERVAL", 5))
API_BASE_URL = os.getenv("API_BASE_URL")

async def run_job(job_payload):
    """
    job_payload may contain:
    {
        "interface": "eth0",
        "cidr": "192.168.100.0/24",
        "scanInterval": 20
    }
    """

    networks = get_network_info()
    if not networks:
        print("[-] No network interface found for Job 1")
        return

    # Auto-select default network or use payload if provided
    cidr = networks[1]["cidr"]
    iface = networks[1]["interface"]
    scan_interval = SCAN_INTERVAL

    print(f"[Job1] Starting discovery on {cidr} ({iface})")

    await start_discovery(
        cidr=cidr,
        iface=iface,
        scan_interval=scan_interval,
        worker_count=3
    )
