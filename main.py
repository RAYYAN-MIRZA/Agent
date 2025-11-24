import asyncio
from network_info import get_network_info
from device_discovery import start_discovery
from status_monitor import monitor_statuses

from dotenv import load_dotenv
import os

from helpers import send_network_info

load_dotenv()

AGENT_HUB_URL = os.getenv("AGENT_HUB_URL")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 20))
PING_WORKERS = int(os.getenv("PING_WORKERS", 50))
PING_INTERVAL = int(os.getenv("PING_INTERVAL", 5))
API_BASE_URL = os.getenv("API_BASE_URL")

async def main():
    networks = get_network_info()

    if not networks:
        print("[-] No valid network interface found!")
        return

    # Adjust the network index if required
    network = networks[1]
    cidr = network["cidr"]
    iface = network["interface"]

    print(f"[+] Using subnet {cidr} on interface {iface}")

    network_info_payload = {
        "Mask": network["netmask"],
        "NetworkId": cidr,
        "BroadcastId": network["broadcastId"]
    }


    await send_network_info(API_BASE_URL+"/agent/network-info", network_info_payload)


    asyncio.create_task(monitor_statuses())

    # Start ARP + Nmap discovery system
    await start_discovery(
        cidr=cidr,
        iface=iface,
        scan_interval=SCAN_INTERVAL,
        worker_count=3
    )

if __name__ == "__main__":
    asyncio.run(main())
