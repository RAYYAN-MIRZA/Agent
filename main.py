# main.py
import asyncio
from network_info import get_network_info
from device_discovery import start_discovery
from status_monitor import monitor_statuses

async def main():
    networks = get_network_info()

    if not networks:
        print("[-] No valid network interface found!")
        return

    # Pick the FIRST network (you can later add UI to select)
    cidr = networks[0]["cidr"]
    iface = networks[0]["interface"]

    print(f"[+] Using subnet {cidr} on interface {iface}")

    # Start status monitor loop
    asyncio.create_task(monitor_statuses())

    # Start dynamic ARP + Nmap discovery
    await start_discovery(
        cidr=cidr,
        iface=iface,
        scan_interval=20,
        worker_count=3
    )

if __name__ == "__main__":
    asyncio.run(main())
