import asyncio
from network_info import get_network_info
from device_discovery import start_discovery
from status_monitor import monitor_statuses

async def main():
    networks = get_network_info()

    if not networks:
        print("[-] No valid network interface found!")
        return

    # Adjust the network index if required
    cidr = networks[1]["cidr"]
    iface = networks[1]["interface"]

    print(f"[+] Using subnet {cidr} on interface {iface}")

    # Status monitor (pings every 10s)
    asyncio.create_task(monitor_statuses())

    # Start ARP + Nmap discovery system
    await start_discovery(
        cidr=cidr,
        iface=iface,
        scan_interval=20,
        worker_count=3
    )

if __name__ == "__main__":
    asyncio.run(main())
