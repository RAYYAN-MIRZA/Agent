# main.py
import asyncio
from device_discovery import start_discovery
from status_monitor import monitor_statuses

async def main():
    # Start status monitor in background
    asyncio.create_task(monitor_statuses())

    # Start device discovery
    await start_discovery(
        cidr="192.168.100.0/24",
        scan_interval=20,
        worker_count=3
    )

if __name__ == "__main__":
    asyncio.run(main())
