# main.py
import asyncio
from device_discovery import start_discovery

async def main():
    # You can adjust CIDR or interface if needed
    await start_discovery(cidr="192.168.100.0/24", scan_interval=20, worker_count=3)

if __name__ == "__main__":
    asyncio.run(main())
