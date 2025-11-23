# status_monitor.py
import asyncio, json, os, time
from helpers import save_json_atomic, ping_ip

IP_MAC_FILE = "data/ip_mac.json"
STATUSES_FILE = "data/statuses.json"

async def check_status(ip, mac):
    is_online = ping_ip(ip)
    return {
        "ip": ip,
        "mac": mac,
        "status": "online" if is_online else "offline",
        "lastSeen": time.time()
    }

async def monitor_statuses():
    while True:
        devices = []
        if os.path.exists(IP_MAC_FILE):
            try:
                with open(IP_MAC_FILE, "r") as f:
                    devices = json.load(f)
            except:
                devices = []

        tasks = [check_status(d["ip"], d["mac"]) for d in devices]
        results = await asyncio.gather(*tasks)

        save_json_atomic(STATUSES_FILE, results)

        await asyncio.sleep(10)
