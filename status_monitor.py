# status_monitor.py
import asyncio, json, os, time, subprocess

IP_MAC_FILE = "data/ip_mac.json"
STATUSES_FILE = "data/statuses.json"

def save_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

async def check_status(ip, mac):
    status = "offline"
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", ip],
                                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        status = "online"
    except:
        status = "offline"
    return {"ip": ip, "mac": mac, "status": status, "lastSeen": time.time()}

async def monitor_statuses():
    while True:
        devices = []
        if os.path.exists(IP_MAC_FILE):
            try:
                with open(IP_MAC_FILE, "r") as f:
                    devices = json.load(f)
            except:
                pass

        tasks = [check_status(d["ip"], d["mac"]) for d in devices]
        results = await asyncio.gather(*tasks)

        save_json_atomic(STATUSES_FILE, results)
        await asyncio.sleep(10)  # configurable interval
