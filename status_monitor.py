import asyncio, json, os, time
from helpers import ping_ip, save_json_atomic
from scapy.all import ARP, Ether, srp

IP_MAC_FILE = "data/ip_mac.json"
STATUSES_FILE = "data/statuses.json"

# Ping concurrency limit
PING_WORKERS = 50
queue = asyncio.Queue()


async def arp_fallback(ip, iface=None):
    """Fallback check using ARP to confirm if host is alive."""
    loop = asyncio.get_event_loop()

    def _arp():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=0.5, retry=0, verbose=0)
        return len(ans) > 0

    return await loop.run_in_executor(None, _arp)


async def check_device(ip, mac):
    # ICMP fast ping
    alive = await ping_ip(ip, timeout=400)

    # ARP fallback if ICMP fails
    if not alive:
        alive = await arp_fallback(ip)

    return {
        "ip": ip,
        "mac": mac,
        "status": "online" if alive else "offline",
        "lastSeen": time.time(),
    }


async def ping_worker():
    """Processes device pings in parallel."""
    while True:
        ip, mac = await queue.get()
        try:
            result = await check_device(ip, mac)

            # Save immediately (non-blocking)
            await save_status(result)

        except Exception as e:
            print(f"[!] Status worker error: {e}")
        finally:
            queue.task_done()


# In-memory cache for real-time updates
status_cache = {}
cache_lock = asyncio.Lock()


async def save_status(entry):
    """Maintain in-memory cache and flush to disk."""
    async with cache_lock:
        status_cache[entry["ip"]] = entry
        save_json_atomic(STATUSES_FILE, list(status_cache.values()))


async def monitor_statuses():
    """Main loop"""
    # Start workers
    for _ in range(PING_WORKERS):
        asyncio.create_task(ping_worker())

    while True:
        devices = []
        if os.path.exists(IP_MAC_FILE):
            try:
                with open(IP_MAC_FILE, "r") as f:
                    devices = json.load(f)
            except:
                devices = []

        # Push devices into the ping queue
        for d in devices:
            queue.put_nowait((d["ip"], d["mac"]))

        await asyncio.sleep(1)  # Real-time update
