import asyncio, json, os, time

from dotenv import load_dotenv
from helpers import ping_ip, save_json_atomic
from scapy.all import ARP, Ether, srp

from redis.asyncio import Redis


load_dotenv()

AGENT_HUB_URL = os.getenv("AGENT_HUB_URL")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 20))
PING_WORKERS = int(os.getenv("PING_WORKERS", 50)) # Ping concurrency limit

IP_MAC_FILE = "data/ip_mac.json"
STATUSES_FILE = "data/statuses.json"
REDIS_HOST = os.getenv("REDIS_HOST", "192.168.100.34")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))


redis_client = Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True
)


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
    """Check if device is online."""
    alive = await ping_ip(ip, timeout=400)
    if not alive:
        alive = await arp_fallback(ip)

    return alive


# In-memory cache for real-time status
status_cache = {}
cache_lock = asyncio.Lock()


async def save_status(ip, mac, alive):
    """Update in-memory cache and write to disk."""
    async with cache_lock:
        entry = status_cache.get(ip, {"ip": ip, "mac": mac, "lastSeen": None})
        entry["status"] = "online" if alive else "offline"
        if alive:
            entry["lastSeen"] = time.time()  # update last online time only if alive
        status_cache[ip] = entry

        save_json_atomic(STATUSES_FILE, list(status_cache.values()))

        try:
            await publish_status_to_redis(ip, mac, alive)
        except Exception as e:
            print(f"[!] Redis publish error: {e}")


async def ping_worker():
    while True:
        ip, mac = await queue.get()
        try:
            alive = await check_device(ip, mac)
            await save_status(ip, mac, alive)
        except Exception as e:
            print(f"[!] Status worker error: {e}")
        finally:
            queue.task_done()


async def monitor_statuses(interval = 10):
    # Start ping workers
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

        for d in devices:
            queue.put_nowait((d["ip"], d["mac"]))

        await asyncio.sleep(interval)


async def publish_status_to_redis(ip, mac, alive):
    data = {
        "ip": ip,
        "mac": mac,
        "status": "online" if alive else "offline",
        "lastSeen": time.time() if alive else None
    }
    await redis_client.publish("device-status", json.dumps(data))
