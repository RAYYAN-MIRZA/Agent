import asyncio
import json
import time

from scapy.all import ARP, Ether, srp

from . import config
from .helpers import ping_ip, save_json_atomic

queue: asyncio.Queue = asyncio.Queue()
status_cache: dict = {}
cache_lock = asyncio.Lock()


async def arp_fallback(ip, iface=None):
    loop = asyncio.get_event_loop()

    def _arp():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=0.5, retry=0, iface=iface, verbose=0)
        return len(ans) > 0

    return await loop.run_in_executor(None, _arp)


async def check_device(ip, mac, iface=None):
    alive = await ping_ip(ip, timeout=400)
    if not alive:
        alive = await arp_fallback(ip, iface=iface)
    return alive


async def save_status(ip, mac, alive):
    async with cache_lock:
        entry = status_cache.get(ip, {"ip": ip, "mac": mac, "lastSeen": None})
        entry["status"] = "online" if alive else "offline"
        if alive:
            entry["lastSeen"] = time.time()
        status_cache[ip] = entry
        save_json_atomic(config.STATUSES_JSON, list(status_cache.values()))


async def ping_worker(iface=None):
    while True:
        ip, mac = await queue.get()
        try:
            alive = await check_device(ip, mac, iface=iface)
            await save_status(ip, mac, alive)
        except Exception as e:
            print(f"[monitor] worker error: {e}")
        finally:
            queue.task_done()


async def run_monitor_loop(interval=None, ping_workers=None, iface=None):
    interval = interval if interval is not None else config.PING_INTERVAL
    ping_workers = ping_workers if ping_workers is not None else config.PING_WORKERS

    for _ in range(ping_workers):
        asyncio.create_task(ping_worker(iface=iface))

    while True:
        devices = []
        if config.IP_MAC_JSON.exists():
            try:
                with open(config.IP_MAC_JSON, "r", encoding="utf-8") as f:
                    devices = json.load(f)
            except Exception:
                devices = []

        for d in devices:
            queue.put_nowait((d["ip"], d["mac"]))

        await asyncio.sleep(interval)
