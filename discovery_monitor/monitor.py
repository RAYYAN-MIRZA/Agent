import asyncio
import json
import logging
import time

from scapy.all import ARP, Ether, srp

from . import config
from .helpers import ping_ip, save_json_atomic

logger = logging.getLogger(__name__)

status_cache: dict = {}
cache_lock = asyncio.Lock()


def _hydrate_status_cache():
    if not config.STATUSES_JSON.exists():
        return
    try:
        with open(config.STATUSES_JSON, encoding="utf-8") as f:
            rows = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Could not hydrate statuses: %s", e)
        return
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        did = row.get("device_id")
        if not did:
            continue
        status_cache[did] = {
            "device_id": did,
            "mac": row.get("mac"),
            "current_ip": row.get("current_ip"),
            "status": row.get("status", "offline"),
            "reachability": row.get("reachability", "offline"),
            "last_seen": row.get("last_seen"),
            "consecutive_fail": int(row.get("consecutive_fail", 0)),
            "consecutive_ok": int(row.get("consecutive_ok", 0)),
        }


async def arp_fallback(ip, iface=None):
    timeout = config.ARP_FALLBACK_TIMEOUT

    def _arp():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=timeout, retry=0, iface=iface, verbose=0)
        return len(ans) > 0

    return await asyncio.to_thread(_arp)


async def probe_device(ip: str, iface):
    icmp_ok = await ping_ip(ip, timeout_ms=config.PING_TIMEOUT_MS)
    if icmp_ok:
        return True, "icmp"
    arp_ok = await arp_fallback(ip, iface=iface)
    if arp_ok:
        return True, "arp_only"
    return False, "offline"


def _persist_statuses_unlocked():
    out = list(status_cache.values())
    out.sort(key=lambda x: x.get("device_id", ""))
    save_json_atomic(config.STATUSES_JSON, out)


async def save_status(device_id: str, mac: str, ip: str, iface):
    ok, reach = await probe_device(ip, iface)
    async with cache_lock:
        entry = status_cache.get(
            device_id,
            {
                "device_id": device_id,
                "mac": mac,
                "current_ip": ip,
                "status": "offline",
                "reachability": "offline",
                "last_seen": None,
                "consecutive_fail": 0,
                "consecutive_ok": 0,
            },
        )
        entry["device_id"] = device_id
        entry["mac"] = mac
        entry["current_ip"] = ip

        if ok:
            entry["consecutive_ok"] = int(entry.get("consecutive_ok", 0)) + 1
            entry["consecutive_fail"] = 0
            if entry["consecutive_ok"] >= config.ONLINE_AFTER_OK:
                entry["status"] = "online"
                entry["reachability"] = reach
                entry["last_seen"] = time.time()
        else:
            entry["consecutive_fail"] = int(entry.get("consecutive_fail", 0)) + 1
            entry["consecutive_ok"] = 0
            if entry["consecutive_fail"] >= config.OFFLINE_AFTER_FAILS:
                entry["status"] = "offline"
                entry["reachability"] = "offline"

        status_cache[device_id] = entry


def _prune_status_to_inventory(device_ids: set[str]):
    for k in list(status_cache.keys()):
        if k not in device_ids:
            del status_cache[k]


async def run_monitor_loop(
    interval=None,
    ping_workers=None,
    iface=None,
    stop_event: asyncio.Event | None = None,
):
    interval = interval if interval is not None else config.PING_INTERVAL
    ping_workers = ping_workers if ping_workers is not None else config.PING_WORKERS
    ev = stop_event or asyncio.Event()
    sem = asyncio.Semaphore(ping_workers)

    _hydrate_status_cache()

    async def check_one(did: str, ip: str, mac: str):
        async with sem:
            await save_status(did, mac, ip, iface)

    while not ev.is_set():
        devices = []
        if config.DEVICES_JSON.exists():
            try:
                with open(config.DEVICES_JSON, encoding="utf-8") as f:
                    devices = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Could not read devices list: %s", e)
                devices = []
        if not isinstance(devices, list):
            devices = []

        device_ids = set()
        tasks = []
        for d in devices:
            if not isinstance(d, dict):
                continue
            did = d.get("device_id")
            ip = d.get("current_ip")
            mac = d.get("mac")
            if not did or not ip or not mac:
                continue
            device_ids.add(did)
            tasks.append(check_one(did, ip, mac))

        async with cache_lock:
            _prune_status_to_inventory(device_ids)
            _persist_statuses_unlocked()

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.exception("monitor batch error: %s", r)
            async with cache_lock:
                _persist_statuses_unlocked()

        try:
            await asyncio.wait_for(ev.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
