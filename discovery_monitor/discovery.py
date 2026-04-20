import asyncio
import json
import logging
import time
import ipaddress

from scapy.all import ARP, Ether, srp

from . import config
from .identity import normalize_mac
from .helpers import nmap_xml_to_json, save_json_atomic

logger = logging.getLogger(__name__)

file_lock = asyncio.Lock()
queue: asyncio.Queue = asyncio.Queue()
nmap_queue: asyncio.Queue = asyncio.Queue()
NMAP_SEMAPHORE = asyncio.Semaphore(config.NMAP_PARALLEL)


def _load_devices_list() -> list[dict]:
    path = config.DEVICES_JSON
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Could not read %s: %s", path, e)
        return []


def _prune_stale(devices: list[dict], now: float) -> list[dict]:
    sec = config.DEVICE_STALE_SECONDS
    if sec <= 0:
        return devices
    return [d for d in devices if now - float(d.get("last_seen", 0)) <= sec]


async def upsert_device(ip: str, mac_raw: str) -> str | None:
    """Merge by MAC; update current_ip and last_seen. Returns device_id or None."""
    mac = normalize_mac(mac_raw)
    if not mac:
        return None
    device_id = mac
    now = time.time()
    async with file_lock:
        devices = _load_devices_list()
        devices = _prune_stale(devices, now)
        found = None
        for d in devices:
            if d.get("device_id") == device_id or normalize_mac(d.get("mac")) == device_id:
                found = d
                break
        if found:
            found["current_ip"] = ip
            found["mac"] = mac
            found["last_seen"] = now
        else:
            devices.append(
                {
                    "device_id": device_id,
                    "mac": mac,
                    "current_ip": ip,
                    "first_seen": now,
                    "last_seen": now,
                }
            )
        devices.sort(key=lambda x: x.get("device_id", ""))
        save_json_atomic(config.DEVICES_JSON, devices)
    return device_id


async def run_nmap(device_id: str, scanned_ip: str):
    async with NMAP_SEMAPHORE:

        def _run():
            import subprocess

            cmd = ["nmap", "-O", "-A", "-oX", "-", scanned_ip]
            try:
                return subprocess.check_output(cmd, universal_newlines=True)
            except Exception as e:
                return f"<nmap_error>{e}</nmap_error>"

        result_raw = await asyncio.to_thread(_run)
        result_json = nmap_xml_to_json(result_raw)

        async with file_lock:
            data = []
            if config.NMAP_JSON.exists():
                try:
                    with open(config.NMAP_JSON, encoding="utf-8") as f:
                        data = json.load(f)
                except (json.JSONDecodeError, OSError):
                    data = []
            if not isinstance(data, list):
                data = []

            by_id = {}
            for row in data:
                if isinstance(row, dict) and row.get("device_id"):
                    by_id[row["device_id"]] = row
            by_id[device_id] = {
                "device_id": device_id,
                "scanned_ip": scanned_ip,
                "nmap_output_raw": result_raw,
                "nmap_output_json": result_json,
                "scannedOn": time.time(),
            }
            merged = sorted(by_id.values(), key=lambda x: x.get("device_id", ""))
            save_json_atomic(config.NMAP_JSON, merged)


async def handle_discovered_device(ip: str, mac: str):
    device_id = await upsert_device(ip, mac)
    if not device_id:
        return
    if config.NMAP_ENABLED:
        nmap_queue.put_nowait((device_id, ip))


async def arp_ping(ip: str, iface=None, timeout: float | None = None):
    t = timeout if timeout is not None else config.ARP_SCAN_TIMEOUT

    def sync_ping():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=t, retry=0, iface=iface, verbose=0)
        return [(r.psrc, r.hwsrc) for _, r in ans]

    return await asyncio.to_thread(sync_ping)


async def arp_scan_fast(cidr: str, iface=None, concurrency=None, stop_event: asyncio.Event | None = None):
    concurrency = concurrency if concurrency is not None else config.ARP_CONCURRENCY
    subnet = ipaddress.IPv4Network(cidr, strict=False)
    hosts = list(subnet.hosts())
    for i in range(0, len(hosts), concurrency):
        if stop_event and stop_event.is_set():
            break
        chunk = hosts[i : i + concurrency]
        tasks = [arp_ping(str(h), iface) for h in chunk]
        results = await asyncio.gather(*tasks)
        for res in results:
            for ip, mac in res:
                queue.put_nowait((ip, mac))


async def worker(stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            ip, mac = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        try:
            await handle_discovered_device(ip, mac)
        except Exception as e:
            logger.exception("discovery worker error for %s: %s", ip, e)
        finally:
            queue.task_done()


async def nmap_worker(stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            item = await asyncio.wait_for(nmap_queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        device_id, ip = item
        try:
            await run_nmap(device_id, ip)
        except Exception as e:
            logger.exception("nmap error for %s %s: %s", device_id, ip, e)
        finally:
            nmap_queue.task_done()


async def run_discovery_loop(
    cidr: str,
    iface=None,
    scan_interval=None,
    worker_count=None,
    stop_event: asyncio.Event | None = None,
):
    scan_interval = scan_interval if scan_interval is not None else config.SCAN_INTERVAL
    worker_count = worker_count if worker_count is not None else config.DISCOVERY_WORKERS
    ev = stop_event or asyncio.Event()

    subtasks: list[asyncio.Task] = []
    for _ in range(worker_count):
        subtasks.append(asyncio.create_task(worker(ev), name="discovery-worker"))

    if config.NMAP_ENABLED:
        for _ in range(config.NMAP_PARALLEL):
            subtasks.append(asyncio.create_task(nmap_worker(ev), name="nmap-worker"))

    try:
        while not ev.is_set():
            await arp_scan_fast(cidr, iface, stop_event=ev)
            if ev.is_set():
                break
            try:
                await asyncio.wait_for(ev.wait(), timeout=scan_interval)
            except asyncio.TimeoutError:
                pass
    finally:
        for t in subtasks:
            t.cancel()
        await asyncio.gather(*subtasks, return_exceptions=True)
