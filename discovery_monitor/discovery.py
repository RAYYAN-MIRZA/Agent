import asyncio
import json
import time
import ipaddress

from scapy.all import ARP, Ether, srp

from . import config
from .helpers import nmap_xml_to_json, save_json_atomic

file_lock = asyncio.Lock()
queue: asyncio.Queue = asyncio.Queue()
nmap_queue: asyncio.Queue = asyncio.Queue()
NMAP_SEMAPHORE = asyncio.Semaphore(config.NMAP_PARALLEL)


async def write_ip_mac(ip, mac):
    async with file_lock:
        data = []
        if config.IP_MAC_JSON.exists():
            try:
                with open(config.IP_MAC_JSON, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                pass

        if not any(d.get("ip") == ip for d in data):
            data.append({"ip": ip, "mac": mac, "discoveredOn": time.time()})
            save_json_atomic(config.IP_MAC_JSON, data)


async def run_nmap(ip):
    loop = asyncio.get_event_loop()
    async with NMAP_SEMAPHORE:
        def _run():
            import subprocess

            cmd = ["nmap", "-O", "-A", "-oX", "-", ip]
            try:
                return subprocess.check_output(cmd, universal_newlines=True)
            except Exception as e:
                return f"<nmap_error>{e}</nmap_error>"

        result_raw = await loop.run_in_executor(None, _run)
        result_json = nmap_xml_to_json(result_raw)

        async with file_lock:
            data = []
            if config.NMAP_JSON.exists():
                try:
                    with open(config.NMAP_JSON, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    pass

            existing = next((d for d in data if d.get("ip") == ip), None)
            if existing is None:
                data.append(
                    {
                        "ip": ip,
                        "nmap_output_raw": result_raw,
                        "nmap_output_json": result_json,
                        "scannedOn": time.time(),
                    }
                )
                save_json_atomic(config.NMAP_JSON, data)


async def handle_discovered_device(ip, mac):
    await write_ip_mac(ip, mac)
    nmap_queue.put_nowait(ip)


async def arp_ping(ip, iface=None, timeout=1):
    loop = asyncio.get_event_loop()

    def sync_ping():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=timeout, retry=0, iface=iface, verbose=0)
        return [(r.psrc, r.hwsrc) for _, r in ans]

    return await loop.run_in_executor(None, sync_ping)


async def arp_scan_fast(cidr: str, iface=None, concurrency=None):
    concurrency = concurrency if concurrency is not None else config.ARP_CONCURRENCY
    subnet = ipaddress.IPv4Network(cidr, strict=False)
    tasks = [arp_ping(str(ip), iface) for ip in subnet.hosts()]

    for i in range(0, len(tasks), concurrency):
        chunk = tasks[i : i + concurrency]
        results = await asyncio.gather(*chunk)
        for res in results:
            for ip, mac in res:
                queue.put_nowait((ip, mac))


async def worker():
    while True:
        ip, mac = await queue.get()
        try:
            await handle_discovered_device(ip, mac)
        except Exception as e:
            print(f"[discovery] worker error for {ip}: {e}")
        finally:
            queue.task_done()


async def nmap_worker():
    while True:
        ip = await nmap_queue.get()
        try:
            await run_nmap(ip)
        except Exception as e:
            print(f"[discovery] nmap error for {ip}: {e}")
        finally:
            nmap_queue.task_done()


async def run_discovery_loop(cidr: str, iface=None, scan_interval=None, worker_count=None):
    scan_interval = scan_interval if scan_interval is not None else config.SCAN_INTERVAL
    worker_count = worker_count if worker_count is not None else config.DISCOVERY_WORKERS

    for _ in range(worker_count):
        asyncio.create_task(worker())

    for _ in range(config.NMAP_PARALLEL):
        asyncio.create_task(nmap_worker())

    while True:
        await arp_scan_fast(cidr, iface)
        await asyncio.sleep(scan_interval)
