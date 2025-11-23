import asyncio
import json
import os
import time
import ipaddress
from scapy.all import ARP, Ether, srp

DATA_DIR = "data"
IP_MAC_FILE = os.path.join(DATA_DIR, "ip_mac.json")
NMAP_FILE = os.path.join(DATA_DIR, "nmap_results.json")
os.makedirs(DATA_DIR, exist_ok=True)

file_lock = asyncio.Lock()

# Queue 1 → fast discovery results
queue = asyncio.Queue()

# Queue 2 → slow Nmap scanning
nmap_queue = asyncio.Queue()

# Nmap concurrency limiter
NMAP_SEMAPHORE = asyncio.Semaphore(3)


def save_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


async def write_ip_mac(ip, mac):
    async with file_lock:
        data = []
        if os.path.exists(IP_MAC_FILE):
            try:
                with open(IP_MAC_FILE, "r") as f:
                    data = json.load(f)
            except:
                pass

        if not any(d.get("ip") == ip for d in data):
            data.append({"ip": ip, "mac": mac, "discoveredOn": time.time()})
            save_json_atomic(IP_MAC_FILE, data)


async def run_nmap(ip):
    loop = asyncio.get_event_loop()
    async with NMAP_SEMAPHORE:
        def _run():
            import subprocess
            cmd = ["nmap", "-O", "-A", "-T4", ip]
            try:
                return subprocess.check_output(cmd, universal_newlines=True)
            except Exception as e:
                return f"Nmap failed: {e}"

        result = await loop.run_in_executor(None, _run)

        async with file_lock:
            data = []
            if os.path.exists(NMAP_FILE):
                try:
                    with open(NMAP_FILE, "r") as f:
                        data = json.load(f)
                except:
                    pass

            # Avoid duplicate Nmap results
            existing = next((d for d in data if d["ip"] == ip), None)
            if existing is None:
                data.append({
                    "ip": ip,
                    "nmap_output": result,
                    "scannedOn": time.time()
                })
                save_json_atomic(NMAP_FILE, data)


async def handle_discovered_device(ip, mac):
    # Store device entry
    await write_ip_mac(ip, mac)

    # Send IP to Nmap queue → fully decoupled, non-blocking
    nmap_queue.put_nowait(ip)


async def arp_ping(ip, iface=None, timeout=1):
    """Simple ARP ping executed using threads."""
    loop = asyncio.get_event_loop()

    def sync_ping():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=timeout, retry=0, iface=iface, verbose=0)
        return [(r.psrc, r.hwsrc) for _, r in ans]

    return await loop.run_in_executor(None, sync_ping)


async def arp_scan_fast(cidr: str, iface=None, concurrency=50):
    subnet = ipaddress.IPv4Network(cidr, strict=False)
    tasks = [arp_ping(str(ip), iface) for ip in subnet.hosts()]

    # Run ARP pings in chunks
    for chunk in [tasks[i:i+concurrency] for i in range(0, len(tasks), concurrency)]:
        results = await asyncio.gather(*chunk)
        for res in results:
            for ip, mac in res:
                queue.put_nowait((ip, mac))


async def worker():
    """Fast worker for processing discovered ARP results."""
    while True:
        ip, mac = await queue.get()
        try:
            await handle_discovered_device(ip, mac)
        except Exception as e:
            print(f"[!] Worker error for {ip}: {e}")
        finally:
            queue.task_done()


async def nmap_worker():
    """Slow worker dedicated to Nmap scanning."""
    while True:
        ip = await nmap_queue.get()
        try:
            await run_nmap(ip)
        except Exception as e:
            print(f"[!] Nmap worker error for {ip}: {e}")
        finally:
            nmap_queue.task_done()


async def start_discovery(cidr="192.168.100.0/24", iface=None, scan_interval=20, worker_count=3):
    # Start fast workers
    for _ in range(worker_count):
        asyncio.create_task(worker())

    # Start Nmap workers (3 parallel scans)
    for _ in range(3):
        asyncio.create_task(nmap_worker())

    # Main ARP scanning loop
    while True:
        await arp_scan_fast(cidr, iface)
        await asyncio.sleep(scan_interval)
