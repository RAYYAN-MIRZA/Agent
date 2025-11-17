#!/usr/bin/env python3
"""
latestAgent3.py
Improved local discovery agent — no external connectivity
Features:
 - ARP scan (scapy)
 - passive mDNS listen
 - ICMP ping (subprocess) + async TCP probes
 - reverse DNS
 - vendor lookup with local cache (manuf)
 - merge devices by MAC (prefer) or IP
 - confidence scoring + decay
 - events.json and health.json maintained
 - FastAPI endpoints (/devices, /events, /health)
 - automatic port fallback if 8000 is taken
Requirements:
 - sudo (for ARP + raw sockets)
 - pip install fastapi uvicorn scapy manuf
Run:
 sudo -E $(which python) latestAgent3.py
"""
import os
import json
import time
import socket
import asyncio
import ipaddress
import subprocess
from datetime import datetime, timezone
from typing import Dict, Tuple, List

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

from scapy.all import ARP, Ether, srp, conf
from manuf import manuf

import sys
import platform

import requests

# ---------- Config ----------
API_URL_BASE = "http://192.168.100.34:5017/api/agent"
PREFERRED_PORT = 8000
SCAN_INTERVAL = 20            # seconds between automatic scans
MDNS_LISTEN_SEC = 6           # seconds for passive mDNS listen
OFFLINE_THRESHOLD = SCAN_INTERVAL * 3
COMMON_PORTS = [22, 80, 443, 445, 3389]   # tcp probes

DATA_DIR = "data"
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
HEALTH_FILE = os.path.join(DATA_DIR, "health.json")
VENDOR_CACHE_FILE = os.path.join(DATA_DIR, "vendor_cache.json")
os.makedirs(DATA_DIR, exist_ok=True)

conf.verb = 0  # scapy quiet
mac_parser = manuf.MacParser()

app = FastAPI()
# ---------- Ensure admin/root ----------
def ensure_admin():
    system = platform.system()
    if system == "Windows":
        import ctypes
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                # Relaunch script with admin rights (UAC prompt)
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join([f'"{arg}"' for arg in sys.argv]), None, 1
                )
                sys.exit(0)  # Exit current non-admin instance
        except Exception as e:
            print("Failed to elevate to admin:", e)
            sys.exit(1)
    else:  # Linux / macOS
        if os.geteuid() != 0:
            print("This script must be run as root. Use sudo.")
            sys.exit(1)

ensure_admin()

# ---------- Utilities ----------
def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def load_json_or(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return default
    return default

def save_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

def get_default_ipv4_interface_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def make_cidr_for_ip(ip: str) -> str:
    net = ipaddress.ip_network(ip + "/24", strict=False)
    return str(net)

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ---------- Vendor cache ----------
def get_vendor_cached(mac: str) -> str:
    if not mac:
        return ""
    mac = mac.upper()
    prefix = mac.replace(":", "")[:6]
    cache = load_json_or(VENDOR_CACHE_FILE, {})
    if prefix in cache:
        return cache[prefix]
    try:
        vendor = mac_parser.get_manuf(mac) or ""
    except Exception:
        vendor = ""
    cache[prefix] = vendor
    save_json_atomic(VENDOR_CACHE_FILE, cache)
    return vendor

# ---------- Device helpers ----------
def make_device_record(ip: str, mac: str, hostname: str = "", sources=None, ports=None, vendor: str = ""):
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "first_seen": now_ts(),
        "last_seen": now_ts(),
        "discovery_sources": sources or [],
        "open_ports": ports or [],
        "evidence": [],
        "confidence": 0,
        "status": "online"
    }

def compute_confidence_and_evidence(device: dict) -> dict:
    evidence = []
    weight = 0
    # ARP
    if "arp" in device.get("discovery_sources", []):
        evidence.append({"type":"arp","weight":40,"details":"MAC present in ARP scan"})
        weight += 40
    # mdns
    if "mdns" in device.get("discovery_sources", []):
        evidence.append({"type":"mdns","weight":30,"details":"mDNS observed"})
        weight += 30
    # ping
    if "ping" in device.get("discovery_sources", []):
        evidence.append({"type":"ping","weight":20,"details":"ICMP responded"})
        weight += 20
    # tcp ports
    if device.get("open_ports"):
        evidence.append({"type":"tcp_ports","weight":20,"details":f"Ports: {device['open_ports']}"})
        weight += 20
    # hostname
    if device.get("hostname"):
        evidence.append({"type":"hostname","weight":10,"details":f"Hostname: {device['hostname']}"})
        weight += 10
    device["evidence"] = evidence
    # confidence integer 0-100
    device["confidence"] = min(100, weight)
    return device

# ---------- ARP + mDNS ----------
def arp_scan(cidr: str, timeout=2) -> List[Tuple[str, str]]:
    # returns list of tuples (ip, mac)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    ans, _ = srp(packet, timeout=timeout, retry=1)
    results = []
    for _, r in ans:
        results.append((r.psrc, r.hwsrc))
    return results

def passive_mdns_collect(duration=6) -> List[str]:
    seen_ips = set()
    MCAST_GRP = "224.0.0.251"
    MCAST_PORT = 5353
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MCAST_PORT))
        mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)
        end = time.time() + duration
        while time.time() < end:
            try:
                _, addr = sock.recvfrom(4096)
                seen_ips.add(addr[0])
            except socket.timeout:
                continue
            except Exception:
                break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except:
            pass
    return list(seen_ips)

# ---------- Active probes ----------
def is_alive_ping(ip: str) -> bool:
    # non-blocking call via subprocess; small timeout
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", ip],
                                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except Exception:
        return False

async def tcp_probe(ip: str, port: int, timeout=0.4) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

# ---------- Persistence wrappers ----------
def load_devices() -> Dict[str, dict]:
    return load_json_or(DEVICES_FILE, {})

def save_devices(devices: Dict[str, dict]):
    save_json_atomic(DEVICES_FILE, devices)

def append_event(evt: dict):
    send_event_to_backend(evt)
    events = load_json_or(EVENTS_FILE, [])
    events.append(evt)
    save_json_atomic(EVENTS_FILE, events)

def save_health(h: dict):
    save_json_atomic(HEALTH_FILE, h)

# ---------- Merge & update logic ----------
def find_existing_key_by_mac_or_ip(devices: Dict[str, dict], mac: str, ip: str) -> str:
    mac_norm = (mac or "").lower()
    # prefer exact mac match
    if mac_norm:
        for k, v in devices.items():
            if v.get("mac", "").lower() == mac_norm:
                return k
    # fallback: match by IP
    for k, v in devices.items():
        if v.get("ip") == ip:
            return k
    return ""

async def enrich_and_update_for_entry(devices: Dict[str, dict], ipaddr: str, mac: str, mdns_seen: bool):
    # determine key (merge logic)
    key = find_existing_key_by_mac_or_ip(devices, mac, ipaddr) or (mac or ipaddr)
    rec = devices.get(key)
    hostname = resolve_hostname(ipaddr)
    vendor = get_vendor_cached(mac)
    # if new
    if not rec:
        rec = make_device_record(ipaddr, mac, hostname=hostname, sources=["arp"] if mac else ["arp"], vendor=vendor)
        if mdns_seen and "mdns" not in rec["discovery_sources"]:
            rec["discovery_sources"].append("mdns")
            rec["last_seen"] = now_ts()
        rec = compute_confidence_and_evidence(rec)
        devices[key] = rec
        append_event({"timestamp": now_ts(), "type": "device_added", "device_ip": ipaddr, "mac": mac})
    else:
        # update existing
        rec["ip"] = ipaddr or rec.get("ip", "")
        if mac and not rec.get("mac"):
            rec["mac"] = mac
        if "arp" not in rec["discovery_sources"]:
            rec["discovery_sources"].append("arp")
        if mdns_seen and "mdns" not in rec["discovery_sources"]:
            rec["discovery_sources"].append("mdns")
        rec["last_seen"] = now_ts()

    # active probes (run in executor to not block loop)
    loop = asyncio.get_event_loop()
    ping_ok = await loop.run_in_executor(None, is_alive_ping, ipaddr)
    if ping_ok and "ping" not in rec["discovery_sources"]:
        rec["discovery_sources"].append("ping")
    # tcp probes concurrent
    port_tasks = [tcp_probe(ipaddr, p) for p in COMMON_PORTS]
    try:
        port_results = await asyncio.gather(*port_tasks)
    except Exception:
        port_results = [False] * len(COMMON_PORTS)
    open_ports = [p for p, ok in zip(COMMON_PORTS, port_results) if ok]
    if open_ports:
        rec["open_ports"] = sorted(list(set(rec.get("open_ports", []) + open_ports)))

    # hostname enrichment if missing
    if not rec.get("hostname") and hostname:
        rec["hostname"] = hostname

    # vendor refresh
    if not rec.get("vendor"):
        rec["vendor"] = vendor

    # recompute confidence
    rec = compute_confidence_and_evidence(rec)
    devices[key] = rec
    return key

def apply_status_logic(devices: Dict[str, dict], seen_keys: set, offline_threshold: int = OFFLINE_THRESHOLD) -> Dict[str, dict]:
    now = datetime.now(timezone.utc)
    for key, dev in list(devices.items()):
        prev_status = dev.get("status", "offline")
        if key in seen_keys:
            dev["status"] = "online"
            dev["last_seen"] = now_ts()
        else:
            try:
                last_seen_dt = datetime.fromisoformat(dev["last_seen"])
                age = (now - last_seen_dt).total_seconds()
            except Exception:
                age = offline_threshold + 1
            if age > offline_threshold:
                dev["status"] = "offline"
                # confidence decay on long absence
                dev["confidence"] = max(0, dev.get("confidence", 0) - 20)
            elif age > (offline_threshold / 2):
                dev["status"] = "offline"
                dev["confidence"] = max(0, dev.get("confidence", 0) - 10)
            else:
                dev["status"] = "online"
        # emit event if changed
        if prev_status != dev["status"]:
            append_event({
                "timestamp": now_ts(),
                "type": "device_status_changed",
                "device_ip": dev.get("ip",""),
                "mac": dev.get("mac",""),
                "from": prev_status,
                "to": dev["status"]
            })
    return devices

# ---------- Main scan & periodic task ----------
async def do_scan_and_write():
    ip = get_default_ipv4_interface_ip()
    cidr = make_cidr_for_ip(ip)
    health = {"scan_time": now_ts(), "subnet": cidr, "devices_found": 0, "passive_packets_seen": 0}

    # passively collect mdns
    mdns_ips = passive_mdns_collect(MDNS_LISTEN_SEC)
    health["passive_packets_seen"] = len(mdns_ips)

    arp_results = arp_scan(cidr, timeout=2)
    devices = load_devices()  # dict keyed by key (mac/ip)
    seen_keys = set()

    # build a quick map of mdns presence
    mdns_set = set(mdns_ips)

    # spawn enrichment tasks per ARP result
    tasks = []
    for ipaddr, mac in arp_results:
        mdns_seen = ipaddr in mdns_set
        tasks.append(enrich_and_update_for_entry(devices, ipaddr, mac, mdns_seen))

    # if mdns-only IPs exist (not in ARP results), add them
    # process ARP tasks first
    if tasks:
        completed = await asyncio.gather(*tasks, return_exceptions=False)
        for k in completed:
            seen_keys.add(k)

    # process mdns-only discovered IPs
    for mip in mdns_ips:
        # skip if present already by ip
        existing_key = find_existing_key_by_mac_or_ip(devices, "", mip)
        if existing_key:
            # mark seen
            seen_keys.add(existing_key)
            rec = devices[existing_key]
            if "mdns" not in rec.get("discovery_sources", []):
                rec["discovery_sources"].append("mdns")
            rec["last_seen"] = now_ts()
            rec = compute_confidence_and_evidence(rec)
            devices[existing_key] = rec
        else:
            # create mdns-only entry
            hostname = resolve_hostname(mip)
            rec = make_device_record(mip, "", hostname=hostname, sources=["mdns"], vendor="")
            rec = compute_confidence_and_evidence(rec)
            key = mip
            devices[key] = rec
            seen_keys.add(key)
            append_event({"timestamp": now_ts(), "type": "device_added_mdns", "device_ip": mip, "mac": ""})

    # apply offline/online logic
    devices = apply_status_logic(devices, seen_keys, OFFLINE_THRESHOLD)

    # health metrics
    devices_list = list(devices.values())
    health["devices_found"] = len(devices_list)
    health["online_count"] = sum(1 for d in devices_list if d.get("status") == "online")
    health["offline_count"] = sum(1 for d in devices_list if d.get("status") == "offline")
    health["notes"] = "scan complete"

    save_devices(devices)
    save_health(health)

    send_full_snapshot()

    print(f"[{now_ts()}] Scan complete: {health['online_count']} online, {health['offline_count']} offline")
    return health

async def periodic_scanner():
    while True:
        try:
            await do_scan_and_write()
        except Exception as e:
            print("Scan error:", e)
        await asyncio.sleep(SCAN_INTERVAL)


def load_json_file(path):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def send_full_snapshot():
    snapshot = {
        "devices": load_json_file(DEVICES_FILE),
        "events": load_json_file(EVENTS_FILE),
        "health": load_json_file(HEALTH_FILE),
        "vendor_cache": load_json_file(VENDOR_CACHE_FILE)
    }
    try:
        r = requests.post(API_URL_BASE + '/send', json=snapshot, timeout=5)
        print(f"[📡] Sent snapshot: {r.status_code}")
    except Exception as e:
        print(f"[❌] Failed to send snapshot: {e}")

def send_event_to_backend(evt: dict):
    try:
        # simple POST, timeout short to not block
        requests.post(API_URL_BASE + '/event', json=evt, timeout=3)
        print(f"[📡] Event sent: {evt.get('type')}")
    except Exception as e:
        print(f"[⚠️] Failed to send event: {e}")

# ---------- FastAPI endpoints ----------
@app.on_event("startup")
async def startup_event():
    # start periodic scanner
    loop = asyncio.get_event_loop()
    loop.create_task(periodic_scanner())

@app.get("/devices")
async def get_devices():
    devices = load_devices()
    return JSONResponse(content=list(devices.values()))

@app.get("/events")
async def get_events():
    return JSONResponse(content=load_json_or(EVENTS_FILE, []))

@app.get("/health")
async def get_health():
    return JSONResponse(content=load_json_or(HEALTH_FILE, {}))

# ---------- Port utility ----------
def find_free_port(preferred: int = PREFERRED_PORT) -> int:
    # try preferred first
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", preferred))
        s.close()
        return preferred
    except OSError:
        try:
            s.close()
        except:
            pass
    # find ephemeral
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.bind(("0.0.0.0", 0))
    port = s2.getsockname()[1]
    s2.close()
    return port

# ---------- Run ----------
if __name__ == "__main__":
    selected_port = find_free_port(PREFERRED_PORT)
    print(f"Agent (local JSON mode) starting on port {selected_port} ... (run as root for best results)")
    uvicorn.run(app, host="0.0.0.0", port=selected_port, log_level="info")
