#!/usr/bin/env python3
"""
agent_ws.py
Minimal LAN agent:
 - ARP scan using scapy (requires root)
 - Short passive mDNS listen (multicast)
 - Compute evidence + confidence
 - Save JSON files under ./data/
 - Broadcast realtime updates to connected WebSocket clients via FastAPI
"""

import os, time, json, asyncio, ipaddress, socket, threading
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn

# scapy imports
from scapy.all import ARP, Ether, srp, conf

# config
SCAN_INTERVAL = 20        # seconds between automatic scans (short for demo)
MDNS_LISTEN_SEC = 6       # seconds to passively listen for mDNS
DATA_DIR = "data"
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
HEALTH_FILE = os.path.join(DATA_DIR, "health.json")

# ensure data dir
os.makedirs(DATA_DIR, exist_ok=True)

app = FastAPI()
clients = set()  # connected websocket clients

# --- Utility functions ----------------------------------------------------
def now_ts():
    return datetime.now(timezone.utc).isoformat()

def save_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

def load_json_or(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return default
    return default

# --- Device model helpers -------------------------------------------------
def make_device_record(ip, mac, hostname="", sources=None, ports=None, vendor=""):
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "first_seen": now_ts(),
        "last_seen": now_ts(),
        "discovery_sources": sources or [],
        "open_ports": ports or [],
        "evidence": [],   # filled later
        "confidence": 0
    }

def compute_confidence_and_evidence(device):
    # very simple weighted scheme for demo
    evidence = []
    weight = 0
    if "arp" in device["discovery_sources"]:
        evidence.append({"type":"arp","weight":40,"details":"MAC present in ARP/ARP scan"})
        weight += 40
    if "mdns" in device["discovery_sources"]:
        evidence.append({"type":"mdns","weight":30,"details":"mDNS service observed"})
        weight += 30
    if device.get("open_ports"):
        evidence.append({"type":"tcp_ports","weight":20,"details":f"Ports: {device['open_ports']}"})
        weight += 20
    if device.get("hostname"):
        evidence.append({"type":"hostname","weight":10,"details":f"Hostname: {device['hostname']}"})
        weight += 10
    # cap 100
    device["evidence"] = evidence
    device["confidence"] = min(100, weight)
    return device

# --- ARP Scanner (scapy) --------------------------------------------------
def get_default_ipv4_interface_ip():
    # attempt to get primary interface ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def make_cidr_for_ip(ip):
    # assume /24 for most home networks (can be improved)
    net = ipaddress.ip_network(ip + "/24", strict=False)
    return str(net)

def arp_scan(cidr, timeout=2):
    """Return list of tuples (ip, mac) found via ARP using scapy srp"""
    # conf.verb = 0 to silence scapy output
    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    ans, _ = srp(packet, timeout=timeout, retry=1)
    results = []
    for _, r in ans:
        ip = r.psrc
        mac = r.hwsrc
        results.append((ip, mac))
    return results

# --- Passive mDNS listener (multicast UDP on 5353) -------------------------
def passive_mdns_collect(duration=6):
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
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                seen_ips.add(src_ip)
            except socket.timeout:
                continue
            except Exception:
                break
    except Exception:
        # likely lack of privilege or no mDNS traffic
        pass
    finally:
        try:
            sock.close()
        except:
            pass
    return list(seen_ips)

# --- Persistence helpers --------------------------------------------------
def load_devices():
    return load_json_or(DEVICES_FILE, {})

def save_devices(devices):
    save_json_atomic(DEVICES_FILE, devices)

def append_event(evt):
    events = load_json_or(EVENTS_FILE, [])
    events.append(evt)
    save_json_atomic(EVENTS_FILE, events)

def save_health(h):
    save_json_atomic(HEALTH_FILE, h)

# --- Broadcast helpers ---------------------------------------------------
async def broadcast_update(payload):
    disconnected = []
    for ws in list(clients):
        try:
            await ws.send_json(payload)
        except Exception:
            disconnected.append(ws)
    for d in disconnected:
        clients.discard(d)

# --- Main scan routine ---------------------------------------------------
async def do_scan_and_broadcast():
    # determine subnet
    ip = get_default_ipv4_interface_ip()
    cidr = make_cidr_for_ip(ip)
    health = {"scan_time": now_ts(), "subnet": cidr, "devices_found": 0, "passive_packets_seen_30s": 0}
    # passive mdns
    mdns_ips = passive_mdns_collect(MDNS_LISTEN_SEC)
    health["passive_packets_seen_30s"] = len(mdns_ips)
    # active arp scan
    arp_results = arp_scan(cidr, timeout=2)
    devices = load_devices()  # dict keyed by mac or ip
    seen_now = set()

    for ipaddr, mac in arp_results:
        seen_now.add(mac)
        key = mac or ipaddr
        # get or create record
        rec = devices.get(key)
        if not rec:
            rec = make_device_record(ipaddr, mac, hostname="", sources=["arp"])
            rec = compute_confidence_and_evidence(rec)
            devices[key] = rec
            append_event({"timestamp": now_ts(), "type": "device_added", "device_ip": ipaddr, "mac": mac})
        else:
            # update
            rec["ip"] = ipaddr
            rec["last_seen"] = now_ts()
            if "arp" not in rec["discovery_sources"]:
                rec["discovery_sources"].append("arp")
            rec = compute_confidence_and_evidence(rec)
            devices[key] = rec

    # incorporate mdns-only discoveries (IPs seen in mdns but not in arp)
    for mip in mdns_ips:
        # see if known
        found = False
        for k, r in devices.items():
            if r.get("ip") == mip:
                found = True
                if "mdns" not in r["discovery_sources"]:
                    r["discovery_sources"].append("mdns")
                    r["last_seen"] = now_ts()
                    r = compute_confidence_and_evidence(r)
                    devices[k] = r
        if not found:
            # new mdns-only device (low confidence)
            rec = make_device_record(mip, mac="", hostname="", sources=["mdns"])
            rec = compute_confidence_and_evidence(rec)
            devices[mip] = rec
            append_event({"timestamp": now_ts(), "type": "device_added_mdns", "device_ip": mip, "mac": ""})

    # mark removed devices if not seen in this scan (very simple)
    removed = []
    for k, r in list(devices.items()):
        # consider removed if last_seen older than 2 * SCAN_INTERVAL
        last_seen = datetime.fromisoformat(r["last_seen"])
        age = (datetime.now(timezone.utc) - last_seen).total_seconds()
        if age > (SCAN_INTERVAL * 3) and r.get("ip") not in [ip for ip, _ in arp_results]:
            removed.append((k, r))
            devices.pop(k, None)
            append_event({"timestamp": now_ts(), "type": "device_removed", "device_ip": r.get("ip"), "mac": r.get("mac","")})

    # finalize devices and health
    devices_list = list(devices.values())
    health["devices_found"] = len(devices_list)
    health["notes"] = "scan complete"
    # save
    save_devices({k: v for k, v in devices.items()})
    save_health(health)

    # broadcast to clients
    payload = {"type":"scan_result", "scan_time": now_ts(), "subnet": cidr, "devices": devices_list, "health": health}
    await broadcast_update(payload)

# --- Background loop to scan periodically --------------------------------
async def periodic_scanner():
    while True:
        try:
            await do_scan_and_broadcast()
        except Exception as e:
            print("Scan error:", e)
        await asyncio.sleep(SCAN_INTERVAL)

# --- FastAPI endpoints ---------------------------------------------------
@app.on_event("startup")
async def startup_event():
    # start periodic scanner background task
    loop = asyncio.get_event_loop()
    loop.create_task(periodic_scanner())

@app.get("/devices")
async def get_devices():
    devices = load_devices()
    # return as list
    return JSONResponse(content=list(devices.values()))

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        # send initial snapshot
        devices = load_devices()
        await ws.send_json({"type":"initial","devices": list(devices.values()), "time": now_ts()})
        while True:
            # keep connection alive; accept pings from client too
            data = await ws.receive_text()
            # if client asks for immediate scan
            if data == "scan_now":
                await do_scan_and_broadcast()
    except WebSocketDisconnect:
        clients.discard(ws)
    except Exception:
        clients.discard(ws)

# --- run server -----------------------------------------------------------
if __name__ == "__main__":
    print("Starting agent - websock realtime demo")
    print("Run as root for best ARP and mDNS results")
    uvicorn.run(app, host="0.0.0.0", port=8000)
