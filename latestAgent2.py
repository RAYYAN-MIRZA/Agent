#!/usr/bin/env python3
"""
agent_ws_status.py
Agent with device status tracking:
 - ARP scan (scapy)
 - passive mDNS listen
 - compute evidence + confidence
 - mark devices as online/offline with thresholds
 - write data/*.json (devices, events, health)
 - broadcast realtime updates via FastAPI WebSocket
"""

import os, time, json, asyncio, ipaddress, socket
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
import uvicorn

from scapy.all import ARP, Ether, srp, conf

# ----- Config -----
SCAN_INTERVAL = 20           # seconds between automatic scans
MDNS_LISTEN_SEC = 6          # seconds for passive mDNS listen
OFFLINE_THRESHOLD = SCAN_INTERVAL * 3  # seconds before marking offline

DATA_DIR = "data"
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
HEALTH_FILE = os.path.join(DATA_DIR, "health.json")
os.makedirs(DATA_DIR, exist_ok=True)

app = FastAPI()
clients = set()

# ----- Utilities -----
def now_ts():
    return datetime.now(timezone.utc).isoformat()

def ts_to_dt(ts):
    return datetime.fromisoformat(ts)

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

# ----- Device helpers -----
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
        "evidence": [],
        "confidence": 0,
        "status": "online"   # new field: online/offline
    }

def compute_confidence_and_evidence(device):
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
    device["evidence"] = evidence
    device["confidence"] = min(100, weight)
    return device

# ----- ARP + mDNS helpers -----
def get_default_ipv4_interface_ip():
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
    net = ipaddress.ip_network(ip + "/24", strict=False)
    return str(net)

def arp_scan(cidr, timeout=2):
    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    ans, _ = srp(packet, timeout=timeout, retry=1)
    results = []
    for _, r in ans:
        ip = r.psrc
        mac = r.hwsrc
        results.append((ip, mac))
    return results

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
        pass
    finally:
        try:
            sock.close()
        except:
            pass
    return list(seen_ips)

# ----- Persistence -----
def load_devices():
    # stored as dict keyed by "key" (prefer mac if present else ip)
    return load_json_or(DEVICES_FILE, {})

def save_devices(devices):
    save_json_atomic(DEVICES_FILE, devices)

def append_event(evt):
    events = load_json_or(EVENTS_FILE, [])
    events.append(evt)
    save_json_atomic(EVENTS_FILE, events)

def save_health(h):
    save_json_atomic(HEALTH_FILE, h)

# ----- Broadcasting -----
async def broadcast_update(payload):
    disconnected = []
    for ws in list(clients):
        try:
            await ws.send_json(payload)
        except Exception:
            disconnected.append(ws)
    for d in disconnected:
        clients.discard(d)

# ----- Status update logic -----
def apply_status_logic(devices_dict, seen_keys, offline_threshold=OFFLINE_THRESHOLD):
    """Update status for each device and create events for status changes.
       devices_dict: {key: device_record}
       seen_keys: set(keys seen this scan)
    """
    now = datetime.now(timezone.utc)
    for key, dev in list(devices_dict.items()):
        prev_status = dev.get("status", "offline")
        # if seen now -> online
        if key in seen_keys:
            dev["status"] = "online"
            dev["last_seen"] = now_ts()
        else:
            # compute age since last_seen
            try:
                last_seen_dt = ts_to_dt(dev["last_seen"])
                age = (now - last_seen_dt).total_seconds()
            except Exception:
                age = offline_threshold + 1
            if age > offline_threshold:
                dev["status"] = "offline"
            else:
                # still consider it online (recently seen) but not in this scan:
                dev["status"] = "offline" if age > (offline_threshold/2) else "online"
        # if status changed, append event
        if prev_status != dev["status"]:
            append_event({
                "timestamp": now_ts(),
                "type": "device_status_changed",
                "device_ip": dev.get("ip",""),
                "mac": dev.get("mac",""),
                "from": prev_status,
                "to": dev["status"]
            })
    return devices_dict

# ----- Main scan & broadcast -----
async def do_scan_and_broadcast():
    ip = get_default_ipv4_interface_ip()
    cidr = make_cidr_for_ip(ip)
    health = {"scan_time": now_ts(), "subnet": cidr, "devices_found": 0, "passive_packets_seen": 0}

    mdns_ips = passive_mdns_collect(MDNS_LISTEN_SEC)
    health["passive_packets_seen"] = len(mdns_ips)

    arp_results = arp_scan(cidr, timeout=2)

    devices = load_devices()  # dict keyed by mac or ip
    seen_keys = set()

    # process arp results
    for ipaddr, mac in arp_results:
        key = mac if mac else ipaddr
        seen_keys.add(key)
        rec = devices.get(key)
        if not rec:
            rec = make_device_record(ipaddr, mac, hostname="", sources=["arp"])
            rec = compute_confidence_and_evidence(rec)
            devices[key] = rec
            append_event({"timestamp": now_ts(), "type": "device_added", "device_ip": ipaddr, "mac": mac})
        else:
            # update existing
            rec["ip"] = ipaddr
            if "arp" not in rec["discovery_sources"]:
                rec["discovery_sources"].append("arp")
            rec = compute_confidence_and_evidence(rec)
            rec["last_seen"] = now_ts()
            devices[key] = rec

    # process mdns-only IPs
    for mip in mdns_ips:
        # find if exists by ip
        found_key = None
        for k, r in devices.items():
            if r.get("ip") == mip:
                found_key = k
                break
        if found_key:
            rec = devices[found_key]
            if "mdns" not in rec["discovery_sources"]:
                rec["discovery_sources"].append("mdns")
            rec["last_seen"] = now_ts()
            rec = compute_confidence_and_evidence(rec)
            devices[found_key] = rec
            seen_keys.add(found_key)
        else:
            # create mdns-only entry, key by ip
            key = mip
            rec = make_device_record(mip, mac="", hostname="", sources=["mdns"])
            rec = compute_confidence_and_evidence(rec)
            devices[key] = rec
            seen_keys.add(key)
            append_event({"timestamp": now_ts(), "type": "device_added_mdns", "device_ip": mip, "mac": ""})

    # apply status determination logic and produce events for changes
    devices = apply_status_logic(devices, seen_keys, OFFLINE_THRESHOLD)

    # health metrics
    devices_list = list(devices.values())
    health["devices_found"] = len(devices_list)
    health["online_count"] = sum(1 for d in devices_list if d.get("status") == "online")
    health["offline_count"] = sum(1 for d in devices_list if d.get("status") == "offline")
    health["notes"] = "scan complete"

    save_devices(devices)
    save_health(health)

    payload = {"type":"scan_result", "scan_time": now_ts(), "subnet": cidr, "devices": devices_list, "health": health}
    await broadcast_update(payload)

# ----- Periodic scanner -----
async def periodic_scanner():
    while True:
        try:
            await do_scan_and_broadcast()
        except Exception as e:
            print("Scan error:", e)
        await asyncio.sleep(SCAN_INTERVAL)

# ----- FastAPI endpoints -----
@app.on_event("startup")
async def startup_event():
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

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        devices = load_devices()
        await ws.send_json({"type":"initial","devices": list(devices.values()), "time": now_ts()})
        while True:
            data = await ws.receive_text()
            if data == "scan_now":
                await do_scan_and_broadcast()
    except WebSocketDisconnect:
        clients.discard(ws)
    except Exception:
        clients.discard(ws)

# ----- Run -----
if __name__ == "__main__":
    print("Agent with status tracking starting (run as root for best results)")
    uvicorn.run(app, host="0.0.0.0", port=8000)
