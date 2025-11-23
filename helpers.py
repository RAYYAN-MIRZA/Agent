import os
import json
import asyncio
import aioping

def save_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

async def ping_ip(ip: str, timeout=1000):
    """
    Ultra-fast async ICMP ping.
    Returns True if host responds.
    """
    try:
        await aioping.ping(ip, timeout=timeout / 1000.0)
        return True
    except TimeoutError:
        return False
    except Exception:
        return False
