import os
import json
import asyncio
import aioping
import aiohttp

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
    
async def send_network_info(url, network_data, max_retries=5, retry_interval=10):
    """
    Sends network info to the backend via POST.
    Retries if backend does not return success.
    """
    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for attempt in range(1, max_retries + 1):
            try:
                async with session.post(url, json=network_data) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status}")

                    result = await resp.json()

                    # Check backend response
                    if result.get("success") is True:
                        is_new = result.get("isNew")
                        code = result.get("code")
                        message = result.get("message", "")
                        print(f"[+] Network info accepted (isNew={is_new}, code={code}, message='{message}')")
                        return True
                    else:
                        raise Exception(f"Backend rejected network info: {result}")

            except Exception as e:
                print(f"[!] Attempt {attempt} failed: {e}")
                if attempt < max_retries:
                    print(f"[+] Retrying in {retry_interval} seconds...")
                    await asyncio.sleep(retry_interval)
                else:
                    raise RuntimeError("Failed to send network info after multiple attempts") from e