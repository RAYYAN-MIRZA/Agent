import os
import json
import asyncio
import aioping
import aiohttp
import xml.etree.ElementTree as ET

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
    
def parse_kv_string(s: str) -> dict:
    """
    Convert a string like:
    "NetBIOS name: UMER, NetBIOS user: <unknown>, NetBIOS MAC: 68:54:5a:81:f2:63"
    into a proper dict:
    {
        "NetBIOS name": "UMER",
        "NetBIOS user": "<unknown>",
        "NetBIOS MAC": "68:54:5a:81:f2:63"
    }
    """
    result = {}
    parts = [p.strip() for p in s.split(",")]
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            result[k.strip()] = v.strip()
        else:
            # fallback: store as raw string
            result[part] = None
    return result

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
                

def xml_to_json_fully(element):
    """
    Generic XML → JSON parser.
    Converts attributes and text.
    If text looks like key: value, it parses into dict.
    """
    node = {}

    # Attributes
    for k, v in element.attrib.items():
        node[f"@{k}"] = str(v)

    # Children
    children = list(element)
    for child in children:
        child_name = child.tag
        child_value = xml_to_json_fully(child)

        # Handle multiple children with same tag
        if child_name in node:
            if isinstance(node[child_name], list):
                node[child_name].append(child_value)
            else:
                node[child_name] = [node[child_name], child_value]
        else:
            node[child_name] = child_value

    # Text
    text = element.text.strip() if element.text else ""
    if text:
        # Try parse key-value strings automatically
        if ":" in text and not children and not element.attrib:
            kv_parsed = parse_kv_string(text)
            return kv_parsed
        else:
            if children or element.attrib:
                node["#text"] = text
            else:
                return text

    return node

def nmap_xml_to_json(xml_str: str) -> dict:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {"error": "Invalid XML"}

    return {root.tag: xml_to_json_fully(root)}