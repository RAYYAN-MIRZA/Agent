# helpers.py
import os
import json
import asyncio
import aioping
import aiohttp
import xml.etree.ElementTree as ET
import re
import html

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
                



def parse_kv_string_generic(s: str) -> dict:
    """
    Generic parser for key-value strings.
    Works with:
      - Keys with spaces
      - Multiple comma-separated key-value pairs
      - Values with parentheses or other symbols
    """
    result = {}
    # Decode HTML entities first
    s = html.unescape(s)
    # Split on commas that are followed by a key pattern (key:)
    parts = re.split(r',\s*(?=[^,]+:\s)', s)
    for part in parts:
        if ':' in part:
            k, v = part.split(':', 1)
            result[k.strip()] = v.strip()
        else:
            # fallback: store as string if no colon
            result[part.strip()] = None
    return result

def xml_to_json_generic(element):
    """
    Fully generic XML → JSON parser for Nmap output.
    - Converts attributes as @key
    - Parses text into key-value dict if possible
    - Handles nested children
    - Handles script outputs automatically
    """
    node = {}

    # 1️⃣ Attributes
    for k, v in element.attrib.items():
        node[f"@{k}"] = html.unescape(v)

    # 2️⃣ Children
    children = list(element)
    for child in children:
        child_name = child.tag
        child_value = xml_to_json_generic(child)

        # Handle multiple children with same tag
        if child_name in node:
            if isinstance(node[child_name], list):
                node[child_name].append(child_value)
            else:
                node[child_name] = [node[child_name], child_value]
        else:
            node[child_name] = child_value

    # 3️⃣ Special handling for <script> outputs
    if element.tag == "script" and "@output" in node:
        output_text = node["@output"]
        kv_parsed = parse_kv_string_generic(output_text)
        node["output_parsed"] = kv_parsed
        node["output_raw"] = output_text

    # 4️⃣ Text content
    text = element.text.strip() if element.text else ""
    if text:
        text = html.unescape(text)
        # Try parse key-value strings if no children or attributes
        if ":" in text and not children and not element.attrib:
            return parse_kv_string_generic(text)
        elif children or element.attrib:
            node["#text"] = text
        else:
            return text

    return node

def nmap_xml_to_json(xml_str: str) -> dict:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {"error": "Invalid XML"}
    return {root.tag: xml_to_json_generic(root)}
