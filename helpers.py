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
                

def xml_to_dict(element):
    """
    Recursively convert an ElementTree element into a dict.
    Handles attributes, text, and child elements.
    """
    node = {}
    
    # Add element attributes first
    if element.attrib:
        node.update({f"@{k}": v for k, v in element.attrib.items()})
    
    # Process children
    children = list(element)
    if children:
        child_dict = {}
        for child in children:
            child_name = child.tag
            child_value = xml_to_dict(child)
            
            # Handle multiple children with same tag
            if child_name in child_dict:
                if type(child_dict[child_name]) is list:
                    child_dict[child_name].append(child_value)
                else:
                    child_dict[child_name] = [child_dict[child_name], child_value]
            else:
                child_dict[child_name] = child_value
        
        node.update(child_dict)
    
    # Add text if element has text
    text = element.text.strip() if element.text else ""
    if text and children:
        node["#text"] = text
    elif text:
        return text
    
    return node

def nmap_xml_to_json(xml_str: str) -> dict:
    """
    Convert Nmap XML output string to a fully nested JSON-like dict.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {"error": "Invalid XML"}
    
    return {root.tag: xml_to_dict(root)}