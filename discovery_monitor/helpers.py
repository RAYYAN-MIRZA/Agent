import asyncio
import html
import json
import os
import re
import xml.etree.ElementTree as ET

import aioping


def save_json_atomic(path, obj):
    path = str(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


async def ping_ip(ip: str, timeout=1000):
    """Async ICMP ping; returns True if host responds."""
    try:
        await aioping.ping(ip, timeout=timeout / 1000.0)
        return True
    except TimeoutError:
        return False
    except Exception:
        return False


def parse_kv_string_generic(s: str) -> dict:
    result = {}
    s = html.unescape(s)
    parts = re.split(r",\s*(?=[^,]+:\s)", s)
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            result[k.strip()] = v.strip()
        else:
            result[part.strip()] = None
    return result


def xml_to_json_generic(element):
    node = {}

    for k, v in element.attrib.items():
        node[f"@{k}"] = html.unescape(v)

    children = list(element)
    for child in children:
        child_name = child.tag
        child_value = xml_to_json_generic(child)

        if child_name in node:
            if isinstance(node[child_name], list):
                node[child_name].append(child_value)
            else:
                node[child_name] = [node[child_name], child_value]
        else:
            node[child_name] = child_value

    if element.tag == "script" and "@output" in node:
        output_text = node["@output"]
        node["output_parsed"] = parse_kv_string_generic(output_text)
        node["output_raw"] = output_text

    text = element.text.strip() if element.text else ""
    if text:
        text = html.unescape(text)
        if ":" in text and not children and not element.attrib:
            return parse_kv_string_generic(text)
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
    return {root.tag: xml_to_json_generic(root)}
