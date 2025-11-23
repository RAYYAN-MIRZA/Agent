# helpers.py
import os
import json
import platform
import subprocess

def save_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)

def ping_ip(ip: str, timeout=1000):
    """Cross-platform ping."""
    system = platform.system().lower()

    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout), ip]
        else:
            # Linux / MacOS
            cmd = ["ping", "-c", "1", "-W", str(timeout // 1000), ip]

        subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL
        )
        return True

    except:
        return False
