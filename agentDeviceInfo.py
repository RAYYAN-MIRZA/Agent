import ctypes
import json
import socket
import uuid
import platform
import sys
from pathlib import Path

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def elevate():
    """Relaunch the script with admin privileges."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

def get_ip_address():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Unknown"

def get_mac_address():
    try:
        mac = uuid.getnode()
        mac_str = ':'.join([format((mac >> ele) & 0xff, '02x')
                           for ele in range(0, 8 * 6, 8)][::-1])
        return mac_str
    except:
        return "Unknown"

def get_device_info():
    return {
        "hostname": socket.gethostname(),
        "ip_address": get_ip_address(),
        "mac_address": get_mac_address(),
        "os": get_os(),
    }

def get_os():
    if platform.system() != "Windows":
        return f"{platform.system()} {platform.release()}"

    try:
        import wmi

        # Create debug file immediately
        debug_file = Path("debug_os_info.txt")
        debug_file.write_text("Attempting to fetch OS info using WMI...\n")

        c = wmi.WMI()
        os_list = c.Win32_OperatingSystem()
        debug_file.write_text(f"Fetched OS list: {os_list}\n")  # overwrite with actual output

        os_info = os_list[0]
        print("INFO", os_info)
        return f"{os_info.Caption} (Build {os_info.BuildNumber})"
    except Exception as e:
        Path("debug_os_info.txt").write_text(f"Error fetching OS info: {e}\n")
        # fallback
        return platform.platform()

def save_to_json(data):
    file_path = Path("device_info.json")
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Device info saved to {file_path.absolute()}")

def main():
    if not is_admin():
        print("[!] Admin privileges required. Requesting elevation...")
        elevate()

    print("[+] Running with admin privileges.")
    device_info = get_device_info()

    print("[+] Device Info Collected:")
    print(json.dumps(device_info, indent=4))

    save_to_json(device_info)

if __name__ == "__main__":
    main()
