# job2.py
import asyncio
import time
from helpers import ping_ip
from status_monitor import arp_fallback, save_status, monitor_statuses

async def status_worker(queue):
    while True:
        ip, mac = await queue.get()
        try:
            alive = await ping_ip(ip, timeout=400)
            if not alive:
                alive = await arp_fallback(ip)
            await save_status(ip, mac, alive)
        except Exception as e:
            print(f"[Job2] Worker error: {e}")
        finally:
            queue.task_done()


async def run_job(job_payload):
    """
    job_payload example:
    {
        "devices": [
            {"ip": "192.168.100.10", "mac": "AA:BB:CC:DD:EE:FF"},
            {"ip": "192.168.100.20", "mac": "11:22:33:44:55:66"}
        ],
        "interval": 10
    }
    """

    # devices = job_payload.get("devices", [])
    # interval = job_payload.get("interval", 10)

    # if not devices:
    #     print("[Job2] No devices provided")

    # print(f"[Job2] Monitoring devices")

    asyncio.create_task(monitor_statuses(5))
