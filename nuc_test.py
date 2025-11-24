from nuclei_scanner import NucleiScanner
import asyncio

async def run():
    scanner = NucleiScanner()
    result = await scanner.scan_ip("192.168.100.37")
    print(result)

asyncio.run(run())
