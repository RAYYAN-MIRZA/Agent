# nuclei_scanner.py
import asyncio
import json
import shutil
from typing import List, Dict, Any


class NucleiScanner:
    def __init__(self, nuclei_path: str = "nuclei", templates_dir: str = None, concurrency: int = 10):
        """
        :param nuclei_path: Path to nuclei binary
        :param templates_dir: If you want to specify custom templates
        :param concurrency: Max concurrent scan tasks for multiple IPs
        """
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir
        self.sem = asyncio.Semaphore(concurrency)

        # Check nuclei is installed
        if shutil.which(nuclei_path) is None:
            raise FileNotFoundError("Nuclei binary not found in PATH. Provide full path.")

    async def _run_single(self, ip: str) -> Dict[str, Any]:
        """
        Run nuclei scan on a single IP asynchronously.
        Returns parsed JSON results.
        """
        cmd = [
            self.nuclei_path,
            "-u", ip,     # you can change this to https or raw IP
            "-json"
        ]

        if self.templates_dir:
            cmd += ["-t", self.templates_dir]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        results = []
        async for line in process.stdout:
            line = line.decode().strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # ignore junk lines

        await process.wait()
        return {
            "ip": ip,
            "results": results,
            "error": None
        }

    async def scan_ip(self, ip: str) -> Dict[str, Any]:
        """
        Public method: scan a single IP.
        """
        async with self.sem:
            return await self._run_single(ip)

    async def scan_multiple(self, ip_list: List[str]) -> Dict[str, Any]:
        """
        Public method: scan a list of IPs concurrently.
        Returns: { "ip1": [...], "ip2": [...], ... }
        """
        tasks = [self.scan_ip(ip) for ip in ip_list]
        results = await asyncio.gather(*tasks)
        return {res["ip"]: res for res in results}


# ----------------------------
# Standalone test runner
# ----------------------------

if __name__ == "__main__":
    async def main():
        scanner = NucleiScanner(
            nuclei_path="nuclei",          # or full path "C:\\tools\\nuclei.exe"
            templates_dir=None,            # None = default templates
            concurrency=5
        )

        # Example single scan
        print("\nRunning single scan...")
        res_single = await scanner.scan_ip("192.168.1.10")
        print(json.dumps(res_single, indent=2))

        # Example multiple scan
        print("\nRunning multiple scan...")
        res_multi = await scanner.scan_multiple(["192.168.1.10", "192.168.1.20"])
        print(json.dumps(res_multi, indent=2))

    asyncio.run(main())
