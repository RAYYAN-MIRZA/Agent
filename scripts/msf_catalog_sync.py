#!/usr/bin/env python3
"""Export Metasploit module catalog and POST to FYP API.

Requires: msfconsole on PATH, requests, and a console auth token.

Example:
  export FYP_API_URL=http://localhost:5000
  export FYP_BEARER_TOKEN=...
  python scripts/msf_catalog_sync.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import requests
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(1)

MODULE_RE = re.compile(r"^(auxiliary|exploit|payload|post|encoder)/")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def parse_csv(path: Path) -> list[dict]:
    import csv

    modules: list[dict] = []
    current: dict | None = None
    children: list[str] = []

    with path.open(encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        next(reader, None)  # header
        for row in reader:
            if len(row) < 6:
                continue
            name = row[1].strip()
            if not name:
                continue
            if MODULE_RE.match(name):
                if current:
                    current["childLines"] = children or None
                    modules.append(current)
                children = []
                desc = row[5].strip()
                cves = " ".join(CVE_RE.findall(f"{name} {desc}"))
                current = {
                    "modulePath": name,
                    "moduleType": name.split("/")[0],
                    "disclosureDate": row[2].strip() if row[2].strip() not in (".", "") else None,
                    "rank": row[3].strip() or "normal",
                    "hasCheck": row[4].strip().lower() == "yes",
                    "description": desc,
                }
            elif current and "\\_" in name:
                children.append(name.strip())
    if current:
        current["childLines"] = children or None
        modules.append(current)
    return modules


def export_msf_csv() -> Path:
    out = Path(tempfile.gettempdir()) / "msf-modules-export.csv"
    subprocess.run(
        ["msfconsole", "-q", "-x", f"search -o {out}; exit"],
        check=True,
        timeout=600,
    )
    if not out.exists():
        raise RuntimeError("msfconsole did not produce export file")
    return out


def main() -> int:
    api = os.environ.get("FYP_API_URL", "http://localhost:5000").rstrip("/")
    token = os.environ.get("FYP_BEARER_TOKEN") or os.environ.get("FYP_ACCESS_TOKEN")
    if not token:
        print("Set FYP_BEARER_TOKEN", file=sys.stderr)
        return 1

    csv_path = export_msf_csv()
    modules = parse_csv(csv_path)
    print(f"Parsed {len(modules)} modules from {csv_path}")

    ver = subprocess.check_output(["msfconsole", "--version"], text=True).strip().splitlines()[0]

    resp = requests.post(
        f"{api}/api/v1/msf-modules/sync",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"modules": modules, "msfVersion": ver},
        timeout=120,
    )
    resp.raise_for_status()
    print(resp.json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
