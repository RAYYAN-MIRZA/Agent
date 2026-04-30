"""Runtime capability detection: probes installed tools and reports structured
capabilities to the backend. Called at startup and periodically to keep
capability advertisements accurate.
"""
from __future__ import annotations

import logging
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

KNOWN_TOOLS = [
    ("nmap", "--version"),
    ("nuclei", "-version"),
    ("zap-cli", "--version"),
    ("masscan", "--version"),
    ("nikto", "-Version"),
    ("testssl.sh", "--version"),
    ("amass", "version"),
    ("subfinder", "-version"),
    ("httpx", "-version"),
]


@dataclass
class ToolCapability:
    name: str
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None


@dataclass
class AgentCapabilities:
    os_type: str = field(default_factory=lambda: platform.system().lower())
    os_release: str = field(default_factory=platform.release)
    architecture: str = field(default_factory=platform.machine)
    agent_version: str = "1.0.0"
    tools: list[ToolCapability] = field(default_factory=list)

    @property
    def capability_labels(self) -> list[str]:
        """Flat string list for heartbeat compatibility."""
        labels = [f"os:{self.os_type}", f"arch:{self.architecture}"]
        for tool in self.tools:
            if tool.available:
                labels.append(tool.name)
                if tool.version:
                    labels.append(f"{tool.name}:{tool.version}")
        return labels

    def has_tool(self, tool_name: str) -> bool:
        return any(t.name == tool_name and t.available for t in self.tools)

    def to_heartbeat_payload(self) -> dict:
        return {
            "osType": self.os_type,
            "osRelease": self.os_release,
            "architecture": self.architecture,
            "agentVersion": self.agent_version,
            "tools": [
                {
                    "name": t.name,
                    "available": t.available,
                    "version": t.version,
                    "path": t.path,
                }
                for t in self.tools
            ],
            "labels": self.capability_labels,
        }


def detect_capabilities(extra_tools: Optional[list[str]] = None) -> AgentCapabilities:
    """Probe system for installed tools and return structured capabilities."""
    caps = AgentCapabilities()

    tools_to_check = list(KNOWN_TOOLS)
    if extra_tools:
        for name in extra_tools:
            if not any(t[0] == name for t in tools_to_check):
                tools_to_check.append((name, "--version"))

    for tool_name, version_flag in tools_to_check:
        tool_path = shutil.which(tool_name)
        if tool_path is None:
            caps.tools.append(ToolCapability(name=tool_name, available=False))
            continue

        version = _get_tool_version(tool_path, version_flag)
        caps.tools.append(ToolCapability(
            name=tool_name,
            available=True,
            version=version,
            path=tool_path,
        ))
        logger.debug("Detected %s at %s (v%s)", tool_name, tool_path, version or "unknown")

    return caps


def _get_tool_version(tool_path: str, version_flag: str) -> Optional[str]:
    """Run the tool's version command and extract a version string."""
    try:
        result = subprocess.run(
            [tool_path, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.strip() or result.stderr.strip()
        if output:
            first_line = output.split("\n")[0]
            return _extract_version_from_line(first_line)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def _extract_version_from_line(line: str) -> str:
    """Best-effort extraction of version string from tool output."""
    import re
    match = re.search(r"(\d+\.\d+[\w.\-]*)", line)
    return match.group(1) if match else line[:50]
