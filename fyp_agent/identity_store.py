"""Persistent agent identity on disk.

After the first successful enrollment we stash the agent id, long-lived
token, and hub URL in ``state.json`` so subsequent boots can skip the
bootstrap step entirely.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass
class AgentIdentity:
    agent_id: str
    agent_token: str
    agent_name: str
    hub_url: str
    heartbeat_interval_seconds: int = 30
    network_id: Optional[str] = None


def load_identity(state_file: Path) -> Optional[AgentIdentity]:
    if not state_file.exists():
        return None
    try:
        with state_file.open("r", encoding="utf-8") as f:
            return AgentIdentity(**json.load(f))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def save_identity(state_file: Path, identity: AgentIdentity) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_file.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(asdict(identity), f, indent=2)
    # atomic-ish rename so a crash mid-write can't corrupt the live file
    os.replace(tmp, state_file)
    try:
        os.chmod(state_file, 0o600)
    except (PermissionError, NotImplementedError):
        pass  # Windows / restricted FS — not critical for dev.


def clear_identity(state_file: Path) -> None:
    if state_file.exists():
        state_file.unlink()
