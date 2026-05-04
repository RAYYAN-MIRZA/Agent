"""Typed, validated configuration for the FYP agent.

We keep YAML support but let environment variables override everything so
the same binary can run in Docker, bare metal, or CI without editing files.
"""
from __future__ import annotations

import os
import pwd
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from dotenv import load_dotenv


DEFAULT_CONFIG_PATH = Path.home() / ".fyp-agent" / "config.yaml"
STATE_FILE_NAME = "state.json"


@dataclass
class AgentConfig:
    """Runtime settings — validated at load time, immutable afterwards."""

    api_base_url: str
    """Root URL of the FYP API, e.g. ``https://api.fyp.local``."""

    enrollment_token: Optional[str] = None
    """One-shot bootstrap token. Consumed on first run, then cleared from disk."""

    agent_name: str = "kali-agent"
    """Human-friendly label that shows up in the UI."""

    hostname: Optional[str] = None
    platform: Optional[str] = None
    capabilities: list[str] = field(default_factory=lambda: ["nmap"])

    heartbeat_interval_seconds: int = 30
    """Overridden by the server on enrollment — this is only a fallback."""

    discovery_enabled: bool = True
    """Run continuous ARP discovery and push results to backend."""

    discovery_interval_seconds: int = 20
    """Seconds between ARP sweeps."""

    discovery_cidr: Optional[str] = None
    """If None, auto-detected from default route."""

    verify_tls: bool = True

    state_dir: Path = field(default_factory=lambda: _default_state_dir())

    log_level: str = "INFO"

    @property
    def state_file(self) -> Path:
        return self.state_dir / STATE_FILE_NAME

    def validate(self) -> None:
        if not self.api_base_url:
            raise ValueError("api_base_url is required")
        if not self.agent_name:
            raise ValueError("agent_name is required")
        self.state_dir.mkdir(parents=True, exist_ok=True)


def load_config(path: Optional[Path] = None) -> AgentConfig:
    """Load defaults → YAML file → env overrides, then validate."""
    _load_dotenv()
    cfg_path = path or DEFAULT_CONFIG_PATH
    data: dict = {}

    if cfg_path.exists():
        with cfg_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    # Env overrides — uppercased + FYP_AGENT_ prefix.
    env_map = {
        "FYP_AGENT_API_BASE_URL": "api_base_url",
        "FYP_AGENT_ENROLLMENT_TOKEN": "enrollment_token",
        "FYP_AGENT_NAME": "agent_name",
        "FYP_AGENT_HOSTNAME": "hostname",
        "FYP_AGENT_PLATFORM": "platform",
        "FYP_AGENT_LOG_LEVEL": "log_level",
        "FYP_AGENT_VERIFY_TLS": "verify_tls",
        "FYP_AGENT_DISCOVERY_CIDR": "discovery_cidr",
    }
    bool_fields = {"verify_tls", "discovery_enabled"}
    int_fields = {"discovery_interval_seconds"}
    for env_key, field_name in env_map.items():
        if env_key in os.environ:
            raw = os.environ[env_key]
            if field_name in bool_fields:
                data[field_name] = raw.lower() in {"1", "true", "yes"}
            elif field_name in int_fields:
                data[field_name] = int(raw)
            else:
                data[field_name] = raw

    if "FYP_AGENT_DISCOVERY_ENABLED" in os.environ:
        data["discovery_enabled"] = os.environ["FYP_AGENT_DISCOVERY_ENABLED"].lower() in {"1", "true", "yes"}
    if "FYP_AGENT_DISCOVERY_INTERVAL" in os.environ:
        data["discovery_interval_seconds"] = int(os.environ["FYP_AGENT_DISCOVERY_INTERVAL"])

    if "FYP_AGENT_CAPABILITIES" in os.environ:
        data["capabilities"] = [c.strip() for c in os.environ["FYP_AGENT_CAPABILITIES"].split(",") if c.strip()]

    state_dir_raw = data.pop("state_dir", None)

    cfg = AgentConfig(**data)
    if state_dir_raw:
        cfg.state_dir = Path(state_dir_raw).expanduser()

    cfg.validate()
    return cfg


def _default_state_dir() -> Path:
    """Resolves the state dir robustly across normal/sudo runs."""
    explicit = os.environ.get("FYP_AGENT_STATE_DIR")
    if explicit:
        return Path(explicit).expanduser()

    # When running via sudo, default to the invoking user's home so state does
    # not silently split between /root and /home/<user>.
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user:
        try:
            sudo_home = Path(pwd.getpwnam(sudo_user).pw_dir)
            return sudo_home / ".fyp-agent"
        except KeyError:
            pass

    return Path.home() / ".fyp-agent"


def _load_dotenv() -> None:
    """Merge ``.env`` into ``os.environ`` for keys not already set (shell wins).

    Loads ``./.env`` (cwd), then ``<repo>/.env`` beside the ``fyp_agent`` package
    so ``python -m fyp_agent`` picks up project env without ``source .env``.
    """
    repo_root = Path(__file__).resolve().parents[1]
    load_dotenv(Path.cwd() / ".env", override=False)
    load_dotenv(repo_root / ".env", override=False)
