"""FYP tool-execution agent.

Connects to the backend's AgentHub, advertises capabilities, and runs
dispatched tools (nmap, etc.) in subprocess isolation — streaming live
stdout/stderr back over SignalR and reporting terminal status when the
external process exits.

The package is intentionally small and framework-light:

    python -m fyp_agent            # bootstrap + run

Configuration is loaded from, in order of precedence:
    1. env vars prefixed FYP_AGENT_*
    2. fyp_agent/config.yaml in CWD
    3. built-in defaults
"""

from .config import AgentConfig, load_config  # noqa: F401
