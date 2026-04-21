"""Agent entry point: ``python -m fyp_agent``.

Flow:
    1. Load config (YAML + env overrides).
    2. Load persisted identity if present; otherwise enroll.
    3. Open SignalR connection, stream heartbeat, process dispatches.

Graceful shutdown on SIGINT/SIGTERM.
"""
from __future__ import annotations

import logging
import signal
import sys
from pathlib import Path

from .config import load_config
from .enrollment import enroll, EnrollmentError
from .executor import RunExecutor
from .hub_client import AgentHubClient
from .identity_store import load_identity, save_identity


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )


def main() -> int:
    config = load_config()
    _configure_logging(config.log_level)
    log = logging.getLogger("fyp_agent")

    identity = load_identity(config.state_file)
    if identity is None:
        log.info("No persisted identity — running enrollment")
        try:
            identity = enroll(config)
        except EnrollmentError as exc:
            log.error("%s", exc)
            return 2
        save_identity(config.state_file, identity)
        log.info("Identity stored at %s", config.state_file)

    executor = RunExecutor(artifact_dir=Path(config.state_dir) / "artifacts")
    client = AgentHubClient(config=config, identity=identity, executor=executor)

    def _shutdown(signum, _frame):
        log.info("Received signal %s — stopping", signum)
        client.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _shutdown)
        except ValueError:  # pragma: no cover — Windows + non-main thread
            pass

    try:
        client.start()
    except KeyboardInterrupt:
        log.info("Interrupted")
        client.stop()

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
