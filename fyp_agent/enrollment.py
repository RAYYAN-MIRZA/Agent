"""Enrollment HTTP flow: exchanges a bootstrap token for long-lived agent credentials."""
from __future__ import annotations

import logging
import platform
import socket
from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from .config import AgentConfig
from .identity_store import AgentIdentity

logger = logging.getLogger(__name__)


class EnrollmentError(RuntimeError):
    pass


@dataclass
class EnrollmentResponse:
    agent_id: str
    agent_token: str
    agent_name: str
    network_id: str
    heartbeat_interval_seconds: int
    hub_url: str


def enroll(config: AgentConfig) -> AgentIdentity:
    """Consume the enrollment token and return a durable identity.

    On success the caller is expected to persist the identity via
    :func:`identity_store.save_identity` so future runs skip this step.
    """
    if not config.enrollment_token:
        raise EnrollmentError(
            "No enrollment token found. Generate one via "
            "POST /api/v1/agents/enrollments and set FYP_AGENT_ENROLLMENT_TOKEN."
        )

    url = urljoin(config.api_base_url.rstrip("/") + "/", "api/v1/agents/enroll")
    body = {
        "enrollmentToken": config.enrollment_token,
        "name": config.agent_name,
        "hostname": config.hostname or socket.gethostname(),
        "platform": config.platform or f"{platform.system()} {platform.release()}",
        "capabilities": config.capabilities,
    }

    logger.info("Enrolling at %s as '%s'", url, config.agent_name)

    try:
        resp = requests.post(url, json=body, timeout=30, verify=config.verify_tls)
    except requests.RequestException as exc:
        raise EnrollmentError(f"Failed to reach {url}: {exc}") from exc

    if resp.status_code == 404:
        raise EnrollmentError("Enrollment token unknown or expired.")
    if resp.status_code == 409:
        raise EnrollmentError(f"Enrollment rejected by server: {resp.text}")
    if not resp.ok:
        raise EnrollmentError(f"Enrollment failed: HTTP {resp.status_code} — {resp.text}")

    data = resp.json()
    parsed = EnrollmentResponse(
        agent_id=data["agentId"],
        agent_token=data["agentToken"],
        agent_name=data["agentName"],
        network_id=data["networkId"],
        heartbeat_interval_seconds=data.get("heartbeatIntervalSeconds", 30),
        hub_url=data["hubUrl"],
    )

    logger.info(
        "Enrollment succeeded: agent_id=%s heartbeat=%ds",
        parsed.agent_id,
        parsed.heartbeat_interval_seconds,
    )

    return AgentIdentity(
        agent_id=parsed.agent_id,
        agent_token=parsed.agent_token,
        agent_name=parsed.agent_name,
        hub_url=parsed.hub_url,
        heartbeat_interval_seconds=parsed.heartbeat_interval_seconds,
    )
