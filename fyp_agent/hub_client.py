"""SignalR hub client for the FYP agent.

Wraps ``signalrcore``'s connection builder with auth, heartbeat, auto
reconnect, and dispatch plumbing. Keeps the executor + state concerns
orthogonal so the rest of the module is unit-testable without SignalR.
"""
from __future__ import annotations

import logging
import platform
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from signalrcore.hub_connection_builder import HubConnectionBuilder

from .artifact_uploader import ArtifactUploadError, ArtifactUploader
from .capabilities import AgentCapabilities, detect_capabilities
from .config import AgentConfig
from .discovery import DiscoveryConfig, DiscoveryRunner
from .executor import ExecutionRequest, RunExecutor, pick_primary_artifact
from .identity_store import AgentIdentity

logger = logging.getLogger(__name__)


class AgentHubClient:
    """Owns the live SignalR connection and dispatches inbound work."""

    EXECUTABLE_ALLOWLIST = frozenset([
        "nmap", "nuclei", "zap-cli", "masscan", "nikto",
        "testssl.sh", "amass", "subfinder", "httpx",
        "ffuf", "hydra", "msfconsole", "trivy", "lynis",
        "sslscan", "airodump-ng", "feroxbuster", "nxc",
    ])

    def __init__(
        self,
        config: AgentConfig,
        identity: AgentIdentity,
        executor: RunExecutor,
        uploader: Optional[ArtifactUploader] = None,
    ):
        self.config = config
        self.identity = identity
        self.executor = executor
        self.uploader = uploader or ArtifactUploader(
            api_base_url=config.api_base_url,
            agent_token=identity.agent_token,
            verify_tls=config.verify_tls,
        )
        self._capabilities: AgentCapabilities = detect_capabilities(config.capabilities)

        self._connection = self._build_connection()
        self._connected_at: Optional[float] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        self._discovery: Optional[DiscoveryRunner] = None
        self._active_runs: dict[str, threading.Thread] = {}
        self._active_runs_lock = threading.Lock()

    # -- public API ------------------------------------------------------

    def start(self) -> None:
        """Opens the connection and blocks indefinitely until stop() is called."""
        logger.info("Connecting to %s", self.identity.hub_url)
        self._connection.start()

        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        try:
            while not self._stopping.is_set():
                time.sleep(1)
        finally:
            self._connection.stop()

    def stop(self) -> None:
        self._stopping.set()
        if self._discovery:
            self._discovery.stop()

    # -- internals -------------------------------------------------------

    def _build_connection(self):
        # SignalR clients can't set arbitrary headers on the WebSocket
        # upgrade in every transport, so we also append the token as a
        # query string. The backend handler accepts either.
        url = self.identity.hub_url
        joiner = "&" if "?" in url else "?"
        url_with_token = f"{url}{joiner}access_token={self.identity.agent_token}"

        connection = (
            HubConnectionBuilder()
            .with_url(
                url_with_token,
                options={
                    "verify_ssl": self.config.verify_tls,
                    "headers": {"Authorization": f"Bearer {self.identity.agent_token}"},
                    "skip_negotiation": False,
                },
            )
            .with_automatic_reconnect(
                {
                    "type": "raw",
                    "keep_alive_interval": 15,
                    "reconnect_interval": 5,
                    "max_attempts": 10,
                }
            )
            .build()
        )

        connection.on_open(self._on_open)
        connection.on_close(self._on_close)
        connection.on_error(lambda data: logger.error("Hub error: %s", data))

        connection.on("Dispatch", self._on_dispatch)
        connection.on("Cancel", self._on_cancel)
        connection.on("HelloAck", self._on_hello_ack)

        return connection

    def _on_open(self) -> None:
        self._connected_at = time.monotonic()
        logger.info("Hub connected")
        self._send_heartbeat(initial=True)
        self._start_discovery()

    def _on_close(self) -> None:
        logger.warning("Hub disconnected")

    def _on_hello_ack(self, args) -> None:
        if not args or len(args) < 2:
            return
        _agent_id, interval = args[0], args[1]
        logger.info("HelloAck received — server heartbeat interval is %ss", interval)
        try:
            self.identity.heartbeat_interval_seconds = int(interval)
        except (TypeError, ValueError):
            pass

    def _on_cancel(self, args) -> None:
        run_id, reason = args[0], args[1] if len(args) > 1 else None
        logger.info("Cancel requested for run %s (%s)", run_id, reason)
        # Phase 5 wires a per-run subprocess registry; for Phase 4 the
        # agent simply logs the request.

    def _on_dispatch(self, args) -> None:
        if not args:
            return
        payload = args[0]
        try:
            req = ExecutionRequest(
                run_id=payload["runId"],
                correlation_id=payload.get("correlationId", ""),
                target=payload.get("target", ""),
                executable=payload["executable"],
                argv=list(payload.get("argv", [])),
                timeout_seconds=payload.get("timeoutSeconds"),
            )
        except (KeyError, TypeError) as exc:
            logger.error("Malformed dispatch payload: %s (%s)", payload, exc)
            return

        if req.executable not in self.EXECUTABLE_ALLOWLIST:
            logger.warning("Rejected dispatch: executable '%s' not in allowlist", req.executable)
            self._invoke("RunCompleted", {
                "runId": req.run_id,
                "success": False,
                "exitCode": None,
                "errorMessage": f"Executable '{req.executable}' not allowed by agent policy",
                "artifactUri": None,
                "completedAt": datetime.now(timezone.utc).isoformat(),
            })
            return

        if not self._capabilities.has_tool(req.executable):
            logger.warning("Tool '%s' not available on this agent", req.executable)
            self._invoke("RunCompleted", {
                "runId": req.run_id,
                "success": False,
                "exitCode": None,
                "errorMessage": f"Tool '{req.executable}' not installed on agent",
                "artifactUri": None,
                "completedAt": datetime.now(timezone.utc).isoformat(),
            })
            return

        worker = threading.Thread(target=self._run_dispatched, args=(req,), daemon=True)
        with self._active_runs_lock:
            self._active_runs[req.run_id] = worker
        worker.start()

    def _run_dispatched(self, req: ExecutionRequest) -> None:
        logger.info("Dispatched run %s → %s %s", req.run_id, req.executable, " ".join(req.argv))

        self._invoke("RunStarted", {
            "runId": req.run_id,
            "startedAt": datetime.now(timezone.utc).isoformat(),
        })

        def on_output(run_id: str, stream: str, chunk: str, at: datetime) -> None:
            self._invoke("RunOutput", {
                "runId": run_id,
                "stream": stream,
                "chunk": chunk,
                "at": at.isoformat(),
            })

        result = self.executor.execute(req, on_output=on_output)

        uploaded_artifacts: list[dict] = []
        primary = pick_primary_artifact(result.artifact_files)
        primary_uri: Optional[str] = None
        first_success_uri: Optional[str] = None
        upload_errors: list[str] = []

        for artifact_file in result.artifact_files:
            try:
                upload = self.uploader.upload(
                    run_id=result.run_id,
                    artifact_path=artifact_file,
                    content_type=_content_type_for(artifact_file),
                )
                uploaded_artifacts.append({
                    "fileName": artifact_file.name,
                    "uri": upload.artifact_uri,
                    "contentType": _content_type_for(artifact_file),
                    "sizeBytes": artifact_file.stat().st_size,
                })
                if first_success_uri is None:
                    first_success_uri = upload.artifact_uri
                if primary is not None and artifact_file == primary:
                    primary_uri = upload.artifact_uri
                logger.info("Uploaded artifact: %s → %s", artifact_file.name, upload.artifact_uri)
            except ArtifactUploadError as exc:
                upload_errors.append(f"{artifact_file.name}: {exc}")
                logger.error("Artifact upload failed for %s: %s", artifact_file.name, exc)

        # Prefer the parser-primary file (e.g. output.xml), else any successful upload.
        artifact_uri = primary_uri if primary_uri is not None else first_success_uri

        error_message = result.error_message
        if artifact_uri is None:
            if not result.artifact_files:
                note = (
                    "No artifact files in run workdir (tool did not write expected outputs "
                    "such as output.xml — check argv and permissions)."
                )
                logger.warning("Run %s: %s", result.run_id, note)
                error_message = _append_error_note(error_message, note)
            elif upload_errors:
                joined = "; ".join(upload_errors[:5])
                if len(upload_errors) > 5:
                    joined += f"; … ({len(upload_errors)} failures)"
                note = f"Artifact upload failed — {joined}"
                logger.error("Run %s: %s", result.run_id, note)
                error_message = _append_error_note(error_message, note)

        self._invoke("RunCompleted", {
            "runId": result.run_id,
            "success": result.success,
            "exitCode": result.exit_code,
            "errorMessage": error_message,
            "artifactUri": artifact_uri,
            "artifacts": uploaded_artifacts,
            "completedAt": result.completed_at.isoformat(),
        })

        with self._active_runs_lock:
            self._active_runs.pop(req.run_id, None)

    def _heartbeat_loop(self) -> None:
        while not self._stopping.is_set():
            time.sleep(max(5, self.identity.heartbeat_interval_seconds))
            try:
                self._send_heartbeat(initial=False)
            except Exception:  # pragma: no cover
                logger.exception("Heartbeat send failed")

    def _send_heartbeat(self, *, initial: bool) -> None:
        payload = {
            "status": "Online",
            "capabilities": self._capabilities.capability_labels,
        }
        if initial:
            payload["capabilityDetails"] = self._capabilities.to_heartbeat_payload()
        logger.debug("Heartbeat → %s", payload)
        self._invoke("Heartbeat", payload)

    def _start_discovery(self) -> None:
        if self._discovery is not None:
            return
        network_id = self.identity.network_id
        if not network_id:
            logger.warning(
                "Discovery disabled: missing network_id in identity. "
                "Re-enroll so the server returns networkId, or set it in state.json."
            )
            return
        discovery_cfg = DiscoveryConfig(
            enabled=self.config.discovery_enabled,
            scan_interval_seconds=self.config.discovery_interval_seconds,
            network_cidr=self.config.discovery_cidr,
        )
        self._discovery = DiscoveryRunner(
            hub_invoke=self._invoke,
            network_id=network_id,
            config=discovery_cfg,
        )
        self._discovery.start()

    def _invoke(self, method: str, payload) -> None:
        # signalrcore's `send` is fire-and-forget; the hub methods are
        # `async Task` on the server so we don't need the return value.
        try:
            self._connection.send(method, [payload])
        except Exception:  # pragma: no cover — never kill the agent loop
            logger.exception("Failed to invoke %s on hub", method)


def _append_error_note(existing: Optional[str], note: str) -> str:
    """Joins a secondary diagnostic onto the tool's errorMessage for the hub."""
    if not existing or not existing.strip():
        return note
    return f"{existing.strip()} | {note}"


def _default_platform_label() -> str:
    return f"{platform.system()} {platform.release()}"


def _content_type_for(path) -> str:
    """Rough MIME guess for the common tool output types."""
    suffix = path.suffix.lower() if hasattr(path, "suffix") else ""
    return {
        ".xml": "application/xml",
        ".json": "application/json",
        ".jsonl": "application/x-ndjson",
        ".txt": "text/plain",
        ".log": "text/plain",
        ".dat": "text/plain",
        ".csv": "text/csv",
        ".pcap": "application/vnd.tcpdump.pcap",
    }.get(suffix, "application/octet-stream")
