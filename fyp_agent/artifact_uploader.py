"""Artifact upload flow.

After a tool finishes, the agent asks the API for a presigned PUT URL and
streams the raw output (e.g. nmap XML) straight to MinIO. The API never
touches the payload — it only issues the ticket.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class ArtifactUploadError(RuntimeError):
    """Raised when any step of the ticket-then-PUT flow fails."""


@dataclass
class UploadResult:
    artifact_uri: str
    object_key: str
    bucket_name: str


class ArtifactUploader:
    """Thin wrapper around the HTTP calls the agent makes to ship artifacts."""

    def __init__(
        self,
        api_base_url: str,
        agent_token: str,
        verify_tls: bool = True,
        timeout_seconds: int = 60,
    ):
        self._base = api_base_url.rstrip("/")
        self._token = agent_token
        self._verify = verify_tls
        self._timeout = timeout_seconds

    def upload(
        self,
        run_id: str,
        artifact_path: Path,
        content_type: str = "application/octet-stream",
        file_name: Optional[str] = None,
    ) -> UploadResult:
        """Requests a ticket, PUTs the file, returns the final artifact URI.

        Any HTTP failure raises :class:`ArtifactUploadError` — callers in
        the hub client catch it, log, and fall back to a null artifactUri
        so the run still closes out cleanly.
        """
        if not artifact_path.exists():
            raise ArtifactUploadError(f"Artifact file does not exist: {artifact_path}")

        ticket = self._request_ticket(
            run_id=run_id,
            file_name=file_name or artifact_path.name,
            content_type=content_type,
        )

        self._put_file(ticket["uploadUrl"], artifact_path, content_type)

        return UploadResult(
            artifact_uri=ticket["artifactUri"],
            object_key=ticket["objectKey"],
            bucket_name=ticket["bucketName"],
        )

    def _request_ticket(self, run_id: str, file_name: str, content_type: str) -> dict:
        url = f"{self._base}/api/v1/runs/{run_id}/artifacts/ticket"
        try:
            resp = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={"fileName": file_name, "contentType": content_type},
                timeout=self._timeout,
                verify=self._verify,
            )
        except requests.RequestException as exc:
            raise ArtifactUploadError(f"Ticket request failed: {exc}") from exc

        if resp.status_code != 200:
            raise ArtifactUploadError(
                f"Ticket request returned {resp.status_code}: {resp.text[:200]}"
            )

        try:
            return resp.json()
        except ValueError as exc:
            raise ArtifactUploadError("Ticket response was not JSON") from exc

    def _put_file(self, upload_url: str, path: Path, content_type: str) -> None:
        # Presigned MinIO dev URLs are plain HTTP on the LAN; do not apply API TLS
        # verification settings to the object-store PUT.
        verify_put = self._verify
        if upload_url.lower().startswith("http://"):
            verify_put = False

        # MinIO/S3 presigned PUT requires Content-Length; streaming file handles
        # can still use chunked encoding and get 411 MissingContentLength.
        body = path.read_bytes()
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
        }

        try:
            resp = requests.put(
                upload_url,
                data=body,
                headers=headers,
                timeout=self._timeout,
                verify=verify_put,
            )
        except requests.RequestException as exc:
            raise ArtifactUploadError(f"Upload PUT failed: {exc}") from exc

        if resp.status_code not in (200, 201, 204):
            raise ArtifactUploadError(
                f"Upload PUT returned {resp.status_code}: {resp.text[:200]}"
            )

        logger.info("Uploaded %s (%d bytes) to %s", path.name, len(body), upload_url)
