"""Subprocess executor: runs a resolved argv, streams output, reports terminal status.

Callbacks are injected so the hub client can wire them to SignalR invocations
without the executor taking a dependency on the transport.
"""
from __future__ import annotations

import logging
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Placeholder the backend emits in argv for per-run working directories.
# The agent expands it to a locally-valid absolute path right before exec.
ARTIFACT_DIR_PLACEHOLDER = "$ARTIFACT_DIR"


@dataclass
class ExecutionRequest:
    run_id: str
    correlation_id: str
    target: str
    executable: str
    argv: list[str]
    timeout_seconds: Optional[int] = None


@dataclass
class ExecutionResult:
    run_id: str
    success: bool
    exit_code: Optional[int]
    error_message: Optional[str]
    stdout_path: Optional[str]
    artifact_files: list[Path] = field(default_factory=list)
    run_workdir: Optional[Path] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


OutputCallback = Callable[[str, str, str, datetime], None]
"""(run_id, stream_name, chunk, timestamp)"""


class RunExecutor:
    """Runs one tool invocation per call to :meth:`execute`.

    The executor is deliberately synchronous — output streaming happens on
    two background pump threads and the caller waits on the main process.
    """

    def __init__(self, artifact_dir: Path):
        self.artifact_dir = artifact_dir
        artifact_dir.mkdir(parents=True, exist_ok=True)

    def execute(
        self,
        req: ExecutionRequest,
        on_output: OutputCallback,
    ) -> ExecutionResult:
        started_at = datetime.now(timezone.utc)

        # Each run gets its own scratch dir. Tools write -oX output (and
        # whatever else they need) here, which we then sweep up for upload.
        run_workdir = self.artifact_dir / req.run_id
        run_workdir.mkdir(parents=True, exist_ok=True)

        resolved_argv = _expand_argv(req.argv, run_workdir)
        argv = [req.executable, *resolved_argv]

        stdout_path = run_workdir / "stdout.log"
        stdout_handle = stdout_path.open("wb")

        logger.info("Executing run %s: %s", req.run_id, " ".join(argv))

        try:
            proc = subprocess.Popen(  # noqa: S603 — argv is resolver-validated
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                text=False,
                cwd=str(run_workdir),
            )
        except FileNotFoundError:
            stdout_handle.close()
            completed_at = datetime.now(timezone.utc)
            return ExecutionResult(
                run_id=req.run_id,
                success=False,
                exit_code=None,
                error_message=f"Executable not found: {req.executable}",
                stdout_path=None,
                run_workdir=run_workdir,
                started_at=started_at,
                completed_at=completed_at,
            )

        t_out = threading.Thread(
            target=_pump,
            args=(proc.stdout, "stdout", req.run_id, on_output, stdout_handle),
            daemon=True,
        )
        t_err = threading.Thread(
            target=_pump,
            args=(proc.stderr, "stderr", req.run_id, on_output, None),
            daemon=True,
        )
        t_out.start()
        t_err.start()

        try:
            exit_code = proc.wait(timeout=req.timeout_seconds)
            timed_out = False
            error_message: Optional[str] = None
        except subprocess.TimeoutExpired:
            proc.kill()
            exit_code = proc.wait()
            timed_out = True
            error_message = f"Exceeded timeout of {req.timeout_seconds}s"
        finally:
            t_out.join(timeout=5)
            t_err.join(timeout=5)
            stdout_handle.close()

        completed_at = datetime.now(timezone.utc)
        success = exit_code == 0 and not timed_out
        # Nikto uses exit 1 when findings are reported; that is a successful scan.
        if req.executable == "nikto" and exit_code == 1 and not timed_out:
            success = True
        # JSON report plugin can crash (exit 255) after a valid txt report was written.
        if (
            req.executable == "nikto"
            and not success
            and not timed_out
            and (run_workdir / "nikto.txt").is_file()
            and (run_workdir / "nikto.txt").stat().st_size > 0
        ):
            success = True
        # msfconsole often exits non-zero while still writing a usable spool log.
        if (
            req.executable == "msfconsole"
            and not success
            and not timed_out
        ):
            spool = run_workdir / "msf-spool.log"
            if spool.is_file() and spool.stat().st_size > 0:
                success = True

        # Whatever the tool dropped into its workdir (XML reports, json
        # summaries, pcaps…) is candidate for upload. Callers pick which
        # file the backend cares about.
        artifact_files = [
            p for p in sorted(run_workdir.glob("*"))
            if p.is_file() and p != stdout_path and _is_upload_candidate(p)
        ]

        return ExecutionResult(
            run_id=req.run_id,
            success=success,
            exit_code=exit_code,
            error_message=error_message
            or (None if success else f"Process exited with code {exit_code}"),
            stdout_path=str(stdout_path) if stdout_path.exists() else None,
            artifact_files=artifact_files,
            run_workdir=run_workdir,
            started_at=started_at,
            completed_at=completed_at,
        )


def _is_upload_candidate(path: Path) -> bool:
    """Skip known-bad Nikto JSON paths (double extension from -o *.json + -Format json)."""
    return not path.name.endswith(".json.json")


def _expand_argv(argv: list[str], run_workdir: Path) -> list[str]:
    """Replaces the <c>$ARTIFACT_DIR</c> placeholder in every argument."""
    expanded = []
    for arg in argv:
        if ARTIFACT_DIR_PLACEHOLDER in arg:
            expanded.append(arg.replace(ARTIFACT_DIR_PLACEHOLDER, str(run_workdir)))
        else:
            expanded.append(arg)
    return expanded


_PRIMARY_ARTIFACT_PRIORITY = [".xml", ".jsonl", ".json", ".txt", ".dat", ".log", ".csv"]


def pick_primary_artifact(files: list[Path], executable: str | None = None) -> Optional[Path]:
    """Heuristic: pick the most parser-friendly file by extension priority."""
    if not files:
        return None
    if executable and executable.lower() == "msfconsole":
        for candidate in files:
            if candidate.name == "msf-spool.log":
                return candidate
    for ext in _PRIMARY_ARTIFACT_PRIORITY:
        for candidate in files:
            if candidate.suffix.lower() == ext:
                return candidate
    return files[0]


def _pump(
    stream,
    name: str,
    run_id: str,
    on_output: OutputCallback,
    sink_file,
) -> None:
    """Reads a subprocess pipe line-by-line, forwarding each chunk."""
    try:
        for raw in iter(stream.readline, b""):
            if not raw:
                break
            if sink_file is not None:
                sink_file.write(raw)
                sink_file.flush()
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover — defensive
                text = repr(raw)
            try:
                on_output(run_id, name, text, datetime.now(timezone.utc))
            except Exception:  # pragma: no cover — never let callback crash pump
                logger.exception("Output callback failed for run %s", run_id)
    finally:
        try:
            stream.close()
        except Exception:  # pragma: no cover
            pass
