"""Query Metasploit compatible payloads for an exploit via msfconsole."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

PAYLOAD_PREFIXES = (
    "windows/", "linux/", "osx/", "android/", "php/", "cmd/", "generic/",
    "java/", "python/", "bsd/", "solaris/", "aix/", "mainframe/", "bsdi/",
    "netware/", "openbsd/", "freebsd/", "multi/", "apple_ios/",
)

_PAYLOAD_PATH_RE = re.compile(
    r"\b((?:windows|linux|osx|android|php|cmd|generic|java|python|bsd|solaris|"
    r"aix|mainframe|bsdi|netware|openbsd|freebsd|multi|apple_ios)/[^\s,;]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class MsfPayloadQueryResult:
    default_payload: Optional[str]
    compatible_payloads: list[str]
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and (
            self.default_payload is not None or len(self.compatible_payloads) > 0
        )


def resolve_msfconsole(explicit: Optional[str] = None) -> Optional[str]:
    if explicit and shutil.which(explicit):
        return explicit
    return shutil.which("msfconsole")


def build_resource_script(exploit_path: str) -> str:
    safe_path = exploit_path.replace('"', '\\"')
    return "\n".join(
        [
            f"use {safe_path}",
            "show payloads",
            "ruby _m = framework.modules.active",
            "if _m.nil?",
            "  puts 'MSF_ERR:no_active_module'",
            "else",
            "  begin",
            "    _p = _m.payload",
            "    puts 'MSF_DEFAULT:' + (_p ? _p.refname : '')",
            "  rescue => _e",
            "    puts 'MSF_DEFAULT:'",
            "  end",
            "  begin",
            "    _m.compatible_payloads.each_key {|k| puts 'MSF_PAYLOAD:' + k.to_s}",
            "  rescue => _e",
            "    puts 'MSF_ERR:' + _e.message",
            "  end",
            "end",
            "exit",
            "",
        ]
    )


def query_exploit_payloads(
    exploit_path: str,
    *,
    msfconsole: Optional[str] = None,
    timeout_seconds: int = 110,
) -> MsfPayloadQueryResult:
    """Run msfconsole with a resource script and parse MSF_* marker lines."""
    exploit_path = (exploit_path or "").strip()
    if not exploit_path.startswith("exploit/"):
        return MsfPayloadQueryResult(None, [], "Path must start with exploit/")

    exe = resolve_msfconsole(msfconsole)
    if not exe:
        return MsfPayloadQueryResult(None, [], "msfconsole not found on PATH")

    script = build_resource_script(exploit_path)
    rc_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".rc",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(script)
            rc_path = f.name

        logger.info(
            "MSF payload probe: %s via %s (timeout=%ss)",
            exploit_path,
            exe,
            timeout_seconds,
        )
        proc = subprocess.run(
            [exe, "-q", "-r", rc_path],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=os.environ.copy(),
        )
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode not in (0, None) and proc.returncode != 0:
            logger.debug("msfconsole exit code %s for %s", proc.returncode, exploit_path)
        return _parse_output(combined)
    except subprocess.TimeoutExpired:
        return MsfPayloadQueryResult(
            None,
            [],
            f"msfconsole payload probe timed out after {timeout_seconds}s",
        )
    except FileNotFoundError:
        return MsfPayloadQueryResult(None, [], "msfconsole not found on PATH")
    except Exception as exc:
        logger.exception("MSF payload query failed for %s", exploit_path)
        return MsfPayloadQueryResult(None, [], str(exc))
    finally:
        if rc_path:
            try:
                os.unlink(rc_path)
            except OSError:
                pass


def _parse_output(combined: str) -> MsfPayloadQueryResult:
    error: Optional[str] = None
    default_payload: Optional[str] = None
    payloads: list[str] = []

    for raw in combined.splitlines():
        line = raw.strip()
        if line.startswith("MSF_ERR:"):
            err = line[len("MSF_ERR:") :].strip()
            if err and err != "no_active_module":
                error = err
            continue
        if line.startswith("MSF_DEFAULT:"):
            val = line[len("MSF_DEFAULT:") :].strip()
            if val:
                default_payload = val
            continue
        if line.startswith("MSF_PAYLOAD:"):
            val = line[len("MSF_PAYLOAD:") :].strip()
            if val:
                payloads.append(val)

    if not payloads:
        payloads = _extract_payload_paths(combined)

    deduped = _dedupe_payloads(payloads)

    if not default_payload and deduped:
        default_payload = deduped[0]

    if not deduped and not default_payload:
        snippet = _tail(combined, 400)
        return MsfPayloadQueryResult(
            None,
            [],
            error
            or (
                "No compatible payloads reported by msfconsole. "
                f"Last output: {snippet}"
            ),
        )

    return MsfPayloadQueryResult(default_payload, deduped, None)


def _extract_payload_paths(text: str) -> list[str]:
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("[", "#", "-", "=")):
            continue
        for match in _PAYLOAD_PATH_RE.finditer(line):
            path = match.group(1).strip().rstrip(",;")
            if "/" in path:
                found.append(path)
        for prefix in PAYLOAD_PREFIXES:
            idx = line.lower().find(prefix)
            if idx < 0:
                continue
            rest = line[idx:]
            end = next((i for i, c in enumerate(rest) if c.isspace()), len(rest))
            path = rest[:end].strip().rstrip(",;")
            if "/" in path:
                found.append(path)
            break
    return _dedupe_payloads(found)


def _dedupe_payloads(paths: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        key = p.lower()
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _tail(text: str, max_len: int) -> str:
    compact = " ".join(text.split())
    if len(compact) <= max_len:
        return compact or "(empty)"
    return compact[-max_len:]
