"""Query Metasploit compatible payloads for an exploit via msfconsole."""
from __future__ import annotations

import logging
import os
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


def query_exploit_payloads(
    exploit_path: str,
    *,
    msfconsole: str = "msfconsole",
    timeout_seconds: int = 45,
) -> MsfPayloadQueryResult:
    """Run msfconsole with a resource script and parse MSF_* marker lines."""
    exploit_path = (exploit_path or "").strip()
    if not exploit_path.startswith("exploit/"):
        return MsfPayloadQueryResult(None, [], "Path must start with exploit/")

    safe_path = exploit_path.replace('"', '\\"')
    script = f"""use {safe_path}
ruby _m = framework.modules.active
if _m.nil?
  puts 'MSF_ERR:no_active_module'
else
  begin
    _p = _m.payload
    puts 'MSF_DEFAULT:' + (_p ? _p.refname : '')
  rescue => _e
    puts 'MSF_DEFAULT:'
  end
  begin
    _m.compatible_payloads.each_key {{|k| puts 'MSF_PAYLOAD:' + k.to_s}}
  rescue => _e
    puts 'MSF_ERR:' + _e.message
  end
end
exit
"""

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

        proc = subprocess.run(
            [msfconsole, "-q", "-r", rc_path],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=os.environ.copy(),
        )
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return _parse_output(combined)
    except subprocess.TimeoutExpired:
        return MsfPayloadQueryResult(None, [], "msfconsole payload probe timed out")
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
            error = line[len("MSF_ERR:") :].strip() or "msf error"
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

    if error and not payloads and not default_payload:
        return MsfPayloadQueryResult(None, [], error)

    if not payloads:
        payloads = _parse_show_payloads_fallback(combined)

    deduped: list[str] = []
    seen: set[str] = set()
    for p in payloads:
        key = p.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    if not default_payload and deduped:
        default_payload = deduped[0]

    if not deduped and not default_payload:
        return MsfPayloadQueryResult(None, [], error or "No compatible payloads reported by msfconsole")

    return MsfPayloadQueryResult(default_payload, deduped, None)


def _parse_show_payloads_fallback(text: str) -> list[str]:
    results: list[str] = []
    in_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if "compatible payloads" in line.lower():
            in_section = True
            continue
        if not in_section:
            continue
        if not line or line.startswith("=") or line.startswith("-"):
            continue
        if line.startswith("[") or line.lower().startswith("msf"):
            break
        for prefix in PAYLOAD_PREFIXES:
            idx = line.lower().find(prefix)
            if idx < 0:
                continue
            rest = line[idx:]
            end = next((i for i, c in enumerate(rest) if c.isspace()), len(rest))
            path = rest[:end].strip()
            if "/" in path:
                results.append(path)
            break
    return results
