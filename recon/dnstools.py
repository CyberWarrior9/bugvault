"""Bulk DNS resolution and wildcard filtering through optional external tools.

Why these two are allowed inside `recon run` when ffuf/feroxbuster/x8 are not:

  * Volume is bounded by the **asset set**, not by a wordlist. Resolving N known
    hostnames costs N queries; a content fuzzer costs len(wordlist) per host.
  * The queries go to **resolvers**, not to the program's hosts, so they do not
    consume the campaign's target-request budget and cannot trip the target's WAF.
  * `puredns` exists to *shrink* the asset set. Wildcard DNS is the largest source
    of phantom subdomains, and the engine has no other defence against it.

Both tools are optional. When a binary is missing the caller records that as a fact
and returns; the engine never silently falls back to unbounded resolution.

Rate limits are always passed explicitly. `puredns --rate-limit` defaults to
*unlimited* and `dnsx -rl` defaults to -1 (disabled), so inheriting either default
would put an unpaced subprocess outside every control the engine has.

No wordlist is used here. `resolve()` takes names the engine already discovered.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# A single invocation is capped so one oversized domain cannot produce an
# unbounded subprocess. Callers batch above this.
MAX_NAMES_PER_RUN = 5000
DEFAULT_TIMEOUT = 300
# Floor for the subprocess rate. policy.max_rps governs *target* HTTP traffic and is
# typically 2; applying 2 q/s to DNS would make resolution useless, so DNS gets its
# own explicit ceiling rather than silently reusing an unrelated number.
DNS_QPS_DEFAULT = 50
DNS_QPS_MAX = 500

PUREDNS_RESOLVERS = Path.home() / ".config" / "puredns" / "resolvers.txt"


def dnsx_path() -> Optional[str]:
    return shutil.which("dnsx")


def puredns_path() -> Optional[str]:
    return shutil.which("puredns")


def _qps(requested: Optional[int]) -> int:
    if not requested or requested <= 0:
        return DNS_QPS_DEFAULT
    return min(int(requested), DNS_QPS_MAX)


def _write_names(names: Sequence[str]) -> str:
    handle, path = tempfile.mkstemp(prefix="recon-dns-", suffix=".txt")
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        for name in names:
            fh.write(f"{name}\n")
    return path


def _run(argv: List[str], timeout: int) -> Optional[str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return None
    return proc.stdout


def resolve(names: Sequence[str], *, qps: Optional[int] = None,
            resolvers: Optional[str] = None,
            timeout: int = DEFAULT_TIMEOUT) -> Optional[List[Dict[str, Any]]]:
    """Resolve known names in bulk with dnsx. Returns parsed JSONL rows, or None.

    None means the tool is unavailable or failed, which the caller must record as a
    fact rather than treat as "nothing resolved".
    """
    exe = dnsx_path()
    if not exe or not names:
        return None
    batch = list(dict.fromkeys(names))[:MAX_NAMES_PER_RUN]
    path = _write_names(batch)
    argv = [exe, "-l", path, "-json", "-silent", "-a", "-cname",
            "-rl", str(_qps(qps))]
    if resolvers:
        argv += ["-r", resolvers]
    try:
        out = _run(argv, timeout)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if out is None:
        return None
    rows: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def wildcard_survivors(domain: str, names: Sequence[str], *, qps: Optional[int] = None,
                       resolvers: Optional[str] = None,
                       timeout: int = DEFAULT_TIMEOUT) -> Optional[List[str]]:
    """Names that survive puredns' wildcard filter. None when unavailable.

    puredns resolves with public resolvers, then validates with trusted ones and
    drops wildcard hits. `--skip-wildcard-filter` is deliberately NOT passed: the
    filtering is the only reason this runs.
    """
    exe = puredns_path()
    if not exe or not names:
        return None
    resolver_file = resolvers or (str(PUREDNS_RESOLVERS) if PUREDNS_RESOLVERS.exists() else None)
    if not resolver_file:
        return None
    batch = list(dict.fromkeys(names))[:MAX_NAMES_PER_RUN]
    path = _write_names(batch)
    argv = [exe, "resolve", path, "--resolvers", resolver_file,
            "--rate-limit", str(_qps(qps)), "--quiet"]
    try:
        out = _run(argv, timeout)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if out is None:
        return None
    return [line.strip().rstrip(".").lower() for line in out.splitlines() if line.strip()]


def availability() -> Dict[str, Any]:
    """What the handler can actually do right now, for facts and the catalog."""
    return {"dnsx": dnsx_path(), "puredns": puredns_path(),
            "puredns_resolvers": str(PUREDNS_RESOLVERS) if PUREDNS_RESOLVERS.exists() else None}
