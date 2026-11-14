"""Shared validation primitives for external interaction evidence (SSRF and blind XSS).

Extracted from recon/ssrf.py so both correlation paths enforce identical rules:
attempt markers, ordered bounded time windows, hash-bound campaign-local
artifacts, and approved callback receiver hosts. No I/O beyond campaign-relative
artifact reads; no network. Assessment always stays with the caller.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .campaign import norm_host

MARKER_RE = re.compile(r"[a-zA-Z0-9_-]{16,96}")
MAX_ARTIFACT = 5_000_000


def timestamp(value):
    """ISO-8601 string with a timezone -> unix seconds (raises ValueError)."""
    if not isinstance(value, str):
        raise ValueError("timestamps must be ISO-8601 strings with a timezone")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return stamp.timestamp()


def valid_marker(marker) -> bool:
    return isinstance(marker, str) and bool(MARKER_RE.fullmatch(marker))


def local_bytes(root, path):
    """Read a campaign-relative artifact; refuse paths that escape the campaign root."""
    base = Path(root).resolve()
    source = Path(path)
    source = (base / source).resolve() if not source.is_absolute() else source.resolve()
    try:
        source.relative_to(base)
    except ValueError as exc:
        raise ValueError("evidence artifacts must remain inside the campaign folder") from exc
    if not source.is_file():
        raise ValueError("evidence artifact must be a regular file")
    with source.open("rb") as stream:
        data = stream.read(MAX_ARTIFACT + 1)
    if len(data) > MAX_ARTIFACT:
        raise ValueError("evidence artifact exceeds five megabytes")
    return data


def _artifact_ref(ref):
    if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
            or not isinstance(ref["path"], str) or not isinstance(ref["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", ref["sha256"])):
        raise ValueError("artifact references require path and lowercase sha256")
    return ref


def verified_bytes(root, ref):
    """Read a {path, sha256} artifact reference and verify its hash."""
    data = local_bytes(root, _artifact_ref(ref)["path"])
    if hashlib.sha256(data).hexdigest() != ref["sha256"]:
        raise ValueError("artifact hash mismatch")
    return data


def validate_callback_hosts(hosts, config_name):
    """Validate an approved-receiver host pattern list; returns the normalized patterns."""
    if not isinstance(hosts, list) or len(hosts) > 20 or any(
            not isinstance(h, str) or not re.fullmatch(r"(?:\*\.)?[a-zA-Z0-9][a-zA-Z0-9.-]*", h)
            for h in hosts):
        raise ValueError(f"{config_name} must be a list of at most 20 approved host patterns")
    return hosts


def approved_callback_host(hosts, host) -> bool:
    """Exact host match or *.suffix wildcard against the approved receiver patterns."""
    validate_callback_hosts(hosts, "callback host list")
    return any(host == norm_host(h) or (h.startswith("*.") and
               host.endswith("." + norm_host(h[2:]))) for h in hosts if h and h != "*")


def require_callback_url(url, hosts, config_name, marker):
    """Validate a callback URL against the approved receiver list and marker binding.

    Returns the normalized host. The URL must be a plain HTTP(S) URL whose
    host/path binds the attempt marker, so evidence cannot be attributed by
    coincidence alone.
    """
    if not isinstance(url, str) or any(c.isspace() for c in url):
        raise ValueError("callback URL must be a single URL string")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname \
            or parsed.username is not None or parsed.fragment:
        raise ValueError("callback URL must be a plain HTTP(S) URL")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid callback port")
    host = norm_host(parsed.hostname)
    if not approved_callback_host(hosts, host):
        raise ValueError(f"callback host has no explicit {config_name} grant")
    if marker.lower() not in (host + parsed.path).lower():
        raise ValueError("callback must bind the attempt marker in host/path")
    return host
