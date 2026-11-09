"""Passive (zero-touch) sources: certificate transparency and the Wayback archive.

These query third parties ABOUT the target through PassiveClient, which refuses any
in-scope host, so they are safe under scanner bans.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import quote, urlsplit

from .extract import is_static, path_ext, query_keys

WAYBACK_LIMIT = 20000
WAYBACK_JS_CAP = 50


def parse_crtsh(data: bytes) -> Set[str]:
    try:
        rows = json.loads(data or b"[]")
    except json.JSONDecodeError:
        return set()
    names: Set[str] = set()
    for r in rows if isinstance(rows, list) else []:
        for n in str(r.get("name_value", "")).splitlines():
            n = n.strip().lower().rstrip(".")
            if n.startswith("*."):
                n = n[2:]
            if n and " " not in n and "@" not in n:
                names.add(n)
    return names


def job_crtsh(ctx, asset: Dict[str, Any]) -> None:
    domain = asset["value"]
    r = ctx.passive.get(f"https://crt.sh/?q={quote('%.' + domain)}&output=json",
                        purpose="crtsh", timeout=90)
    if r.status != 200:
        ctx.store.add_fact(asset["id"], f"crt.sh returned HTTP {r.status}", "observed",
                           kind="source-error", source="crtsh")
        return
    names = parse_crtsh(r.body)
    kept = 0
    for n in sorted(names):
        if ctx.scope.host_in(n):
            ctx.add("host", n, source="crtsh")
            kept += 1
        else:
            ctx.intel(n, f"certificate name related to {domain}, outside scope", "crtsh")
    ctx.store.add_fact(asset["id"], f"crt.sh: {len(names)} names, {kept} in scope", "observed",
                       kind="source-summary", source="crtsh")


def parse_wayback(data: bytes) -> List[Tuple[str, str, str, str]]:
    try:
        rows = json.loads(data or b"[]")
    except json.JSONDecodeError:
        return []
    if not rows:
        return []
    out = []
    for r in rows[1:]:  # first row is the header
        if isinstance(r, list) and len(r) >= 4:
            out.append((r[0], r[1], r[2], r[3]))
    return out


def job_wayback(ctx, asset: Dict[str, Any]) -> None:
    domain = asset["value"]
    url = ("https://web.archive.org/cdx/search/cdx?url=" + quote(domain) +
           "&matchType=domain&output=json&fl=original,timestamp,statuscode,mimetype"
           f"&collapse=urlkey&limit={WAYBACK_LIMIT}")
    r = ctx.passive.get(url, purpose="wayback", timeout=180)
    if r.status != 200:
        ctx.store.add_fact(asset["id"], f"wayback returned HTTP {r.status}", "observed",
                           kind="source-error", source="wayback")
        return
    rows = parse_wayback(r.body)
    js_added = endpoints = 0
    for orig, ts, status, mime in sorted(rows, key=lambda x: x[1], reverse=True):
        try:
            path = urlsplit(orig).path
        except ValueError:
            continue
        ext = path_ext(path)
        if ext in ("js", "mjs"):
            if js_added < WAYBACK_JS_CAP and ctx.scope.is_in(orig):
                ctx.add("js", orig.split("?", 1)[0], source="wayback",
                        attrs={"archived": True, "depth": 0})
                js_added += 1
            continue
        if ext == "map":
            if ctx.scope.is_in(orig):
                ctx.add("sourcemap", orig.split("?", 1)[0], source="wayback")
            continue
        if is_static(path):
            continue
        if ctx.add_endpoint(orig, "wayback", params=query_keys(orig),
                            extra={"archived": True, "archive_last": ts,
                                   "archive_status": [status]}):
            endpoints += 1
    ctx.store.add_fact(asset["id"], f"wayback: {len(rows)} URLs, {endpoints} in-scope endpoints,"
                       f" {js_added} archived JS queued", "observed", kind="source-summary",
                       source="wayback")
