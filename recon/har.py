"""Authenticated mapping from your own browsing (ARTEX's capture-extension idea, offline).

Log in to the target yourself in a normal browser (captcha, 2FA, email OTP all fine),
click through the app, then export the traffic as a HAR (DevTools > Network > Export
HAR, or Burp/Caido). Import one HAR per canary account:

    python3 -m recon import-har <campaign> alice.har --account alice
    python3 -m recon import-har <campaign> bob.har   --account bob

Stored: endpoint, method, parameter NAMES, status, whether auth headers were present,
and values ONLY for ID-like parameters (digits/UUID/hex) - that is the object graph
used for cross-account IDOR candidates. Header values, cookie values, tokens and
bodies are never stored. Each capture also keeps value-free CSRF metadata
(`recon/csrfmeta.py`): request MIME, auth mechanism, anti-CSRF token channel names,
custom-header flags, Origin/Referer origins and Sec-Fetch values, Set-Cookie names
with their attributes, and GraphQL operation type+name. Out-of-scope entries become
intel.
"""
from __future__ import annotations

import json
import re
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .csrfmeta import GRAPHQL_ROUTE, graphql_operations, har_cookie_records, request_meta
from .extract import id_like, is_static, origin_of, path_ext
from .ingest import HTTP_METHODS, MAX_RECORDS, read_artifact

AUTH_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token",
                "x-csrf-token", "x-xsrf-token", "api-key", "token", "x-session-token"}
STATIC_MIME = ("image/", "font/", "text/css", "video/", "audio/")
SENSITIVE_PARAM = re.compile(r"token|secret|password|passwd|cookie|auth|session|csrf|xsrf|otp|pin|key", re.I)


MAX_JSON_DEPTH = 6
MAX_JSON_LEAVES = 200


def _flatten(obj: Any) -> List[Tuple[str, Any]]:
    """Full-depth JSON leaf names as dotted/bracketed paths, bounded.

    Arrays record the wrapper (``items[]``) *and* descend into the first element
    (``items[0].id``): whether a value is array-wrapped matters for request-shape
    variants. Depth and leaf count are capped; malformed shapes yield partial
    results, never errors.
    """
    out: List[Tuple[str, Any]] = []

    def walk(node: Any, prefix: str, depth: int) -> None:
        if depth > MAX_JSON_DEPTH or len(out) >= MAX_JSON_LEAVES:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{prefix}.{k}" if prefix else str(k), depth + 1)
        elif isinstance(node, list):
            if prefix:
                out.append((f"{prefix}[]", node))
            if node:
                walk(node[0], f"{prefix}[0]" if prefix else "[0]", depth + 1)
        elif prefix:
            out.append((prefix, node))

    if isinstance(obj, (dict, list)):
        walk(obj, "", 0)
    return out[:MAX_JSON_LEAVES]


def request_params(req: Dict[str, Any]) -> Tuple[List[Tuple[str, Any]], List[Tuple[str, Any]], str]:
    url = req.get("url", "")
    q = [(p.get("name", ""), p.get("value", "")) for p in req.get("queryString") or []]
    if not q:
        q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    pd = req.get("postData") or {}
    mime = (pd.get("mimeType") or "").split(";")[0].strip().lower()
    body: List[Tuple[str, Any]] = []
    if pd.get("params"):
        body = [(p.get("name", ""), p.get("value", "")) for p in pd["params"]]
    elif pd.get("text"):
        try:
            body = _flatten(json.loads(pd["text"]))
        except ValueError:
            body = parse_qsl(pd["text"], keep_blank_values=True)
    return [x for x in q if x[0]], [x for x in body if x[0]], mime


def import_har(ctx, path: Path, account: Optional[str], role: str = "", tenant: str = "",
               workflow_state: str = "") -> Dict[str, int]:
    content = read_artifact(path)
    data = json.loads(content.decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("log"), dict):
        raise ValueError("expected HAR object with log.entries")
    entries = data["log"].get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_RECORDS:
        raise ValueError(f"HAR entries must be a list of at most {MAX_RECORDS} records")
    context = {"account": account or "", "role": role, "tenant": tenant,
               "workflow_state": workflow_state, "basis": "captured-real-traffic"}
    import_id = ctx.store.register_import("har", content, context)
    stats = {"entries": len(entries), "endpoints": 0, "js": 0, "out_of_scope": 0,
              "static": 0, "duplicate_samples": 0, "malformed": 0}
    for index, e in enumerate(entries):
        if not _valid_entry(e):
            stats["malformed"] += 1
            continue
        req = e.get("request") or {}
        url = req.get("url", "")
        if not url.startswith(("http://", "https://")):
            continue
        method = (req.get("method") or "GET").upper()
        if not ctx.scope.is_in(url):
            stats["out_of_scope"] += 1
            aid = ctx.intel(origin_of(url), f"seen in {account or 'HAR'} traffic", "har")
            ctx.store.provenance(aid, import_id, index, "captured-real-traffic")
            continue
        resp = e.get("response") or {}
        rmime = ((resp.get("content") or {}).get("mimeType") or "").lower()
        path_ = urlsplit(url).path
        if "javascript" in rmime or path_ext(path_) in ("js", "mjs"):
            aid = ctx.add("js", origin_of(url) + path_, source="har",
                          attrs={"page_origin": origin_of(url), "depth": 0})
            ctx.store.provenance(aid, import_id, index, "captured-real-traffic")
            stats["js"] += 1
            continue
        if is_static(path_) or rmime.startswith(STATIC_MIME):
            stats["static"] += 1
            continue
        hdr_names = {(h.get("name") or "").lower() for h in req.get("headers") or []}
        auth = bool(hdr_names & AUTH_HEADERS)
        q, body, mime = request_params(req)
        ids: Dict[str, str] = {}
        for name, val in q + body:
            if (not SENSITIVE_PARAM.search(name) and isinstance(val, (str, int))
                    and not isinstance(val, bool) and id_like(str(val))):
                ids[name] = str(val)
        for i, seg in enumerate(path_.split("/")):
            if seg and id_like(seg):
                ids[f"path[{i}]"] = seg
        names = [n for n, _ in q] + [n for n, _ in body]
        resp_headers = resp.get("headers") if isinstance(resp.get("headers"), list) else []
        csrf_meta = request_meta(
            [(h.get("name"), h.get("value")) for h in req.get("headers") or []],
            mime, [n for n, _ in q], [n for n, _ in body],
            [(h.get("name"), h.get("value")) for h in resp_headers if isinstance(h, dict)],
            [c.get("name") for c in req.get("cookies") or [] if isinstance(c, dict)]
            if isinstance(req.get("cookies"), list) else [],
            graphql_operations(url, (req.get("postData") or {}).get("text"))
            if GRAPHQL_ROUTE.search(path_) else [])
        if not csrf_meta["set_cookies"]:
            csrf_meta["set_cookies"] = har_cookie_records(resp.get("cookies"))
        eid = ctx.add_endpoint(url, "har", method=method, params=names, extra={
            "auth_seen": auth, "id_params": sorted(ids),
            "accounts": [account] if account else [],
            "content_types": [mime] if mime else [],
            "basis": "captured-real-traffic",
        })
        if eid is None:
            continue
        stats["endpoints"] += 1
        ctx.store.provenance(eid, import_id, index, "captured-real-traffic")
        if not ctx.store.add_observation(eid, method, account, {
            "query": [n for n, _ in q], "body": [n for n, _ in body], "ids": ids,
            "auth": auth}, resp.get("status"), "har",
                capture_key=f"har:{import_id}:{index}", context={
                    **context, "import_id": import_id, "record_index": index, "path": path_,
                    "csrf_meta": csrf_meta,
                    "response_text_sha256": hashlib.sha256(
                        (resp.get("content") or {})["text"].encode()).hexdigest()
                    if isinstance((resp.get("content") or {}).get("text"), str) else None}):
            stats["duplicate_samples"] += 1
    ctx.store.record_import_result(import_id, stats)
    return stats


def _valid_entry(entry: Any) -> bool:
    """Validate external shape before parsing; malformed records never abort a whole import."""
    try:
        if not isinstance(entry, dict):
            return False
        req = entry.get("request")
        resp = entry.get("response") or {}
        if not isinstance(req, dict) or not isinstance(resp, dict):
            return False
        status = resp.get("status")
        if status is not None and (not isinstance(status, int) or isinstance(status, bool)
                                   or not 0 <= status <= 599):
            return False
        url = req.get("url")
        if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 32 for c in url):
            return False
        p = urlsplit(url)
        origin_of(url)
        if p.scheme not in ("http", "https") or not p.hostname or p.username is not None:
            return False
        method = req.get("method", "GET")
        if not isinstance(method, str) or method.upper() not in HTTP_METHODS:
            return False
        for key in ("headers", "queryString"):
            rows = req.get(key) or []
            if not isinstance(rows, list) or any(not isinstance(r, dict) or
                    not isinstance(r.get("name", ""), str) for r in rows):
                return False
        post = req.get("postData") or {}
        content = resp.get("content") or {}
        if not isinstance(post, dict) or not isinstance(content, dict):
            return False
        if not isinstance(post.get("text", ""), str) or not isinstance(post.get("mimeType", ""), str):
            return False
        if not isinstance(content.get("mimeType", ""), str):
            return False
        params = post.get("params") or []
        return isinstance(params, list) and all(isinstance(r, dict) and
                      isinstance(r.get("name", ""), str) for r in params)
    except (ValueError, TypeError):
        return False
