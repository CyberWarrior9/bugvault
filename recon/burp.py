"""Burp history import (offline): closes the header/cookie capture gap honestly.

Accepts three operator-produced formats, converts them to the same observation
shape as HAR imports (names only; values kept ONLY for ID-like parameters):

* Burp "Save items"/"Save selected items" XML export (base64 request/response)
* Burp/JSON export with ``requests`` (or a list of) items
* a raw HTTP request file (Host header supplies the origin; HTTP by default,
  ``--scheme https`` for TLS captures)

Unlike HAR, header and cookie NAMES are recorded (request ``Cookie``/``X-*``
names; values never), so the field ledger covers those locations too. Like HAR,
each capture keeps value-free CSRF metadata (MIME, auth mechanism, token channel
names, Origin/Referer origins, Set-Cookie names and attributes). When the
export contains responses, they are stored like native captures (basis
``imported-burp-capture``) so ``recon fields trace`` can follow canary markers
through them. Out-of-scope items become intel. Nothing is ever sent.
"""
from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .csrfmeta import GRAPHQL_ROUTE, graphql_operations, request_meta
from .extract import id_like, is_static, origin_of, path_ext
from .har import AUTH_HEADERS, SENSITIVE_PARAM, STATIC_MIME, _flatten
from .ingest import HTTP_METHODS, MAX_RECORDS, read_artifact

MAX_ITEM_BYTES = 2_000_000
MAX_PART_NAMES = 200


class Item:
    __slots__ = ("url", "method", "status", "request_bytes", "response_bytes")

    def __init__(self, url, method, status, request_bytes, response_bytes):
        self.url, self.method, self.status = url, method, status
        self.request_bytes, self.response_bytes = request_bytes, response_bytes


def _decode(node) -> bytes:
    raw = node.text or ""
    flag = (node.get("base64") or "").lower() == "true" or re.fullmatch(
        r"[A-Za-z0-9+/=\s]{200,}", raw[:400] or "")
    data = base64.b64decode(re.sub(r"\s+", "", raw)) if flag else raw.encode("utf-8", "replace")
    return data[:MAX_ITEM_BYTES]


def _xml_items(content: bytes) -> List[Item]:
    root = ET.fromstring(content.decode("utf-8-sig", "replace"))
    items = []
    for node in root.iter():
        if not node.tag.endswith("item"):
            continue
        child = {c.tag.split("}")[-1]: c for c in node}
        url = (child.get("url").text or "").strip() if child.get("url") is not None else ""
        method = ((child.get("method").text or "GET").strip().upper()
                  if child.get("method") is not None else "GET")
        status = None
        if child.get("status") is not None:
            try:
                status = int(child["status"].text)
            except (ValueError, TypeError):
                status = None
        request = _decode(child["request"]) if child.get("request") is not None else b""
        response = _decode(child["response"]) if child.get("response") is not None else b""
        if not url and request:
            url = _url_from_request_line(request)
        if url:
            items.append(Item(url, method, status, request, response))
    return items


def _json_items(content: bytes) -> List[Item]:
    data = json.loads(content.decode("utf-8-sig"))
    if isinstance(data, dict):
        data = data.get("requests") or data.get("items") or [data]
    if not isinstance(data, list):
        raise ValueError("expected a JSON list of Burp items")
    items = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("each Burp item must be an object")
        url = str(entry.get("url") or "")
        method = str(entry.get("method") or "GET").upper()
        status = entry.get("status")
        status = int(status) if isinstance(status, int) else None
        request = _flagged_bytes(entry.get("request"))
        response = _flagged_bytes(entry.get("response"))
        if not url and request:
            url = _url_from_request_line(request)
        if url:
            items.append(Item(url, method, status, request, response))
    return items


def _flagged_bytes(node) -> bytes:
    if node is None:
        return b""
    if isinstance(node, dict):
        text = str(node.get("text") or "")
        if (node.get("base64") or "").lower() == "true":
            return base64.b64decode(re.sub(r"\s+", "", text))[:MAX_ITEM_BYTES]
        return text.encode("utf-8", "replace")[:MAX_ITEM_BYTES]
    if isinstance(node, str):
        return node.encode("utf-8", "replace")[:MAX_ITEM_BYTES]
    raise ValueError("unsupported request/response encoding in Burp JSON")


def parse_raw_request(data: bytes, scheme: str = "http") -> Tuple[str, str, Dict[str, str], bytes]:
    """Raw HTTP request bytes -> (method, url, headers{name: value}, body)."""
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = data.partition(b"\n\n")
    lines = head.decode("iso-8859-1", "replace").splitlines()
    if not lines:
        raise ValueError("empty raw request")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("raw request must start with 'METHOD target HTTP/1.1'")
    method, target = parts[0].upper(), parts[1]
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        name, sep2, value = line.partition(":")
        if sep2:
            headers[name.strip().lower()] = value.strip()
    host = headers.get("host", "").strip()
    if target.lower().startswith(("http://", "https://")):
        url = target
    elif not host:
        raise ValueError("raw request needs a Host header (or an absolute-form target)")
    else:
        url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
    return method, url, headers, body[:MAX_ITEM_BYTES]


def _url_from_request_line(request: bytes) -> str:
    try:
        method, url, _, _, _, _ = parse_raw_request(request)
        return url
    except ValueError:
        return ""


def _body_pairs(content_type: str, body: bytes) -> List[Tuple[str, Any]]:
    mime = (content_type or "").split(";")[0].strip().lower()
    text = body.decode("utf-8", "replace")
    if mime in ("application/x-www-form-urlencoded", "") and "=" in text:
        return [(k, v) for k, v in parse_qsl(text, keep_blank_values=True)]
    if "multipart" in mime:
        return [(m.group(1), "") for m in
                re.finditer(r'name="([^"]{1,200})"', text)][:MAX_PART_NAMES]
    if "json" in mime or text[:1] in ("{", "["):
        try:
            return _flatten(json.loads(text))
        except ValueError:
            return []
    return []


def item_fields(item: Item) -> Dict[str, Any]:
    """Names-only observation buckets for one item (values kept only when ID-like)."""
    method, url = item.method, item.url
    request = item.request_bytes
    head = request.partition(b"\r\n\r\n")[0].decode("iso-8859-1", "replace")
    headers = {}
    for line in head.splitlines()[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    header_names = [n for n in headers if n not in ("host", "content-length", "content-type")]
    cookie_names = []
    for raw in re.findall(r"(?im)^cookie\s*:[^\r\n]*", head):
        cookie_names += [p.split("=", 1)[0].strip() for p in raw.split(":", 1)[1].split(";")
                         if p.split("=", 1)[0].strip()]
    q = [(k, v) for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    content_type = headers.get("content-type", "")
    body = _body_pairs(content_type, request.partition(b"\r\n\r\n")[2]
                       if b"\r\n\r\n" in request else b"")
    ids: Dict[str, str] = {}
    for name, val in q + body:
        if (not SENSITIVE_PARAM.search(name) and isinstance(val, (str, int))
                and not isinstance(val, bool) and id_like(str(val))):
            ids[name] = str(val)
    for i, seg in enumerate(urlsplit(url).path.split("/")):
        if seg and id_like(seg):
            ids[f"path[{i}]"] = seg
    auth = bool({n for n in headers} & AUTH_HEADERS)
    return {"query": [n for n, _ in q], "body": [n for n, _ in body],
            "header": header_names, "cookie": cookie_names, "ids": ids, "auth": auth}


def _head_pairs(raw: bytes) -> List[Tuple[str, str]]:
    head = raw.partition(b"\r\n\r\n")[0].decode("iso-8859-1", "replace")
    pairs = []
    for line in head.splitlines()[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            pairs.append((name.strip(), value.strip()))
    return pairs


def item_meta(item: Item, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Value-free CSRF metadata (recon/csrfmeta.py) for one item; repeated Set-Cookie kept."""
    request_headers = _head_pairs(item.request_bytes)
    content_type = next((v for n, v in request_headers if n.lower() == "content-type"), "")
    ops = (graphql_operations(item.url, item.request_bytes.partition(b"\r\n\r\n")[2])
           if GRAPHQL_ROUTE.search(urlsplit(item.url).path) else [])
    return request_meta(request_headers, content_type, fields.get("query") or [],
                        fields.get("body") or [], _head_pairs(item.response_bytes or b""),
                        graphql_ops=ops)


def read_items(path: Path, scheme: str = "http") -> Tuple[List[Item], str]:
    content = read_artifact(path)
    text = content.lstrip()
    if text[:5] == b"<?xml" or text[:7] == b"<items " or text[:6] == b"<items":
        items = _xml_items(content)
        return items[:MAX_RECORDS], "burp-xml"
    if text[:1] in (b"{", b"["):
        items = _json_items(content)
        return items[:MAX_RECORDS], "burp-json"
    method, url, headers, _ = parse_raw_request(content, scheme)
    return [Item(url, method, None, content, b"")], "raw-request"


def import_burp(ctx, path: Path, account: Optional[str], role: str = "", tenant: str = "",
                workflow_state: str = "", scheme: str = "http") -> Dict[str, Any]:
    items, kind = read_items(Path(path), scheme)
    if len(items) > MAX_RECORDS:
        raise ValueError(f"Burp export exceeds {MAX_RECORDS} item limit")
    content = read_artifact(path)
    context = {"account": account or "", "role": role, "tenant": tenant,
               "workflow_state": workflow_state, "basis": "captured-real-traffic"}
    import_id = ctx.store.register_import("burp", content, context)
    stats = {"items": len(items), "format": kind, "endpoints": 0, "out_of_scope": 0,
             "static": 0, "duplicate_samples": 0, "malformed": 0, "responses_stored": 0}
    for index, item in enumerate(items):
        try:
            url = item.url
            if not url.startswith(("http://", "https://")):
                stats["malformed"] += 1
                continue
            method = item.method.upper()
            if method not in HTTP_METHODS:
                stats["malformed"] += 1
                continue
            if not ctx.scope.is_in(url):
                stats["out_of_scope"] += 1
                aid = ctx.intel(origin_of(url), f"seen in {account or 'Burp'} traffic", "burp")
                ctx.store.provenance(aid, import_id, index, "captured-real-traffic")
                continue
            path_ = urlsplit(url).path
            if is_static(path_):
                stats["static"] += 1
                continue
            fields = item_fields(item)
            names = fields["query"] + fields["body"] + fields["header"] + fields["cookie"]
            mime = (item.request_bytes.partition(b"\r\n\r\n")[0].decode("iso-8859-1", "replace"))
            ct = ""
            for line in mime.splitlines()[1:]:
                n, _, v = line.partition(":")
                if n.strip().lower() == "content-type":
                    ct = v.strip().split(";")[0].lower()
            eid = ctx.add_endpoint(url, "burp", method=method, params=names, extra={
                "auth_seen": fields["auth"], "id_params": sorted(fields["ids"]),
                "accounts": [account] if account else [],
                "content_types": [ct] if ct else [],
                "basis": "captured-real-traffic"})
            if eid is None:
                stats["static"] += 1
                continue
            stats["endpoints"] += 1
            ctx.store.provenance(eid, import_id, index, "captured-real-traffic")
            if not ctx.store.add_observation(
                    eid, method, account, fields, item.status, "burp",
                    capture_key=f"burp:{import_id}:{index}",
                    context={**context, "import_id": import_id, "record_index": index,
                             "path": path_, "csrf_meta": item_meta(item, fields)}):
                stats["duplicate_samples"] += 1
                continue
            if item.response_bytes or item.request_bytes:
                resp_head = item.response_bytes.partition(b"\r\n\r\n")[0].decode(
                    "iso-8859-1", "replace")
                resp_headers: Dict[str, str] = {}
                for line in resp_head.splitlines()[1:]:
                    n, _, v = line.partition(":")
                    if n.strip():
                        # Names only; header values (incl. Set-Cookie) are never stored.
                        resp_headers[n.strip()] = f"(len {len(v.strip())})"
                resp_body = item.response_bytes.partition(b"\r\n\r\n")[2] \
                    if b"\r\n\r\n" in item.response_bytes else b""
                req_body = item.request_bytes.partition(b"\r\n\r\n")[2] \
                    if b"\r\n\r\n" in item.request_bytes else b""
                ctx.store.record_request(
                    method, url, item.status, "burp-import",
                    [n for n in (fields["header"] + fields["cookie"])], resp_headers,
                    body=resp_body, body_complete=True, basis="imported-burp-capture",
                    context={"import_id": import_id, "record_index": index},
                    req_body=req_body, req_content_type=ct or None)
                stats["responses_stored"] += 1
        except (ValueError, TypeError, AttributeError):
            stats["malformed"] += 1
    ctx.store.record_import_result(import_id, stats)
    return stats
