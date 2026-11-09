"""Bounded, offline scanner artifact ingestion. Never executes a scanner or fetches a URL.

Only documented surface records are accepted. Scanner finding/vulnerability records
are counted as unsupported, never promoted to confirmed findings.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit

from .campaign import norm_host
from .extract import origin_of, path_ext, query_keys

FORMATS = ("bbot", "subfinder", "httpx", "katana", "scopesentry")
MAX_ARTIFACT_BYTES = 25_000_000
MAX_RECORDS = 50_000
HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "WS"}


def read_artifact(path: Path, limit: int = MAX_ARTIFACT_BYTES) -> bytes:
    with Path(path).open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"artifact exceeds {limit} byte limit")
    return content


def _records(content: bytes, source: str) -> List[Tuple[int, Any]]:
    text = content.decode("utf-8-sig")
    if text.lstrip().startswith("[") or source == "scopesentry":
        data = json.loads(text)
        # ScopeSentry exports vary; support only explicit, bounded list envelopes.
        for _ in range(3):
            if not isinstance(data, dict):
                break
            keys = [k for k in ("data", "list", "items", "results") if k in data]
            if len(keys) != 1:
                raise ValueError("expected exactly one data/list/items/results envelope")
            data = data[keys[0]]
        if not isinstance(data, list):
            raise ValueError("expected a JSON list of records")
        records = list(enumerate(data))
    else:
        records = []
        for index, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                record = line.strip() if source == "subfinder" else None
            records.append((index, record))
    if len(records) > MAX_RECORDS:
        raise ValueError(f"artifact exceeds {MAX_RECORDS} record limit")
    return records


def _host(value: Any) -> Tuple[str, str]:
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("invalid host")
    host = norm_host(value)
    try:
        return "ip", str(ipaddress.ip_address(host))
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ValueError("invalid host")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
               for label in host.split(".")):
            raise ValueError("invalid host")
        return "host", host


def _url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid URL")
    p = urlsplit(value)
    if p.scheme not in ("http", "https", "ws", "wss") or not p.hostname or p.username is not None:
        raise ValueError("expected an HTTP(S)/WS(S) URL without credentials")
    _host(p.hostname)
    origin_of(value)  # validate port
    return value


def _surface_records(source: str, record: Any) -> Iterable[Tuple[str, str, str, Dict[str, Any]]]:
    """Yield kind, value, method, safe metadata; no raw headers, bodies or findings."""
    if source == "subfinder":
        value = record.get("host") if isinstance(record, dict) else record
        kind, value = _host(value)
        yield kind, value, "", {}
        return
    if not isinstance(record, dict):
        raise ValueError("expected a record object")
    if source == "bbot":
        typ, data = str(record.get("type", "")).upper(), record.get("data")
        if typ in ("DNS_NAME", "IP_ADDRESS"):
            kind, host = _host(data)
            yield kind, host, "", {}
        elif typ in ("URL", "URL_UNVERIFIED", "HTTP_RESPONSE"):
            obj = data if isinstance(data, dict) else {"url": data}
            yield "url", _url(obj.get("url")), obj.get("method", ""), {}
        elif typ == "OPEN_TCP_PORT":
            p = urlsplit("tcp://" + str(data))
            kind, host = _host(p.hostname)
            if not p.port:
                raise ValueError("missing port")
            display = f"[{host}]" if ":" in host else host
            yield "network-service", f"{display}:{p.port}", "", {"host": host, "port": p.port}
        return
    if source == "katana":
        req = record.get("request", {})
        if not isinstance(req, dict):
            raise ValueError("invalid Katana request")
        yield "url", _url(req.get("endpoint")), req.get("method", ""), {}
    elif source == "httpx":
        attrs: Dict[str, Any] = {}
        status = record.get("status_code")
        if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
            attrs["reported_status"] = status
        tech = record.get("tech")
        if isinstance(tech, list) and all(isinstance(t, str) for t in tech):
            attrs["reported_tech"] = [t[:100] for t in tech[:50]]
        yield "url", _url(record.get("url")), record.get("method", ""), attrs
    elif source == "scopesentry":
        if str(record.get("type", "")).lower() in ("vulnerability", "finding", "risk"):
            return
        if record.get("url"):
            yield "url", _url(record["url"]), record.get("method", ""), {}
        else:
            value = record.get("subdomain") or record.get("domain") or record.get("ip") or record.get("host")
            kind, value = _host(value)
            if record.get("port") is not None:
                port = int(record["port"])
                if not 1 <= port <= 65535:
                    raise ValueError("invalid port")
                display = f"[{value}]" if ":" in value else value
                yield "network-service", f"{display}:{port}", "", {"host": value, "port": port}
            else:
                yield kind, value, "", {}


def import_artifact(ctx, path: Path, source: str) -> Dict[str, Any]:
    if source not in FORMATS:
        raise ValueError(f"unsupported format: {source}")
    content = read_artifact(path)
    records = _records(content, source)  # reject invalid envelopes/size before writing
    import_id = ctx.store.register_import(source, content, {"adapter_version": 1})
    stats: Dict[str, Any] = {"import_id": import_id, "records": len(records), "accepted": 0,
                             "unsupported": 0, "malformed": 0, "out_of_scope": 0,
                             "new_assets": 0, "duplicate_records": 0, "errors": []}
    for index, record in records:
        try:
            surfaces = list(_surface_records(source, record))
            # Validate all methods before inserting any part of this record.
            for _, _, method, _ in surfaces:
                if not isinstance(method, str) or (method and method.upper() not in HTTP_METHODS):
                    raise ValueError("invalid HTTP method")
            if not surfaces:
                stats["unsupported"] += 1
                continue
            new_links = 0
            for kind, value, method, attrs in surfaces:
                before = ctx.store.total_assets()
                method = method.upper() or None
                basis = "imported-tool-output"
                attrs["bases"] = [basis]
                if kind == "url":
                    if not ctx.scope.is_in(value):
                        aid = ctx.intel(origin_of(value), "out-of-scope imported URL", source)
                        stats["out_of_scope"] += 1
                    elif path_ext(urlsplit(value).path) in ("js", "mjs", "map"):
                        typ = "sourcemap" if path_ext(urlsplit(value).path) == "map" else "js"
                        aid = ctx.add(typ, origin_of(value) + (urlsplit(value).path or "/"), source,
                                      {**attrs, "page_origin": origin_of(value), "depth": 0})
                    else:
                        ctx.add("service", origin_of(value), source, attrs)
                        aid = ctx.add_endpoint(value, source, method=method, params=query_keys(value),
                                               extra={"basis": basis})
                        if aid is None:  # a static URL still has origin-level provenance
                            aid = ctx.store.find_asset("service", origin_of(value))["id"]
                else:
                    host = attrs.get("host", value)
                    if ctx.scope.host_in(host):
                        aid = ctx.add(kind, value, source, attrs, in_scope=True)
                    else:
                        aid = ctx.intel(value, "out-of-scope imported host/service", source)
                        stats["out_of_scope"] += 1
                new_links += int(ctx.store.provenance(aid, import_id, index, basis))
                stats["new_assets"] += ctx.store.total_assets() - before
            stats["duplicate_records"] += int(new_links == 0)
            stats["accepted"] += 1
        except (ValueError, TypeError, AttributeError):
            stats["malformed"] += 1
            if len(stats["errors"]) < 20:
                # Do not echo untrusted raw records (possibly secrets) into logs/reports.
                stats["errors"].append({"record": index, "error": "invalid surface record"})
    ctx.store.record_import_result(import_id, stats)
    return stats
