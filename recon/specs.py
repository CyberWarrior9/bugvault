"""OpenAPI/Swagger spec import (offline): declared fields with exact locations.

Reads an operator-supplied JSON spec file (the operator fetched it in-scope or
it was shared by the program; this module performs no fetch). Each
path x method becomes an endpoint with ``spec_fields`` attrs (method, location,
name), which `recon fields sync` turns into ledger rows with the spec's exact
location (query/path/header/cookie/body->json, form, multipart). Declared request
content types and security schemes (cookie / browser-managed / header authority)
are kept per operation for the CSRF action ledger. Swagger 2.0 ``host``/``basePath``
specs and OpenAPI 3 ``servers`` are both supported; YAML is not parsed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

from .ingest import read_artifact
from .campaign import HTTP_METHODS

MAX_FIELDS_PER_OPERATION = 200
MAX_DEPTH = 6


def _leaf_names(schema: Any, prefix: str, depth: int, out: List[str]) -> None:
    """Schema property leaf names as dotted paths; arrays record the wrapper."""
    if depth > MAX_DEPTH or len(out) >= MAX_FIELDS_PER_OPERATION or not isinstance(schema, dict):
        return
    if schema.get("type") == "object" or "properties" in schema:
        for name, sub in (schema.get("properties") or {}).items():
            sub = sub or {}
            path = f"{prefix}.{name}" if prefix else str(name)
            if sub.get("type") == "object" or "properties" in sub:
                _leaf_names(sub, path, depth + 1, out)
            elif sub.get("type") == "array":
                out.append(f"{path}[]")
                items = sub.get("items")
                if isinstance(items, dict) and items.get("properties"):
                    _leaf_names(items, f"{path}[0]", depth + 2, out)
            else:
                out.append(path)
    elif schema.get("type") == "array":
        out.append(f"{prefix}[]" if prefix else "[]")


def _base_url(data: Dict[str, Any]) -> str:
    if isinstance(data.get("servers"), list) and data["servers"]:
        base = str(data["servers"][0].get("url") or "")
        if base.startswith(("http://", "https://")):
            return base.rstrip("/")
    host = str(data.get("host") or "")
    if host:
        schemes = data.get("schemes") or ["https"]
        base = f"{str(schemes[0]).lower()}://{host}"
        bp = str(data.get("basePath") or "")
        return (base + bp).rstrip("/")
    raise ValueError("spec needs servers[].url (OpenAPI 3) or host/basePath (Swagger 2); "
                     "it is imported offline, never fetched")


FORM_TYPES = {"application/x-www-form-urlencoded": "form", "multipart/form-data": "multipart"}


def _scheme_labels(data: Dict[str, Any]) -> Dict[str, str]:
    """Security scheme name -> CSRF authority label (cookie / browser-auth / header)."""
    schemes = ((data.get("components") or {}).get("securitySchemes")
               if isinstance(data.get("components"), dict) else None) or data.get("securityDefinitions")
    labels: Dict[str, str] = {}
    for name, scheme in (schemes.items() if isinstance(schemes, dict) else []):
        if not isinstance(scheme, dict):
            continue
        kind, where = str(scheme.get("type", "")).lower(), str(scheme.get("in", "")).lower()
        http_scheme = str(scheme.get("scheme", "")).lower()
        if kind == "apikey":
            labels[str(name)] = "cookie" if where == "cookie" else "header"
        elif kind == "basic" or (kind == "http" and http_scheme in ("basic", "digest")):
            labels[str(name)] = "browser-auth"
        elif kind in ("http", "oauth2", "openidconnect"):
            labels[str(name)] = "header"
    return labels


def parse_operation_details(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every supported operation: method, url, fields [{method, location, name}],
    declared request content types and authority labels (offline; never fetched)."""
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        raise ValueError("expected an OpenAPI/Swagger object with a paths map")
    base = _base_url(data)
    labels = _scheme_labels(data)
    root_security = data.get("security") if isinstance(data.get("security"), list) else None
    root_consumes = data.get("consumes") if isinstance(data.get("consumes"), list) else []
    out = []
    for path, ops in data["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            method = method.upper()
            if method not in HTTP_METHODS or not isinstance(op, dict):
                continue
            fields: List[Dict[str, str]] = []
            for param in op.get("parameters") or []:
                if isinstance(param, dict) and isinstance(param.get("name"), str):
                    where = {"formData": "form"}.get(param.get("in"), param.get("in"))
                    if where in ("query", "path", "header", "cookie", "form"):
                        fields.append({"method": method, "location": where,
                                       "name": param["name"][:200]})
                    elif where == "body":  # Swagger 2 body parameter
                        leaves: List[str] = []
                        _leaf_names(param.get("schema"), "", 0, leaves)
                        fields += [{"method": method, "location": "body", "name": leaf[:200]}
                                   for leaf in leaves[:MAX_FIELDS_PER_OPERATION]]
            body = (op.get("requestBody") or {}).get("content", {}) \
                if isinstance(op.get("requestBody"), dict) else {}
            body = body if isinstance(body, dict) else {}
            content_types = sorted({str(t).split(";")[0].strip().lower() for t in body}
                                   | {str(t).split(";")[0].strip().lower()
                                      for t in (op.get("consumes") if isinstance(op.get("consumes"), list)
                                                else root_consumes)
                                      if any(f["location"] in ("form", "body") for f in fields)})
            json_type = next((t for t in body if "json" in str(t).lower()), None)
            form_type = next((t for t in body if str(t).split(";")[0].strip().lower() in FORM_TYPES), None)
            chosen = json_type or form_type
            schema = (body.get(chosen) or {}).get("schema") if chosen else None
            location = "body" if chosen == json_type else FORM_TYPES.get(
                str(chosen).split(";")[0].strip().lower(), "body")
            leaves = []
            _leaf_names(schema, "", 0, leaves)
            fields += [{"method": method, "location": location, "name": leaf[:200]}
                       for leaf in leaves[:MAX_FIELDS_PER_OPERATION]]
            security = op.get("security") if isinstance(op.get("security"), list) else root_security
            auth = sorted({labels.get(str(name), "header") for req in security or []
                           if isinstance(req, dict) for name in req})
            out.append({"method": method, "url": base + path,
                        "fields": fields[:MAX_FIELDS_PER_OPERATION],
                        "content_types": [t for t in content_types if t][:10], "auth": auth})
    return out


def parse_operations(data: Dict[str, Any]) -> List[Tuple[str, str, List[Dict[str, str]]]]:
    """(method, url, [{method, location, name}]) for every supported operation."""
    return [(op["method"], op["url"], op["fields"]) for op in parse_operation_details(data)]


def import_openapi(ctx, path: Path) -> Dict[str, Any]:
    content = read_artifact(path)
    data = json.loads(content.decode("utf-8-sig"))
    operations = parse_operation_details(data)
    context = {"basis": "openapi-spec", "adapter_version": 1}
    import_id = ctx.store.register_import("openapi", content, context)
    stats = {"operations": len(operations), "endpoints": 0, "fields": 0,
             "out_of_scope": 0, "duplicate_samples": 0, "malformed": 0}
    for index, op in enumerate(operations):
        method, url, fields = op["method"], op["url"], op["fields"]
        try:
            names = [f["name"] for f in fields]
            extra: Dict[str, Any] = {"spec_fields": fields, "accounts": [],
                                     "basis": "openapi-spec"}
            if op["content_types"]:
                extra["spec_content_types"] = op["content_types"]
            if op["auth"]:
                extra["spec_auth"] = op["auth"]
            eid = ctx.add_endpoint(url, "openapi", method=method, params=names, extra=extra)
            if eid is None:
                stats["out_of_scope"] += 1
                continue
            stats["endpoints"] += 1
            stats["fields"] += len(fields)
            ctx.store.provenance(eid, import_id, index, "openapi-spec")
        except (ValueError, TypeError, AttributeError):
            stats["malformed"] += 1
    ctx.store.record_import_result(import_id, stats)
    return stats
