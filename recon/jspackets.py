"""Value-free, offline test cards for JS operation leads (never request scripts)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .extract import endpoint_key

_ID = re.compile(r"\{(?:id|[A-Za-z_]*[Ii][Dd])\}|/(?:[0-9]+|[0-9a-f]{16,})(?=/|$)")


def packet(ctx, lead: dict) -> dict:
    """Only captured *names*/labels/IDs-as-parameter-names, never values or bodies."""
    url, method = lead["url"], lead["method"]
    if lead["family"] == "J07":
        return {"operation": None, "state": "never-submit", "ceiling": "source map alone: never submit",
                "control": "test a separate endpoint or non-public disclosure in its destination skill",
                "executes": False}
    if lead["family"] == "J17":
        return {"operation": None, "asset": url, "state": "review",
                "ceiling": "info-disclosure only if source is non-public and lower-role delivery is policy-relevant",
                "control": "same exact asset under the owning operator-controlled session",
                "min_proof": "paired complete response bodies, non-public content and distinct role context",
                "executes": False}
    shape = lead["shape"]
    if isinstance(shape, str):
        import json
        shape = json.loads(shape)
    endpoint = ctx.store.find_asset("endpoint", endpoint_key(url)) if url.startswith(("http://", "https://")) else None
    observations = [o for o in ctx.store.observations(endpoint["id"])] if endpoint else []
    observations = [o for o in observations if o["source"] != "runtime" and
                    (method == "UNKNOWN" or o["method"] == method)]
    contexts = []
    names = set(shape.get("headers", []))
    objects = []
    for o in observations[:20]:
        meta = o["context"].get("csrf_meta", {})
        names.update(meta.get("explicit_auth_headers", []))
        names.update(meta.get("session_cookie_names", []))
        names.update(meta.get("csrf_cookie_names", []))
        contexts.append({"capture": o["id"], "account": o["account"] or "unbound",
                         "role": o["context"].get("role") or "unbound",
                         "tenant": o["context"].get("tenant") or "unbound",
                         "workflow": o["context"].get("workflow_state") or "unbound"})
        if o["account"]:
            objects.extend({"parameter": name, "capture": o["id"],
                            "ownership": "operator-must-confirm"}
                           for name in o["params"].get("ids", {}))
    names = sorted({n for n in names if isinstance(n, str) and re.fullmatch(r"[\w-]{1,100}", n)})[:30]
    blocked = []
    if shape.get("base_unresolved"):
        blocked.append("base-unresolved")
    if shape.get("transport") == "encrypted" or shape.get("signed"):
        blocked.append("signed/encrypted: capture a fresh legitimate request")
    if method == "UNKNOWN":
        blocked.append("method-unresolved")
    if not contexts or any(not c["account"] or c["account"] == "unbound" or
                           c["role"] == "unbound" for c in contexts):
        blocked.append("role-sensitive operation has no labelled real capture")
    if _ID.search(url) and not objects:
        blocked.append("ID operation has no captured operator-owned object reference")
    if objects and _ID.search(url):
        blocked.append("object ownership still requires operator confirmation")
    ceiling = "T2 minimum: destination replay plus distinct negative control"
    if lead["family"] == "J07":
        ceiling = "never-submit alone"
    return {"operation": {"method": method, "url_template": endpoint_key(url) if
                           url.startswith(("http://", "https://")) else url,
                           "base_source": shape.get("base", "")},
            "transport": shape.get("transport", "unknown"),
            "auth_carrier": {"names": names, "value_source": "labelled capture/browser jar; values omitted"},
            "contexts": contexts, "objects": objects[:30],
            "fields": [{"name": name, "basis": shape.get("field_basis", "call-site")}
                       for name in shape.get("fields", [])[:60]],
            "gate": "static candidate only", "ladder": lead.get("lane", "general"),
            "min_proof": "unauthorized server-side capability on an owned record/action",
            "control": "separate negative control from the destination skill",
            "ceiling": ceiling, "budget": ctx.policy.max_requests,
            "state": "blocked" if blocked else "ready", "blocked_reasons": blocked,
            "executes": False}
