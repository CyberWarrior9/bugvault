"""Heuristic investigation priority and endpoint x bug-class applicability.

Higher scores prioritize interesting source/auth/version/parameter signals. They
cannot establish what other researchers tested or predict duplicate-report status.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlsplit

from .extract import VERSION_SEG

LINKED_SOURCES = {"html", "sitemap", "har", "form", "oidc"}
CODE_SOURCES = {"js", "inline", "sourcemap"}
INFERRED_ONLY = {"version-sibling"}

INTERNAL = re.compile(r"admin|internal|debug|staff|employee|backoffice|manage|console|"
                      r"export|import|backup|restore|batch|bulk|webhook|callback|migrat|"
                      r"impersonat|sudo|actuator|metrics|health|swagger|openapi|graphiql", re.I)
AUTH_PATH = re.compile(r"login|signin|sign-in|signup|register|password|passwd|reset|forgot|"
                       r"otp|mfa|2fa|totp|verif|session|token|oauth|authorize|sso|saml|"
                       r"change-?email|email/change|recover", re.I)
MONEY = re.compile(r"pay|checkout|order|cart|coupon|promo|voucher|redeem|gift|transfer|"
                   r"withdraw|balance|wallet|credit|refund|invite|vote|claim|reward|"
                   r"subscri|billing|plan|quota|limit", re.I)
RENDER = re.compile(r"export|report|pdf|render|preview|screenshot|thumbnail|convert|print",
                    re.I)
UPLOAD = re.compile(r"upload|import|avatar|attachment|/files?(?:/|$)|media|image", re.I)
URLISH = {"url", "uri", "link", "href", "src", "redirect", "redirect_uri", "redirect_url",
          "redirecturl", "return", "returnto", "return_to", "returnurl", "return_url", "next",
          "continue", "dest", "destination", "target", "callback", "callback_url", "webhook",
          "webhook_url", "feed", "image_url", "imageurl", "avatar_url", "proxy", "fetch",
          "domain", "host", "site", "endpoint", "origin"}
REDIRECTISH = {"redirect", "redirect_uri", "redirect_url", "redirecturl", "return", "returnto",
               "return_to", "returnurl", "return_url", "next", "continue", "dest",
               "destination", "goto", "to", "r", "u"}
FILEISH = {"file", "filename", "filepath", "file_path", "path", "doc", "document", "template",
           "include", "dir", "folder", "download", "attachment", "lang", "locale"}


def sources(a: Dict[str, Any]) -> Set[str]:
    return set(a.get("attrs", {}).get("sources", []))


def is_inferred_only(a: Dict[str, Any]) -> bool:
    s = sources(a)
    return bool(s) and s <= INFERRED_ONLY


def version_index(endpoints: List[Dict[str, Any]]) -> Dict[str, int]:
    """'https://h/api/v*/users' -> highest version number seen (real endpoints only)."""
    idx: Dict[str, int] = {}
    for e in endpoints:
        if is_inferred_only(e):
            continue
        m = VERSION_SEG.search(urlsplit(e["value"]).path)
        if m:
            key = VERSION_SEG.sub("/v*", e["value"], count=1)
            idx[key] = max(idx.get(key, 0), int(m.group(1)))
    return idx


def freshness(e: Dict[str, Any], vidx: Dict[str, int]) -> Tuple[int, List[str]]:
    a = e.get("attrs", {})
    s = sources(e)
    path = urlsplit(e["value"]).path
    score, why = 0, []
    linked = bool(s & LINKED_SOURCES)
    if s and s <= {"wayback"}:
        score += 3
        why.append("archived-only: existed, gone from current UI/JS")
    elif "sourcemap" in s and not linked and not (s & {"js", "inline"}):
        score += 3
        why.append("only in source-map original code")
    elif s & CODE_SOURCES and not linked and "runtime" not in s:
        score += 2
        why.append("referenced in JS, never linked/called in UI")
    if "runtime" in s and not (s & {"har", "html", "sitemap"}):
        score += 1
        why.append("called only behind the client login gate")
    if "robots" in s:
        score += 2
        why.append("robots.txt-disallowed")
    if a.get("auth_seen"):
        score += 2
        why.append("authenticated surface")
    m = VERSION_SEG.search(path)
    if m:
        key = VERSION_SEG.sub("/v*", e["value"], count=1)
        if vidx.get(key, 0) > int(m.group(1)):
            score += 2
            why.append(f"older API version (v{vidx[key]} exists)")
    n = len(a.get("params", []))
    if n:
        score += min(3, n)
        why.append(f"{n} params")
    if a.get("id_params") or "{id}" in path:
        score += 1
        why.append("object IDs in request")
    if INTERNAL.search(path):
        score += 1
        why.append("internal/admin/export-type path")
    if a.get("api_like"):
        score += 1
    return score, why


def applicable_classes(e: Dict[str, Any]) -> Dict[str, str]:
    """Which bug classes apply to this endpoint, with the reason (seeds coverage rows)."""
    a = e.get("attrs", {})
    path = urlsplit(e["value"]).path.lower()
    params = {p.lower() for p in a.get("params", [])}
    methods = {m.upper() for m in a.get("methods", []) if m}
    writes = methods & {"POST", "PUT", "PATCH", "DELETE"}
    out: Dict[str, str] = {}
    if a.get("id_params") or "{id}" in path:
        out["idor-bola"] = "object identifiers in path/params"
    if a.get("api_like") and not out.get("idor-bola"):
        out["access-control"] = "API endpoint: call unauthenticated / as lower role"
    if INTERNAL.search(path):
        out["access-control"] = "internal/admin-type path: unguarded-sibling check"
    if params & URLISH:
        out["ssrf"] = f"URL-like params: {sorted(params & URLISH)}"
    if params & REDIRECTISH:
        out["open-redirect"] = f"redirect-like params: {sorted(params & REDIRECTISH)}"
    if params & FILEISH:
        out["file-read"] = f"file/path-like params: {sorted(params & FILEISH)}"
    if params:
        out["xss"] = "reflected/stored input"
        out["sqli"] = "parameterized input"
    if writes:
        out["csrf"] = f"state-changing methods {sorted(writes)}"
        if writes & {"POST", "PUT", "PATCH"}:
            out["mass-assignment"] = "write endpoint: add privileged fields"
    if AUTH_PATH.search(path):
        out["ato"] = "auth/account flow"
        if re.search(r"otp|mfa|2fa|totp|verif", path):
            out["mfa-bypass"] = "second-factor flow"
        if re.search(r"oauth|authorize|sso|openid", path):
            out["oauth"] = "OAuth/OIDC flow"
        if "saml" in path:
            out["saml"] = "SAML flow"
    if MONEY.search(path):
        out["business-logic"] = "value/limit/state transitions"
        if writes or not methods:
            out["race-conditions"] = "check-then-act on money/limits"
    if RENDER.search(path):
        out["ssrf"] = out.get("ssrf", "server-side render/export (headless browser SSRF)")
    if UPLOAD.search(path) and (writes or not methods):
        out["file-upload"] = "upload/import surface"
    if "graphql" in path or "gql" in path:
        out["graphql"] = "GraphQL: node()/field authz, batching"
        out.setdefault("idor-bola", "GraphQL object access")
    if re.search(r"\.xml$|soap|wsdl|xmlrpc", path) or "xml" in " ".join(a.get("content_types", [])):
        out["xxe"] = "XML parsing surface"
    return out
