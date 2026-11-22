"""Heuristic investigation priority and endpoint x bug-class applicability.

Higher scores prioritize interesting source/auth/version/parameter signals. They
cannot establish what other researchers tested or predict duplicate-report status.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlsplit

from .csrfmeta import ACTION_PARAMS, MUTATING, split_camel
from .extract import VERSION_SEG

LINKED_SOURCES = {"html", "sitemap", "har", "form", "oidc"}
CODE_SOURCES = {"js", "inline", "sourcemap"}
INFERRED_ONLY = {"version-sibling"}

INTERNAL = re.compile(r"admin|internal|debug|staff|employee|backoffice|manage|console|"
                      r"export|import|backup|restore|batch|bulk|webhook|callback|migrat|"
                      r"impersonat|sudo|actuator|metrics|health|swagger|openapi|graphiql", re.I)
AUTH_PATH = re.compile(r"login|signin|sign-in|signup|register|password|passwd|reset|forgot|"
                       r"otp|mfa|2fa|totp|verif|session|token|logout|signout|oauth|authorize|sso|saml|"
                       r"change-?email|email/change|recover", re.I)
MONEY = re.compile(r"(?<![a-z0-9])(?:pay|checkout|orders?|carts?|coupons?|promos?|vouchers?|"
                   r"redeem|gifts?|transfer|withdraw|balances?|wallets?|credits?|refunds?|"
                   r"invites?|votes?|claim|rewards?|subscriptions?|billing|plans?|quotas?|limits?|"
                   r"entitlements?|approvals?|trials?)(?![a-z0-9])", re.I)
RENDER = re.compile(r"export|report|pdf|render|preview|screenshot|thumbnail|convert|print",
                    re.I)
UPLOAD = re.compile(r"upload|import|avatar|attachment|/files?(?:/|$)|media|image", re.I)
SECURITY_SURFACE = re.compile(r"(?:^|/)(?:\.env(?:\.|$)|\.git(?:/|$)|config(?:\.|/)|"
                              r"actuator(?:/|$)|debug(?:/|$)|[^/]+\.(?:bak|old|backup)$)", re.I)
URLISH = {"url", "uri", "link", "href", "src", "redirect", "redirect_uri", "redirect_url",
          "redirecturl", "return", "returnto", "return_to", "returnurl", "return_url", "next",
          "continue", "dest", "destination", "target", "callback", "callback_url", "webhook",
          "webhook_url", "feed", "image_url", "imageurl", "avatar_url", "proxy", "fetch",
          "domain", "host", "site", "endpoint", "origin"}
SSRF_SURFACE = re.compile(r"(?:^|[/_-])(?:fetch|proxy|import|webhooks?|callbacks?|subscribe|"
                          r"feeds?|unfurl|embed|oembed|pingback|trackback)(?:[/_-]|$)", re.I)
SSRF_FIELDS = {re.sub(r"[^a-z0-9]", "", p) for p in URLISH} | {
    "image", "avatar", "sourceurl", "destinationurl", "callbackurl", "webhookurl",
    "fetchurl", "remoteurl", "baseurl", "apiurl", "documenturl", "fileurl", "targeturl",
    "feedurl", "serviceurl", "consumeruri", "subscribeurl", "shards"}


def ssrf_parameters(params) -> List[str]:
    """Name heuristics only, including camelCase and JSON/form leaf fields; never a fetch proof."""
    matched = []
    for value in params:
        if not isinstance(value, str):
            continue
        leaves = re.findall(r"[a-z][a-z0-9_-]*", value.lower())
        leaf = re.sub(r"[^a-z0-9]", "", leaves[-1]) if leaves else ""
        if leaf in SSRF_FIELDS or leaf.endswith(("url", "uri")):
            matched.append(value)
    return sorted(set(matched))


REDIRECTISH = {"redirect", "redirect_uri", "redirect_url", "redirecturl", "return", "returnto",
               "return_to", "returnurl", "return_url", "next", "continue", "dest",
               "destination", "goto", "to", "r", "u"}
FILEISH = {"file", "filename", "filepath", "file_path", "path", "doc", "document", "template",
           "include", "dir", "folder", "download", "attachment", "lang", "locale"}

# Content-ish fields: the classic stored-XSS / HTML-injection carriers (first name,
# last name, username, bio, comment, ...). Leaf-name normalized like SSRF_FIELDS.
CONTENTISH = {"bio", "biography", "description", "comment", "comments", "content", "message",
              "text", "body", "html", "about", "summary", "notes", "note", "markdown",
              "signature", "title", "name", "firstname", "first_name", "lastname",
              "last_name", "username", "nickname", "displayname", "display_name", "city",
              "address", "headline", "status"}
# Template-y fields on render/export surfaces: SSTI candidates.
TEMPLATEISH = {"template", "tpl", "theme", "lang", "locale", "format", "layout", "view",
               "style", "render", "engine", "skin", "preview_id", "jinja", "velocity",
               "freemarker", "twig"}


def _leaf(value: str) -> str:
    words = re.findall(r"[a-z][a-z0-9_-]*", value.lower())
    return re.sub(r"[^a-z0-9]", "", words[-1]) if words else ""


def content_parameters(params) -> List[str]:
    return sorted({p for p in params if isinstance(p, str) and _leaf(p) in CONTENTISH})


def template_parameters(params) -> List[str]:
    return sorted({p for p in params if isinstance(p, str) and _leaf(p) in TEMPLATEISH})


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
    # Explicit operator review only: banners/H2 support do not prove a parser pair.
    if a.get("http_smuggling_review") is True:
        out["http-smuggling"] = ("operator-designated HTTP boundary review; "
                                 "topology and parser disagreement unverified")
    # Explicit operator review only: no cache header, CDN fingerprint or asset path
    # proves shared-cache keying/eligibility; the row marks a designated review.
    if a.get("cache_review") is True:
        out["cache"] = ("operator-designated shared-cache review; keying, eligibility "
                        "and layer unverified")
    if a.get("id_params") or "{id}" in path:
        out["idor-bola"] = "object identifiers in path/params"
    if a.get("api_like") and not out.get("idor-bola"):
        out["access-control"] = "API endpoint: call unauthenticated / as lower role"
    if INTERNAL.search(path):
        out["access-control"] = "internal/admin-type path: unguarded-sibling check"
    ssrf_fields = ssrf_parameters(a.get("params", []))
    if ssrf_fields:
        out["ssrf"] = f"URL-like params (candidate, not a fetch proof): {ssrf_fields}"
    elif SSRF_SURFACE.search(path):
        out["ssrf"] = "fetch/import/proxy/webhook surface (candidate; verify server-side behavior)"
    if params & REDIRECTISH:
        out["open-redirect"] = f"redirect-like params: {sorted(params & REDIRECTISH)}"
    if params & FILEISH:
        out["file-read"] = f"file/path-like params: {sorted(params & FILEISH)}"
    if params:
        out["xss"] = "reflected/stored input"
        out["sqli"] = "parameterized input"
        content = content_parameters(a.get("params", []))
        if content:
            out["html-injection"] = f"content-ish fields (stored/rendered input): {content[:6]}"
        tpl = template_parameters(a.get("params", []))
        if tpl:
            out["ssti"] = f"tier 1: template-ish fields (candidate, not evaluation proof): {tpl[:6]}"
        elif RENDER.search(path) or re.search(r"email|notify|invoice|mail|theme", path, re.I):
            out["ssti"] = "tier 2: input on a render/delivery surface (candidate only)"
        else:
            out["ssti"] = "tier 3: parameterized input; low-prior template evaluation check"
    if writes:
        out["csrf"] = f"state-changing methods {sorted(writes)}"
        out["mass-assignment"] = ("write endpoint candidate (including DELETE; "
                                  "assignable fields and server acceptance unproven)")
    elif urlsplit(e["value"]).scheme in ("ws", "wss"):
        out["csrf"] = "realtime handshake: a cookie-authenticated connection can carry actions"
    elif not methods - {"GET", "HEAD"}:
        # GET-only or method unknown: a state-change verb or action selector still makes
        # it a CSRF action candidate (a cross-site GET navigation carries Lax cookies).
        verbs = sorted({m.group(0).lower() for m in
                        MUTATING.finditer(split_camel(urlsplit(e["value"]).path))})
        selectors = sorted(params & ACTION_PARAMS)
        if verbs or selectors:
            out["csrf"] = f"GET/unknown-method action with a state-change signal: {(verbs + selectors)[:4]}"
    if AUTH_PATH.search(path):
        out["ato"] = "auth/account flow"
        out["security-misconfiguration"] = ("auth entry-point security-policy review; "
                                             "weak policy alone is not a confirmed finding")
        if re.search(r"otp|mfa|2fa|totp|verif", path):
            out["mfa-bypass"] = "second-factor flow"
        if re.search(r"oauth|authorize|sso|openid", path):
            out["oauth"] = "OAuth/OIDC flow"
        if "saml" in path:
            out["saml"] = "SAML flow"
    if a.get("security_review") is True or SECURITY_SURFACE.search(path):
        out["security-misconfiguration"] = ("operator-designated/config-exposure posture review; "
                                             "verify exact response and consequence")
    selectors = [str(v) for k in ("graphql_ops", "selectors", "actions") for v in a.get(k, [])
                 if isinstance(v, str)]
    selectors += [str(a.get("selector", ""))]
    semantic = bool(MONEY.search(split_camel(path)) or any(MONEY.search(split_camel(v)) for v in selectors))
    mutation = any(re.search(r"\bmutation\b", v, re.I) for v in selectors)
    action = bool(MUTATING.search(split_camel(path)) or any(MUTATING.search(split_camel(v)) for v in selectors))
    limited = bool(params & {"limit", "quantity", "amount", "coupon", "promo", "idempotency_key"})
    if semantic or mutation or action and limited:
        out["business-logic"] = "candidate action/limit signal; owner rule and effect unverified"
        if writes or mutation or methods == {"GET"} and action or not methods:
            out["race-conditions"] = "candidate write/limited action; shared resource and overlap unverified"
    if RENDER.search(path):
        out["ssrf"] = out.get("ssrf", "server-side render/export (headless browser SSRF)")
    if UPLOAD.search(path) and (writes or not methods):
        out["file-upload"] = "upload/import surface"
        out.setdefault("ssti", "tier 2: upload/import may be rendered later (candidate only)")
    if "graphql" in path or "gql" in path:
        out["graphql"] = "GraphQL: node()/field authz, batching"
        out.setdefault("idor-bola", "GraphQL object access")
    if re.search(r"\.xml$|soap|wsdl|xmlrpc", path) or "xml" in " ".join(a.get("content_types", [])):
        out["xxe"] = "XML parsing surface"
    return out
