"""Privacy-preserving request and cookie metadata for CSRF action contexts.

Pure functions: no I/O, no network. Header and cookie VALUES never leave these
functions, except enumerated security attributes (SameSite, Sec-Fetch-*) and
parsed origins (scheme://host[:port]; never a path or query). Token values,
session values and Referer paths/queries are dropped.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlsplit

META_VERSION = 1

# Names of anti-CSRF token channels (parameters, headers, cookies). Deliberately
# excludes bare `token`/`nonce`/`state`: those are usually reset, API or protocol
# values, handled by the identity-transaction family instead.
TOKENISH = re.compile(
    r"csrf|xsrf|authenticity[_-]?token|anti-?forgery|request-?verification-?token|"
    r"__requestverificationtoken|csrfmiddlewaretoken|^_token$|wpnonce|^__rvt$", re.I)
# Constant custom-header defenses (presence forces a CORS preflight cross-origin).
STATIC_FLAG_HEADERS = {"x-requested-with", "x-csrf"}
EXPLICIT_AUTH_HEADERS = {"authorization", "x-api-key", "api-key", "x-auth-token",
                         "x-access-token", "x-session-token"}
SESSIONISH_COOKIE = re.compile(r"sess|sid|auth|jwt|login|remember|identity|aspnetcore|"
                               r"aspxauth|connect\.sid", re.I)
SAMESITE_VALUES = ("lax", "strict", "none")
# Authorization schemes the browser itself caches and re-sends (ambient, like cookies),
# versus tokens application code attaches explicitly (bearer).
BROWSER_AUTH_SCHEMES = {"basic", "digest", "ntlm", "negotiate"}
AMBIENT_AUTH = ("cookie", "cookie+header", "browser-auth")
SIMPLE_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
def words(*alternatives: str) -> "re.Pattern[str]":
    """Whole-token match inside a route/name: `delete` hits /items/delete, not /deleted."""
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(alternatives) + r")(?![a-z0-9])", re.I)


# State-change verbs in a route or parameter name: the GET/fieldless action signal.
MUTATING = words(
    "delete", "remove", "destroy", "purge", "drop", "logout", "log-?out", "signout",
    "sign-?out", "approve", "reject", "confirm", "cancel", "activate", "deactivate", "enable",
    "disable", "unsubscribe", "subscribe", "follow", "unfollow", "invite", "accept", "decline",
    "transfer", "withdraw", "grant", "revoke", "link", "unlink", "connect", "disconnect",
    "reset", "change", "update", "set", "toggle", "add", "create", "save", "submit", "publish",
    "unpublish", "archive", "unarchive", "restore", "vote", "like", "unlike", "join", "leave",
    "block", "unblock", "verify", "claim", "redeem", "assign", "unassign", "move", "rename",
    "send", "mark", "clear", "install", "uninstall", "import")
ACTION_PARAMS = {"action", "do", "op", "cmd", "command", "task", "_method", "method", "operation"}
GRAPHQL_ROUTE = words("graphql", "gql")
_GQL_DOC = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w{0,80})")
_GQL_ANON = re.compile(r"\s*(query|mutation|subscription)?\s*[{(]")
_GQL_NAME = re.compile(r"[A-Za-z_]\w{0,80}")


def split_camel(text: str) -> str:
    """`updateEmail` -> `update-Email`, so whole-word patterns see camelCase words."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", text or "")


def graphql_operations(url: str, body: Any) -> List[str]:
    """`<type> <name>` of the GraphQL operations one request carries, e.g.
    `mutation updateEmail`. Structure only: documents and variables are never kept.
    A persisted query without a document yields `persisted <name>` (type unknown)."""
    docs: List[Tuple[str, str]] = []
    try:
        query = parse_qs(urlsplit(url or "").query)
    except ValueError:
        query = {}
    if "query" in query or "operationName" in query:
        docs.append(((query.get("query") or [""])[0], (query.get("operationName") or [""])[0]))
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    if isinstance(text, str) and text.strip():
        try:
            data = json.loads(text[:2_000_000])
        except ValueError:
            data = None
            form = parse_qs(text[:200_000])
            if "query" in form or "operationName" in form:
                docs.append(((form.get("query") or [""])[0], (form.get("operationName") or [""])[0]))
        for item in (data if isinstance(data, list) else [data])[:20]:
            if isinstance(item, dict) and ("query" in item or "operationName" in item):
                doc, name = item.get("query"), item.get("operationName")
                docs.append((doc if isinstance(doc, str) else "", name if isinstance(name, str) else ""))
    ops: List[str] = []
    for doc, name in docs:
        found = [f"{t} {n}" for t, n in _GQL_DOC.findall(doc[:20000])]
        if name and _GQL_NAME.fullmatch(name):
            found = [f for f in found if f.endswith(" " + name)] or found or [f"persisted {name}"]
        if not found:
            anon = _GQL_ANON.match(doc)
            if anon:
                found = [f"{anon.group(1) or 'query'} (anonymous)"]
        ops += found
    return sorted(set(ops))[:10]
_SEC_FETCH = {"sec-fetch-site": "site", "sec-fetch-mode": "mode", "sec-fetch-dest": "dest",
              "sec-fetch-user": "user"}
_SEC_VALUE = re.compile(r"[a-z?0-9-]{1,24}")
_DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443}
MAX_NAMES = 60
MAX_SET_COOKIES = 40


def mime_of(content_type: Any) -> str:
    """Canonical media type without parameters (boundaries/charsets never churn identity)."""
    if not isinstance(content_type, str):
        return ""
    return content_type.split(";", 1)[0].strip().lower()[:100]


def norm_origin(value: Any) -> Optional[str]:
    """`scheme://host[:port]` of an http(s)/ws(s) URL or origin, `null` for an opaque
    origin, None when unparseable. Paths, queries and credentials are discarded."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text == "null":
        return "null"
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in _DEFAULT_PORT or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port and port != _DEFAULT_PORT[parts.scheme] else ""
    return f"{parts.scheme}://{host}{suffix}"


def parse_set_cookie(value: Any) -> Optional[Dict[str, Any]]:
    """Name and attributes of one Set-Cookie header value; the cookie value is discarded.

    `samesite` stays None when the attribute is omitted: an omitted SameSite is
    browser-default behaviour, not the same thing as an explicit `Lax`."""
    if not isinstance(value, str) or not value.strip():
        return None
    parts = value.split(";")
    name, sep, _ = parts[0].partition("=")
    name = name.strip()
    if not sep or not name or len(name) > 200 or any(c in name for c in ' \t,"\\;'):
        return None
    record: Dict[str, Any] = {
        "name": name, "samesite": None, "secure": False, "httponly": False,
        "domain": None, "path": None, "partitioned": False, "persistent": False,
        "prefix": "__Host-" if name.startswith("__Host-") else
                  "__Secure-" if name.startswith("__Secure-") else None}
    for attr in parts[1:]:
        key, _, val = attr.strip().partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "samesite":
            record["samesite"] = val.lower() if val.lower() in SAMESITE_VALUES else "invalid"
        elif key == "secure":
            record["secure"] = True
        elif key == "httponly":
            record["httponly"] = True
        elif key == "domain" and val:
            record["domain"] = val.lower().lstrip(".")[:253] or None
        elif key == "path" and val.startswith("/"):
            record["path"] = val[:200]
        elif key == "partitioned":
            record["partitioned"] = True
        elif key in ("max-age", "expires") and val:
            record["persistent"] = True
    return record


def cookie_applies(record: Dict[str, Any], source_host: str, target_host: str) -> bool:
    """Would a cookie set by `source_host` be sent to `target_host` (host/Domain scope)?"""
    domain = record.get("domain")
    if not domain:
        return (source_host or "") == (target_host or "")
    return target_host == domain or (target_host or "").endswith("." + domain)


def request_meta(headers: Sequence[Tuple[str, str]], content_type: Any = "",
                 query_names: Iterable[str] = (), body_names: Iterable[str] = (),
                 response_headers: Sequence[Tuple[str, str]] = (),
                 request_cookie_names: Iterable[str] = (),
                 graphql_ops: Iterable[str] = ()) -> Dict[str, Any]:
    """Security-relevant, value-free summary of one captured request/response."""
    names: List[str] = []
    cookie_names = [c for c in request_cookie_names if isinstance(c, str)]
    origin, referer_origin, referer_sent, auth_scheme = None, None, False, None
    sec: Dict[str, str] = {}
    for raw_name, raw_value in headers:
        name = (raw_name or "").strip().lower() if isinstance(raw_name, str) else ""
        value = raw_value if isinstance(raw_value, str) else ""
        if not name or name.startswith(":") or len(name) > 100:
            continue
        names.append(name)
        if name == "authorization":
            word = value.strip().split(" ", 1)[0].lower()
            auth_scheme = word if re.fullmatch(r"[a-z0-9-]{1,20}", word) else ("" if not word else "other")
        elif name == "cookie":
            cookie_names += [p.split("=", 1)[0].strip() for p in value.split(";")
                             if p.split("=", 1)[0].strip()]
        elif name == "origin":
            origin = norm_origin(value) or "invalid"
        elif name == "referer":
            referer_sent = True
            referer_origin = norm_origin(value)
        elif name in _SEC_FETCH:
            low = value.strip().lower()
            sec[_SEC_FETCH[name]] = low if _SEC_VALUE.fullmatch(low) else "other"
    header_set = sorted(set(names))[:MAX_NAMES]
    cookies = sorted({c for c in cookie_names if 0 < len(c) <= 200})[:MAX_NAMES]
    explicit = sorted(set(header_set) & EXPLICIT_AUTH_HEADERS)
    browser_auth = auth_scheme in BROWSER_AUTH_SCHEMES
    if browser_auth:
        explicit = [h for h in explicit if h != "authorization"]
    has_cookie = bool(cookies) or "cookie" in header_set
    auth = ("cookie+header" if has_cookie and explicit else "cookie" if has_cookie
            else "header" if explicit else "browser-auth" if browser_auth else "none")
    channels = sorted(
        {f"query:{n}" for n in query_names if isinstance(n, str) and TOKENISH.search(n)}
        | {f"body:{n}" for n in body_names if isinstance(n, str) and TOKENISH.search(n)}
        | {f"header:{n}" for n in header_set if TOKENISH.search(n) and n not in STATIC_FLAG_HEADERS})
    set_cookies = []
    for raw_name, raw_value in response_headers:
        if isinstance(raw_name, str) and raw_name.strip().lower() == "set-cookie":
            record = parse_set_cookie(raw_value)
            if record and len(set_cookies) < MAX_SET_COOKIES:
                set_cookies.append(record)
    return {"v": META_VERSION, "content_type": mime_of(content_type), "auth": auth,
            "authorization_scheme": auth_scheme,
            "explicit_auth_headers": explicit, "token_channels": channels[:40],
            "header_flags": sorted(set(header_set) & STATIC_FLAG_HEADERS),
            "csrf_cookie_names": [c for c in cookies if TOKENISH.search(c)][:20],
            "session_cookie_names": [c for c in cookies if SESSIONISH_COOKIE.search(c)][:20],
            "cookie_count": len(cookies), "origin": origin, "referer_origin": referer_origin,
            "referer_sent": referer_sent, "sec_fetch": sec, "set_cookies": set_cookies,
            "graphql_operations": [o for o in graphql_ops if isinstance(o, str)][:10]}


def har_cookie_records(cookies: Any) -> List[Dict[str, Any]]:
    """Fallback Set-Cookie attributes from a HAR `response.cookies` list (values dropped)."""
    out = []
    for c in cookies if isinstance(cookies, list) else []:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            continue
        parts = [f"{c['name']}=x"]
        if isinstance(c.get("sameSite"), str):
            parts.append(f"SameSite={c['sameSite']}")
        if c.get("secure") is True:
            parts.append("Secure")
        if c.get("httpOnly") is True:
            parts.append("HttpOnly")
        if isinstance(c.get("domain"), str) and c["domain"]:
            parts.append(f"Domain={c['domain']}")
        if isinstance(c.get("path"), str) and c["path"]:
            parts.append(f"Path={c['path']}")
        if c.get("expires"):
            parts.append("Max-Age=1")
        record = parse_set_cookie("; ".join(parts))
        if record and len(out) < MAX_SET_COOKIES:
            out.append(record)
    return out
