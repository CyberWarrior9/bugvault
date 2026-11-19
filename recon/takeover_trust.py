"""Bounded, offline trust-reference parsing, not browser or takeover proof.

``name`` is the referenced hostname (possibly ``*.example`` for CSP). ``reference``
is the *source URL*, preserving its path, with userinfo, query and fragment removed.
Its SHA-256 binds the exact supplied URL without exporting query secrets. Callers
attach response/artifact IDs; this module does no I/O and invents no evidence IDs.
Every edge is conditional, including when the supplied capture is complete.

Cookie Domain matching uses labels, never an eTLD+1 guess. There is deliberately no
PSL dependency: obvious public suffixes are rejected, all other Domain attributes
retain public-suffix/acceptance uncertainty. No cookie is inferred to be a session.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from html import unescape
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

MAX_BODY = 1_000_000
MAX_HEADERS = 256
MAX_HEADER_VALUE = 65_536
MAX_REFERENCES = 512
MAX_LITERALS = 4096
_SCHEMES = {"http", "https", "ws", "wss"}
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,200}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
# A rejection guard, NOT a bundled PSL or a registrable-domain calculator. All
# unlisted suffixes remain unknown, not certified safe or browser-accepted.
_OBVIOUS_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
                     "org.au", "co.jp", "co.nz", "com.br", "co.in", "co.za",
                     "github.io", "appspot.com", "blogspot.com"}
_FILE_SUFFIXES = {"js", "mjs", "cjs", "css", "html", "htm", "json", "map", "png",
                  "jpg", "jpeg", "gif", "svg", "woff", "woff2", "txt", "xml", "pdf"}
_URL = re.compile(r'''(?i)(?<![\w])(?:https?|wss)://[^\s<>"'`\\]+''')
_STRING = re.compile(r'''(["'`])((?:\\.|(?!\1)[^\\\r\n]){0,8192})\1''')
_OAUTH_KEYS = {"redirect_uri", "post_logout_redirect_uri"}
_OAUTH_LITERAL = re.compile(
    r'''(?<![\w$-])(["']?)(redirect_uri|post_logout_redirect_uri)\1\s*[:=]\s*'''
    r'''(["'])((?:\\.|(?!\3)[^\\\r\n]){1,8192})\3''')
_SECRET_PATTERN = r"[\w-]*(?:token|nonce|secret|password|state|codes?|cookie|authorization)|api[_-]?key"
_SECRET_KEY = re.compile(r'''["']?(?:''' + _SECRET_PATTERN + r''')["']?\s*[:=]\s*\[?\s*$''', re.I)
_SECRET_NAME = re.compile(_SECRET_PATTERN, re.I)


def _host(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    value = value.removesuffix(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if "%" in value:  # Scoped IPv6 zone IDs aren't DNS trust targets.
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(value) > 253 or not all(_LABEL.fullmatch(p) for p in value.split(".")):
        return None
    return value


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parts(value: Any, schemes=_SCHEMES):
    if not isinstance(value, str) or re.search(r"[\x00-\x20\x7f\\]", value):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in schemes or not _host(parts.hostname) or port == 0:
        return None
    return parts


def _safe_url(value: Any, schemes=_SCHEMES) -> Optional[str]:
    parts = _parts(value, schemes)
    if parts is None:
        return None
    host = _host(parts.hostname)
    authority = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        authority += f":{parts.port}"
    return urlunsplit((parts.scheme, authority, parts.path, "", ""))


def _candidate_host(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if "://" in value:
        parts = _parts(value)
        return _host(parts.hostname) if parts else None
    return _host(value)


def _source(value: str) -> Optional[Dict[str, Any]]:
    """A CSP host-source, or a hostname/URL for host_matches. No raw secrets."""
    if not isinstance(value, str) or not value or re.search(r"[\s\\@?#]", value):
        return None
    scheme = None
    if "://" in value:
        scheme, value = value.split("://", 1)
        scheme = scheme.lower()
        if scheme not in _SCHEMES:
            return None
    authority, slash, path = value.partition("/")
    port = None
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host, tail = authority[:end + 1], authority[end + 1:]
        if tail and not tail.startswith(":"):
            return None
        raw_port = tail[1:] if tail else None
    else:
        host, sep, raw_port = authority.partition(":")
        raw_port = raw_port if sep else None
    if raw_port is not None:
        if raw_port == "*":
            port = "*"
        elif re.fullmatch(r"[0-9]{1,5}", raw_port) and 0 < int(raw_port) <= 65535:
            port = int(raw_port)
        else:
            return None
    wildcard = host.startswith("*.")
    host = _host(host[2:] if wildcard else host)
    if not host or (wildcard and _is_ip(host)):
        return None
    name = "*." + host if wildcard else host
    netloc = f"[{name}]" if ":" in name else name
    if port is not None:
        netloc += f":{port}"
    expression = (scheme + "://" if scheme else "") + netloc + ("/" + path if slash else "")
    return {"name": name, "expression": expression, "scheme": scheme, "port": port,
            "path": "/" + path if slash else None}


def host_matches(candidate: str, reference: str) -> bool:
    """Hostname-only exact or explicit ``*.`` match; scheme/port/path aren't proof.

    Wildcards match one or more labels, not their apex. Bare ``*`` and lookalike
    suffixes never match. Cookie Domain scope is a different operation below.
    """
    host, source = _candidate_host(candidate), _source(reference)
    if not host or not source:
        return False
    name = source["name"]
    return host.endswith("." + name[2:]) if name.startswith("*.") else host == name


def _headers(headers: Any) -> Tuple[Dict[str, List[str]], bool]:
    out: Dict[str, List[str]] = {}
    limited = False
    items = headers.items() if isinstance(headers, Mapping) else headers
    if not isinstance(items, (list, tuple)) and not isinstance(headers, Mapping):
        return out, False
    count = 0
    for item in items:
        if isinstance(item, Mapping):
            key, value = item.get("name"), item.get("value")
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            key, value = item
        else:
            continue
        if not isinstance(key, str):
            continue
        key = key.strip().lower()
        if not _TOKEN.fullmatch(key):
            continue
        for val in value if isinstance(value, (list, tuple)) else [value]:
            if not isinstance(val, str):
                continue
            if len(val) > MAX_HEADER_VALUE:
                limited = True
                # Do not parse a partial security header as a complete policy.
                continue
            for line in val.splitlines():
                count += 1
                if count > MAX_HEADERS:
                    return out, True
                if line.strip():
                    out.setdefault(key, []).append(line.strip())
    return out, limited


def _domain_matches(host: str, domain: str) -> bool:
    return host == domain or (not _is_ip(host) and host.endswith("." + domain))


def _default_path(path: str) -> str:
    return path.rsplit("/", 1)[0] if path.startswith("/") and path.count("/") > 1 else "/"


def _cookie_records(url: str, headers: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    setter = _parts(url, {"http", "https"})
    if setter is None:
        return []
    setter_host = _host(setter.hostname)
    records = []
    for value in headers.get("set-cookie", []):
        # Also tolerate folded headers without splitting the comma in Expires.
        for cookie in re.split(r",(?=\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)", value):
            first, *attributes = cookie.split(";")
            name, sep, _ = first.partition("=")
            name = name.strip()
            if not sep or not _TOKEN.fullmatch(name):
                continue
            attrs = {}
            for attribute in attributes:
                key, _, val = attribute.strip().partition("=")
                attrs[key.strip().lower()] = val.strip()
            raw_domain = attrs.get("domain", "")
            host_only = not raw_domain
            domain = setter_host if host_only else _host(raw_domain.removeprefix("."))
            if (not domain or raw_domain.endswith(".") or
                    not _domain_matches(setter_host, domain)):
                continue
            if not host_only and ("." not in domain or domain in _OBVIOUS_SUFFIXES):
                continue
            secure = "secure" in attrs
            prefix = "__Host-" if name.startswith("__Host-") else (
                "__Secure-" if name.startswith("__Secure-") else None)
            explicit_path = attrs.get("path", "").startswith("/")
            path = attrs["path"] if explicit_path else _default_path(setter.path)
            prefix_valid = (not prefix or (secure and setter.scheme == "https" and
                            (prefix != "__Host-" or
                             ("domain" not in attrs and attrs.get("path") == "/"))))
            if not prefix_valid:
                continue
            samesite = attrs.get("samesite")
            if samesite is not None:
                samesite = samesite.lower() if samesite.lower() in {"lax", "strict", "none"} else "invalid"
            records.append({
                "name": name, "domain": domain, "setter_host": setter_host,
                "host_only": host_only, "secure": secure, "httponly": "httponly" in attrs,
                "samesite": samesite, "path": path.split("?", 1)[0].split("#", 1)[0],
                "path_explicit": explicit_path, "path_redacted": "?" in path or "#" in path,
                "prefix": prefix, "prefix_valid": bool(prefix_valid),
                "public_suffix": "not-applicable" if host_only else "unknown",
                "session_inferred": False, "browser_acceptance": "unknown",
                "partitioned": "partitioned" in attrs,
                "blocking_uncertainty": ["browser-acceptance-and-delivery-not-observed"] +
                    ([] if host_only else ["public-suffix-not-checked"]) +
                    (["secure-cookie-on-insecure-setter"] if secure and setter.scheme != "https" else []) +
                    (["samesite-none-without-secure"] if samesite == "none" and not secure else [])})
            if len(records) >= MAX_REFERENCES:
                return records
    return records


def cookie_context(url: str, headers: Any, candidate: str) -> List[Dict[str, Any]]:
    """Redacted cookie scope observations relevant to a host, never session proof.

    Reject malformed Domains, setter/Domain mismatches, invalid prefixes and the
    obvious suffix guard above. Other public suffixes remain UNKNOWN. A host-only
    cookie is returned only for its setter; extract_trust omits host-only edges.
    URL candidates also get path/transport diagnostics, not a delivery assertion.
    """
    target = _candidate_host(candidate)
    if not target:
        return []
    parsed_headers, limited = _headers(headers)
    target_url = _parts(candidate) if "://" in candidate else None
    out = []
    records = _cookie_records(url, parsed_headers)
    limited |= len(records) >= MAX_REFERENCES
    for record in records:
        if not _domain_matches(target, record["domain"]):
            continue
        if record["host_only"] and target != record["setter_host"]:
            continue
        record["incomplete"] = limited
        record["candidate"] = target
        record["path_matches"] = None
        record["secure_transport_matches"] = None
        if target_url:
            path, scope = target_url.path or "/", record["path"]
            record["path_matches"] = (None if record["path_redacted"] else path == scope or
                (path.startswith(scope) and (scope.endswith("/") or path[len(scope):].startswith("/"))))
            record["secure_transport_matches"] = not record["secure"] or target_url.scheme in {"https", "wss"}
        out.append(record)
    return out


def _policies(headers: Dict[str, List[str]]):
    for header, report_only in (("content-security-policy", False),
                                ("content-security-policy-report-only", True)):
        index = 0
        for raw in headers.get(header, []):
            for policy in raw.split(","):
                directives = {}
                for directive in policy.split(";"):
                    words = directive.split()
                    if words and re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", words[0]):
                        directives.setdefault(words[0].lower(), words[1:])
                yield report_only, index, directives
                index += 1


def _report_groups(headers: Dict[str, List[str]]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for raw in headers.get("reporting-endpoints", []):
        for match in re.finditer(r'(?:^|,)\s*([a-z*][a-z0-9_.*-]*)\s*=\s*"([^"\r\n]+)"', raw):
            groups.setdefault(match[1], []).append(match[2])
    for raw in headers.get("report-to", []):
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            continue
        for group in data if isinstance(data, list) else [data]:
            if not isinstance(group, dict) or not isinstance(group.get("group", "default"), str):
                continue
            endpoints = group.get("endpoints", [])
            if isinstance(endpoints, list):
                for endpoint in endpoints[:MAX_REFERENCES]:
                    if isinstance(endpoint, dict) and isinstance(endpoint.get("url"), str):
                        groups.setdefault(group.get("group", "default"), []).append(endpoint["url"])
    return groups


def _csp(url: str, headers: Dict[str, List[str]], add):
    setter = _parts(url)
    if setter is None:
        return
    policies = list(_policies(headers))
    enforced = sum(not report_only for report_only, _, _ in policies)
    groups = _report_groups(headers)
    for report_only, index, directives in policies:
        targets = [("csp-script", "script-src", ("script-src", "default-src")),
                   ("csp-connect", "connect-src", ("connect-src", "default-src")),
                   ("csp-frame", "frame-src", ("frame-src", "child-src", "default-src"))]
        if "script-src-elem" in directives:
            targets.append(("csp-script", "script-src-elem", ("script-src-elem",)))
        if "frame-ancestors" in directives:
            # Ancestor policy does not inherit default-src.
            targets.append(("csp-frame", "frame-ancestors", ("frame-ancestors",)))
        for kind, effective, fallbacks in targets:
            directive = next((d for d in fallbacks if d in directives), None)
            if directive is None:
                continue
            tokens = directives[directive]
            nonce = any(t.lower().startswith("'nonce-") for t in tokens)
            hashed = any(re.match(r"'sha(?:256|384|512)-", t, re.I) for t in tokens)
            dynamic = any(t.lower() == "'strict-dynamic'" for t in tokens)
            uncertainty = ["browser-policy-not-evaluated"]
            if report_only:
                uncertainty.append("report-only-not-enforced")
            if kind == "csp-script" and (nonce or hashed):
                uncertainty.append("nonce-or-hash-may-be-required")
            if kind == "csp-script" and dynamic:
                uncertainty.append("strict-dynamic-may-ignore-host-sources")
            if enforced > (0 if report_only else 1):
                uncertainty.append("other-enforced-policies-may-block")
            for token in tokens:
                if token.lower() == "'self'":
                    source = {"name": _host(setter.hostname), "expression": "'self'",
                              "scheme": setter.scheme, "port": setter.port, "path": None}
                else:
                    source = _source(token)
                if not source:
                    continue
                details = dict(source)
                details.pop("name")
                details.update({"directive": directive, "effective_directive": effective,
                                "fallback": directive != effective, "report_only": report_only,
                                "policy_index": index, "nonce_present": nonce,
                                "hash_present": hashed, "strict_dynamic": dynamic,
                                "blocking_uncertainty": uncertainty})
                add(source["name"], kind, details)
        for directive in ("report-uri", "report-to"):
            for token in directives.get(directive, []):
                values = [token] if directive == "report-uri" else groups.get(token, [])
                for value in values:
                    try:
                        absolute = urljoin(url, value)
                    except ValueError:
                        continue
                    target = _safe_url(absolute, {"http", "https"})
                    if target:
                        add(_host(urlsplit(target).hostname), "csp-report", {
                            "target": target, "directive": directive, "report_only": report_only,
                            "policy_index": index, "delivery_proven": False,
                            "blocking_uncertainty": ["report-delivery-not-observed"]})


def _cors(headers: Dict[str, List[str]], add):
    origins = headers.get("access-control-allow-origin", [])
    if len(origins) != 1:
        return
    raw = origins[0]
    parts = _parts(raw, {"http", "https"})
    if (parts is None or parts.username is not None or parts.password is not None or
            parts.path or parts.query or parts.fragment or "?" in raw or "#" in raw or
            parts.netloc.endswith(":")):
        return  # Wildcard, null, origin lists and malformed origins have no named host.
    credentials = headers.get("access-control-allow-credentials", [])
    add(_host(parts.hostname), "cors", {
        "origin": _safe_url(raw), "credentials": credentials == ["true"],
        "credentials_header": "absent" if not credentials else
            "true" if credentials == ["true"] else "invalid",
        "header_only": True, "behavior_proven": False, "read_proven": False,
        "blocking_uncertainty": ["request-origin-and-browser-read-not-tested"]})


def _hsts(url: str, headers: Dict[str, List[str]], add):
    setter = _parts(url, {"http", "https"})
    if not setter:
        return
    for raw in headers.get("strict-transport-security", []):
        attrs = {}
        invalid = False
        for word in raw.split(";"):
            key, _, value = word.strip().partition("=")
            key = key.strip().lower()
            if key in attrs:
                invalid = True
            attrs[key] = value.strip().strip('"')
        age = attrs.get("max-age", "")
        if invalid or not re.fullmatch(r"[0-9]{1,18}", age):
            continue
        add(_host(setter.hostname), "hsts", {
            "max_age": int(age), "include_subdomains": "includesubdomains" in attrs,
            "preload": "preload" in attrs, "preload_list_membership": "unknown",
            "secure_setter": setter.scheme == "https", "sibling_takeover_implied": False,
            "browser_policy_proven": False})


def _decode_literal(text: str) -> str:
    # Only inert string escapes, never evaluation, interpolation or URL fetching.
    text = re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})",
                  lambda m: chr(int(m[1] or m[2], 16)), text)
    return unescape(re.sub(r'''\\([/"'\\])''', r"\1", text))


class _Inputs(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.redirects = []
        self.secret_values = set()

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return
        attrs = dict(attrs)
        name, value = attrs.get("name"), attrs.get("value")
        if (isinstance(name, str) and _SECRET_NAME.fullmatch(name) and isinstance(value, str)
                and len(self.secret_values) < MAX_LITERALS):
            self.secret_values.add(_decode_literal(value))
        if (name in _OAUTH_KEYS and isinstance(value, str) and
                len(self.redirects) < MAX_REFERENCES):
            self.redirects.append((attrs["name"], attrs["value"]))


def _oauth_params(value: str, location: str, add):
    parts = _parts(value)
    if parts is None:
        return False
    try:
        params = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=256)
    except ValueError:
        return True
    for key, target in params:
        if key in _OAUTH_KEYS:
            _oauth(key, target, location, add)
    return False


def _oauth(key: str, value: str, location: str, add):
    target = _safe_url(value, {"http", "https"})
    if not target:
        return
    add(_host(urlsplit(target).hostname), "oauth-redirect", {
        "parameter": key, "target": target, "location": location,
        "observed_request": location == "request-url-parameter",
        "accepted_allowlist": False, "acceptance": "unknown",
        "blocking_uncertainty": ["reference-not-provider-allowlist-or-accepted-redirect"]})


def _json_secret_values(body: str) -> Tuple[set, bool]:
    """Suppress whole sensitive JSON subtrees, including arrays of codes/tokens."""
    try:
        data = json.loads(body)
    except ValueError:
        return set(), False
    except RecursionError:
        return set(), True
    values = set()
    stack = [(data, False)]
    count = 0
    while stack:
        count += 1
        if count > MAX_LITERALS:
            return values, True
        node, sensitive = stack.pop()
        if isinstance(node, dict):
            if len(node) > MAX_LITERALS:
                return values, True
            stack.extend((value, sensitive or bool(_SECRET_NAME.fullmatch(key)))
                         for key, value in node.items())
        elif isinstance(node, list):
            if len(node) > MAX_LITERALS:
                return values, True
            stack.extend((value, sensitive) for value in node)
        elif sensitive and isinstance(node, str):
            values.add(_decode_literal(node))
    return values, False


def _body(body: str, add) -> bool:
    # Keep string delimiters intact. Decoding escaped quotes across the full body
    # would turn a token's *contents* into apparent standalone URL literals.
    text = body
    parser = _Inputs()
    json_secrets, limited = _json_secret_values(body)
    if limited:
        return True
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        limited = True
    limited |= len(parser.redirects) >= MAX_REFERENCES or len(parser.secret_values) >= MAX_LITERALS
    secret_values = parser.secret_values | json_secrets
    if len(secret_values) >= MAX_LITERALS:
        return True  # Never scan untracked secret input values beyond the cap.
    for key, value in parser.redirects:
        if _decode_literal(value) not in secret_values:
            _oauth(key, value, "body-input-literal", add)
    for index, match in enumerate(_OAUTH_LITERAL.finditer(text)):
        if index >= MAX_LITERALS:
            return True
        value = _decode_literal(match[4])
        if value not in secret_values:
            _oauth(match[2], value, "body-literal", add)
    literal_spans = []
    literals = []
    scan_end = len(text)
    for index, match in enumerate(_STRING.finditer(text)):
        if index >= MAX_LITERALS:
            limited = True
            scan_end = match.start()
            break
        literal_spans.append((match.start(), match.end()))
        value = _decode_literal(match[2])
        if (not _SECRET_KEY.search(text[max(0, match.start() - 100):match.start()]) and
                value not in secret_values):
            literals.append(value)

    def content(value):
        nonlocal limited
        target = _safe_url(value, {"http", "https", "wss"})
        if target:
            add(_host(urlsplit(target).hostname), "content-reference", {
                "target": target, "literal_type": "url", "behavior_proven": False})
            limited |= _oauth_params(value, "body-url-parameter", add)

    for index, match in enumerate(_URL.finditer(text[:scan_end])):
        if index >= MAX_LITERALS:
            limited = True
            break
        if any(start <= match.start() < end for start, end in literal_spans):
            continue
        value = unescape(match[0].rstrip(".,);}"))
        if value not in secret_values:
            content(value)
    for value in literals:
        if _parts(value, {"http", "https", "wss"}):
            # Treat a URL literal as ONE URL, not its nested token query values.
            content(value)
            continue
        for match in _URL.finditer(value):
            content(match[0].rstrip(".,);}"))
        host = _host(value)
        if (host and "." in host and not _is_ip(host) and
                host.rsplit(".", 1)[1] not in _FILE_SUFFIXES and
                (host.rsplit(".", 1)[1].isalpha() or host.rsplit(".", 1)[1].startswith("xn--"))):
            add(host, "content-reference", {"target": host, "literal_type": "bare-host",
                                             "behavior_proven": False})
    return limited


def extract_trust(url: str, headers: Any, body: str = "", complete: bool = True) -> List[Dict[str, Any]]:
    """Extract conditional, secret-redacted observations from ONE captured response.

    Headers may be a mapping (including list values), name/value pairs or HAR-style
    name/value dictionaries. Multiple Set-Cookie lines are independent. Body and
    extraction caps mark all retained edges incomplete; absence is never a negative.
    Neither redirect references nor CORS/CSP headers establish accepted behavior.
    """
    reference = _safe_url(url, {"http", "https"})
    if reference is None:
        return []
    parsed_headers, limited = _headers(headers)
    if isinstance(body, bytes):
        limited |= len(body) > MAX_BODY
        body = body[:MAX_BODY].decode("utf-8", "replace")
    elif not isinstance(body, str):
        body = ""
    limited |= len(body) > MAX_BODY
    body = body[:MAX_BODY]
    source_hash = hashlib.sha256(url.encode("utf-8", "surrogatepass")).hexdigest()
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(name, kind, details):
        nonlocal limited
        key = (name, kind, json.dumps(details, sort_keys=True))
        if key in seen:
            return
        if len(out) >= MAX_REFERENCES:
            limited = True
            return
        seen.add(key)
        out.append({"name": name, "kind": kind, "reference": reference,
                    "conditional": True, "details": dict(details, source_url_sha256=source_hash)})

    cookies = _cookie_records(url, parsed_headers)
    limited |= len(cookies) >= MAX_REFERENCES
    for record in cookies:
        if not record["host_only"]:
            add(record["domain"], "cookie-domain", record)
    _csp(url, parsed_headers, add)
    _cors(parsed_headers, add)
    _hsts(url, parsed_headers, add)
    params_limited = _oauth_params(url, "request-url-parameter", add)
    limited |= params_limited
    body_limited = _body(body, add)
    limited |= body_limited
    for edge in out:
        edge["details"]["incomplete"] = not complete or limited
    return out
