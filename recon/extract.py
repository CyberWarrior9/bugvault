"""Pure parsing helpers (no I/O): endpoint normalization, JS/HTML/source-map extraction.

Ideas adapted (not copied) from ARTEX's api-recon methodology:
  * static harvest of every bundle + lazy chunk + source map before anything dynamic
  * "anchor window" parameter inference: look around each endpoint literal for the
    HTTP method and the object-literal keys passed with it
  * permission-string harvest, later used to fake a full-permission user at runtime
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit

from .campaign import norm_host
from .csrfmeta import TOKENISH

# ---------------------------------------------------------------- normalization

STATIC_EXT = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "tif", "tiff",
    "css", "scss", "less", "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3",
    "wav", "ogg", "avi", "mov", "flv", "pdf", "zip", "gz", "tar", "rar", "7z", "dmg",
    "exe", "apk", "ipa", "swf", "map", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue",
    "md", "txt", "csv", "manifest", "webmanifest", "wasm",
}
ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[0-9a-f]{24}|[0-9a-f]{32}|[0-9a-f]{40})$", re.I)
ID_VALUE = ID_SEGMENT
TEMPLATE_PARAM = re.compile(r"\$\{[^}]*\}|\{[^}/]*\}|(?<=/):[A-Za-z_]\w*")
API_HINT = re.compile(
    r"(?:^|/)(?:api|apis|v\d+(?:\.\d+)?|graphql|gql|rest|rpc|jsonrpc|internal|admin|ajax|"
    r"service|services|gateway|backend|bff|webhooks?|oauth2?|auth|sso|saml|ws)(?:/|$|\.)"
    r"|\.(?:json|php|aspx?|ashx|asmx|jsp|do|action|cgi|pl)$", re.I)
VERSION_SEG = re.compile(r"/v(\d+)(?=/|$)", re.I)


def origin_of(url: str) -> str:
    p = urlsplit(url)
    scheme = p.scheme.lower()
    host = norm_host(p.hostname or "")
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    if port and not ((scheme in ("http", "ws") and port == 80) or
                     (scheme in ("https", "wss") and port == 443)):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


def template_path(path: str) -> str:
    """/api/users/123/orders/${oid} -> /api/users/{id}/orders/{id}"""
    path = TEMPLATE_PARAM.sub("{id}", path or "/")
    segs = ["{id}" if ID_SEGMENT.match(s) else s for s in path.split("/")]
    out = "/".join(segs)
    out = re.sub(r"/{2,}", "/", out)
    if len(out) > 1 and out.endswith("/"):
        out = out[:-1]
    return out or "/"


def endpoint_key(url: str) -> str:
    return origin_of(url) + template_path(urlsplit(url).path)


def path_ext(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def is_static(path: str) -> bool:
    return path_ext(path) in STATIC_EXT


def looks_api(path: str) -> bool:
    return bool(API_HINT.search(path or ""))


def query_keys(url: str) -> List[str]:
    q = urlsplit(url).query
    return sorted({k for k, _ in parse_qsl(q, keep_blank_values=True) if k})


def id_like(value: str) -> bool:
    return bool(ID_VALUE.match(str(value)))


# ---------------------------------------------------------------- JS extraction

_STR = re.compile(r"""(["'`])((?:https?:)?//[^\s"'`<>\\]{3,300}|/[^\s"'`<>\\]{1,300})\1""")
_PATH_OK = re.compile(r"^/[A-Za-z0-9_\-./{}$:@~%+=,;!]*$")
_METHOD_CALL = re.compile(r"\.(get|post|put|patch|delete|head)\s*\(\s*$", re.I)
_METHOD_KV = re.compile(r"""method\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD)["'`]""", re.I)
_OBJ_KEY = re.compile(r"""(?:^|[,{]\s*)["']?([A-Za-z_$][\w$]{0,40})["']?\s*:""")
_ROUTE_PATTERNS = [
    re.compile(r"""\bpath\s*:\s*["'`](/[A-Za-z0-9_\-/:.*]*)["'`]"""),
    re.compile(r"""<Route[^>]*\bpath=["'](/[^"']*)["']"""),
    re.compile(r"""\b(?:navigate|push|replace|navigateByUrl)\(\s*["'`](/[A-Za-z0-9_\-/:.]+)["'`]"""),
]
_PERM = re.compile(r"""["']([a-z][a-z0-9_-]{1,30}(?::[a-z0-9_*-]{1,30}){1,3})["']""")
_PERM_DENY = re.compile(r"^(?:https?|wss?|mailto|data|javascript|tel|blob|about|urn|file)\b|"
                        r"^\w+:\d+$|^(?:hh|mm|ss)\b")
_CHUNK = re.compile(r"""["'`]((?:\.{0,2}/)?[\w\-./@]+\.m?js)["'`]""")
_SOURCEMAP = re.compile(r"""[#@]\s*sourceMappingURL=([^\s'"*]+)""")
_GQL_OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w*)\s*[({]")
_HASH_ROUTING = re.compile(r"createWebHashHistory|createHashHistory|HashRouter|"
                           r"mode\s*:\s*[\"']hash[\"']|useHash\s*:\s*true|withHashLocation")
SECRET_PATTERNS = {
    "aws-access-key-id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    "stripe-live-secret": re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}
_OPTION_KEYS = {
    "method", "headers", "header", "url", "baseurl", "params", "data", "body", "timeout",
    "responsetype", "withcredentials", "credentials", "mode", "cache", "signal", "redirect",
    "onuploadprogress", "ondownloadprogress", "transformrequest", "transformresponse",
    "validatestatus", "paramsserializer", "content-type", "accept", "authorization",
    "query", "variables", "type", "default", "function", "return", "case", "get", "set",
    "path", "name", "component", "meta", "children", "redirectto", "loader", "props",
}
_NOISE_PATHS = re.compile(r"^/(?:[a-z]{1,2}|\*+|\.+|[\d/.\-:]+|mm/dd.*|yyyy.*|dd/mm.*)$", re.I)


@dataclass
class EndpointLiteral:
    raw: str
    method: Optional[str] = None
    params: List[str] = field(default_factory=list)


@dataclass
class JsFindings:
    endpoints: List[EndpointLiteral] = field(default_factory=list)
    routes: List[str] = field(default_factory=list)
    perms: List[str] = field(default_factory=list)
    secrets: List[Tuple[str, str]] = field(default_factory=list)  # (kind, redacted)
    graphql_ops: List[str] = field(default_factory=list)
    chunks: List[str] = field(default_factory=list)
    sourcemap: Optional[str] = None
    hash_routing: bool = False
    auth_gates: List[str] = field(default_factory=list)       # symbols for the runtime deep-pass
    crypto_entrypoints: List[str] = field(default_factory=list)  # pre-encryption hook points


def redact(secret: str) -> str:
    return f"{secret[:6]}…(len {len(secret)})"


def _balanced_object(text: str, start: int, limit: int = 600) -> str:
    i = text.find("{", start, start + 120)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, min(len(text), i + limit)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return text[i:i + limit]


_CALL_GLUE = re.compile(r"^[\s,+\w.$()\[\]]{0,60}$")
_ROUTE_CTX = re.compile(r"(?:\bpath\s*[:=]\s*\{?\s*|(?:navigate|push|replace|navigateByUrl)"
                        r"\(\s*)$")
_BODY_KEY_CTX = re.compile(r"\b(?:body|data|params|variables|payload|fields)\s*:\s*")
_AUTH_GATE = re.compile(r"(?<![A-Za-z0-9_])(isAuthenticated|isLoggedIn|isAuthorized|isAdmin|"
                        r"hasPermission|hasRole|checkPermission|requirePermission|requireRole|"
                        r"hasAccess|canAccess|canEdit|canManage|currentUser|loggedIn)(?![A-Za-z0-9_])")
_CRYPTO_CALL = re.compile(r"(?<![A-Za-z0-9_])(JSEncrypt|CryptoJS|encryptPayload|encryptBody|"
                          r"signPayload|signBody|encryptRequest|getPublicKey|setPublicKey|"
                          r"encrypt\(|decrypt\(|hmacSign)(?![A-Za-z0-9_])")


def _leaf_keys(blob: str, depth: int, out: List[str]) -> None:
    """Object-literal leaf keys, bounded depth; JSON.stringify(...) is unwrapped."""
    if depth > 2 or len(out) >= 30:
        return
    inner = _balanced_object(blob, 0, limit=600)
    if not inner:
        return
    for k in _OBJ_KEY.findall(inner):
        if k.lower() not in _OPTION_KEYS and k not in out:
            out.append(k)
    for m in _BODY_KEY_CTX.finditer(inner):
        tail = inner[m.end():].lstrip()
        if tail.startswith("JSON.stringify"):
            paren = tail.find("(", 0, 16)
            if paren >= 0:
                tail = tail[paren + 1:]
        if tail[:1] in ("{", "[") or tail[:1] == "":
            _leaf_keys(tail[:400], depth + 1, out)


def _options_object(text: str, end: int) -> str:
    """The object literal passed WITH this URL in the same call, e.g.
    fetch("/x" + id, {method: "POST", body: ...}) -> '{method: ..., body: ...}'.
    Empty when the next '{' belongs to unrelated code."""
    i = text.find("{", end, end + 80)
    if i < 0 or not _CALL_GLUE.match(text[end:i]):
        return ""
    return _balanced_object(text, i)


def _method_near(text: str, start: int, end: int, opts: str) -> Optional[str]:
    mm = _METHOD_CALL.search(text[max(0, start - 60):start])
    if mm:
        return mm.group(1).upper()
    mk = _METHOD_KV.search(opts)
    if mk:
        return mk.group(1).upper()
    # axios({method: "post", url: "/x"}): method earlier in the SAME object literal
    before = text[max(0, start - 120):start]
    brace = before.rfind("{")
    if brace >= 0 and "}" not in before[brace:]:
        mk = _METHOD_KV.search(before[brace:])
        if mk:
            return mk.group(1).upper()
    return None


def _window_params(text: str, end: int) -> List[str]:
    obj = _options_object(text, end)
    keys = []
    for k in _OBJ_KEY.findall(obj):
        if k.lower() not in _OPTION_KEYS and k not in keys:
            keys.append(k)
    # request-body keys one level deeper: body:/data:/params:/variables: values
    leaf: List[str] = []
    for m in _BODY_KEY_CTX.finditer(obj):
        tail = obj[m.end():].lstrip()
        if tail.startswith("JSON.stringify"):
            paren = tail.find("(", 0, 16)
            if paren >= 0:
                tail = tail[paren + 1:]
        _leaf_keys(tail[:400], 1, leaf)
    for k in leaf:
        if k.lower() not in _OPTION_KEYS and k not in keys:
            keys.append(k)
    return keys[:30]


def _valid_path_literal(s: str) -> bool:
    if s.startswith("//"):
        return "." in s.split("/")[2] if len(s.split("/")) > 2 else False
    if s.startswith("http"):
        return True
    path = s.split("?", 1)[0].split("#", 1)[0]
    if len(path) < 3 or not _PATH_OK.match(path) or _NOISE_PATHS.match(path):
        return False
    if not re.search(r"[A-Za-z]{2,}", path):
        return False
    return True


def extract_from_js(text: str) -> JsFindings:
    f = JsFindings()
    seen: Set[str] = set()
    for m in _STR.finditer(text):
        s = m.group(2)
        if not _valid_path_literal(s):
            continue
        path_only = urlsplit(s if not s.startswith("//") else "https:" + s).path
        if is_static(path_only):
            continue
        if _ROUTE_CTX.search(text[max(0, m.start() - 40):m.start()]):
            continue  # frontend router path, collected separately as a route
        method = _method_near(text, m.start(), m.end(), _options_object(text, m.end()))
        params = _window_params(text, m.end())
        key = f"{s}|{method}"
        if key in seen:
            continue
        seen.add(key)
        f.endpoints.append(EndpointLiteral(raw=s, method=method, params=params))
    routes: List[str] = []
    for pat in _ROUTE_PATTERNS:
        for r in pat.findall(text):
            if r not in routes and len(r) < 120:
                routes.append(r)
    f.routes = routes[:300]
    perms = []
    for p in _PERM.findall(text):
        if not _PERM_DENY.match(p) and p not in perms:
            perms.append(p)
    f.perms = perms[:500]
    for kind, pat in SECRET_PATTERNS.items():
        for s in set(pat.findall(text)):
            f.secrets.append((kind, redact(s)))
    f.graphql_ops = sorted({f"{a} {b}" for a, b in _GQL_OP.findall(text)})[:300]
    f.auth_gates = sorted(set(_AUTH_GATE.findall(text)))[:40]
    f.crypto_entrypoints = sorted(set(
        token.rstrip("(") for token in _CRYPTO_CALL.findall(text)))[:40]
    chunks = []
    for c in _CHUNK.findall(text):
        if c not in chunks and not c.startswith("http"):
            chunks.append(c)
    f.chunks = chunks[:500]
    sm = _SOURCEMAP.findall(text)
    f.sourcemap = sm[-1] if sm else None
    f.hash_routing = bool(_HASH_ROUTING.search(text))
    return f


def decode_inline_sourcemap(ref: str) -> Optional[dict]:
    if not ref.startswith("data:"):
        return None
    try:
        meta, payload = ref.split(",", 1)
        raw = base64.b64decode(payload) if ";base64" in meta else payload.encode()
        return json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None


def sourcemap_sources(sm: dict) -> List[Tuple[str, str]]:
    """(source_name, content) pairs, skipping vendored/bootstrap code."""
    names = sm.get("sources") or []
    contents = sm.get("sourcesContent") or []
    out = []
    for i, name in enumerate(names):
        content = contents[i] if i < len(contents) else None
        if not content or "node_modules/" in name or "webpack/bootstrap" in name:
            continue
        out.append((name, content))
    return out


# ---------------------------------------------------------------- HTML extraction

class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: List[str] = []
        self.inline_scripts: List[str] = []
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self.standalone: List[Dict] = []   # named inputs OUTSIDE any <form>
        self.title = ""
        self._in_script = False
        self._in_title = False
        self._buf: List[str] = []
        self._form: Optional[Dict] = None
        self._label: Optional[List[str]] = None
        self._last_label = ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script, self._buf = True, []
        elif tag == "link" and a.get("href") and (
                a.get("rel", "").lower() in ("modulepreload", "preload", "prefetch")
                and (a.get("as", "script") == "script" or a["href"].endswith(".js"))):
            self.scripts.append(a["href"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                          "inputs": [], "enctype": a.get("enctype", "").strip().lower()[:100],
                          "token_fields": []}
            self.forms.append(self._form)
        elif tag == "label":
            self._label = []
        elif tag in ("input", "select", "textarea") and self._form is not None and a.get("name"):
            self._form["inputs"].append(a["name"])
            if TOKENISH.search(a["name"]) and len(self._form["token_fields"]) < 10:
                self._form["token_fields"].append(a["name"][:200])  # name only, never the value
        elif tag in ("input", "select", "textarea") and self._form is None:
            name = a.get("name") or a.get("id") or ""
            if len(self.standalone) < 200:
                self.standalone.append({
                    "tag": tag, "name": name[:200],
                    "type": a.get("type", "")[:40],
                    "label": (self._last_label or a.get("placeholder")
                              or a.get("aria-label") or "")[:120]})
        elif a.get("contenteditable", "").lower() == "true" and self._form is None:
            name = a.get("name") or a.get("id") or a.get("aria-label") \
                or a.get("data-testid") or ""
            if len(self.standalone) < 200 and (name or self._last_label):
                self.standalone.append({
                    "tag": "contenteditable", "name": name[:200], "type": "rich",
                    "label": self._last_label[:120]})
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._buf))
            self._in_script = False
        elif tag == "form":
            self._form = None
        elif tag == "label":
            if self._label is not None:
                self._last_label = " ".join("".join(self._label).split())[:120]
            self._label = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)
        elif self._in_title:
            self.title += data
        elif self._label is not None:
            self._label.append(data)


def parse_page(html: str) -> PageParser:
    p = PageParser()
    try:
        p.feed(html)
        p.close()
    except Exception:  # malformed HTML: keep whatever was parsed
        pass
    p.title = " ".join(p.title.split())[:200]
    return p


def resolve(base: str, ref: str) -> str:
    if ref.startswith("//"):
        return urlsplit(base).scheme + ":" + ref
    return urljoin(base, ref)


def parse_robots(text: str) -> Tuple[List[str], List[str]]:
    paths, sitemaps = [], []
    for line in text.splitlines():
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k in ("disallow", "allow") and v.startswith("/"):
            v = v.split("*", 1)[0].rstrip("$")
            if len(v) > 1 and v not in paths:
                paths.append(v)
        elif k == "sitemap" and v:
            sitemaps.append(v if "://" in v else line.split(":", 1)[1].strip())
    return paths, sitemaps


def parse_sitemap(text: str) -> List[str]:
    return [u.strip() for u in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", text)][:2000]
