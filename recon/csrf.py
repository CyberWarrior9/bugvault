"""CSRF action ledger: offline action x context x case accounting for `hunt-csrf`.

The unit of CSRF coverage is a state-changing *action* (fieldless actions and GET
mutations included) on one exact origin, under one captured or declared
*context* (representation, authority, account/role/tenant/workflow), worked per
*case family* and variant from a recorded browser initiator. This module
inventories, plans, records and summarizes. It sends no traffic, launches no
browser or scanner and never promotes a finding; cross-origin exercises run in
the dedicated browser through Burp under the campaign's execution plan.

Design decisions encoded here (case catalogue: .claude/skills/hunt-csrf/references):
- actions are keyed per endpoint family x method x selector, so origins, methods
  and GraphQL operations never pool, and an action without fields still exists;
- contexts carry facet hashes (tokens, headers, cookies, origin metadata, shape);
  an event goes stale only when a facet its case depends on changes, so a new
  import reopens exactly the affected cases;
- an `observed` attack case is a browser-initiated request from a different
  origin that was delivered and changed an independent state readback; replayed
  requests are diagnostic and cannot carry a browser initiator;
- a case-level `negative` is accepted once every applicable variant is resolved.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .callbacks import local_bytes
from .csrfmeta import (ACTION_PARAMS, AMBIENT_AUTH, MUTATING, SIMPLE_TYPES, TOKENISH,
                       cookie_applies, mime_of, norm_origin, request_meta, split_camel, words)
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS csrf_actions(
  id INTEGER PRIMARY KEY,
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  origin TEXT NOT NULL,
  route TEXT NOT NULL,
  method TEXT NOT NULL,
  selector TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  priority TEXT NOT NULL,
  basis TEXT NOT NULL,
  sources TEXT NOT NULL DEFAULT '[]',
  hint TEXT NOT NULL DEFAULT '',
  fieldless INTEGER NOT NULL DEFAULT 0,
  created TEXT NOT NULL,
  updated TEXT NOT NULL,
  UNIQUE(asset_id, method, selector));
CREATE TABLE IF NOT EXISTS csrf_contexts(
  id INTEGER PRIMARY KEY,
  action_id INTEGER NOT NULL REFERENCES csrf_actions(id),
  content_type TEXT NOT NULL,
  auth TEXT NOT NULL,
  account TEXT NOT NULL,
  role TEXT NOT NULL,
  tenant TEXT NOT NULL,
  workflow TEXT NOT NULL,
  basis TEXT NOT NULL,
  facets TEXT NOT NULL,
  detail TEXT NOT NULL,
  created TEXT NOT NULL,
  updated TEXT NOT NULL,
  UNIQUE(action_id, content_type, auth, account, role, tenant, workflow));
CREATE TABLE IF NOT EXISTS csrf_case_events(
  id INTEGER PRIMARY KEY,
  context_id INTEGER NOT NULL REFERENCES csrf_contexts(id),
  case_id TEXT NOT NULL,
  variant TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  attempt_kind TEXT NOT NULL,
  initiator TEXT NOT NULL,
  initiator_origin TEXT NOT NULL DEFAULT '',
  relationship TEXT NOT NULL DEFAULT '',
  delivery TEXT NOT NULL DEFAULT '',
  preflight TEXT NOT NULL DEFAULT '',
  browser TEXT NOT NULL DEFAULT '',
  prerequisite TEXT NOT NULL DEFAULT '',
  facets TEXT NOT NULL,
  counts TEXT NOT NULL,
  artifacts TEXT NOT NULL,
  tool_refs TEXT NOT NULL,
  note TEXT NOT NULL,
  created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS csrf_events_ctx ON csrf_case_events(context_id, case_id, id);
"""

STATES = ("attempted", "observed", "negative", "blocked", "inconclusive", "n-a")
TERMINAL = ("observed", "negative", "blocked", "inconclusive", "n-a")
ATTEMPT_KINDS = ("browser", "replay", "review")
INITIATORS = ("same-origin", "same-site", "cross-site", "opaque", "none")
DELIVERIES = ("form-post", "form-get", "navigation", "subresource", "iframe", "fetch",
              "websocket", "redirect", "client-script")
PREFLIGHT = ("none", "allowed", "denied", "unknown")
ARTIFACT_ROLES = ("before", "after", "request", "response", "messages", "initiator-page",
                  "preflight", "sibling-control", "trace")
FACETS = ("tokens", "headers", "cookies", "origin", "shape")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
PRIORITY_ORDER = ("identity", "security", "value", "admin", "write")
READINESS_OPEN = ("ready", "waiting-baseline", "waiting-capture", "needs-confirmation")
DEFAULT_EFFORT_CAP = 3
MAX_ACTIONS = 5000
MAX_OBSERVATIONS = 2000
MAX_CONTEXTS_PER_ACTION = 60
MAX_SELECTORS = 40
MAX_ARTIFACTS = 8
EVIDENCE_DIR = "csrf-evidence"


_words = words
GRAPHQL = _words("graphql", "gql")
REALTIME = _words("ws", "wss", "websocket", "websockets", "socket", "sockets", "socket\\.io",
                  "sockjs", "signalr", "hub", "hubs", "cable", "realtime", "negotiate")
PRIORITY_RULES = (
    ("identity", _words("e-?mail", "emails", "phone", "password", "passwd", "passphrase", "mfa",
                        "2fa", "otp", "totp", "recovery", "backup-?codes?", "webauthn",
                        "passkeys?", "username", "login", "signin", "sign-?in", "oauth", "oidc",
                        "sso", "saml", "connect", "disconnect", "link", "unlink", "social",
                        "identity", "identities")),
    ("security", _words("api-?keys?", "apikeys?", "tokens?", "webhooks?", "integrations?",
                        "permissions?", "roles?", "grants?", "invites?", "invitations?",
                        "members?", "collaborators?", "privileges?", "scopes?", "secrets?",
                        "ssh", "keys?", "sharing", "share", "visibility", "acl")),
    ("value", _words("pay", "payments?", "checkout", "orders?", "transfers?", "withdraw\\w*",
                     "refunds?", "billing", "subscriptions?", "subscribe", "plans?", "coupons?",
                     "redeem", "wallets?", "balance", "gifts?", "credits?", "purchases?", "cart",
                     "invoices?", "payouts?", "donations?", "donate")),
    ("admin", _words("admin", "administrator", "staff", "manage", "management", "console",
                     "backoffice", "settings", "config", "configuration", "preferences")),
)
IDENTITY_FLOW = _words("login", "logout", "signin", "sign-?in", "signout", "session", "sessions",
                       "oauth", "oauth2", "authorize", "callback", "connect", "link", "unlink",
                       "associate", "social", "sso", "oidc", "openid", "saml")
LOGIN_FLOW = _words("login", "signin", "sign-?in", "session", "sessions")
LINK_FLOW = _words("connect", "link", "associate", "social", "callback", "oauth", "oauth2",
                   "authorize")
OAUTH_FLOW = _words("oauth", "oauth2", "authorize", "callback", "oidc", "openid", "sso", "token")
SAML_FLOW = _words("saml", "saml2", "acs", "sso")


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _short(value: Any) -> str:
    return digest(value)[:16]


# ---------------------------------------------------------------- case catalogue
# (id, title, family applicability, facets the case depends on, hint, tools,
#  variants: (variant id, variant applicability, technique)). Independently written;
# provenance and corrections in .claude/skills/hunt-csrf/references/sources.md.
CASES: Tuple[Dict[str, Any], ...] = tuple({
    "id": c[0], "title": c[1], "applies": c[2], "facets": c[3], "hint": c[4], "tools": c[5],
    "variants": c[6]} for c in (
    ("baseline", "Action authority baseline", "always", ("shape", "tokens"),
     "captured or declared state-changing action",
     "dedicated browser + DevTools; Burp history",
     (("legit-request", "always", "capture the legitimate same-origin request exactly as the app "
       "emits it: method, MIME, every token channel, which credentials ride along"),
      ("state-readback", "always", "fix an independent before/after readback of the owned state "
       "or identity this action changes (a response status is not a readback)"),
      ("delivery-mode", "always", "note how the app sends it (form, navigation, fetch/XHR, "
       "WebSocket message) and from which page"))),
    ("token-enforcement", "Token enforcement across every accepted channel", "ambient",
     ("tokens", "shape", "headers"), "form field, header or interceptor carrying an anti-CSRF token",
     "source/interceptor review; Burp Repeater as a diagnostic; browser for the real attempt",
     (("omit-all-channels", "always", "the request with no token in any channel; a token left in a "
       "second channel still validates, so remove every copy at once"),
      ("empty-value", "token", "parameter or header present but empty"),
      ("invalid-value", "token", "same-format, same-length value that was never issued"),
      ("alternate-channel", "token", "token moved to another channel the server reads "
       "(body, query, header) or the expected channel dropped while another stays"),
      ("duplicate-precedence", "token", "repeated parameter / query-vs-body copies: which one the "
       "validator reads versus which one the handler uses"))),
    ("token-context", "Token binding, lifecycle and transport", "token", ("tokens",),
     "identified token design (synchronizer, masked, signed, double-submit, custom header)",
     "two supplied accounts in separate browser contexts; Burp Repeater comparisons",
     (("cross-session", "token", "token issued to another session of the same test account"),
      ("cross-account", "token", "token issued to the other supplied account used with this "
       "account's session"),
      ("lifecycle", "token", "token across logout/login, renewal and expiry; a stable per-session "
       "token is a valid design, so test the transitions rather than the stability"),
      ("leak-surface", "token", "where the token is readable by another origin: URL/query, "
       "Referer, cached page, error page, JS-readable endpoint"))),
    ("cookie-binding", "Double-submit and cookie-paired tokens", "cookie-pair", ("tokens", "cookies"),
     "a CSRF-named cookie next to a submitted token",
     "DevTools cookie inspector; framework documentation for the pairing design",
     (("pair-design", "cookie-pair", "classify the pair: naive equality, signed/HMAC, or bound to "
       "the session"),
      ("pair-mismatch", "cookie-pair", "cookie and submitted value from different issuances"),
      ("cookie-planting", "cookie-pair", "with an established cookie-setting primitive (sibling "
       "Set-Cookie, header injection): plant a matching pair while the victim's session stays "
       "the victim's"))),
    ("origin-metadata", "Origin, Referer and Fetch Metadata checks", "ambient",
     ("origin", "cookies", "headers"), "server checks Origin/Referer/Sec-Fetch-* instead of, or "
     "next to, a token", "dedicated browser + DevTools; Burp to read the emitted headers",
     (("cross-site-origin", "always", "a browser-emitted cross-site Origin from the recorded "
       "initiator page"),
      ("absent-referer", "always", "Referer suppressed by referrer policy on the initiator; "
       "record Origin and Referer separately"),
      ("null-origin", "always", "opaque origin from a sandboxed frame or data: document"),
      ("lookalike-origin", "always", "registrable lookalike host that defeats prefix, suffix or "
       "substring allowlists"),
      ("sibling-origin", "always", "same-site sibling initiator against a check that trusts the "
       "whole site"),
      ("fetch-metadata", "always", "Sec-Fetch-Site/Mode/Dest enforcement and its "
       "missing-header fallback"),
      ("redirect-hop", "always", "initiation through a redirect on a trusted origin and which "
       "metadata survives the hop"))),
    ("cookie-delivery", "Session cookie delivery by site relationship", "ambient", ("cookies",),
     "ambient session cookie and its SameSite/Domain/Path attributes",
     "dedicated browser on the recorded build; DevTools cookie and network panels",
     (("top-level-get", "get", "cross-site top-level GET navigation (Lax cookies still attach)"),
      ("top-level-post", "nonget", "cross-site top-level form POST"),
      ("subresource-frame", "always", "image/script/iframe-embedded request"),
      ("credentialed-fetch", "always", "fetch/XHR with credentials included, as a simple request"),
      ("same-site-sibling", "always", "initiation from a same-site sibling origin; requires "
       "control of that origin"),
      ("default-lax-age", "samesite-default", "cookie without SameSite: fresh versus aged "
       "behaviour on the recorded browser build"),
      ("redirect-method-change", "always", "a POST that becomes a GET through a 302/303 chain"))),
    ("representation", "Body representation and preflight", "body", ("shape",),
     "JSON, multipart or API action with a request body",
     "browser forms/fetch; DevTools for the preflight and the actual request",
     (("form-urlencoded", "not-urlencoded", "same operation as application/x-www-form-urlencoded"),
      ("multipart", "not-multipart", "same operation as browser-built multipart/form-data"),
      ("text-plain", "always", "text/plain body, JSON-shaped when the parser is lenient"),
      ("content-type-parameters", "always", "parser leniency on MIME parameters, charset and "
       "casing that a browser can actually emit"),
      ("preflight-path", "non-simple", "non-simple request: the preflight decision and the "
       "actual request recorded separately; an unreadable response can still be a delivered "
       "write"))),
    ("middleware-coverage", "Methods, routes and middleware coverage", "ambient", ("shape",),
     "alternate method, version or handler for the same action",
     "import ledger and route inventory; Burp Repeater; browser for the effective request",
     (("get-mutation", "nonget", "the same state change through GET with query parameters"),
      ("override-parameter", "rewrite-method", "_method-style override sent as a form/query "
       "parameter from a POST form"),
      ("path-variant", "always", "trailing slash, case, encoding and normalization of the "
       "protected route"),
      ("legacy-version", "always", "older API version or alternate handler serving the same "
       "action"),
      ("exempt-route", "always", "route prefixes or handlers excluded from the CSRF middleware"))),
    ("graphql-operation", "GraphQL operation transport", "graphql", ("shape",),
     "GraphQL endpoint or client document naming a mutation",
     "JS/capture review of operation documents; browser",
     (("get-transport", "always", "the selected mutation sent as GET query parameters"),
      ("simple-body-transport", "always", "urlencoded, multipart or text/plain POST bodies the "
       "server still parses as GraphQL"),
      ("batch-alias", "always", "batched or aliased operations carrying the mutation"),
      ("persisted-query", "always", "persisted/hash-identified invocation of the operation"))),
    ("client-input-request", "Client-side CSRF through the app's request builder", "client",
     ("shape",), "SPA/JS client that builds authenticated requests from URL, hash or messages",
     "static JS tracing; DevTools initiator/call-stack view",
     (("url-param-sink", "always", "query parameter steering the URL, method or body of an "
       "authenticated request the app sends itself"),
      ("hash-route-sink", "always", "fragment or client-route state steering a request"),
      ("postmessage-sink", "always", "postMessage data reaching a request builder without an "
       "origin check"),
      ("path-traversal-sink", "always", "attacker-controlled path segment resolving to a "
       "different API route"))),
    ("identity-transaction", "Login, linking and SSO transactions", "identity",
     ("tokens", "shape"), "login, logout, link/connect, OAuth/OIDC callback",
     "separate browser contexts for the two supplied identities; auth captures",
     (("login-csrf", "login", "force the victim browser into the attacker's account"),
      ("link-callback-swap", "link", "attacker-started link/connect callback completed inside "
       "the victim's session"),
      ("state-binding", "oauth", "state, PKCE and nonce bound to the initiating browser session "
       "and transaction, evaluated together"),
      ("error-path-disclosure", "oauth", "state or code exposed on error and retry paths"))),
    ("saml-transaction", "SAML response correlation", "saml", ("shape",),
     "SAML SP/ACS flow", "browser SAML capture; hunt-saml for signature/parser work",
     (("unsolicited-response", "always", "IdP-initiated response accepted without a matching "
       "request where the SP should require one"),
      ("inresponseto-binding", "always", "InResponseTo bound to the browser session that "
       "started the flow"),
      ("relaystate-binding", "always", "RelayState treated as transaction state, not only as a "
       "redirect target"),
      ("response-replay", "always", "an already consumed assertion replayed"))),
    ("realtime-authority", "WebSocket and SignalR action authority", "realtime",
     ("headers", "cookies"), "WebSocket/SignalR/Socket.IO endpoint",
     "browser + Burp WebSocket history; DevTools frames",
     (("handshake-origin", "always", "cross-site handshake: Origin validation on upgrade or "
       "negotiate"),
      ("cookie-handshake", "always", "ambient cookie authenticating the connection"),
      ("message-authorization", "always", "a protected message or action executed over the "
       "cross-site connection (a 101 alone only switches protocols)"),
      ("transport-fallback", "always", "negotiate, SSE and long-polling transports enforcing "
       "the same checks"))),
    ("bff-protection", "Backend-for-frontend header protection", "bff", ("headers", "cookies"),
     "constant custom header (e.g. X-CSRF: 1) or a /bff route family",
     "browser fetch with and without the header; DevTools preflight",
     (("required-header", "always", "required constant header plus restrictive CORS: a valid "
       "defense when enforced, so confirm enforcement rather than assume a bypass"),
      ("excluded-route", "always", "routes or hubs excluded from the header requirement"),
      ("cors-policy", "always", "a preflight policy that would admit the header cross-origin"),
      ("cookie-scope", "always", "session cookie Domain widened beyond the host"))),
    ("effect-handoff", "Effect chains and restoration", "always", (),
     "a demonstrated action in this context",
     "findings/chain ledger; hunt-ato, hunt-xss, hunt-oauth, hunt-ssrf handoffs",
     (("ato-chain", "always", "email/password/MFA/link change carried through to account "
       "access on the supplied victim account"),
      ("privilege-chain", "always", "role, invite or permission change exercised"),
      ("integration-chain", "always", "webhook, integration or API-key change exercised; a "
       "server-side fetch that follows goes to hunt-ssrf"),
      ("token-theft-chain", "always", "same-origin script or XSS-read token driving the action; "
       "hand off to hunt-xss"),
      ("state-restore", "always", "owned state restored after the demonstration"))),
))
CASE_BY_ID = {c["id"]: c for c in CASES}
ATTACK_CASES = tuple(c["id"] for c in CASES if c["id"] not in ("baseline", "effect-handoff"))


# ---------------------------------------------------------------- applicability
def _ambient(f: Dict[str, Any]) -> Tuple[Optional[bool], str]:
    auth = f["auth"]
    if auth in AMBIENT_AUTH:
        return True, f"ambient credential the browser attaches by itself ({auth})"
    if auth == "header":
        return False, ("credential travels in an explicitly attached header that a cross-site "
                       "page cannot add; the client-input-request family covers app-built requests")
    if auth == "none":
        return None, ("no credential in the capture (sanitized export or unauthenticated "
                      "action): confirm in the browser whether a cookie authenticates it")
    return None, "authority unknown for this context: confirm whether a cookie authenticates it"


def _with_ambient(check):
    def wrapped(f):
        ok, reason = _ambient(f)
        return (ok, reason) if ok is not True else check(f)
    return wrapped


def _tokens(f):
    if f["declared"]:
        return None, "capture the action to see its token channels"
    if f["tokens"]:
        return True, f"token channels {f['tokens'][:4]}"
    return False, "no anti-CSRF token channel in the captures for this context"


def _cookie_pair(f):
    if f["csrf_cookies"]:
        return True, f"CSRF-named cookie(s) {sorted(set(f['csrf_cookies']))[:3]}"
    if f["declared"]:
        return None, "capture the action to see its cookies"
    return False, "no CSRF-named cookie observed for this host"


def _body(f):
    if f["method"] == "UNKNOWN":
        return None, "method unknown: capture the action"
    if f["method"] in WRITE_METHODS:
        return True, f"{f['method']} carries a body"
    return False, f"{f['method']} carries no body; middleware-coverage covers GET variants"


def _flag(ok, yes, no):
    return (True, yes) if ok else (False, no)


def _samesite_default(f):
    cookies = f["cookies"]
    if not cookies:
        return None, "no Set-Cookie attributes captured for this host"
    omitted = sorted({c["name"] for c in cookies if c.get("samesite") in (None, "invalid")})
    return _flag(bool(omitted), f"cookies without explicit SameSite: {omitted[:4]}",
                 "every captured cookie sets SameSite explicitly")


APPLIES = {
    "always": lambda f: (True, ""),
    "ambient": _ambient,
    "token": _with_ambient(_tokens),
    "cookie-pair": _with_ambient(_cookie_pair),
    "body": _with_ambient(_body),
    "graphql": lambda f: _flag(f["kind"] == "graphql", "GraphQL endpoint", "not a GraphQL endpoint"),
    "client": lambda f: _flag(f["client"], "JS client / SPA source", "no JS client source recorded"),
    "identity": lambda f: _flag(bool(IDENTITY_FLOW.search(f["route"])), "identity/linking flow",
                                "not a login/linking/SSO route"),
    "saml": lambda f: _flag(bool(SAML_FLOW.search(f["route"])), "SAML flow", "not a SAML route"),
    "realtime": lambda f: _flag(f["kind"] == "realtime", "realtime endpoint", "not a realtime endpoint"),
    "bff": lambda f: _flag("x-csrf" in f["flags"] or "/bff" in f["route"],
                           "constant custom-header defense or /bff route",
                           "no constant custom-header defense observed"),
    "get": lambda f: _flag(f["method"] in ("GET", "UNKNOWN"), "GET action", "not a GET action"),
    "nonget": lambda f: _flag(f["method"] != "GET", "non-GET action", "the action is already GET"),
    "rewrite-method": lambda f: _flag(f["method"] in ("PUT", "PATCH", "DELETE"),
                                      "PUT/PATCH/DELETE reachable from a POST form only by override",
                                      "no method override needed for this method"),
    "not-urlencoded": lambda f: _flag(f["content_type"] != "application/x-www-form-urlencoded",
                                      "original body is not urlencoded", "already urlencoded"),
    "not-multipart": lambda f: _flag(f["content_type"] != "multipart/form-data",
                                     "original body is not multipart", "already multipart"),
    "non-simple": lambda f: _flag(f["content_type"] not in SIMPLE_TYPES or bool(f["flags"]),
                                  "non-simple MIME or custom header", "already a simple request"),
    "samesite-default": _samesite_default,
    "login": lambda f: _flag(bool(LOGIN_FLOW.search(f["route"])), "login/session route",
                             "not a login route"),
    "link": lambda f: _flag(bool(LINK_FLOW.search(f["route"])), "link/connect/callback route",
                            "not a linking route"),
    "oauth": lambda f: _flag(bool(OAUTH_FLOW.search(f["route"])), "OAuth/OIDC/SSO route",
                             "not an OAuth/OIDC route"),
}


# ---------------------------------------------------------------- site relationship
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "ltd", "plc", "ne", "or", "go",
                 "gob", "nic", "mil", "sch"}


def _registrable(host: str) -> str:
    bare = host.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return bare
    except ValueError:
        pass
    labels = bare.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def site_relationship(target_origin: str, initiator_origin: str) -> str:
    """Schemeful same-origin / same-site / cross-site / opaque, by heuristic registrable
    domain (last two labels, common ccTLD second levels): not a Public Suffix List lookup."""
    if initiator_origin == "null":
        return "opaque"
    t, i = urlsplit(target_origin), urlsplit(initiator_origin)
    web = {"ws": "http", "wss": "https"}
    ts, is_ = web.get(t.scheme, t.scheme), web.get(i.scheme, i.scheme)
    th, ih = (t.hostname or "").lower(), (i.hostname or "").lower()
    if (ts, th, t.port or 0) == (is_, ih, i.port or 0) and t.scheme == i.scheme:
        return "same-origin"
    if ts != is_:
        return "cross-site"
    if th == ih or _registrable(th) == _registrable(ih):
        return "same-site"
    return "cross-site"


# ---------------------------------------------------------------- ledger
class CsrfLedger:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------------- config
    def effort_cap(self) -> int:
        config = self.ctx.campaign.raw.get("csrf", {})
        if not isinstance(config, dict):
            raise ValueError("csrf config must be an object")
        cap = config.get("per_case_effort_cap", DEFAULT_EFFORT_CAP)
        if type(cap) is not int or not 1 <= cap <= 10:
            raise ValueError("csrf.per_case_effort_cap must be 1..10")
        return cap

    # ---------------- inventory
    @staticmethod
    def _names(observations: Iterable[Dict[str, Any]], op_attrs: Dict[str, Any]) -> List[str]:
        names = set(str(n) for n in op_attrs.get("params") or [] if n)
        for o in observations:
            params = o.get("params") or {}
            names |= {str(n) for n in (params.get("query") or []) + (params.get("body") or []) if n}
        return sorted(names)

    @staticmethod
    def _mutation_hint(method: str, route: str, kind: str, names: Sequence[str]) -> Optional[str]:
        if method in WRITE_METHODS:
            return f"{method} write method"
        if method in ("HEAD", "OPTIONS", "TRACE", "CONNECT"):
            return None
        if kind == "realtime":
            return "realtime endpoint: a cookie-authenticated connection carries actions"
        if kind == "graphql":
            return "GraphQL endpoint: mutations can travel over GET"
        verbs = sorted({m.group(0).lower() for m in MUTATING.finditer(split_camel(route))})
        if verbs:
            return f"{method} with state-change verb(s) in the route: {verbs[:4]}"
        lowered = {n.lower() for n in names}
        selectors = sorted(lowered & ACTION_PARAMS)
        if selectors:
            return f"{method} with action-selector parameter(s): {selectors[:4]}"
        verb_params = sorted(n for n in lowered if MUTATING.fullmatch(n))
        if verb_params:
            return f"{method} with state-change parameter name(s): {verb_params[:4]}"
        return None

    @staticmethod
    def _priority(route: str) -> str:
        words_text = split_camel(route)  # `updateEmail` ranks as an email change
        for label, pattern in PRIORITY_RULES:
            if pattern.search(words_text):
                return label
        return "write"

    @staticmethod
    def _observation_meta(observation: Dict[str, Any], fallback_ct: str) -> Dict[str, Any]:
        context = observation.get("context") or {}
        meta = context.get("csrf_meta")
        if isinstance(meta, dict) and meta.get("v") == 1:
            if not meta.get("content_type"):
                meta = dict(meta, content_type=fallback_ct)
            return meta
        params = observation.get("params") or {}
        headers = [(n, "") for n in params.get("header") or [] if isinstance(n, str)]
        meta = request_meta(headers, fallback_ct, params.get("query") or [],
                            params.get("body") or [],
                            request_cookie_names=params.get("cookie") or [])
        if "header" not in params and "cookie" not in params:
            meta["auth"] = "unknown"  # legacy HAR capture: header names were not kept
        meta["basis"] = "derived-from-legacy-params"
        return meta

    def _facets(self, detail: Dict[str, Any], cookies: List[Dict[str, Any]]) -> Dict[str, str]:
        return {
            "tokens": _short([detail["token_channels"], detail["csrf_cookie_names"]]),
            "headers": _short([detail["header_flags"], detail["explicit_auth_headers"]]),
            "cookies": _short(sorted(cookies, key=lambda c: (c["name"], c.get("domain") or "",
                                                              c.get("path") or ""))),
            "origin": _short([detail["origins_seen"], detail["referer_sent"],
                              detail["sec_fetch_site"]]),
            "shape": _short(detail["shape"]),
        }

    def _host_cookies(self, records: List[Tuple[str, Dict[str, Any]]], host: str) -> List[Dict[str, Any]]:
        latest: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for source_host, record in records:
            if cookie_applies(record, source_host, host):
                latest[(record["name"], record.get("domain") or "", record.get("path") or "")] = record
        return [latest[k] for k in sorted(latest)]

    def _upsert_action(self, asset_id, origin, route, method, selector, kind, priority, basis,
                       sources, hint, fieldless, stats) -> int:
        row = self.db.execute("SELECT * FROM csrf_actions WHERE asset_id=? AND method=? AND selector=?",
                              (asset_id, method, selector)).fetchone()
        values = (origin, route, kind, priority, basis, json.dumps(sorted(set(sources))), hint,
                  int(fieldless))
        if row is None:
            cur = self.db.execute(
                "INSERT INTO csrf_actions(origin, route, kind, priority, basis, sources, hint,"
                " fieldless, asset_id, method, selector, created, updated)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                values + (asset_id, method, selector, now(), now()))
            stats["actions_added"] += 1
            return cur.lastrowid
        current = (row["origin"], row["route"], row["kind"], row["priority"], row["basis"],
                   row["sources"], row["hint"], row["fieldless"])
        if current != values:
            self.db.execute("UPDATE csrf_actions SET origin=?, route=?, kind=?, priority=?, basis=?,"
                            " sources=?, hint=?, fieldless=?, updated=? WHERE id=?",
                            values + (now(), row["id"]))
            stats["actions_updated"] += 1
        return row["id"]

    def _upsert_context(self, action_id, key, basis, detail, facets, stats) -> int:
        content_type, auth, account, role, tenant, workflow = key
        row = self.db.execute(
            "SELECT * FROM csrf_contexts WHERE action_id=? AND content_type=? AND auth=? AND"
            " account=? AND role=? AND tenant=? AND workflow=?",
            (action_id, content_type, auth, account, role, tenant, workflow)).fetchone()
        detail_json, facets_json = json.dumps(detail, sort_keys=True), json.dumps(facets, sort_keys=True)
        if row is None:
            count = self.db.execute("SELECT COUNT(*) FROM csrf_contexts WHERE action_id=?",
                                    (action_id,)).fetchone()[0]
            if count >= MAX_CONTEXTS_PER_ACTION:
                stats["contexts_capped"] += 1
                return 0
            cur = self.db.execute(
                "INSERT INTO csrf_contexts(action_id, content_type, auth, account, role, tenant,"
                " workflow, basis, facets, detail, created, updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (action_id, content_type, auth, account, role, tenant, workflow, basis,
                 facets_json, detail_json, now(), now()))
            stats["contexts_added"] += 1
            return cur.lastrowid
        if row["facets"] != facets_json:
            stats["contexts_changed"] += 1
        if (row["facets"], row["detail"], row["basis"]) != (facets_json, detail_json, basis):
            self.db.execute("UPDATE csrf_contexts SET basis=?, facets=?, detail=?, updated=? WHERE id=?",
                            (basis, facets_json, detail_json, now(), row["id"]))
        return row["id"]

    def sync(self) -> Dict[str, Any]:
        """Reconcile actions/contexts from the store. Idempotent; sends no traffic."""
        from .score import is_inferred_only
        store = self.ctx.store
        ops_by_endpoint: Dict[int, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        for op in store.operations():
            ops_by_endpoint[op["endpoint_id"]][(op["method"] or "UNKNOWN").upper()] = op["attrs"]
        services = {a["value"]: a.get("attrs", {}) for a in store.assets("service")}
        endpoints = [a for a in store.assets("endpoint", in_scope=True)
                     if not is_inferred_only(a) and self.ctx.scope.is_in(a["value"])]
        observations = {a["id"]: store.observations(a["id"])[-MAX_OBSERVATIONS:] for a in endpoints}
        cookie_records = self._cookie_records()
        stats: Counter = Counter()
        for asset in endpoints[:MAX_ACTIONS]:
            parts = urlsplit(asset["value"])
            origin = norm_origin(asset["value"]) or asset["value"]
            route = parts.path or "/"
            host = (parts.hostname or "").lower()
            attrs = asset.get("attrs", {})
            kind = ("realtime" if parts.scheme in ("ws", "wss") or REALTIME.search(route)
                    else "graphql" if GRAPHQL.search(route) else "http")
            ops = ops_by_endpoint.get(asset["id"]) or {
                str(m).upper(): {} for m in (attrs.get("methods") or ["UNKNOWN"]) if m}
            if len(ops) > 1:
                ops.pop("UNKNOWN", None)  # a known method supersedes an unmethoded JS literal
            host_cookies = self._host_cookies(cookie_records, host)
            service = services.get(origin.replace("ws://", "http://").replace("wss://", "https://"), {})
            for method, op_attrs in sorted(ops.items()):
                rows = [o for o in observations[asset["id"]]
                        if (o.get("method") or "").upper() == method]
                names = self._names(rows, op_attrs)
                hint = self._mutation_hint(method, route, kind, names)
                if not hint:
                    continue
                basis = "captured" if rows else "declared"
                action_id = self._upsert_action(
                    asset["id"], origin, route, method, "", kind, self._priority(route), basis,
                    attrs.get("sources", []), hint, not names, stats)
                self._sync_contexts(action_id, method, rows, op_attrs, names, host_cookies, stats)
                if kind == "graphql":
                    # One action per mutation (and per persisted operation of unknown type):
                    # declared from client code, captured when a request carried its name.
                    declared = {op for op in service.get("graphql_ops") or []
                                if isinstance(op, str) and op.lower().startswith("mutation ")}
                    captured: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
                    for o in rows:
                        meta = (o.get("context") or {}).get("csrf_meta") or {}
                        for op in meta.get("graphql_operations") or []:
                            if isinstance(op, str) and op.startswith(("mutation ", "persisted ")):
                                captured[op].append(o)
                    for op_name in sorted(declared | set(captured))[:MAX_SELECTORS]:
                        op_rows = captured.get(op_name, [])
                        sel_id = self._upsert_action(
                            asset["id"], origin, route, method, op_name[:120], kind,
                            self._priority(f"{route} {op_name}"),
                            "captured" if op_rows else "declared",
                            list(attrs.get("sources", [])) + (["js"] if op_name in declared else []),
                            f"GraphQL {op_name[:80]} "
                            + ("captured in traffic" if op_rows else "named in client code"),
                            False, stats)
                        self._sync_contexts(sel_id, method, op_rows, op_attrs,
                                            self._names(op_rows, {}) or names, host_cookies, stats)
        self.db.commit()
        totals = {k: self.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for k, t in (("actions", "csrf_actions"), ("contexts", "csrf_contexts"),
                               ("events", "csrf_case_events"))}
        return {"schema_version": 1, **{k: stats.get(k, 0) for k in (
                    "actions_added", "actions_updated", "contexts_added", "contexts_changed",
                    "contexts_capped")}, "totals": totals,
                "basis": "actions from captured observations, endpoint operations, forms, JS and "
                         "spec declarations; read-only GETs without a state-change signal are "
                         "not actions; nothing was sent", "executed": False}

    def _sync_contexts(self, action_id, method, rows, op_attrs, names, host_cookies, stats):
        groups: Dict[Tuple[str, ...], List[Tuple[Dict[str, Any], Dict[str, Any]]]] = defaultdict(list)
        declared_types = [mime_of(t) for t in (op_attrs.get("content_types") or [])]
        fallback_ct = declared_types[0] if len(set(declared_types)) == 1 else ""
        for o in rows:
            meta = self._observation_meta(o, fallback_ct)
            context = o.get("context") or {}
            key = (meta.get("content_type") or "", meta.get("auth") or "unknown",
                   o.get("account") or "", str(context.get("role") or "")[:200],
                   str(context.get("tenant") or "")[:200], str(context.get("workflow_state") or "")[:200])
            groups[key].append((o, meta))
        for key, items in groups.items():
            detail = self._detail([m for _, m in items], names, [o["id"] for o, _ in items])
            self._upsert_context(action_id, key, "captured", detail,
                                 self._facets(detail, host_cookies), stats)
        if rows:
            return
        enctypes = [mime_of(t) or "application/x-www-form-urlencoded"
                    for t in op_attrs.get("form_enctypes") or []]
        types = sorted(set(enctypes + [mime_of(t) for t in op_attrs.get("spec_content_types") or []]
                           + declared_types)) or [""]
        spec_auth = sorted(set(op_attrs.get("spec_auth") or []))
        auth = (spec_auth[0] if len(spec_auth) == 1 and spec_auth[0] in AMBIENT_AUTH + ("header",)
                else "cookie+header" if spec_auth == ["cookie", "header"] else "unknown")
        token_fields = [f"body:{n}" for n in op_attrs.get("csrf_token_fields") or [] if isinstance(n, str)]
        for content_type in types[:10]:
            detail = {"token_channels": sorted(set(token_fields + [
                          f"param:{n}" for n in names if TOKENISH.search(n)])),
                      "header_flags": [], "explicit_auth_headers": [], "csrf_cookie_names": [],
                      "session_cookie_names": [], "origins_seen": [], "referer_sent": False,
                      "sec_fetch_site": [], "shape": names[:200], "observation_ids": [],
                      "metadata_basis": ["declared"]}
            self._upsert_context(action_id, (content_type, auth, "", "", "", ""), "declared",
                                 detail, self._facets(detail, host_cookies), stats)

    @staticmethod
    def _detail(metas: List[Dict[str, Any]], names: List[str], observation_ids: List[int]) -> Dict[str, Any]:
        def union(key):
            return sorted({v for m in metas for v in (m.get(key) or []) if isinstance(v, str)})
        return {"token_channels": union("token_channels"), "header_flags": union("header_flags"),
                "explicit_auth_headers": union("explicit_auth_headers"),
                "csrf_cookie_names": union("csrf_cookie_names"),
                "session_cookie_names": union("session_cookie_names"),
                "origins_seen": sorted({m.get("origin") or "absent" for m in metas}),
                "referer_sent": any(m.get("referer_sent") for m in metas),
                "sec_fetch_site": sorted({(m.get("sec_fetch") or {}).get("site", "absent")
                                          for m in metas}),
                "shape": names[:200], "observation_ids": sorted(observation_ids)[-50:],
                "metadata_basis": sorted({m.get("basis", "capture") for m in metas})}

    # ---------------- evaluation
    def _actions(self, action_id=None, host=None) -> List[Dict[str, Any]]:
        q, args = "SELECT * FROM csrf_actions", []
        clauses = []
        if action_id is not None:
            if type(action_id) is not int or action_id < 1:
                raise ValueError("action ID must be a positive integer")
            clauses.append("id=?")
            args.append(action_id)
        if host:
            wanted = norm_origin(host) if "://" in host else None
            if wanted:
                clauses.append("origin=?")
                args.append(wanted)
            else:
                clauses.append("(origin LIKE ? OR origin LIKE ?)")
                args += [f"%://{host.lower()}", f"%://{host.lower()}:%"]
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        rows = [dict(r) for r in self.db.execute(q + " ORDER BY id", args)]
        if action_id is not None and not rows:
            raise ValueError(f"unknown CSRF action {action_id}")
        return rows

    def _events(self, context_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
        out: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for i in range(0, len(context_ids), 500):
            chunk = context_ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for r in self.db.execute(f"SELECT * FROM csrf_case_events WHERE context_id IN ({marks})"
                                     " ORDER BY id", chunk):
                event = dict(r)
                for key in ("facets", "counts", "artifacts", "tool_refs"):
                    event[key] = json.loads(event[key])
                out[event["context_id"]].append(event)
        return out

    def _facts(self, action, context, detail, cookies, services, effect) -> Dict[str, Any]:
        origin = action["origin"].replace("ws://", "http://").replace("wss://", "https://")
        service = services.get(origin, {})
        sources = set(json.loads(action["sources"]))
        return {"method": action["method"], "kind": action["kind"],
                "route": f"{action['route']} {action['selector']}".lower(),
                "content_type": context["content_type"], "auth": context["auth"],
                "declared": context["basis"] == "declared", "tokens": detail["token_channels"],
                "flags": detail["header_flags"],
                "csrf_cookies": detail["csrf_cookie_names"] + [
                    c["name"] for c in cookies if TOKENISH.search(c["name"])],
                "cookies": cookies,
                "client": bool(sources & {"js", "inline", "sourcemap", "runtime"})
                          or bool(service.get("spa") or service.get("hash_routing")),
                "effect": effect}

    @staticmethod
    def _stale(event, case, facets) -> bool:
        return any(event["facets"].get(f) != facets.get(f) for f in case["facets"])

    def _card(self, case, facts, events, facets, baseline_outcome, cap) -> Dict[str, Any]:
        ok, reason = APPLIES[case["applies"]](facts)
        current = [e for e in events if not self._stale(e, case, facets)]
        stale = [e for e in events if self._stale(e, case, facets)]
        variants, open_variants = [], []
        for vid, tag, technique in case["variants"]:
            v_ok, v_reason = (ok, reason) if ok is not True else APPLIES[tag](facts)
            latest = [e for e in current if e["variant"] == vid]
            if latest:
                state = latest[-1]["state"]
            elif v_ok is False:
                state = "n-a-suggested"
            else:
                state = "open"
            if state in ("open", "attempted"):
                open_variants.append(vid)
            variants.append({"id": vid, "technique": technique, "applicable": v_ok,
                             "reason": v_reason, "state": state})
        case_level = [e for e in current if not e["variant"] and e["state"] in TERMINAL]
        if any(e["state"] == "observed" for e in current):
            outcome, outcome_basis = "observed", "recorded"
        elif case_level:
            outcome, outcome_basis = case_level[-1]["state"], "recorded"
        elif not open_variants and any(v["state"] in TERMINAL for v in variants):
            states = {v["state"] for v in variants}
            outcome = ("blocked" if "blocked" in states else "inconclusive" if "inconclusive" in states
                       else "negative" if "negative" in states else "n-a")
            outcome_basis = "derived from resolved variants"
        elif current:
            outcome, outcome_basis = "in-progress", "variants open"
        elif stale:
            outcome, outcome_basis = "stale", "context facets changed since the last events"
        else:
            outcome, outcome_basis = "untested", ""
        if case["id"] != "baseline" and baseline_outcome == "n-a":
            readiness = "n-a-baseline"  # the baseline showed the action changes no state
        elif case["id"] == "effect-handoff":
            readiness = "ready" if facts["effect"] else "waiting-effect"
        elif ok is False:
            readiness = "n-a-suggested"
        elif facts["declared"] and case["id"] != "baseline":
            readiness = "waiting-capture"
        elif ok is None:
            readiness = "needs-confirmation"
        elif case["id"] != "baseline" and baseline_outcome != "observed":
            readiness = "waiting-baseline"
        else:
            readiness = "ready"
        attempts = sum(1 for e in current if e["attempt_kind"] in ("browser", "replay")
                       and e["state"] in ("attempted", "negative", "inconclusive"))
        is_open = readiness in READINESS_OPEN and outcome in ("untested", "in-progress", "stale")
        return {"case": case["id"], "title": case["title"], "applicable": ok, "reason": reason,
                "readiness": readiness, "outcome": outcome, "outcome_basis": outcome_basis,
                "open": is_open, "attempts": attempts,
                "effort_cap_reached": attempts >= cap and outcome not in ("observed", "negative", "n-a"),
                "variants": variants, "open_variants": open_variants,
                "events": len(current), "stale_events": len(stale), "hint": case["hint"],
                "tools": case["tools"]}

    def _evaluate(self, action_id=None, host=None) -> List[Dict[str, Any]]:
        cap = self.effort_cap()
        actions = self._actions(action_id, host)
        services = {a["value"]: a.get("attrs", {}) for a in self.ctx.store.assets("service")}
        contexts_by_action: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        if actions:
            ids = [a["id"] for a in actions]
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                for r in self.db.execute("SELECT * FROM csrf_contexts WHERE action_id IN (%s) ORDER BY id"
                                         % ",".join("?" * len(chunk)), chunk):
                    contexts_by_action[r["action_id"]].append(dict(r))
        events = self._events([c["id"] for cs in contexts_by_action.values() for c in cs])
        cookie_cache: Dict[str, List[Dict[str, Any]]] = {}
        records = self._cookie_records() if actions else []
        out = []
        for action in actions:
            contexts = contexts_by_action.get(action["id"], [])
            has_captured = any(c["basis"] == "captured" for c in contexts)
            evaluated = []
            for context in contexts:
                ctx_events = events.get(context["id"], [])
                superseded = context["basis"] == "declared" and has_captured and not ctx_events
                facets, detail = json.loads(context["facets"]), json.loads(context["detail"])
                host_name = (urlsplit(action["origin"]).hostname or "").lower()
                if host_name not in cookie_cache:
                    cookie_cache[host_name] = self._host_cookies(records, host_name)
                cookies = cookie_cache[host_name]
                by_case: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
                for e in ctx_events:
                    by_case[e["case_id"]].append(e)
                effect = any(e["state"] == "observed" and e["case_id"] in ATTACK_CASES
                             and not self._stale(e, CASE_BY_ID[e["case_id"]], facets)
                             for e in ctx_events)
                facts = self._facts(action, context, detail, cookies, services, effect)
                baseline = self._card(CASE_BY_ID["baseline"], facts, by_case.get("baseline", []),
                                      facets, "observed", cap)
                cards = [baseline] + [self._card(c, facts, by_case.get(c["id"], []), facets,
                                                 baseline["outcome"], cap) for c in CASES[1:]]
                evaluated.append({"context_id": context["id"], "basis": context["basis"],
                                  "superseded": superseded, "content_type": context["content_type"],
                                  "auth": context["auth"], "account": context["account"],
                                  "role": context["role"], "tenant": context["tenant"],
                                  "workflow": context["workflow"], "facets": facets,
                                  "token_channels": detail["token_channels"],
                                  "header_flags": detail["header_flags"],
                                  "origins_seen": detail["origins_seen"],
                                  "cookies": [{k: c.get(k) for k in ("name", "samesite", "domain",
                                                                     "secure", "httponly")}
                                              for c in cookies][:10],
                                  "observation_ids": detail["observation_ids"], "cases": cards})
            out.append({"action_id": action["id"], "asset_id": action["asset_id"],
                        "origin": action["origin"], "route": action["route"],
                        "method": action["method"], "selector": action["selector"],
                        "kind": action["kind"], "priority": action["priority"],
                        "basis": action["basis"], "fieldless": bool(action["fieldless"]),
                        "hint": action["hint"], "sources": json.loads(action["sources"]),
                        "method_granted": action["method"] in self.ctx.policy.allowed_methods
                        or action["method"] == "UNKNOWN", "contexts": evaluated})
        return out

    def _cookie_records(self) -> List[Tuple[str, Dict[str, Any]]]:
        """(source host, Set-Cookie attribute record) from every capture, oldest first."""
        hosts = {r["id"]: (urlsplit(r["value"]).hostname or "").lower() for r in self.db.execute(
            "SELECT id, value FROM assets WHERE kind='endpoint'")}
        records = []
        for o in self.ctx.store.observations()[-20000:]:
            meta = (o.get("context") or {}).get("csrf_meta") or {}
            for r in meta.get("set_cookies") or []:
                if isinstance(r, dict) and isinstance(r.get("name"), str):
                    records.append((hosts.get(o["endpoint_id"], ""), r))
        return records

    # ---------------- plan / status
    def plan(self, action_id=None, host=None, limit=25) -> Dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("limit must be 1..500")
        sync = self.sync()
        actions = self._evaluate(action_id, host)
        actions.sort(key=lambda a: (self._rank(a), a["action_id"]))
        blockers = []
        if self.ctx.policy.mode == "passive":
            blockers.append("passive mode: no live target requests")
        if "csrf" in (self.ctx.campaign.raw.get("excluded_bug_classes") or []):
            blockers.append("CSRF is excluded by campaign rules")
        shown = actions[:limit]
        for action in shown:
            for context in action["contexts"]:
                if context["superseded"]:
                    context["cases"] = []
                    context["note"] = "declared-only context superseded by captured contexts"
        return {"schema_version": 1, "skill": "hunt-csrf", "blockers": blockers,
                "per_case_effort_cap": self.effort_cap(), "sync": {k: v for k, v in sync.items()
                                                                    if k not in ("basis",)},
                "actions": shown, "actions_total": len(actions), "truncated": len(actions) > limit,
                "next": self._next(actions)[:20],
                "execution": "offline only; cross-origin exercises run in the dedicated browser "
                             "through Burp under the campaign execution plan; this plan grants "
                             "nothing",
                "evidence_basis": "operator-recorded events with hash-bound artifacts; not "
                                  "independently verified exploitability",
                "finding_promoted": False, "executed": False}

    @staticmethod
    def _rank(action: Dict[str, Any]) -> int:
        try:
            return PRIORITY_ORDER.index(action["priority"])
        except ValueError:
            return len(PRIORITY_ORDER)

    def _next(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        order = {r: i for i, r in enumerate(("ready", "needs-confirmation", "waiting-capture",
                                             "waiting-baseline"))}
        items = []
        for action in actions:
            for context in action["contexts"]:
                if context["superseded"]:
                    continue
                for card in context["cases"]:
                    if card["open"]:
                        items.append((self._rank(action), order.get(card["readiness"], 9),
                                      action["action_id"], context["context_id"],
                                      [c["id"] for c in CASES].index(card["case"]),
                                      {"action_id": action["action_id"],
                                       "context_id": context["context_id"],
                                       "target": f"{action['method']} {action['origin']}{action['route']}"
                                                 + (f" [{action['selector']}]" if action["selector"] else ""),
                                       "priority": action["priority"], "case": card["case"],
                                       "readiness": card["readiness"],
                                       "open_variants": card["open_variants"][:8]}))
        return [i[-1] for i in sorted(items, key=lambda i: i[:5])]

    def status(self, host=None) -> Dict[str, Any]:
        self.sync()
        actions = self._evaluate(None, host)
        outcomes, readiness = Counter(), Counter()
        hosts: Dict[str, Counter] = defaultdict(Counter)
        stale, confirm, capped, capture = [], [], [], []
        for action in actions:
            h = hosts[action["origin"]]
            h["actions"] += 1
            h["captured" if action["basis"] == "captured" else "declared-only"] += 1
            for context in action["contexts"]:
                if context["superseded"]:
                    continue
                h["contexts"] += 1
                for card in context["cases"]:
                    outcomes[card["outcome"]] += 1
                    readiness[card["readiness"]] += 1
                    if card["open"]:
                        h["open"] += 1
                    h[card["outcome"]] += 1
                    label = {"action_id": action["action_id"], "context_id": context["context_id"],
                             "case": card["case"]}
                    if card["outcome"] == "stale":
                        stale.append(label)
                    if card["readiness"] == "needs-confirmation" and card["open"]:
                        confirm.append(label)
                    if card["readiness"] == "waiting-capture" and card["open"]:
                        capture.append(label)
                    if card["effort_cap_reached"]:
                        capped.append(label)
        coarse = []
        for row in self.db.execute("SELECT c.asset_id, c.status FROM coverage c WHERE"
                                   " c.bug_class='csrf' AND c.status IN ('tested','refuted','n-a')"):
            open_cases = sum(card["open"] for a in actions if a["asset_id"] == row["asset_id"]
                             for c in a["contexts"] if not c["superseded"] for card in c["cases"])
            if open_cases:
                coarse.append({"asset_id": row["asset_id"], "coarse_status": row["status"],
                               "open_action_cases": open_cases})
        return {"schema_version": 1,
                "actions": len(actions),
                "hosts": [{"origin": o, **{k: c.get(k, 0) for k in (
                    "actions", "captured", "declared-only", "contexts", "open", "observed",
                    "negative", "blocked", "inconclusive", "stale")}}
                          for o, c in sorted(hosts.items())],
                "outcomes": dict(sorted(outcomes.items())),
                "readiness": dict(sorted(readiness.items())),
                "open_cases": sum(h["open"] for h in hosts.values()),
                "stale_cases": stale[:100], "needs_confirmation": confirm[:100],
                "waiting_capture": capture[:100], "effort_cap_reached": capped[:100],
                "coarse_rows_with_open_cases": coarse[:100],
                "next": self._next(actions)[:20],
                "basis": "per-origin action x context x case ledger; coarse `cov` rows never close "
                         "open action cases; completeness covers inventoried actions only",
                "executed": False}

    def report_rows(self) -> Dict[str, List[List[Any]]]:
        data = self.status()
        hosts = [[h["origin"], h["actions"], h["captured"], h["declared-only"], h["contexts"],
                  h["open"], h["observed"], h["negative"], h["blocked"] + h["inconclusive"],
                  h["stale"]] for h in data["hosts"]]
        nxt = [[n["action_id"], n["context_id"], n["target"], n["priority"], n["case"],
                n["readiness"], ", ".join(n["open_variants"])] for n in data["next"]]
        return {"hosts": hosts, "next": nxt,
                "coarse": [[c["asset_id"], c["coarse_status"], c["open_action_cases"]]
                           for c in data["coarse_rows_with_open_cases"]]}

    # ---------------- record
    def record(self, context_id, case_id, state, variant="", attempt_kind="browser",
               initiator="none", initiator_origin="", delivery="", preflight="", browser="",
               prerequisite="", artifacts=(), tool_refs=(), requests=0, connections=0,
               messages=0, note="") -> Dict[str, Any]:
        if type(context_id) is not int or context_id < 1:
            raise ValueError("context ID must be a positive integer")
        context = self.db.execute("SELECT * FROM csrf_contexts WHERE id=?", (context_id,)).fetchone()
        if context is None:
            raise ValueError(f"unknown CSRF context {context_id}; run `recon csrf plan`")
        action = self.db.execute("SELECT * FROM csrf_actions WHERE id=?",
                                 (context["action_id"],)).fetchone()
        asset = self.ctx.store.get_asset(action["asset_id"])
        self.ctx.scope.check(asset["value"])
        case = CASE_BY_ID.get(case_id)
        if case is None:
            raise ValueError(f"unknown CSRF case; one of {[c['id'] for c in CASES]}")
        variant = variant or ""
        if variant and variant not in {v[0] for v in case["variants"]}:
            raise ValueError(f"unknown variant for {case_id}; one of {[v[0] for v in case['variants']]}")
        checks = ((state, STATES, "state"), (attempt_kind, ATTEMPT_KINDS, "attempt kind"),
                  (initiator, INITIATORS, "initiator"))
        for value, allowed, label in checks:
            if value not in allowed:
                raise ValueError(f"{label} must be one of {allowed}")
        if delivery and delivery not in DELIVERIES:
            raise ValueError(f"delivery must be one of {DELIVERIES}")
        if preflight and preflight not in PREFLIGHT:
            raise ValueError(f"preflight must be one of {PREFLIGHT}")
        for value, limit, label in ((note, 2000, "note"), (browser, 120, "browser"),
                                    (prerequisite, 300, "prerequisite")):
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError(f"{label} must be at most {limit} characters")
        counts = {"requests": requests, "connections": connections, "messages": messages}
        if any(type(v) is not int or not 0 <= v <= 10000 for v in counts.values()):
            raise ValueError("request/connection/message counts must be 0..10000")
        refs = list(tool_refs or [])
        if len(refs) > 20 or any(not isinstance(r, str) or not re.fullmatch(r"[\w.:/#@-]{1,120}", r)
                                 for r in refs):
            raise ValueError("tool references are at most 20 labels like burp-history:1234")
        if initiator_origin:
            normalized = norm_origin(initiator_origin)
            if normalized is None:
                raise ValueError("initiator origin must be scheme://host[:port] or null")
            initiator_origin = normalized
        if (initiator == "opaque") != (initiator_origin == "null") and initiator_origin:
            raise ValueError("an opaque initiator is recorded with initiator origin `null`")
        if attempt_kind in ("replay", "review") and initiator != "none":
            raise ValueError("a replayed or reviewed request has no browser initiator; record "
                             "initiator `none` (a forged Origin/Cookie header is a diagnostic, "
                             "not browser initiation)")
        relationship = (site_relationship(action["origin"], initiator_origin)
                        if initiator_origin else "")
        blobs = self._read_artifacts(artifacts)
        roles = {role: sha for role, sha, _ in blobs}
        if state in ("n-a", "blocked", "inconclusive") and not note.strip():
            raise ValueError(f"a {state} outcome needs a note naming the reason")
        facets = json.loads(context["facets"])
        if state == "observed":
            self._check_observed(case, action, context_id, attempt_kind, initiator,
                                 initiator_origin, relationship, delivery, preflight, prerequisite,
                                 roles, note, facets)
        if state == "negative":
            if not note.strip():
                raise ValueError("a negative outcome needs a note describing what was exercised")
            if not blobs and attempt_kind != "review":
                raise ValueError("a negative outcome needs at least one artifact (or attempt "
                                 "kind `review` for a source/config review)")
            if not variant:
                self._check_variants_resolved(case, action, context, context_id)
        kept = self._store_artifacts(blobs)
        cur = self.db.execute(
            "INSERT INTO csrf_case_events(context_id, case_id, variant, state, attempt_kind,"
            " initiator, initiator_origin, relationship, delivery, preflight, browser,"
            " prerequisite, facets, counts, artifacts, tool_refs, note, created)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (context_id, case_id, variant, state, attempt_kind, initiator, initiator_origin,
             relationship, delivery, preflight, browser.strip(), prerequisite.strip(),
             json.dumps(facets, sort_keys=True), json.dumps(counts), json.dumps(kept),
             json.dumps(refs), note.strip(), now()))
        self.db.commit()
        return {"event_id": cur.lastrowid, "action_id": action["id"], "context_id": context_id,
                "case": case_id, "variant": variant, "state": state,
                "relationship": relationship or None,
                "relationship_conflict": bool(relationship and initiator in ("same-site", "cross-site")
                                              and relationship != initiator),
                "relationship_basis": "heuristic registrable domain (no Public Suffix List lookup)"
                if relationship else None,
                "artifacts": kept, "tool_refs": refs,
                "basis": "operator-recorded event with hash-bound artifacts; external tool IDs are "
                         "references, never native fact IDs",
                "executed": False, "finding_promoted": False}

    def _check_observed(self, case, action, context_id, attempt_kind, initiator,
                        initiator_origin, relationship, delivery, preflight, prerequisite,
                        roles, note, facets) -> None:
        if "before" not in roles or "after" not in roles or roles["before"] == roles["after"]:
            raise ValueError("observed needs distinct `before` and `after` state-readback "
                             "artifacts: an unchanged readback (for example a 200 error "
                             "envelope) is not a state change")
        if case["id"] == "baseline":
            if attempt_kind == "review":
                raise ValueError("the baseline is observed by exercising the legitimate action")
            return
        if case["id"] == "effect-handoff":
            if not note.strip():
                raise ValueError("an effect handoff needs a note naming the downstream effect")
            return
        if "request" not in roles:
            raise ValueError("observed needs the captured browser `request` artifact")
        if attempt_kind != "browser":
            raise ValueError("an observed CSRF case is browser-initiated; replays are diagnostics")
        if initiator not in ("same-site", "cross-site", "opaque") or not initiator_origin:
            raise ValueError("observed needs the browser initiator relationship and origin "
                             "(same-site/cross-site/opaque with --initiator-origin)")
        if relationship == "same-origin":
            raise ValueError("the initiator origin equals the target origin; that is the app "
                             "itself, not a cross-origin request")
        if not delivery:
            raise ValueError("observed needs the delivery mode the browser used")
        if preflight == "denied":
            raise ValueError("a denied preflight means the browser never sent the actual "
                             "request; record negative for this variant")
        if case["id"] == "realtime-authority" and "messages" not in roles:
            raise ValueError("realtime observed needs the `messages` artifact: a 101 handshake "
                             "only switches protocols")
        if (initiator == "same-site" or relationship == "same-site") and not prerequisite.strip():
            raise ValueError("a same-site initiator needs --prerequisite naming how that sibling "
                             "origin is controlled (owned lab, finding id, program-supplied host)")
        baseline = [e for e in self._events([context_id]).get(context_id, [])
                    if e["case_id"] == "baseline" and e["state"] == "observed"
                    and not self._stale(e, CASE_BY_ID["baseline"], facets)]
        if not baseline:
            raise ValueError("record the baseline (legitimate action + readback) for this "
                             "context first")

    def _check_variants_resolved(self, case, action, context, context_id) -> None:
        detail, facets = json.loads(context["detail"]), json.loads(context["facets"])
        host_name = (urlsplit(action["origin"]).hostname or "").lower()
        services = {a["value"]: a.get("attrs", {}) for a in self.ctx.store.assets("service")}
        events = self._events([context_id]).get(context_id, [])
        effect = any(e["state"] == "observed" and e["case_id"] in ATTACK_CASES for e in events)
        facts = self._facts(dict(action), dict(context), detail,
                            self._host_cookies(self._cookie_records(), host_name), services, effect)
        card = self._card(case, facts, [e for e in events if e["case_id"] == case["id"]],
                          facets, "observed", self.effort_cap())
        if card["open_variants"]:
            raise ValueError(f"case-level negative needs every applicable variant resolved "
                             f"first; open: {card['open_variants']} (record each, or n-a with "
                             f"a reason)")

    def _read_artifacts(self, artifacts) -> List[Tuple[str, str, bytes]]:
        items = list(artifacts or [])
        if len(items) > MAX_ARTIFACTS:
            raise ValueError(f"at most {MAX_ARTIFACTS} artifacts per event")
        out = []
        for item in items:
            if isinstance(item, str):
                role, sep, path = item.partition("=")
                if not sep:
                    raise ValueError("artifacts are ROLE=PATH")
            elif isinstance(item, dict):
                role, path = item.get("role"), item.get("path")
            else:
                raise ValueError("artifacts are ROLE=PATH")
            if role not in ARTIFACT_ROLES or not isinstance(path, str) or not path:
                raise ValueError(f"artifact role must be one of {ARTIFACT_ROLES}")
            if role in {r for r, _, _ in out}:
                raise ValueError(f"artifact role {role} given twice")
            data = local_bytes(self.ctx.campaign.root, path)
            out.append((role, hashlib.sha256(data).hexdigest(), data))
        return out

    def _store_artifacts(self, blobs) -> List[Dict[str, Any]]:
        dest = self.ctx.campaign.state_dir / EVIDENCE_DIR
        if dest.is_symlink() or self.ctx.campaign.state_dir.is_symlink():
            raise ValueError("refusing a symlinked evidence store")
        kept = []
        for role, sha, data in blobs:
            dest.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = dest / sha
            if path.exists() or path.is_symlink():
                if path.is_symlink() or local_bytes(self.ctx.campaign.root, path.resolve()) != data:
                    raise ValueError("stored CSRF evidence was modified")
            else:
                with path.open("xb") as stream:
                    stream.write(data)
                path.chmod(0o600)
            kept.append({"role": role, "path": path.relative_to(self.ctx.campaign.root).as_posix(),
                         "sha256": sha, "bytes": len(data)})
        return kept

    def verify_artifacts(self) -> Dict[str, Any]:
        """Re-hash every stored artifact reference (missing/modified evidence stays visible)."""
        bad = []
        for r in self.db.execute("SELECT id, artifacts FROM csrf_case_events ORDER BY id"):
            for ref in json.loads(r["artifacts"]):
                try:
                    data = local_bytes(self.ctx.campaign.root, ref["path"])
                    ok = hashlib.sha256(data).hexdigest() == ref["sha256"]
                except (ValueError, OSError):
                    ok = False
                if not ok:
                    bad.append({"event_id": r["id"], "role": ref["role"], "path": ref["path"]})
        return {"checked_events": self.db.execute("SELECT COUNT(*) FROM csrf_case_events").fetchone()[0],
                "missing_or_modified": bad}


def report_rows(ctx) -> Dict[str, List[List[Any]]]:
    return CsrfLedger(ctx).report_rows()
