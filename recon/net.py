"""The only two ways recon code may touch the network.

ScopedClient  - talks to the TARGET. Methods are granted by policy.allowed_methods
                (GET/HEAD by default; POST/PUT/PATCH/DELETE/OPTIONS are an explicit
                operator grant for programs permitting state-changing tests). Scope is
                checked on the first URL and on every redirect hop (an out-of-scope
                Location is recorded, never followed). Policy-mode-checked. Rate-limited
                per host. Every request is logged with response and request body hashes.
                Write methods never auto-follow redirects: the 3xx is returned so a
                payload is never silently re-sent to another target.
PassiveClient - talks to third-party INTEL sources only (crt.sh, web.archive.org).
                Refuses any host that is in the target's scope, so passive mode is
                guaranteed zero-touch.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlsplit

from .campaign import Campaign, OutOfScope, PolicyViolation, norm_host
from .extract import origin_of
from .egress import ConnectionGuard, PinnedHTTPHandler, PinnedHTTPSHandler
from .store import Store

MAX_REDIRECTS = 5
REDIRECT_CODES = (301, 302, 303, 307, 308)
INTEL_HOSTS = frozenset({"crt.sh", "web.archive.org"})
KEV_HOSTS = frozenset({"www.cisa.gov"})
# Exploit search: the only intel source that takes a POST. It receives product + version
# strings only (e.g. "jenkins 2.401"), never a target hostname, URL or header.
EXPLOIT_SEARCH_HOSTS = frozenset({"sploitus.com"})


class FetchError(Exception):
    pass


class BudgetExceeded(PolicyViolation):
    pass


class RequestBudget:
    """Shared target + intel HTTP budget per Recon instance; includes failed attempts."""
    def __init__(self, max_requests: int, max_seconds: float):
        self.remaining = max_requests
        self.deadline = time.monotonic() + max_seconds
        self.lock = threading.Lock()

    def check(self) -> None:
        if self.remaining <= 0 or time.monotonic() >= self.deadline:
            raise BudgetExceeded("per-run request/time budget exhausted; explicit next run required")

    def consume(self) -> float:
        with self.lock:
            self.check()
            self.remaining -= 1
            return max(0.001, self.deadline - time.monotonic())


@dataclass
class Response:
    url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    set_cookie: str = ""
    truncated: bool = False
    redirect_chain: List[str] = field(default_factory=list)
    blocked_redirect: Optional[str] = None
    request_id: Optional[int] = None

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()


class RateLimiter:
    def __init__(self, rps: float):
        self.interval = 1.0 / rps
        self._next: Dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        with self._lock:
            now = time.monotonic()
            t = max(now, self._next.get(host, 0.0))
            self._next[host] = t + self.interval
        if t > now:
            time.sleep(t - now)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # surface 3xx to us so every hop can be scope-checked


def _build_opener(verify_tls: bool, guard):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),  # no proxy can bypass pinned-peer policy
        PinnedHTTPHandler(guard), PinnedHTTPSHandler(guard, ctx),
        _NoRedirect)


class _BaseClient:
    def __init__(self, campaign: Campaign, store: Store, limiter: Optional[RateLimiter] = None,
                 timeout: float = 20.0, budget: Optional[RequestBudget] = None):
        self.campaign = campaign
        self.store = store
        self.policy = campaign.policy
        self.limiter = limiter or RateLimiter(campaign.policy.max_rps)
        self.timeout = timeout
        self.budget = budget or RequestBudget(self.policy.max_requests, self.policy.max_seconds)
        intel = isinstance(self, PassiveClient)
        self.opener = _build_opener(True if intel else campaign.policy.verify_tls,
                                    ConnectionGuard(campaign, store, intel=intel))

    def _headers(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        h = {"User-Agent": self.policy.user_agent, "Accept": "*/*"}
        h.update(self.policy.headers)
        h.update(extra or {})
        if any(k.lower() in ("host", "proxy-authorization", "proxy-connection") for k in h):
            raise PolicyViolation("Host/proxy header overrides are not supported by the scoped client")
        return h

    def _send(self, method: str, url: str, purpose: str, headers: Dict[str, str],
              max_bytes: int, timeout: Optional[float], data: Optional[bytes] = None,
              req_body: bytes = b"", req_content_type: Optional[str] = None) -> Response:
        max_bytes = min(max_bytes, self.policy.max_body_bytes)
        host = norm_host(urlsplit(url).hostname or "")
        if isinstance(self, ScopedClient):
            self.policy.require("active", "target HTTP transport")
            self.campaign.scope.check(url)
            if method not in self.policy.allowed_methods:
                raise PolicyViolation(
                    f"method {method} is not granted by policy.allowed_methods for this campaign")
        if self.policy.proxy:
            raise PolicyViolation("configured proxies cannot enforce pinned-peer egress; direct transport required")
        self.limiter.wait(host)
        time.sleep(self.store.reserve_pacing_slot(host, self.limiter.interval))
        remaining_time = self.budget.consume()
        if not self.store.reserve_network_attempt(self.policy.max_campaign_requests):
            raise BudgetExceeded("persistent campaign HTTP attempt budget exhausted")
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            try:
                with self.opener.open(req, timeout=min(timeout or self.timeout, remaining_time)) as r:
                    status, hdrs = r.status, r.headers
                    body = r.read(max_bytes + 1) if method != "HEAD" else b""
            except urllib.error.HTTPError as e:
                status, hdrs = e.code, e.headers
                try:
                    body = e.read(max_bytes + 1) if (e.fp and method != "HEAD") else b""
                finally:
                    e.close()
        except PolicyViolation as e:
            self.store.record_request(method, url, None, purpose, headers.keys(), {}, error=str(e))
            raise
        except (urllib.error.URLError, socket.timeout, ConnectionError, ssl.SSLError,
                OSError) as e:
            self.store.record_request(method, url, None, purpose, headers.keys(), {},
                                      error=f"{type(e).__name__}: {e}",
                                      req_body=req_body, req_content_type=req_content_type)
            raise FetchError(f"{url}: {e}")
        truncated = len(body) > max_bytes
        body = body[:max_bytes]
        hmap = {k.lower(): v for k, v in hdrs.items()}
        set_cookie = "; ".join(hdrs.get_all("set-cookie") or [])
        request_id = self.store.record_request(
            method, url, status, purpose, headers.keys(), hmap, body,
            body_complete=not truncated and method != "HEAD",
            basis="target-http" if isinstance(self, ScopedClient) else "intel-http",
            req_body=req_body, req_content_type=req_content_type)
        return Response(url=url, status=status, headers=hmap, body=body,
                        set_cookie=set_cookie, truncated=truncated, request_id=request_id)


class ScopedClient(_BaseClient):
    def get(self, url: str, purpose: str, need: str = "active", follow: bool = True,
            headers: Optional[Dict[str, str]] = None, max_bytes: Optional[int] = None,
            method: str = "GET", timeout: Optional[float] = None) -> Response:
        if method not in ("GET", "HEAD"):
            raise PolicyViolation("read helpers are GET/HEAD; use request() for write methods")
        self.policy.require(need, f"{purpose} request")
        self.campaign.scope.check(url)
        cap = max_bytes or self.policy.max_body_bytes
        h = self._headers(headers)
        chain: List[str] = []
        current = url
        resp: Optional[Response] = None
        for _ in range(MAX_REDIRECTS + 1):
            resp = self._send(method, current, purpose, h, cap, timeout)
            chain.append(current)
            loc = resp.headers.get("location")
            if not follow or resp.status not in REDIRECT_CODES or not loc:
                break
            nxt = urljoin(current, loc)
            try:
                self.campaign.scope.check(nxt)
            except OutOfScope:
                resp.blocked_redirect = nxt
                break
            if origin_of(nxt) != origin_of(current):
                # Arbitrary program headers may be sensitive; preserve only generic headers.
                h = {k: v for k, v in h.items() if k.lower() in ("user-agent", "accept")}
            current = nxt
        assert resp is not None
        resp.redirect_chain = chain
        return resp

    def request(self, method: str, url: str, purpose: str, *, body: Optional[bytes] = None,
                content_type: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
                need: str = "active", timeout: Optional[float] = None,
                max_bytes: Optional[int] = None) -> Response:
        """Any granted HTTP method, with an optional request body (payload evidence).

        Write methods (POST/PUT/PATCH/DELETE/OPTIONS) require an explicit
        policy.allowed_methods grant, are scope-checked like every other request, and
        never auto-follow redirects: a 3xx Location is returned to the caller so the
        payload is never silently re-sent to another target.
        """
        method = method.upper()
        if method in ("GET", "HEAD"):
            if body:
                raise PolicyViolation("GET/HEAD cannot carry a request body; use a write method")
            return self.get(url, purpose, need=need, follow=(method == "GET"),
                            headers=headers, method=method, timeout=timeout,
                            max_bytes=max_bytes)
        if method not in self.policy.allowed_methods:
            raise PolicyViolation(
                f"method {method} is not granted by policy.allowed_methods for this campaign")
        self.policy.require(need, f"{purpose} request")
        self.campaign.scope.check(url)
        if body is not None and len(body) > self.policy.max_body_bytes:
            raise PolicyViolation("request body exceeds policy.max_body_bytes")
        h = self._headers(headers)
        if content_type:
            h = {k: v for k, v in h.items() if k.lower() != "content-type"}
            h["Content-Type"] = content_type
        elif body is not None and not any(k.lower() == "content-type" for k in h):
            h["Content-Type"] = "application/octet-stream"
        resp = self._send(method, url, purpose, h, max_bytes or self.policy.max_body_bytes,
                          timeout, data=body, req_body=body or b"",
                          req_content_type=h.get("Content-Type"))
        resp.redirect_chain = [url]
        return resp

    def post_json(self, url: str, payload: object, purpose: str, **kw) -> Response:
        import json as _json
        return self.request("POST", url, purpose, body=_json.dumps(payload).encode(),
                            content_type="application/json", **kw)

    def post_form(self, url: str, fields: Dict[str, str], purpose: str, **kw) -> Response:
        from urllib.parse import urlencode as _urlencode
        return self.request("POST", url, purpose, body=_urlencode(fields).encode(),
                            content_type="application/x-www-form-urlencoded", **kw)


class PassiveClient(_BaseClient):
    def get(self, url: str, purpose: str, timeout: Optional[float] = None,
            max_bytes: int = 50_000_000, allowed_hosts: Iterable[str] = INTEL_HOSTS) -> Response:
        host = norm_host(urlsplit(url).hostname or "")
        parts = urlsplit(url)
        if parts.username is not None or parts.port not in (None, 443):
            raise PolicyViolation("intel sources require the standard HTTPS origin without credentials")
        if host not in set(allowed_hosts) or host not in (INTEL_HOSTS | KEV_HOSTS):
            raise PolicyViolation(f"passive client may only query intel sources, not {host!r}")
        if self.campaign.scope.mentions_host(host):
            raise PolicyViolation(f"{host!r} is in target scope; passive client refuses it")
        if urlsplit(url).scheme != "https":
            raise PolicyViolation("intel sources must be fetched over https")
        # Target auth/program headers must never be sent to third-party intel providers.
        return self._send("GET", url, purpose,
                          {"User-Agent": self.policy.user_agent, "Accept": "application/json"},
                          max_bytes, timeout)

    def post_json(self, url: str, payload: Dict[str, object], purpose: str,
                  timeout: Optional[float] = None, max_bytes: int = 5_000_000) -> Response:
        """JSON POST to an exploit-search host. Refuses payloads naming any in-scope host."""
        import json as _json
        host = norm_host(urlsplit(url).hostname or "")
        parts = urlsplit(url)
        if parts.username is not None or parts.port not in (None, 443):
            raise PolicyViolation("exploit search requires the standard HTTPS origin without credentials")
        if host not in EXPLOIT_SEARCH_HOSTS or urlsplit(url).scheme != "https":
            raise PolicyViolation(f"POST is only allowed to exploit-search hosts, not {host!r}")
        if self.campaign.scope.mentions_host(host):
            raise PolicyViolation(f"{host!r} is in target scope; passive client refuses it")
        # This endpoint is deliberately not a generic JSON POST/DLP mechanism.
        # The fixed product catalog plus a numeric version is the complete contract.
        from .vulnintel import PRODUCTS
        import re as _re
        query = payload.get("query")
        if (not isinstance(query, str) or not any(_re.fullmatch(
                _re.escape(name) + r" \d+(?:\.\d+){0,3}[a-z]?", query)
                for name, _, _ in PRODUCTS.values()) or payload != {
                    "query": query, "type": "exploits", "sort": "default", "title": False, "offset": 0}):
            raise PolicyViolation("exploit search accepts only the fixed product/version query schema")
        body = _json.dumps(payload).encode()
        text = body.decode().lower()
        for rule in self.campaign.scope.include:
            needle = (rule.host or rule.suffix or "").lstrip("*.").lower()
            if needle and needle in text:
                raise PolicyViolation("exploit-search payload mentions an in-scope host; refused")
        return self._send("POST", url, purpose,
                          {"User-Agent": self.policy.user_agent, "Accept": "application/json",
                           "Content-Type": "application/json", "Origin": "https://sploitus.com",
                           "Referer": "https://sploitus.com/"},
                          max_bytes, timeout, data=body)
