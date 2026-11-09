"""The only two ways recon code may touch the network.

ScopedClient  - talks to the TARGET. GET/HEAD only. Scope-checked on the first URL and
                on every redirect hop (an out-of-scope Location is recorded, never
                followed). Policy-mode-checked. Rate-limited per host. Every request
                is logged to the store with its response body hash.
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


def _build_opener(verify_tls: bool, proxy: Optional[str]):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies),  # ignore env proxies unless configured
        urllib.request.HTTPSHandler(context=ctx),
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
        self.opener = _build_opener(campaign.policy.verify_tls, campaign.policy.proxy)

    def _headers(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        h = {"User-Agent": self.policy.user_agent, "Accept": "*/*"}
        h.update(self.policy.headers)
        h.update(extra or {})
        return h

    def _send(self, method: str, url: str, purpose: str, headers: Dict[str, str],
              max_bytes: int, timeout: Optional[float], data: Optional[bytes] = None) -> Response:
        host = norm_host(urlsplit(url).hostname or "")
        self.limiter.wait(host)
        remaining_time = self.budget.consume()
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
        except (urllib.error.URLError, socket.timeout, ConnectionError, ssl.SSLError,
                OSError) as e:
            self.store.record_request(method, url, None, purpose, headers.keys(), {},
                                      error=f"{type(e).__name__}: {e}")
            raise FetchError(f"{url}: {e}")
        truncated = len(body) > max_bytes
        body = body[:max_bytes]
        hmap = {k.lower(): v for k, v in hdrs.items()}
        set_cookie = "; ".join(hdrs.get_all("set-cookie") or [])
        self.store.record_request(method, url, status, purpose, headers.keys(), hmap, body)
        return Response(url=url, status=status, headers=hmap, body=body,
                        set_cookie=set_cookie, truncated=truncated)


class ScopedClient(_BaseClient):
    def get(self, url: str, purpose: str, need: str = "active", follow: bool = True,
            headers: Optional[Dict[str, str]] = None, max_bytes: Optional[int] = None,
            method: str = "GET", timeout: Optional[float] = None) -> Response:
        if method not in ("GET", "HEAD"):
            raise PolicyViolation("recon client is read-only: GET/HEAD only")
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


class PassiveClient(_BaseClient):
    def get(self, url: str, purpose: str, timeout: Optional[float] = None,
            max_bytes: int = 50_000_000, allowed_hosts: Iterable[str] = INTEL_HOSTS) -> Response:
        host = norm_host(urlsplit(url).hostname or "")
        if host not in set(allowed_hosts):
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
        if host not in EXPLOIT_SEARCH_HOSTS or urlsplit(url).scheme != "https":
            raise PolicyViolation(f"POST is only allowed to exploit-search hosts, not {host!r}")
        if self.campaign.scope.mentions_host(host):
            raise PolicyViolation(f"{host!r} is in target scope; passive client refuses it")
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
