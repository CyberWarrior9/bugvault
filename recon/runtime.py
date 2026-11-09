"""Runtime SPA harvest with mocked login (ARTEX api-recon idea, reimplemented).

The headless browser loads the app, but every API call (xhr/fetch/eventsource or an
API-looking path) is answered by a MOCK - success-shaped, full permissions, empty
data - so the SPA renders its post-login shell and fires the calls behind every
route and tab. The backend never sees those calls; we only record what the frontend
WOULD call. Only GET documents/static assets that are in scope reach the target.

Hard rules enforced in `decide()` (unit-tested, browser-independent):
  * out-of-scope URL            -> abort (recorded as intel)
  * API call                    -> stub/mock (live passthrough only if runtime.live_api
                                   AND method is GET)
  * non-GET non-API request     -> abort (form posts never leave the browser)
  * document navigation we did not explicitly request (clicked links)
                                -> abort + record as endpoint
  * WebSockets                  -> mocked, never connected to the server

Requires: pip3 install playwright && python3 -m playwright install chromium
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit

from .campaign import PolicyViolation
from .extract import is_static, looks_api, origin_of
from .net import FetchError

API_TYPES = {"xhr", "fetch", "eventsource"}
LOGIN_GATE = re.compile(r"(?i)/(login|signin|sign-in|sign_in|auth/login|sso|account/login)\b")
CLICK_SELECTORS = [
    "[role=tab]", "[role=menuitem]", ".ant-tabs-tab", ".el-tabs__item", ".nav-tabs a",
    ".ant-menu-item", ".el-menu-item", ".MuiTab-root", "nav button", "aside a",
]
DEFAULT_LOCAL_STORAGE = {
    "token": "bugvault-mock-token", "access_token": "bugvault-mock-token",
    "accessToken": "bugvault-mock-token", "Authorization": "Bearer bugvault-mock-token",
    "jwt": "bugvault-mock-token", "isLogin": "true",
    "user": json.dumps({"id": 1, "username": "bugvault", "roles": ["admin"], "isAdmin": True}),
}


class RuntimeUnavailable(Exception):
    pass


def default_mock(perms: List[str]) -> Dict[str, Any]:
    perms = list(perms) + ["*", "*:*:*", "admin"]
    user = {"id": 1, "username": "bugvault", "name": "bugvault", "roles": ["admin"],
            "role": "admin", "isAdmin": True, "permissions": perms}
    return {"code": 0, "status": 0, "success": True, "ok": True, "message": "ok", "msg": "ok",
            "data": {"list": [], "items": [], "records": [], "rows": [], "total": 0,
                     "permissions": perms, "perms": perms, "roles": ["admin"], "menus": [],
                     "user": user, **user},
            "result": {}, "permissions": perms, "roles": ["admin"], "user": user}


def match_stub(stubs: List[Dict[str, Any]], url: str, method: str) -> Optional[Dict[str, Any]]:
    for st in stubs or []:
        if re.search(st.get("match", "$^"), url) and (
                not st.get("method") or st["method"].upper() == method.upper()):
            return st
    return None


def is_api_request(url: str, resource_type: str) -> bool:
    path = urlsplit(url).path
    return resource_type in API_TYPES or (looks_api(path) and not is_static(path))


def decide(url: str, method: str, resource_type: str, *, in_scope: bool,
           requested_docs: Set[str], live_api: bool, is_nav: bool) -> str:
    """-> 'abort-scope' | 'mock' | 'live' | 'abort-write' | 'abort-nav' | 'continue'"""
    if url.startswith(("data:", "blob:", "about:")):
        return "continue"
    if not in_scope:
        return "abort-scope"
    if is_api_request(url, resource_type):
        return "live" if (live_api and method.upper() == "GET") else "mock"
    if method.upper() != "GET":
        return "abort-write"
    if is_nav and resource_type == "document" and url.split("#", 1)[0] not in requested_docs:
        return "abort-nav"
    return "continue"


def route_targets(origin: str, routes: List[str], hash_mode: bool, limit: int) -> List[str]:
    out: List[str] = []
    for r in routes:
        r = re.sub(r":[A-Za-z_]\w*\??|\{[^}]*\}|\*+", "1", r)
        r = re.sub(r"/{2,}", "/", r) or "/"
        t = f"{origin}/#{r}" if hash_mode else origin + r
        if t not in out:
            out.append(t)
        if len(out) >= limit:
            break
    return out


def _post_keys(post_data: Optional[str]) -> List[str]:
    if not post_data:
        return []
    try:
        body = json.loads(post_data)
        if isinstance(body, dict):
            return list(body.keys())[:50]
        if isinstance(body, list) and body and isinstance(body[0], dict):
            return list(body[0].keys())[:50]
    except ValueError:
        pass
    return [k for k, _ in parse_qsl(post_data, keep_blank_values=True)][:50]


def job_runtime(ctx, svc: Dict[str, Any]) -> None:
    ctx.policy.require("active", "runtime browser")
    if not ctx.campaign.runtime.get("enabled", False):
        raise PolicyViolation("runtime harvest is opt-in: set runtime.enabled=true after scope review")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise PolicyViolation("runtime harvest skipped: playwright not installed "
                              "(pip3 install playwright && python3 -m playwright install chromium)")
    origin = svc["value"]
    a = svc["attrs"]
    rt = ctx.campaign.runtime
    stubs = rt.get("stubs") or []
    live_api = bool(rt.get("live_api"))
    max_routes = int(rt.get("max_routes", 60))
    max_clicks = int(rt.get("max_clicks_per_page", 15))
    local_storage = rt.get("local_storage") or DEFAULT_LOCAL_STORAGE
    perms = a.get("perm_candidates", [])
    routes = [r["value"][len(origin):] for r in ctx.store.assets("route", in_scope=True)
              if r["value"].startswith(origin + "/")]
    targets = [origin + "/"] + route_targets(origin, routes, bool(a.get("hash_routing")),
                                             max_routes)
    requested: Set[str] = set()
    stats = {"api_calls": 0, "aborted_scope": 0, "aborted_write": 0, "aborted_nav": 0,
             "login_gated": 0, "pages": 0}
    mock_body = json.dumps(default_mock(perms))

    def handle(route):
        req = route.request
        url, method, rtype = req.url, req.method, req.resource_type
        action = decide(url, method, rtype, in_scope=ctx.scope.is_in(url),
                        requested_docs=requested, live_api=live_api,
                        is_nav=req.is_navigation_request())
        if action == "abort-scope":
            stats["aborted_scope"] += 1
            ctx.intel(origin_of(url), f"browser request blocked ({rtype})", "runtime")
            return route.abort()
        if action in ("mock", "live"):
            stats["api_calls"] += 1
            ctx.add_endpoint(url, "runtime", method=method,
                              params=_post_keys(req.post_data) +
                              [k for k, _ in parse_qsl(urlsplit(url).query)],
                              extra={"basis": "client-attempted" if action == "live" else "synthetic-ui"})
            if action == "live":
                return fetch_scoped(route)
            st = match_stub(stubs, url, method)
            if st:
                return route.fulfill(status=int(st.get("status", 200)),
                                     content_type="application/json",
                                     body=json.dumps(st.get("body", {})))
            return route.fulfill(status=200, content_type="application/json", body=mock_body)
        if action == "abort-write":
            stats["aborted_write"] += 1
            ctx.add_endpoint(url, "runtime", method=method, params=_post_keys(req.post_data),
                             extra={"basis": "client-attempted"})
            return route.abort()
        if action == "abort-nav":
            stats["aborted_nav"] += 1
            ctx.add_endpoint(url, "runtime-link")
            return route.abort()
        return fetch_scoped(route)

    def fetch_scoped(route):
        """No browser network passthrough: the same client gates every target hop."""
        req = route.request
        if not req.url.startswith(("http://", "https://")):
            return route.abort()
        try:
            resp = ctx.client.get(req.url, purpose="runtime-" + req.resource_type,
                                  method=req.method, follow=False,
                                  headers={"Accept-Encoding": "identity"})
        except (PolicyViolation, FetchError):
            return route.abort()
        loc = resp.headers.get("location")
        if 300 <= resp.status < 400 and loc:
            nxt = urljoin(req.url, loc)
            if not ctx.scope.is_in(nxt):
                stats["aborted_scope"] += 1
                ctx.intel(origin_of(nxt), "browser redirect blocked", "runtime")
                return route.abort()
            if req.resource_type == "document":
                requested.add(nxt.split("#", 1)[0])
        # Hop-by-hop/length headers no longer describe a fulfilled browser response.
        headers = {k: v for k, v in resp.headers.items()
                   if k not in ("transfer-encoding", "content-length", "connection", "set-cookie")}
        return route.fulfill(status=resp.status, headers=headers, body=resp.body)

    init_js = "(() => { try { const kv = %s; for (const k in kv) {" \
              " localStorage.setItem(k, kv[k]); sessionStorage.setItem(k, kv[k]); } }" \
              " catch (e) {} })();" % json.dumps(local_storage)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(user_agent=ctx.policy.user_agent,
                                          ignore_https_errors=not ctx.policy.verify_tls,
                                          service_workers="block")
            context.add_init_script(init_js)
            cookies = rt.get("cookies") or []
            if cookies:
                context.add_cookies(cookies)
            context.route("**/*", handle)
            if not hasattr(context, "route_web_socket"):
                raise PolicyViolation("runtime requires Playwright with route_web_socket; refusing passthrough")
            if hasattr(context, "route_web_socket"):
                def ws_handler(ws):  # never connect_to_server(): fully mocked
                    if ctx.scope.is_in(ws.url):
                        ctx.add_endpoint(ws.url, "runtime", method="WS", extra={"basis": "synthetic-ui"})
                    else:
                        ctx.intel(origin_of(ws.url), "websocket blocked", "runtime")
                context.route_web_socket(re.compile(".*"), ws_handler)
            page = context.new_page()
            for target in targets:
                ctx.client.budget.check()
                requested.add(target.split("#", 1)[0])
                try:
                    page.goto(target, wait_until="domcontentloaded", timeout=20000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=6000)
                    except Exception:
                        pass
                except Exception:
                    continue
                stats["pages"] += 1
                if LOGIN_GATE.search(page.url) and not LOGIN_GATE.search(target):
                    stats["login_gated"] += 1
                    ctx.store.add_fact(svc["id"], f"route {target} bounced to client login "
                                       f"({page.url}); add a runtime stub for the auth/me "
                                       "endpoint", "observed", kind="runtime-gate",
                                       source="runtime")
                    continue
                clicks = 0
                for sel in CLICK_SELECTORS:
                    if clicks >= max_clicks:
                        break
                    try:
                        els = page.query_selector_all(sel)
                    except Exception:
                        continue
                    for el in els:
                        if clicks >= max_clicks:
                            break
                        try:
                            el.click(timeout=1500)
                            page.wait_for_timeout(400)
                            clicks += 1
                        except Exception:
                            continue
        finally:
            browser.close()
    ctx.store.update_attrs(svc["id"], {"runtime": stats})
    ctx.store.add_fact(svc["id"], f"runtime harvest: {stats['pages']} pages, "
                       f"{stats['api_calls']} API calls recorded (mocked), "
                       f"{stats['login_gated']} login-gated, {stats['aborted_scope']} "
                       "out-of-scope requests blocked", "observed", kind="runtime-summary",
                       source="runtime")
