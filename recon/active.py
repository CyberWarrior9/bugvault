"""Active recon jobs (need policy mode >= active). All traffic goes through ScopedClient.

probe      DNS + CNAME, HTTP(S) liveness, fingerprint, takeover fingerprint
wellknown  robots/sitemap/security.txt/openid-configuration + soft-404 calibration
jsharvest  root HTML -> scripts, inline JS, same-origin links, forms; SPA detection
jsparse    one JS file -> endpoints (+method/params window), routes, perms, secrets,
           GraphQL ops, lazy chunks, source map
mapparse   source map -> original sources -> same extraction (source = "sourcemap")
"""
from __future__ import annotations

import ipaddress
import json
import secrets
import shutil
import socket
import subprocess
from collections import deque
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .extract import (decode_inline_sourcemap, extract_from_js, is_static, looks_api, origin_of, parse_page,
                      parse_robots, parse_sitemap, resolve, sourcemap_sources)
from .fingerprint import fingerprint, is_spa, takeover_match, takeover_providers_for_cname, WAF_CDN_TAGS
from .net import FetchError

MAX_LINKS = 300
MAX_SITEMAPS = 4
MAX_JS_DEPTH = 3
MAX_JS_PER_ORIGIN = 300
MAX_SOURCEMAP_BYTES = 30_000_000


def service_entries(ctx, svc: Dict[str, Any]) -> List[str]:
    entries = svc["attrs"].get("entry_urls", []) or [svc["value"] + "/"]
    return [u for u in entries if ctx.scope.is_in(u)]


# ---------------------------------------------------------------- probe

def resolve_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({i[4][0] for i in infos})


def dig_cname(host: str) -> Optional[str]:
    if not shutil.which("dig"):
        return None
    try:
        out = subprocess.run(["dig", "+short", "CNAME", host], capture_output=True, text=True,
                             timeout=8).stdout.strip().splitlines()
    except (subprocess.SubprocessError, OSError):
        return None
    return out[0].rstrip(".") if out else None


def _takeover_chain_context(ctx, host: str) -> List[str]:
    """Impact context for a takeover lead: does a stored cookie domain span this host?

    Implements the doctrine's first escalation ladder rung mechanically: a takeover on
    a host covered by `Domain=.parent` session cookies turns a parked lead into a
    session-theft chain candidate. OAuth/CSP allowlist checks need response bodies and
    remain hunter work.
    """
    parent = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    hits: List[str] = []
    for row in ctx.store.db.execute(
            "SELECT url, resp_headers FROM requests WHERE status IS NOT NULL AND error IS NULL"):
        try:
            headers = json.loads(row["resp_headers"] or "{}")
        except (TypeError, ValueError):
            continue
        for value in [v for k, v in headers.items() if k.lower() == "set-cookie"]:
            if f"domain=.{parent}" in value.lower():
                note = f"session cookie domain spans *.{parent} (seen on {row['url']})"
                if note not in hits:
                    hits.append(note)
    return hits[:5]


def job_probe(ctx, asset: Dict[str, Any]) -> None:
    host = asset["value"]
    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    ips = [host] if is_ip else resolve_ips(host)
    cname = None if is_ip else dig_cname(host)
    providers = takeover_providers_for_cname(cname)
    ctx.store.update_attrs(asset["id"], {"ips": ips, "cname": cname, "resolves": bool(ips),
                                         "cname_providers": providers})
    for ip in ips:
        ctx.add("ip", ip, source="dns", attrs={"hosts": [host]})
        try:
            if ipaddress.ip_address(ip).is_private and not is_ip:
                ctx.store.add_fact(asset["id"], f"public name resolves to private IP {ip}",
                                   "observed", kind="dns", source="probe")
        except ValueError:
            pass
    if not ips:
        if cname:
            detail = (f"dangling CNAME to takeover-able provider(s) {', '.join(providers)}"
                      if providers else "check for a dangling record (subdomain takeover)")
            ctx.store.add_fact(asset["id"], f"CNAME {cname} but no address: {detail}",
                               "inferred", kind="takeover-lead", source="probe")
            for note in _takeover_chain_context(ctx, host):
                ctx.store.add_fact(asset["id"], f"takeover impact context: {note}", "observed",
                                   kind="takeover-impact-context", source="probe")
        elif not is_ip and not shutil.which("dig"):
            ctx.store.add_fact(asset["id"], "no address and dig unavailable: CNAME could not "
                               "be checked for a dangling takeover record", "observed",
                               kind="collection-gap", source="probe")
        return
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            r = ctx.client.get(url, purpose="probe")
        except FetchError:
            continue
        body = r.text()
        tags = fingerprint(r.headers, body, r.set_cookie)
        attrs: Dict[str, Any] = {
            "live": True, "status": r.status, "title": parse_page(body).title,
            "server": r.headers.get("server", ""), "tech": tags,
            "waf_cdn": [t for t in tags if t in WAF_CDN_TAGS], "spa": is_spa(body, tags),
            "redirect_chain": r.redirect_chain[1:],
            "cname_providers": providers,
        }
        if r.blocked_redirect:
            attrs["redirect_out_of_scope"] = r.blocked_redirect
            ctx.intel(origin_of(r.blocked_redirect), f"{url} redirects here", "probe")
        sid = ctx.add("service", origin_of(url), source="probe", attrs=attrs)
        if cname:
            for svc in takeover_match(body):
                ctx.store.add_fact(sid, f"{svc} unclaimed-resource fingerprint behind CNAME "
                                   f"{cname}", "inferred", kind="takeover-lead",
                                   evidence=url, source="probe")
                for note in _takeover_chain_context(ctx, host):
                    ctx.store.add_fact(sid, f"takeover impact context: {note}", "observed",
                                       kind="takeover-impact-context", evidence=url,
                                       source="probe")


# ---------------------------------------------------------------- well-known

def _ok_text(r) -> bool:
    return r.status == 200 and not r.content_type.startswith(("image/", "font/"))


def job_wellknown(ctx, svc: Dict[str, Any]) -> None:
    origin = svc["value"]
    if not ctx.scope.is_in(origin + "/"):
        ctx.store.add_fact(svc["id"], "root well-known collection skipped: origin root is outside "
                           "the granted entry-path scope", "observed", kind="collection-gap", source="wellknown")
        return
    # soft-404 calibration: what does "not found" look like here?
    try:
        r = ctx.client.get(f"{origin}/bugvault-404-{secrets.token_hex(6)}", purpose="soft404",
                           follow=False, max_bytes=200_000)
        ctx.store.update_attrs(svc["id"], {"soft404": {"status": r.status,
                                                       "length": len(r.body)}})
    except FetchError:
        pass
    sitemaps: List[str] = []
    try:
        r = ctx.client.get(f"{origin}/robots.txt", purpose="robots", max_bytes=500_000)
        if _ok_text(r) and "<html" not in r.text()[:500].lower():
            paths, sitemaps = parse_robots(r.text())
            for p in paths[:MAX_LINKS]:
                ctx.add_endpoint(origin + p, "robots")
            ctx.store.add_fact(svc["id"], f"robots.txt: {len(paths)} paths", "observed",
                               kind="wellknown", evidence=f"{origin}/robots.txt", source="robots")
    except FetchError:
        pass
    queue = [resolve(origin + "/", s) for s in (sitemaps or ["/sitemap.xml"])][:MAX_SITEMAPS]
    done = 0
    while queue and done < MAX_SITEMAPS:
        sm_url = queue.pop(0)
        done += 1
        if not ctx.scope.is_in(sm_url):
            ctx.intel(origin_of(sm_url), "sitemap hosted outside scope", "sitemap")
            continue
        try:
            r = ctx.client.get(sm_url, purpose="sitemap", max_bytes=10_000_000)
        except FetchError:
            continue
        if r.status != 200 or "<loc>" not in r.text():
            continue
        for u in parse_sitemap(r.text()):
            if u.endswith(".xml") and len(queue) + done < MAX_SITEMAPS:
                queue.append(u)
            else:
                ctx.add_endpoint(u, "sitemap")
    try:
        r = ctx.client.get(f"{origin}/.well-known/security.txt", purpose="security.txt",
                           max_bytes=100_000)
        if _ok_text(r) and "contact" in r.text().lower():
            ctx.store.add_fact(svc["id"], "security.txt present", "observed", kind="wellknown",
                               detail=r.text()[:1500], source="wellknown")
    except FetchError:
        pass
    try:
        r = ctx.client.get(f"{origin}/.well-known/openid-configuration", purpose="oidc",
                           max_bytes=500_000)
        if r.status == 200:
            cfg = json.loads(r.text())
            for k, v in cfg.items():
                if k.endswith("_endpoint") and isinstance(v, str):
                    ctx.add_endpoint(v, "oidc")
            ctx.store.update_attrs(svc["id"], {"oidc": True})
            ctx.store.add_fact(svc["id"], "OpenID configuration exposed (OAuth/OIDC surface)",
                               "observed", kind="wellknown", source="oidc")
    except (FetchError, ValueError):
        pass


# ---------------------------------------------------------------- JS harvest

def _process_js_text(ctx, text: str, base_url: str, page_origin: str, source: str,
                     asset_id: int, depth: int) -> None:
    f = extract_from_js(text)
    svc_id = ctx.service_for(page_origin)
    for lit in f.endpoints:
        raw = lit.raw
        url = "https:" + raw if raw.startswith("//") else (
            raw if raw.startswith("http") else page_origin + raw)
        ctx.add_endpoint(url, source, method=lit.method, params=lit.params + _qkeys(raw))
    for route in f.routes:
        ctx.add("route", page_origin + route, source=source)
    svc_attrs: Dict[str, Any] = {}
    if f.perms:
        svc_attrs["perm_candidates"] = f.perms
    if f.hash_routing:
        svc_attrs["hash_routing"] = True
    if f.graphql_ops:
        svc_attrs["graphql_ops"] = f.graphql_ops
    if f.routes:
        svc_attrs["spa"] = True
    if svc_attrs:
        ctx.store.update_attrs(svc_id, svc_attrs)
        if svc_attrs.get("spa"):
            ctx.enqueue("runtime", svc_id)
    for kind, red in f.secrets:
        ctx.store.add_fact(asset_id, f"possible {kind} in client code: {red}", "inferred",
                           kind="secret-lead", evidence=base_url, source=source,
                           detail="Verify scope/permissions before claiming impact; public "
                                  "browser keys (e.g. Maps) are usually never-submit.")
    if source == "sourcemap":
        return
    if depth < MAX_JS_DEPTH:
        for c in f.chunks:
            # bundler-rooted names ("static/js/x.js") resolve from the site root,
            # everything else relative to the script that referenced it
            if c.startswith(("static/", "assets/", "_next/", "_nuxt/", "js/")):
                curl = page_origin + "/" + c
            else:
                curl = resolve(base_url, c)
            if ctx.store.count_assets("js", origin_of(curl)) < MAX_JS_PER_ORIGIN:
                _add_js(ctx, curl, page_origin, depth + 1, source="chunk")
    if f.sourcemap:
        inline = decode_inline_sourcemap(f.sourcemap)
        if inline is not None:
            _process_sourcemap(ctx, inline, base_url + "#inline-map", page_origin, asset_id)
        else:
            ctx.add("sourcemap", resolve(base_url, f.sourcemap).split("?", 1)[0], source="js",
                    attrs={"page_origin": page_origin})
    elif ctx.policy.allows("loud") and base_url.endswith(".js"):
        ctx.add("sourcemap", base_url + ".map", source="guess",
                attrs={"page_origin": page_origin, "guessed": True})


def _qkeys(raw: str) -> List[str]:
    if "?" not in raw:
        return []
    from urllib.parse import parse_qsl
    return [k for k, _ in parse_qsl(raw.split("?", 1)[1], keep_blank_values=True) if k]


def _add_js(ctx, url: str, page_origin: str, depth: int, source: str) -> None:
    url = url.split("#", 1)[0].split("?", 1)[0]
    if not ctx.scope.is_in(url):
        ctx.intel(origin_of(url), f"third-party script {urlsplit(url).path[:100]}", source)
        return
    ctx.add("js", url, source=source, attrs={"page_origin": page_origin, "depth": depth})


def job_jsharvest(ctx, svc: Dict[str, Any]) -> None:
    """Bounded same-origin HTML BFS, starting at exact operator-provided entry URLs."""
    origin = svc["value"]
    cfg = ctx.campaign.raw.get("collection", {})
    max_pages, max_depth = cfg.get("max_pages", 1), cfg.get("max_depth", 2)
    queue = deque((u, 0) for u in service_entries(ctx, svc))
    seen = set()
    pages = 0
    while queue and pages < max_pages:
        url, depth = queue.popleft()
        url = url.split("#", 1)[0]
        if url in seen or not ctx.scope.is_in(url) or origin_of(url) != origin:
            continue
        seen.add(url)
        pages += 1
        r = ctx.client.get(url, purpose="jsharvest")
        seen.update(r.redirect_chain)
        if r.status != 200 or ("html" not in r.content_type and "<html" not in r.text()[:500].lower()):
            continue
        base = r.redirect_chain[-1] if r.redirect_chain else url
        # A permitted cross-origin redirect may be recorded but must not be interpreted
        # as this service's relative API paths, scripts or frontend routes.
        if origin_of(base) != origin:
            continue
        links = _harvest_page(ctx, svc, r, base)
        if depth < max_depth:
            for link in links[:MAX_LINKS]:
                path = urlsplit(link).path
                if (origin_of(link) == origin and ctx.scope.is_in(link)
                        and not is_static(path) and not looks_api(path) and link not in seen):
                    queue.append((link, depth + 1))
    ctx.store.update_attrs(svc["id"], {"collection": {"pages": pages, "max_pages": max_pages,
                                                       "remaining_frontier": len(queue)}})


def _harvest_page(ctx, svc, r, base) -> List[str]:
    origin = svc["value"]
    if r.blocked_redirect:
        ctx.store.update_attrs(svc["id"], {"redirect_out_of_scope": r.blocked_redirect})
    html = r.text()
    page = parse_page(html)
    tags = fingerprint(r.headers, html, r.set_cookie)
    spa = is_spa(html, tags)
    ctx.store.update_attrs(svc["id"], {"tech": tags, "spa": spa, "title": page.title,
                                       "status": r.status, "live": True,
                                       "hash_routing": "#/" in html})
    for src in page.scripts:
        _add_js(ctx, resolve(base, src), origin, 0, source="html")
    for i, code in enumerate(page.inline_scripts):
        if code.strip():
            _process_js_text(ctx, code, base, origin, "inline", svc["id"], 0)
    links = []
    for href in page.links[:MAX_LINKS]:
        if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            continue
        url = resolve(base, href)
        ctx.add_endpoint(url, "html")
        if url.startswith(("http://", "https://")):
            try:
                origin_of(url)
            except ValueError:
                continue
            links.append(url)
    for form in page.forms:
        action = resolve(base, form["action"] or base)
        extra = {}
        if form["method"] != "GET":  # a GET form's enctype never reaches the server
            extra["form_enctypes"] = [form.get("enctype") or "application/x-www-form-urlencoded"]
        if form.get("token_fields"):
            extra["csrf_token_fields"] = form["token_fields"]
        ctx.add_endpoint(action, "form", method=form["method"], params=form["inputs"],
                         extra=extra or None)
    if page.standalone:
        ctx.store.update_attrs(svc["id"], {"standalone_inputs": page.standalone[:200]})
    if spa:
        ctx.enqueue("runtime", svc["id"])
    return links


def job_jsparse(ctx, js: Dict[str, Any]) -> None:
    url = js["value"]
    a = js["attrs"]
    page_origin = a.get("page_origin") or origin_of(url)
    r = ctx.client.get(url, purpose="jsparse")
    if r.status != 200:
        ctx.store.update_attrs(js["id"], {"status": r.status})
        return
    ctx.store.update_attrs(js["id"], {"status": 200, "bytes": len(r.body),
                                      "truncated": r.truncated})
    _process_js_text(ctx, r.text(), url, page_origin, "js", js["id"], int(a.get("depth", 0)))


def _process_sourcemap(ctx, sm: dict, url: str, page_origin: str, asset_id: int) -> None:
    files = sourcemap_sources(sm)
    names = [n for n in (sm.get("sources") or []) if "node_modules/" not in n]
    ctx.store.update_attrs(asset_id, {"original_sources": names[:200]})
    ctx.store.add_fact(asset_id, f"source map exposes {len(names)} original files "
                       f"({len(files)} with content)", "observed", kind="sourcemap",
                       evidence=url, source="mapparse",
                       detail="Lead, not a finding: report only with secrets or a hidden-"
                              "endpoint impact chain.")
    total = 0
    for name, content in files:
        total += len(content)
        if total > MAX_SOURCEMAP_BYTES:
            break
        _process_js_text(ctx, content, url, page_origin, "sourcemap", asset_id, MAX_JS_DEPTH)


def job_mapparse(ctx, sm: Dict[str, Any]) -> None:
    url = sm["value"]
    page_origin = sm["attrs"].get("page_origin") or origin_of(url)
    r = ctx.client.get(url, purpose="mapparse", max_bytes=MAX_SOURCEMAP_BYTES)
    if r.status != 200:
        ctx.store.update_attrs(sm["id"], {"status": r.status})
        return
    try:
        data = json.loads(r.text())
    except ValueError:
        ctx.store.update_attrs(sm["id"], {"status": r.status, "invalid_json": True})
        return
    ctx.store.update_attrs(sm["id"], {"status": 200})
    _process_sourcemap(ctx, data, url, page_origin, sm["id"])
