"""Exploit lookup: fingerprinted versions -> searchsploit / Sploitus / CISA KEV -> ranked leads.

Sends NO request to the target. Inputs are responses already recorded by `run` (headers +
saved bodies) and versions reported by imported httpx records. Third parties see only
product + version strings ("jenkins 2.401"):

  searchsploit  local Exploit-DB copy (subprocess, if installed)
  Sploitus      https://sploitus.com/search (JSON POST via PassiveClient.post_json)
  CISA KEV      known_exploited_vulnerabilities.json (GET, cached 24 h in .recon-cache/)

Every result is a `lead` (findings.py) with a precondition checklist. Nothing here runs an
exploit; a lead only becomes `confirmed` through the replay + negative-control gate.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .extract import origin_of
from .findings import Findings
from .campaign import PolicyViolation
from .net import FetchError
from .reliability import ProviderError, SourceRunner

REPO = Path(__file__).resolve().parents[1]
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_CACHE = REPO / ".recon-cache" / "kev.json"
KEV_TTL = 24 * 3600
SPLOITUS_URL = "https://sploitus.com/search"
MAX_BODY_SCAN = 2_000_000
VER = r"(\d+(?:\.\d+){1,3}[a-z]?)"

# product id -> (display/search name, kind, aliases matched against KEV vendor+product)
PRODUCTS: Dict[str, Tuple[str, str, Tuple[str, ...]]] = {
    "apache-httpd": ("Apache HTTP Server", "server", ("apache http server",)),
    "nginx": ("nginx", "server", ("nginx",)),
    "iis": ("Microsoft IIS", "server", ("internet information services", " iis")),
    "openssl": ("OpenSSL", "server", ("openssl",)),
    "php": ("PHP", "server", ("php ", "php")),
    "tomcat": ("Apache Tomcat", "server", ("apache tomcat",)),
    "jetty": ("Eclipse Jetty", "server", ("jetty",)),
    "openresty": ("OpenResty", "server", ("openresty",)),
    "lighttpd": ("lighttpd", "server", ("lighttpd",)),
    "aspnet": ("ASP.NET", "server", ("asp.net",)),
    "jenkins": ("Jenkins", "app", ("jenkins",)),
    "gitlab": ("GitLab", "app", ("gitlab",)),
    "confluence": ("Atlassian Confluence", "app", ("confluence",)),
    "jira": ("Atlassian Jira", "app", ("jira",)),
    "grafana": ("Grafana", "app", ("grafana",)),
    "wordpress": ("WordPress", "app", ("wordpress",)),
    "drupal": ("Drupal", "app", ("drupal",)),
    "joomla": ("Joomla", "app", ("joomla",)),
    "jquery": ("jQuery", "client-lib", ("jquery",)),
    "angularjs": ("AngularJS", "client-lib", ("angularjs",)),
    "bootstrap": ("Bootstrap", "client-lib", ("bootstrap",)),
    "lodash": ("Lodash", "client-lib", ("lodash",)),
    "moment": ("Moment.js", "client-lib", ("moment.js",)),
    "vue": ("Vue.js", "client-lib", ("vue.js",)),
}

HEADER_TOKENS = {  # Server / X-Powered-By "Product/1.2.3" tokens
    "apache": "apache-httpd", "nginx": "nginx", "microsoft-iis": "iis", "openssl": "openssl",
    "php": "php", "jetty": "jetty", "openresty": "openresty", "lighttpd": "lighttpd",
    "apache-coyote": "tomcat", "tomcat": "tomcat",
}
HEADER_RULES = (
    ("x-jenkins", "jenkins"), ("x-aspnet-version", "aspnet"), ("x-grafana-version", "grafana"),
)
BODY_RULES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = tuple((pid, re.compile(rx, re.I)) for pid, rx in (
    ("wordpress", r'<meta[^>]+generator[^>]+WordPress\s+' + VER),
    ("drupal", r'<meta[^>]+generator[^>]+Drupal\s+(\d+(?:\.\d+)*)'),
    ("joomla", r'<meta[^>]+generator[^>]+Joomla!\s+' + VER),
    ("confluence", r'ajs-version-number"\s+content="' + VER),
    ("jira", r'ajs-version-number"\s+content="' + VER + r'"[^>]*>\s*<meta[^>]+ajs-build'),
    ("gitlab", r'gon\.version\s*=\s*"' + VER),
    ("grafana", r'"buildInfo"\s*:\s*\{[^}]*"version"\s*:\s*"' + VER),
    ("jenkins", r'Jenkins ver\.\s*' + VER),
    ("jquery", r'jQuery (?:JavaScript Library )?v' + VER),
    ("angularjs", r'AngularJS v' + VER),
    ("bootstrap", r'Bootstrap v' + VER),
    ("lodash", r'@license\s+Lodash[^\n]*?\b' + VER),
    ("moment", r'//!\s*version\s*:\s*' + VER),
    ("vue", r'Vue\.js v' + VER),
))
CMS = {"wordpress", "drupal", "joomla"}
ADDON = re.compile(r"\b(plugin|theme|extension|component|module)\b", re.I)
RANGE_RX = re.compile(r"(?:(\d+(?:\.\d+)*[a-z]?)\s*)?(<=|<|=<)\s*(\d+(?:\.\d+)*[a-z]?)"
                      r"|(?<![\w.])(\d+(?:\.\d+)+[a-z]?)(?![\w.])")


@dataclass
class Sighting:
    origin: str
    product: str
    version: str
    evidence: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return PRODUCTS[self.product][0]

    @property
    def kind(self) -> str:
        return PRODUCTS[self.product][1]


def _vt(v: str) -> Tuple[int, ...]:
    numbers = [int(x) for x in re.findall(r"\d+", v)[:4]]
    suffix = re.search(r"[a-z]$", v.lower())
    return tuple(numbers + [0] * (4 - len(numbers)) +
                 [ord(suffix.group()) - ord("a") + 1 if suffix else 0])


def _vcmp(a: str, b: str) -> int:
    ta, tb = _vt(a), _vt(b)
    n = max(len(ta), len(tb))
    ta, tb = ta + (0,) * (n - len(ta)), tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def title_covers(title: str, version: str) -> Optional[str]:
    """'exact' if the advisory title names this version, 'range' if a range in the title
    (e.g. '< 2.4.50', '2.4.0 < 2.4.50', '1.x <= 1.20.0') contains it, else None."""
    t = title.lower()
    for m in RANGE_RX.finditer(t):
        lo, op, hi, single = m.group(1), m.group(2), m.group(3), m.group(4)
        if op:
            lower_ok = lo is None or _vcmp(version, lo) >= 0
            upper_ok = _vcmp(version, hi) < 0 if op == "<" else _vcmp(version, hi) <= 0
            if lower_ok and upper_ok:
                return "range"
        elif single and _vcmp(single, version) == 0:
            return "exact"
    return None


def extract_versions(headers: Dict[str, str], body: str) -> List[Tuple[str, str, str]]:
    """[(product_id, version, evidence)] from one response."""
    out: List[Tuple[str, str, str]] = []
    for hname in ("server", "x-powered-by"):
        val = headers.get(hname, "") or ""
        for tok, ver in re.findall(r"([A-Za-z][\w.-]*)/" + VER, val):
            pid = HEADER_TOKENS.get(tok.lower())
            if pid:
                out.append((pid, ver, f"{hname}: {val[:120]}"))
    for hname, pid in HEADER_RULES:
        val = (headers.get(hname) or "").strip()
        m = re.match(VER, val) or re.match(r"(\d+(?:\.\d+)*)", val)
        if m:
            out.append((pid, m.group(1), f"{hname}: {val[:60]}"))
    if body:
        for pid, rx in BODY_RULES:
            m = rx.search(body)
            if m:
                out.append((pid, m.group(1), f"body: {m.group(0)[:100]}"))
    return out


def collect_sightings(ctx) -> List[Sighting]:
    store, scope = ctx.store, ctx.campaign.scope
    seen: Dict[Tuple[str, str, str], Sighting] = {}

    def add(origin: str, pid: str, ver: str, ev: str, location: str) -> None:
        s = seen.setdefault((origin, pid, ver), Sighting(origin, pid, ver))
        if ev not in s.evidence and len(s.evidence) < 5:
            s.evidence.append(ev)
        if location not in s.locations and len(s.locations) < 10:
            s.locations.append(location)

    for r in store.db.execute("SELECT url, resp_headers, body_sha256 FROM requests"
                              " WHERE status IS NOT NULL AND error IS NULL"):
        url = r["url"]
        if not scope.is_in(url):
            continue  # intel-source traffic (crt.sh, KEV, Sploitus) is never a sighting
        headers = json.loads(r["resp_headers"] or "{}")
        body = ""
        if r["body_sha256"]:
            p = store.bodies_dir / r["body_sha256"]
            if p.exists():
                body = p.read_bytes()[:MAX_BODY_SCAN].decode("utf-8", "replace")
        for pid, ver, ev in extract_versions(headers, body):
            add(origin_of(url), pid, ver, f"observed {url} -> {ev}", url)
    # imported httpx tech like "Nginx:1.18.0" (untrusted tool output, labelled as such)
    names = {v[0].lower(): k for k, v in PRODUCTS.items()} | {k: k for k in PRODUCTS}
    for a in store.assets(in_scope=True):
        for t in a["attrs"].get("reported_tech", []) or []:
            m = re.match(r"([^:]+):" + VER + "$", t.strip())
            if m and m.group(1).strip().lower() in names:
                add(origin_of(a["value"]) if "://" in a["value"] else f"https://{a['value']}",
                    names[m.group(1).strip().lower()], m.group(2), f"imported tech {t}", a["value"])
    return list(seen.values())


# ---------------- sources ----------------
def load_kev(ctx, kev_file: Optional[Path] = None, refresh: bool = False,
             log: Callable[[str], None] = lambda m: None) -> List[Dict[str, Any]]:
    if kev_file:
        data = json.loads(Path(kev_file).read_text())
    elif not refresh and KEV_CACHE.exists() and time.time() - KEV_CACHE.stat().st_mtime < KEV_TTL:
        data = json.loads(KEV_CACHE.read_text())
    else:
        r = ctx.passive.get(KEV_URL, "kev-feed", allowed_hosts={"www.cisa.gov"})
        if r.status != 200:
            raise RuntimeError(f"KEV feed HTTP {r.status}")
        data = json.loads(r.body)
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise ValueError("invalid KEV feed envelope")
        if any(not isinstance(v, dict) or not isinstance(v.get("cveID"), str)
               for v in data["vulnerabilities"]):
            raise ValueError("invalid KEV feed records")
        KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
        KEV_CACHE.write_bytes(r.body)
        log(f"KEV: fetched {len(data.get('vulnerabilities', []))} entries")
    if (not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list)
            or any(not isinstance(v, dict) or not isinstance(v.get("cveID"), str)
                   for v in data["vulnerabilities"])):
        raise ValueError("invalid KEV feed records")
    return list(data["vulnerabilities"])


def kev_for(product: str, kev: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    aliases = PRODUCTS[product][2]
    hits = []
    for v in kev:
        hay = f" {v.get('vendorProject', '')} {v.get('product', '')} ".lower()
        if any(re.search(r"(?<!\w)" + re.escape(a.strip()) + r"(?!\w)", hay) for a in aliases):
            hits.append(v)
    return hits


def searchsploit(query: str, binary: Optional[str] = None, timeout: int = 30) -> List[Dict[str, Any]]:
    exe = binary or shutil.which("searchsploit")
    if not exe:
        return []
    try:
        process = subprocess.run([exe, "--json", query], capture_output=True,
                                 text=True, timeout=timeout, check=False)
        if process.returncode:
            raise ProviderError("searchsploit returned nonzero exit status")
        data = json.loads(process.stdout)
        if not isinstance(data, dict) or not isinstance(data.get("RESULTS_EXPLOIT"), list):
            raise ProviderError("invalid SearchSploit result envelope")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        raise ProviderError("SearchSploit unavailable or invalid output") from exc
    res = []
    for e in data.get("RESULTS_EXPLOIT", []) or []:
        if not isinstance(e, dict) or not isinstance(e.get("Title"), str):
            raise ProviderError("invalid SearchSploit record")
        res.append({"source": "exploit-db", "title": e.get("Title", ""),
                    "id": f"EDB-{e.get('EDB-ID', '')}", "type": e.get("Type", ""),
                    "date": e.get("Date_Published", ""),
                    "cves": [c for c in re.split(r"[;,\s]+", e.get("Codes", "") or "")
                             if c.upper().startswith("CVE-")],
                    "href": f"https://www.exploit-db.com/exploits/{e.get('EDB-ID', '')}"})
    return res


def sploitus(ctx, query: str, log: Callable[[str], None] = lambda m: None) -> List[Dict[str, Any]]:
    payload = {"query": query, "type": "exploits", "sort": "default", "title": False, "offset": 0}
    try:
        r = ctx.passive.post_json(SPLOITUS_URL, payload, "exploit-search")
    except PolicyViolation:
        raise
    if r.status != 200:
        log(f"sploitus: HTTP {r.status} (often bot protection); continuing without it")
        raise ProviderError(f"Sploitus returned HTTP {r.status}")
    try:
        data = json.loads(r.body)
    except json.JSONDecodeError as exc:
        raise ProviderError("invalid Sploitus JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("exploits"), list):
        raise ProviderError("invalid Sploitus result envelope")
    res = []
    for e in data.get("exploits", []) or []:
        if not isinstance(e, dict) or not isinstance(e.get("title"), str):
            raise ProviderError("invalid Sploitus record")
        text = f"{e.get('title', '')} {e.get('id', '')} {str(e.get('source', ''))[:20000]}"
        res.append({"source": "sploitus", "title": e.get("title", ""), "id": e.get("id", ""),
                    "type": e.get("type", ""), "date": e.get("published", ""),
                    "score": e.get("score"), "href": e.get("href", ""),
                    "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)))})
    return res


# ---------------- ranking + leads ----------------
def preconditions(s: Sighting) -> List[str]:
    steps = [f"Version evidence: {s.evidence[0]}. Banners can be stale or spoofed; confirm with "
             "a second signal (another header, asset hash, behaviour) before anything else.",
             "Read the advisory: which component, route, module, config and auth level does it "
             "need? Confirm that component is reachable at an in-scope URL (`recon check`).",
             "Prove the precondition without a payload first (version/behaviour probe). "
             "Only then a minimal, non-destructive proof the program allows: no DoS, no "
             "persistence, no data beyond what proves impact."]
    if s.kind == "client-lib":
        steps.append("Outdated client library alone is usually closed as informative: report "
                     "only with a working sink in THIS app (e.g. a reachable XSS gadget).")
    return steps


def rank(s: Sighting, exploits: List[Dict[str, Any]], kev: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    score, why = 0, []
    kev_cves = {v.get("cveID", "").upper() for v in kev}
    linked = sorted({c.upper() for e in exploits for c in e["cves"]} & kev_cves)
    if linked:
        score += 5
        why.append(f"exploit code for KEV CVE(s) {', '.join(linked[:4])}")
    elif kev:
        score += 2
        why.append(f"{len(kev)} KEV CVE(s) for this product (version applicability unchecked)")
    cover = [e.get("covers") for e in exploits]
    if "exact" in cover:
        score += 3
        why.append("public exploit names this exact version")
    elif "range" in cover:
        score += 2
        why.append("public exploit's version range includes it")
    if any(re.search(r"remote|webapps|rce|unauth", f"{e.get('type','')} {e['title']}", re.I)
           for e in exploits):
        score += 1
        why.append("remote/webapp exploit")
    if s.kind in ("server", "app"):
        score += 1
    else:
        score -= 4
        why.append("client-side library (low report value without a sink)")
    return score, why


def lookup(ctx, *, kev_file: Optional[Path] = None, use_kev: bool = True,
           use_sploitus: bool = True, use_searchsploit: bool = True,
           searchsploit_bin: Optional[str] = None,
           log: Callable[[str], None] = print, refresh: bool = False) -> Dict[str, Any]:
    fx = Findings(ctx)
    sightings = collect_sightings(ctx)
    kev_all: List[Dict[str, Any]] = []
    if use_kev and sightings:
        try:
            kev_all = load_kev(ctx, kev_file, log=log)
        except PolicyViolation:
            raise
        except (FetchError, OSError, ValueError, RuntimeError) as e:
            log(f"KEV unavailable: {type(e).__name__}: {e}")
    have_ss = bool(use_searchsploit and (searchsploit_bin or shutil.which("searchsploit")))
    if use_searchsploit and not have_ss:
        log("searchsploit not installed (brew install exploitdb / apt install exploitdb); skipped")
    stats = {"sightings": len(sightings), "leads_new": 0, "leads_updated": 0,
             "no_match": 0, "unresolved": 0, "provider_events": 0}
    runner = SourceRunner(ctx)
    cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    event_refs: Dict[Tuple[str, str], List[int]] = {}
    incomplete = set()
    for s in sorted(sightings, key=lambda x: (x.origin, x.product, x.version)):
        key = (s.product, s.version)
        if key not in cache:
            query = f"{s.name} {s.version}"
            def relevant(found):
                uniq: Dict[str, Dict[str, Any]] = {}
                for e in found:
                    if s.product in CMS and ADDON.search(e["title"]):
                        continue
                    e["covers"] = title_covers(e["title"], s.version)
                    if e["covers"]:
                        uniq.setdefault(e["source"] + e["id"], e)
                return list(uniq.values())

            sources = []
            if have_ss:
                # Product-only search catches titles like "jQuery < 3.5.0".
                sources.append(("searchsploit", lambda: relevant(
                    searchsploit(query, searchsploit_bin) + searchsploit(s.name, searchsploit_bin))))
            if use_sploitus:
                sources.append(("sploitus", lambda: relevant(sploitus(ctx, query, log))))
            cache[key], events = runner.first_result(query, sources, refresh=refresh)
            event_refs[key] = events
            stats["provider_events"] += len(events)
            if events and any(r[0] in ("failed", "suppressed") for r in ctx.store.db.execute(
                    "SELECT state FROM provider_events WHERE id IN (%s)" % ",".join("?" for _ in events), events)):
                incomplete.add(key)
        exploits = cache[key]
        kev = kev_for(s.product, kev_all) if kev_all else []
        if not exploits and not kev:
            stats["unresolved" if key in incomplete or not event_refs.get(key) else "no_match"] += 1
            continue
        score, why = rank(s, exploits, kev)
        detail = {"version": s.version, "kind": s.kind, "evidence": s.evidence, "why": why,
                  "provider_event_ids": event_refs.get(key, []), "lookup_incomplete": key in incomplete,
                  "exploits": exploits[:15],
                  "kev": [{k: v.get(k) for k in ("cveID", "vulnerabilityName", "dateAdded",
                                                  "knownRansomwareCampaignUse")} for v in kev[:15]],
                  "preconditions": preconditions(s)}
        svc = ctx.store.find_asset("service", s.origin)
        title = (f"{s.name} {s.version} on {s.origin}: {len(exploits)} public exploit(s)"
                 + (f", {len(kev)} KEV" if kev else ""))
        fid, created = fx.add(title, "known-cve", asset_id=svc["id"] if svc else None,
                              url=next((u for u in s.locations if ctx.scope.is_in(u)), s.origin + "/"),
                              tech=[s.product], source="exploit-lookup",
                              priority=score, detail=detail,
                              dedup_key=f"cve:{s.origin}:{s.product}:{s.version}",
                              note="; ".join(why))
        if created:
            stats["leads_new"] += 1
        else:
            ctx.store.db.execute("UPDATE findings SET detail=?, priority=?, title=? WHERE id=?"
                                 " AND stage='lead'", (json.dumps(detail), score, title, fid))
            ctx.store.db.commit()
            stats["leads_updated"] += 1
    return stats
