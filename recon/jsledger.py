"""Offline JS build/lead ledger. References are leads, not security test results.

All network work is outside this module. Even the retained-asset queue requires a
separate explicit `recon run` under the campaign's normal scoped client.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .extract import (SECRET_PATTERNS, endpoint_key, extract_from_js, origin_of,
                      parse_page, path_ext, sourcemap_sources)
from .jschunks import reconstruct
from .jsgraph import importmap_urls, precache_urls, worker_urls
from .jsintel import JsInventory, jwt_metadata, secret_class
from .factcheck import response_hash
from .store import now

FAMILIES = tuple("J%02d" % n for n in range(1, 18))
RUNGS = ("current-live", "version-sibling", "archived-chunk", "removed-op")
STAGES = ("js-inventory", "js-manifest", "js-reconstruct", "js-retention", "js-stale",
          "js-map", "js-extract", "js-transport", "js-globals", "js-gate", "js-rank", "js-reconcile")
_NEXT = re.compile(r"/_next/static/([^/]+)/")
_ENTRY = re.compile(r"/(?:main|app|entry)[.-]([0-9a-f]{6,})\.m?js(?:\.map)?$", re.I)
_NAME = re.compile(r"^[A-Za-z_$][\w$.[\]-]{0,99}$")
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "UNKNOWN"}
_SAFE_PATH = re.compile(r"\A(?:/|https?://)[^\s]{1,500}\Z")
_RPC_PATH = re.compile(r"/[A-Za-z_$][\w$]*(?:\.v\d+)?\.[A-Za-z_$][\w$]*/[A-Za-z_$][\w$]{1,80}")
_RPC_EVENT = re.compile(r"\b(?:invoke|emit|send)\s*\(\s*['\"]([A-Za-z_$][\w$.:-]{1,100})['\"]")
_TRPC = re.compile(r"\btrpc\.([A-Za-z_$][\w$.]{1,100})\.(?:query|mutate|mutation)\s*\(")
_VERSION = re.compile(r"\b(?:next(?:\.js)?|react|angular|dompurify)\W{0,10}(\d+\.\d+\.\d+)\b", re.I)
SCHEMA = """
CREATE TABLE IF NOT EXISTS js_builds(
 id INTEGER PRIMARY KEY, origin TEXT NOT NULL, build_key TEXT NOT NULL,
 first_request INTEGER NOT NULL, last_request INTEGER NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 UNIQUE(origin,build_key));
CREATE TABLE IF NOT EXISTS js_artifacts(
 request_id INTEGER PRIMARY KEY, build_id INTEGER, asset_id INTEGER NOT NULL,
 origin TEXT NOT NULL, url TEXT NOT NULL, sha256 TEXT NOT NULL, snapshot TEXT NOT NULL,
 kind TEXT NOT NULL, complete INTEGER NOT NULL, basis TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS js_edges(
 request_id INTEGER NOT NULL, url TEXT NOT NULL, kind TEXT NOT NULL,
 PRIMARY KEY(request_id,url,kind));
CREATE TABLE IF NOT EXISTS js_leads(
 lead_key TEXT PRIMARY KEY, origin TEXT NOT NULL, family TEXT NOT NULL,
 subject TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT 'UNKNOWN',
 priority INTEGER NOT NULL, reason TEXT NOT NULL, gain TEXT NOT NULL,
 shape TEXT NOT NULL DEFAULT '{}', state TEXT NOT NULL DEFAULT 'extracted');
CREATE TABLE IF NOT EXISTS js_sightings(
 lead_key TEXT NOT NULL, request_id INTEGER NOT NULL, sha256 TEXT NOT NULL,
 offset INTEGER NOT NULL, rule TEXT NOT NULL, extractor TEXT NOT NULL,
 PRIMARY KEY(lead_key,request_id,rule));
CREATE TABLE IF NOT EXISTS js_lead_builds(
 lead_key TEXT NOT NULL, build_id INTEGER NOT NULL,
 PRIMARY KEY(lead_key,build_id));
CREATE TABLE IF NOT EXISTS js_stage_events(
 id INTEGER PRIMARY KEY, origin TEXT NOT NULL, build_id INTEGER NOT NULL,
 stage TEXT NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS js_events(
 id INTEGER PRIMARY KEY, lead_key TEXT NOT NULL, state TEXT NOT NULL,
 ref TEXT NOT NULL, reason TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS js_ladder_rungs(
 id INTEGER PRIMARY KEY, lead_key TEXT NOT NULL, rung TEXT NOT NULL,
 outcome TEXT NOT NULL, response_id INTEGER, response_hash TEXT NOT NULL,
 reason TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS js_asset_pairs(
 id INTEGER PRIMARY KEY, url TEXT NOT NULL, low_response INTEGER NOT NULL,
 owner_response INTEGER NOT NULL, low_hash TEXT NOT NULL, owner_hash TEXT NOT NULL,
 outcome TEXT NOT NULL, created TEXT NOT NULL,
 UNIQUE(url,low_response,owner_response));
"""


def build_key(url: str) -> str:
    """Never infer a build from an arbitrary chunk's name or import timestamp."""
    path = urlsplit(url).path
    match = _NEXT.search(path)
    if match:
        return "next:" + match.group(1)[:100]
    match = _ENTRY.search(path)
    return "entry:" + match.group(1) if match else ""


def _clean_names(values) -> List[str]:
    return list(dict.fromkeys(v for v in values if isinstance(v, str) and _NAME.fullmatch(v)))[:60]


def _safe_url(url: str) -> bool:
    return bool(_SAFE_PATH.fullmatch(url)) and not any(p.search(url) for p in SECRET_PATTERNS.values())


class JsLedger(JsInventory):
    def __init__(self, ctx):
        super().__init__(ctx)
        self.db.executescript(SCHEMA)

    def _build(self, origin: str, key: str, request_id: int) -> Optional[int]:
        if not key:
            return None
        self.db.execute("INSERT OR IGNORE INTO js_builds"
                        "(origin,build_key,first_request,last_request,first_seen,last_seen)"
                        " VALUES(?,?,?,?,?,?)", (origin, key, request_id, request_id, now(), now()))
        self.db.execute("UPDATE js_builds SET last_request=MAX(last_request,?),last_seen=?"
                        " WHERE origin=? AND build_key=?", (request_id, now(), origin, key))
        return self.db.execute("SELECT id FROM js_builds WHERE origin=? AND build_key=?",
                               (origin, key)).fetchone()[0]

    def _edge(self, request_id: int, url: str, kind: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError:
            return  # malformed external reference, never a fetch candidate
        if parts.query or parts.fragment or parts.username or parts.password:
            row = self.db.execute("SELECT asset_id FROM js_artifacts WHERE request_id=?",
                                  (request_id,)).fetchone()
            if row:
                self.store.add_fact(row[0], "query-bearing JS asset reference withheld from graph",
                                    "observed", kind="collection-gap", source="js-ledger")
            return
        if _safe_url(url):
            self.db.execute("INSERT OR IGNORE INTO js_edges VALUES(?,?,?)", (request_id, url, kind))

    def _register(self, origin: str, family: str, subject: str, request_id: int,
                  sha: str, build_id: Optional[int], url: str = "", method: str = "UNKNOWN",
                  priority: int = 3, reason: str = "static reference only", gain: str = "requires server validation",
                  shape: Optional[dict] = None, offset: int = 0) -> None:
        if not _safe_url(url or "/") or len(subject) > 400 or family not in FAMILIES:
            return
        key = "js:" + hashlib.sha256((origin + "\0" + family + "\0" + subject).encode()).hexdigest()[:24]
        if self.db.execute("SELECT count(*) FROM js_leads").fetchone()[0] >= 10_000:
            raise ValueError("JS lead cap reached; ledger incomplete")
        self.db.execute("INSERT OR IGNORE INTO js_leads"
                        "(lead_key,origin,family,subject,url,method,priority,reason,gain,shape)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (key, origin, family, subject, url, method, priority, reason, gain,
                         json.dumps(shape or {}, sort_keys=True)))
        self.db.execute("INSERT OR IGNORE INTO js_sightings VALUES(?,?,?,?,?,?)",
                        (key, request_id, sha, max(0, offset), family + ":static", "js-ledger-v1"))
        if build_id:
            self.db.execute("INSERT OR IGNORE INTO js_lead_builds VALUES(?,?)", (key, build_id))

    def _analyze(self, response: dict, data: bytes, build_id: Optional[int], kind: str) -> None:
        rid, url, sha = response["id"], response["url"], response["body_sha256"]
        origin = origin_of(url)
        if kind == "html":
            page = parse_page(data.decode("utf-8", "replace"))
            for src in page.scripts[:500]:
                from .extract import resolve
                self._edge(rid, resolve(url, src), "html-script")
            for mapping in page.import_maps[:10]:
                urls, _ = importmap_urls(mapping, url, page.inline_scripts)
                for ref in urls:
                    self._edge(rid, ref, "importmap")
            return
        if kind == "sourcemap":
            if not response["body_complete"]:
                self.store.add_fact(response["asset_id"],
                                    "source map body incomplete; no map exposure verdict",
                                    "observed", kind="collection-gap", source="js-ledger")
                return
            try:
                doc = json.loads(data)
            except ValueError:
                return
            if not isinstance(doc, dict) or doc.get("version") != 3:
                return
            sources = sourcemap_sources(doc)
            for name, text in sources:
                self._text(response, text, build_id, original=name)
            self._register(origin, "J07", urlsplit(url).path, rid, sha, build_id,
                           url.split("?", 1)[0], priority=4,
                           reason="source map served; exposure alone is not a finding",
                           gain="review original sources for a separately testable operation")
            return
        text = data.decode("utf-8", "replace")
        self._text(response, text, build_id)
        graph = reconstruct(text, url)
        for chunk in graph.chunks:
            self._edge(rid, chunk.url, chunk.source)
        for remote in graph.remotes:
            self._edge(rid, remote, "federation-remote")
        for worker in worker_urls(text, url):
            self._edge(rid, worker, "service-worker")
        precached, clipped = precache_urls(text, url)
        for ref in precached:
            self._edge(rid, ref, "precache")
        if clipped:
            self.store.add_fact(response["asset_id"], "service-worker precache parser capped",
                                "observed", kind="collection-gap", source="js-ledger")
        for gap in graph.gaps:
            self.store.add_fact(response["asset_id"], gap, "observed",
                                kind="collection-gap", source="js-ledger")

    def _text(self, response: dict, text: str, build_id: Optional[int], original: str = "") -> None:
        rid, sha, artifact = response["id"], response["body_sha256"], response["url"]
        origin = origin_of(artifact)
        f = extract_from_js(text)
        a = self.store.find_asset("js", artifact.split("?", 1)[0])
        page_origin = (a or {}).get("attrs", {}).get("page_origin") or origin
        for e in f.endpoints[:2000]:
            target = e.raw if e.raw.startswith(("http://", "https://", "ws://", "wss://")) else (
                "https:" + e.raw if e.raw.startswith("//") else page_origin + e.raw)
            if not _safe_url(target) or not self.ctx.scope.is_in(target):
                continue
            method = e.method or "UNKNOWN"
            if method not in _METHODS:
                continue
            subject = method + " " + endpoint_key(target)
            clean_base = urlsplit(e.base) if e.base else None
            shape = {"transport": e.transport, "headers": _clean_names(e.headers),
                     "fields": _clean_names(e.params), "base": e.base[:120] if e.base and
                     _safe_url(e.base) and not clean_base.query and not clean_base.fragment and
                     not clean_base.username and not clean_base.password else "",
                     "base_unresolved": bool(e.base_unresolved), "signed": bool(e.signed),
                     "field_basis": "source-map" if original else "call-site"}
            self._register(origin, "J01", subject, rid, sha, build_id, endpoint_key(target), method,
                           2, "operation referenced in client code; authorization untested",
                           "test server-side authorization with operator-owned accounts", shape,
                           max(0, text.find(e.raw)))
            if re.search(r"/v[1-9]\d*(?:/|$)|/(?:legacy|beta|internal)(?:/|$)", target, re.I):
                self._register(origin, "J02", subject, rid, sha, build_id, endpoint_key(target), method,
                               3, "version/legacy path reference; sibling existence untested",
                               "compare server-side checks on the old and current operations", shape)
            if re.search(r"/(?:admin|debug|test|mock|impersonat|actuator)", target, re.I):
                self._register(origin, "J12", subject, rid, sha, build_id, endpoint_key(target), method,
                               2, "sensitive-looking client path; server behavior untested",
                               "test access to the captured admin/debug function", shape)
        for action in f.server_actions:
            self._register(origin, "J03", action["id"], rid, sha, build_id,
                           artifact.split("?", 1)[0], "POST", 2,
                           "server-action reference; page association and execution unverified",
                           "test authorization on a captured owned-account action",
                           {"base_unresolved": True, "transport": "unknown"})
        for doc in f.graphql_documents:
            self._register(origin, "J04", str(doc["operation"]), rid, sha, build_id,
                           artifact.split("?", 1)[0],
                           "POST" if str(doc["operation"]).startswith("mutation") else "UNKNOWN", 2,
                           "GraphQL document referenced; endpoint unbound",
                           "test object or field policy on a captured GraphQL operation",
                           {"fields": _clean_names([v.get("name") for v in doc["variables"]]),
                            "transport": "graphql", "base_unresolved": True})
        for match in list(_RPC_PATH.finditer(text))[:100]:
            self._register(origin, "J05", match.group(0), rid, sha, build_id,
                           artifact.split("?", 1)[0], priority=3,
                           reason="RPC path literal; transport, target and authorization unbound",
                           gain="validate function policy from a captured owned-account call",
                           shape={"base_unresolved": True, "transport": "unknown"}, offset=match.start())
        for pattern in (_RPC_EVENT, _TRPC):
            for match in list(pattern.finditer(text))[:100]:
                self._register(origin, "J05", match.group(1), rid, sha, build_id,
                               artifact.split("?", 1)[0], priority=4,
                               reason="RPC/realtime method name; transport and target unbound",
                               gain="compare captured method policy under test roles",
                               shape={"base_unresolved": True, "transport": "unknown"}, offset=match.start())
        for perm in f.perms:
            self._register(origin, "J08", perm, rid, sha, build_id, artifact.split("?", 1)[0], priority=3,
                           reason="client permission string; server gate untested",
                           gain="compare gated operation against the lower role")
        for flow in f.client_flows:
            self._register(origin, "J09", flow["kind"], rid, sha, build_id, artifact.split("?", 1)[0], priority=3,
                           reason="static source/sink candidate, not execution proof",
                           gain="validate browser-initiated behavior with a distinct control")
        for host in f.host_refs:
            self._register(origin, "J10", host, rid, sha, build_id, artifact.split("?", 1)[0], priority=4,
                           reason="host literal; scope and server behavior unknown",
                           gain="map in-scope backend relationships")
        for symbol in f.auth_gates + f.crypto_entrypoints:
            self._register(origin, "J13", symbol, rid, sha, build_id, artifact.split("?", 1)[0], priority=4,
                           reason="client auth/crypto symbol, not server behavior",
                           gain="understand a captured request's auth carrier")
        for match in list(_VERSION.finditer(text))[:40]:
            self._register(origin, "J11", match.group(0)[:100], rid, sha, build_id,
                           artifact.split("?", 1)[0], priority=5,
                           reason="client version banner; server applicability not established",
                           gain="review applicable advisory prerequisites offline", offset=match.start())
        if re.search(r"\b(?:presigned(?:Url|Post)|getSignedUrl|uploadPart)\b", text):
            self._register(origin, "J14", "signed-storage-flow", rid, sha, build_id,
                           artifact.split("?", 1)[0], priority=3,
                           reason="client signed-storage symbol, not an upload sink proof",
                           gain="inventory the exact captured upload lifecycle")
        if re.search(r"\b(?:WebAssembly|eval\s*\(|new\s+Function\s*\()", text):
            self._register(origin, "J16", "dynamic-code-gap", rid, sha, build_id,
                           artifact.split("?", 1)[0], priority=5,
                           reason="dynamic/WASM code cannot be completely statically reconstructed",
                           gain="operator instrumentation needed; never a negative verdict")
        for label, pattern in SECRET_PATTERNS.items():
            for match in list(pattern.finditer(text))[:200]:
                value = match.group(0)
                classification = secret_class(label, value)
                self._register(origin, "J06", label + ":" + hashlib.sha256(value.encode()).hexdigest(),
                               rid, sha, build_id, artifact.split("?", 1)[0],
                               priority=0 if classification == "privileged-looking" else 5,
                               reason=classification + "; validity and scope untested",
                               gain="identity and scope only if the published rules allow it",
                               shape={"secret_class": classification,
                                      "jwt": jwt_metadata(value) if label == "jwt" else {}},
                               offset=match.start())

    def sync(self, origin: Optional[str] = None) -> Dict[str, Any]:
        if not self.verify()["ok"]:
            raise ValueError("JS evidence integrity failed; sync refused")
        base = super().sync()  # integrity and existing evidence-gated coverage seeding
        rows = self.db.execute("SELECT r.id,r.url FROM requests r JOIN response_capture c ON"
                               " c.request_id=r.id WHERE r.status=200 AND r.error IS NULL"
                               " AND r.body_sha256 IS NOT NULL ORDER BY r.id")
        added = 0
        relevant = 0
        for row in rows:
            url = row["url"]
            if origin and origin_of(url) != origin:
                continue
            if not self.ctx.scope.is_in(url):
                continue
            ext = path_ext(urlsplit(url).path)
            if ext not in ("js", "mjs", "cjs", "map", "", "html", "htm"):
                continue
            response = self.store.response(row["id"])
            kind = ("sourcemap" if ext == "map" else "js" if ext in ("js", "mjs", "cjs")
                    else "html" if ext in ("", "html", "htm") and re.search(
                        rb"<!doctype html|<html\b", self._body(response)[:500], re.I) else "")
            if not kind:
                continue
            relevant += 1
            if relevant > 3000:
                raise ValueError("JS ledger asset cap reached; inventory incomplete")
            data = self._body(response)
            sha = response["body_sha256"]
            old = self.db.execute("SELECT sha256 FROM js_artifacts WHERE request_id=?",
                                  (row["id"],)).fetchone()
            if old and old["sha256"] != sha:
                raise ValueError("JS artifact response snapshot changed; run js verify")
            build_id = self._build(origin_of(url), build_key(url), row["id"]) if not old else None
            asset = (self.store.find_asset("sourcemap" if kind == "sourcemap" else "js",
                                           url.split("?", 1)[0]) if kind != "html" else None)
            asset_id = asset["id"] if asset else self.ctx.service_for(url)
            if old:
                continue
            self.db.execute("INSERT OR IGNORE INTO js_artifacts VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (row["id"], build_id, asset_id, origin_of(url), url, sha,
                             response_hash(response), kind,
                             int(bool(response["body_complete"])), response["basis"]))
            added += 1
            self._analyze({**response, "asset_id": asset_id}, data, build_id, kind)
            if kind == "js":
                self.store.seed_coverage(self.ctx.service_for(url), {"js-bundle":
                    "parsed stored JS; build/role/stage completeness and downstream impact untested"})
        self.db.commit()
        self._reconcile_builds()
        self._drift_leads(origin)
        self._stages(origin)
        self._queue_retired()  # enqueue only; no HTTP until an explicit `recon run`
        return {**base, "build_artifacts_added": added, "builds": self.db.execute(
            "SELECT count(*) FROM js_builds").fetchone()[0], "complete": self.status(origin=origin)["complete"],
                "note": "offline build and lead reconciliation; gaps and destination tests remain open"}

    def _reconcile_builds(self) -> None:
        """Assign unkeyed captured chunks only when the retained graph identifies one build."""
        changed = True
        while changed:
            changed = False
            for artifact in self.db.execute("SELECT request_id,url,origin FROM js_artifacts"
                                            " WHERE build_id IS NULL AND kind IN ('js','sourcemap')").fetchall():
                keys = {r[0] for r in self.db.execute(
                    "SELECT DISTINCT src.build_id FROM js_edges e JOIN js_artifacts src"
                    " ON src.request_id=e.request_id WHERE e.url=? AND src.build_id IS NOT NULL"
                    " AND src.origin=?", (artifact["url"], artifact["origin"]))}
                if len(keys) != 1:
                    continue  # zero/multiple candidate builds: retain an explicit gap
                bid = keys.pop()
                self.db.execute("UPDATE js_artifacts SET build_id=? WHERE request_id=?",
                                (bid, artifact["request_id"]))
                self.db.execute("INSERT OR IGNORE INTO js_lead_builds"
                                " SELECT lead_key,? FROM js_sightings WHERE request_id=?",
                                (bid, artifact["request_id"]))
                changed = True
        self.db.commit()

    def _drift_leads(self, origin: Optional[str]) -> None:
        for host in {r["origin"] for r in self._build_rows(origin)}:
            for subject in self._sets(host)["zombie"]:
                older = self.db.execute("SELECT s.request_id,s.sha256,a.build_id,l.url FROM js_leads l"
                    " JOIN js_sightings s ON s.lead_key=l.lead_key"
                    " JOIN js_artifacts a ON a.request_id=s.request_id"
                    " WHERE l.origin=? AND l.family='J01' AND l.subject=?"
                    " AND a.build_id IS NOT NULL ORDER BY s.request_id LIMIT 1",
                    (host, subject)).fetchone()
                if older:
                    self._register(host, "J15", "removed:" + subject, older["request_id"],
                                   older["sha256"], older["build_id"], older["url"],
                                   priority=2, reason="removed from current build; server liveness unknown",
                                   gain="enter the J01 four-rung lane, not a finding")
        self.db.commit()

    def _build_rows(self, origin: Optional[str] = None) -> List[dict]:
        rows = [dict(r) for r in self.db.execute(
            "SELECT * FROM js_builds" + (" WHERE origin=?" if origin else "") +
            " ORDER BY origin,id", (origin,) if origin else ())]
        grouped = defaultdict(list)
        for r in rows:
            grouped[r["origin"]].append(r)
        for _, group in grouped.items():
            # max_builds limits the comparison horizon, never retention/deletion.
            horizon = self.ctx.campaign.raw.get("js", {}).get("stale", {}).get("max_builds", 5)
            for r in group:
                r["current"] = r is group[-1]
                r["in_horizon"] = r in group[-horizon:]
                r["artifact_count"] = self.db.execute(
                    "SELECT count(*) FROM js_artifacts WHERE build_id=?", (r["id"],)).fetchone()[0]
        return rows

    def builds(self, origin: Optional[str] = None) -> dict:
        rows = self._build_rows(origin)
        for row in rows:
            sets = self._sets(row["origin"])
            row["js_only"] = len(sets["js_only"]) if row["current"] else 0
            row["zombie"] = len(sets["zombie"]) if row["current"] else 0
            row["retired_assets"] = sum(1 for a in self.db.execute(
                "SELECT url FROM js_artifacts WHERE build_id=?", (row["id"],))
                if not row["current"] and self._retired_hit(a["url"], row["origin"]))
        return {"builds": rows, "executed": False}

    def _retired_hit(self, url: str, origin: str) -> bool:
        current = next((r for r in self._build_rows(origin) if r["current"]), None)
        return bool(current and self.db.execute(
            "SELECT 1 FROM requests WHERE url=? AND status=200 AND id>?"
            " AND purpose='jsretained' LIMIT 1",
            (url, current["first_request"])).fetchone())

    def _sets(self, origin: str) -> dict:
        builds = [b for b in self._build_rows(origin) if b["in_horizon"]]
        if not builds:
            return {k: [] for k in ("current", "earlier", "captured", "js_only", "zombie")}
        by_build = defaultdict(set)
        for row in self.db.execute("SELECT b.build_id,l.subject FROM js_lead_builds b "
                                   "JOIN js_leads l ON l.lead_key=b.lead_key WHERE l.family='J01'"
                                   " AND l.origin=?", (origin,)):
            by_build[row["build_id"]].add(row["subject"])
        current = by_build[builds[-1]["id"]]
        earlier = set().union(*(by_build[b["id"]] for b in builds[:-1]))
        captured = set()
        for o in self.store.observations():
            if o["source"] == "runtime" or o["status"] is None:
                continue
            target = self.store.get_asset(o["endpoint_id"])["value"]
            if origin_of(target) == origin:
                captured.add((o["method"] or "UNKNOWN") + " " + endpoint_key(target))
        captured_paths = {s.split(" ", 1)[1] for s in captured}
        js_only = {s for s in current if s not in captured and not (
            s.startswith("UNKNOWN ") and s.split(" ", 1)[1] in captured_paths)}
        return {"current": sorted(current), "earlier": sorted(earlier),
                "captured": sorted(captured), "js_only": sorted(js_only),
                "zombie": sorted(earlier - current)}

    def diff(self, origin: str, from_build: str = "", to_build: str = "") -> dict:
        rows = self._build_rows(origin)
        by_key = {r["build_key"]: r for r in rows}
        if len(rows) < 2:
            return {"origin": origin, "gap": "two explicitly identified builds required", "executed": False}
        left = by_key.get(from_build) if from_build else rows[-2]
        right = by_key.get(to_build) if to_build else rows[-1]
        if not left or not right or left["id"] == right["id"]:
            raise ValueError("choose two distinct retained builds for this origin")
        def operations(bid):
            return {r[0] for r in self.db.execute(
                "SELECT l.subject FROM js_leads l JOIN js_lead_builds b"
                " ON b.lead_key=l.lead_key WHERE b.build_id=? AND l.family='J01'", (bid,))}
        a, b = operations(left["id"]), operations(right["id"])
        return {"origin": origin, "from": left["build_key"], "to": right["build_key"],
                "new": sorted(b-a), "removed": sorted(a-b), "sets": self._sets(origin),
                "executed": False}

    def _graph(self, origin: str) -> dict:
        edges = [dict(r) for r in self.db.execute("SELECT e.* FROM js_edges e JOIN js_artifacts a"
                  " ON e.request_id=a.request_id WHERE a.origin=?", (origin,))]
        fetched = {r[0] for r in self.db.execute("SELECT url FROM js_artifacts"
                                                  " WHERE kind='js' AND complete=1")}
        known = {r["url"] for r in edges if r["kind"] != "federation-remote"}
        federation = {r["url"] for r in edges if r["kind"] == "federation-remote"}
        traffic = {a["value"] for a in self.store.assets("js", in_scope=True)
                   if origin_of(a["value"]) == origin and
                   set(a["attrs"].get("sources", [])) & {"burp", "har", "runtime"}}
        # A manifest reference does not prove the traffic-only script body was
        # collected; clear this gap only after a complete stored capture exists.
        traffic_only = sorted(traffic - fetched)
        precache = {r["url"] for r in edges if r["kind"] == "precache"}
        composed = {r["url"] for r in edges if r["kind"] in
                    ("webpack-runtime", "vite-dependency-map", "next-manifest")}
        out_scope = sorted({r["url"] for r in edges if not self.ctx.scope.is_in(r["url"])})
        pending = sorted(u for u in known | federation if self.ctx.scope.is_in(u) and u not in fetched)
        incomplete = sorted({r["url"] for r in self.db.execute(
            "SELECT url FROM js_artifacts WHERE origin=? AND complete=0", (origin,))})
        unlinked = self.db.execute("SELECT count(*) FROM js_artifacts WHERE origin=?"
                                   " AND build_id IS NULL AND kind IN ('js','sourcemap')", (origin,)).fetchone()[0]
        return {"referenced": len(known), "fetched": len(fetched & known), "composed": len(composed),
                "composed_only": len(composed - {r["url"] for r in edges if r["kind"] == "html-script"}),
                "precache_only": len(precache - composed -
                                      {r["url"] for r in edges if r["kind"] in ("html-script", "importmap")}),
                "importmap_resolved": len({r["url"] for r in edges if r["kind"] == "importmap"}),
                "traffic_only": traffic_only, "out_of_scope": out_scope, "pending": pending,
                "incomplete": incomplete, "unlinked_build_assets": unlinked,
                "federation_remotes": sorted(federation)[:100],
                "federation_remote_count": len(federation),
                "federation_remotes_truncated": len(federation) > 100}

    def _stages(self, only_origin: Optional[str] = None) -> None:
        for b in self._build_rows(only_origin):
            origin, bid = b["origin"], b["id"]
            graph, sets = self._graph(origin), self._sets(origin)
            raw = {"js-inventory": ("gap", "traffic-only, incomplete, or missing asset references") if
                   graph["traffic_only"] or graph["pending"] or graph["incomplete"] or
                   graph["unlinked_build_assets"] else ("complete", "bounded references reconciled"),
                   "js-manifest": ("gap", "no verified manifest for this build"),
                   "js-reconstruct": ("gap", "unresolved federation, missing asset or unrecognized runtime") if
                   graph["out_of_scope"] or graph["pending"] or graph["incomplete"] or not graph["composed"] and not
                   graph["precache_only"] else ("complete", "bounded graph reconciled"),
                   "js-retention": ("gap", "old-asset fetch disabled or pending") if
                   self.ctx.campaign.raw.get("js", {}).get("stale", {}).get("max_old_assets", 0) == 0
                   else ("pending", "requires explicit recon run for retained assets"),
                   "js-stale": ("pending", "top-band stale operations need four recorded rungs"),
                   "js-map": ("gap", "map candidate/retrieval coverage not established"),
                   "js-extract": ("gap", "unknown runtime expressions cannot be statically covered"),
                   "js-transport": ("gap", "unknown transport on some operations"),
                   "js-globals": ("gap", "client wrapper coverage not established"),
                   "js-gate": ("gap", "unobserved client-side gates possible"),
                   "js-rank": ("complete", "ranked by stale lane and static signals"),
                   "js-reconcile": ("gap", "traffic or assets missing/incomplete") if graph["traffic_only"] or
                   graph["pending"] or graph["incomplete"] or graph["unlinked_build_assets"]
                   else ("complete", "known graph references reconciled")}
            # A recognized manifest is a narrow fact, not proof of *all* manifests.
            if self.db.execute("SELECT 1 FROM js_edges e JOIN js_artifacts a"
                               " ON e.request_id=a.request_id WHERE a.build_id=?"
                               " AND e.kind IN ('webpack-runtime','vite-dependency-map','next-manifest','precache')"
                               " LIMIT 1", (bid,)).fetchone():
                raw["js-manifest"] = ("complete", "recognized runtime/manifest for this build")
            top = {"J01": set(sets["js_only"] + sets["zombie"])}
            for subject in top["J01"]:
                lead = self.db.execute("SELECT lead_key FROM js_leads WHERE origin=?"
                                       " AND family='J01' AND subject=?", (origin, subject)).fetchone()
                if not lead or len({r[0] for r in self.db.execute(
                        "SELECT rung FROM js_ladder_rungs WHERE lead_key=?", (lead[0],))}) < 4:
                    break
            else:
                raw["js-stale"] = ("complete", "all top-band operation rungs recorded")
            if not graph["composed"] and not graph["precache_only"]:
                raw["js-manifest"] = ("gap", "no verified manifest for this build")
            for stage, (state, reason) in raw.items():
                prev = self.db.execute("SELECT state,reason FROM js_stage_events WHERE origin=?"
                                       " AND build_id=? AND stage=? ORDER BY id DESC LIMIT 1",
                                       (origin, bid, stage)).fetchone()
                if not prev or (prev[0], prev[1]) != (state, reason):
                    self.db.execute("INSERT INTO js_stage_events"
                                    "(origin,build_id,stage,state,reason,created) VALUES(?,?,?,?,?,?)",
                                    (origin, bid, stage, state, reason, now()))
        self.db.commit()

    def _queue_retired(self) -> None:
        cfg = self.ctx.campaign.raw.get("js", {}).get("stale", {})
        cap = cfg.get("max_old_assets", 0)
        if not cap or not self.ctx.policy.allows("active"):
            return
        for origin in {r["origin"] for r in self._build_rows()}:
            ordered = self._retained_candidates(origin)
            for r in ordered[:cap]:
                if self.ctx.scope.is_in(r["url"]):
                    self.ctx.enqueue("jsretained", r["asset_id"])
            if len(ordered) > cap:
                self.store.add_fact(self.ctx.service_for(origin),
                                    f"retained asset cap {cap}: {len(ordered)-cap} not queued",
                                    "observed", kind="collection-gap", source="js-ledger")

    def _retained_candidates(self, origin: str) -> List[dict]:
        older = [r for r in self._build_rows(origin) if r["in_horizon"] and not r["current"]]
        if not older:
            return []
        candidates = self.db.execute("SELECT DISTINCT a.url,a.asset_id FROM js_artifacts a"
                                     " WHERE a.build_id IN (%s) AND a.kind='js'" %
                                     ",".join("?" * len(older)), [r["id"] for r in older]).fetchall()
        return sorted([dict(r) for r in candidates], key=lambda r: (not any(x in r["url"].lower()
                      for x in ("admin", "internal", "auth")), r["url"]))

    def resume_retained(self, origin: str, reason: str) -> dict:
        if not reason.strip() or len(reason) > 300:
            raise ValueError("resuming retained asset checks needs a bounded review reason")
        service = self.store.find_asset("service", origin)
        if not service or not any(self.ctx.scope.is_in(r["url"]) for r in
                                  self._retained_candidates(origin)):
            raise ValueError("unknown or out-of-scope JS retained origin")
        self.store.update_attrs(service["id"], {"js_retained_stop": "",
                                                   "js_retained_review": reason.strip()})
        # Explicit review can retry skipped jobs, but only current approved candidates
        # will pass the handler's cap check on the next separate `recon run`.
        cap = self.ctx.campaign.raw.get("js", {}).get("stale", {}).get("max_old_assets", 0)
        allowed = {r["asset_id"] for r in self._retained_candidates(origin)[:cap]}
        for job in self.store.jobs():
            if job["kind"] == "jsretained" and job["asset_id"] in allowed and job["state"] == "skipped":
                self.db.execute("UPDATE jobs SET state='queued',note=NULL,updated=? WHERE id=?",
                                (now(), job["id"]))
        self.db.commit()
        return {"origin": origin, "review_recorded": True, "executed": False}

    def verify(self) -> dict:
        result = super().verify()
        for a in self.db.execute("SELECT * FROM js_artifacts ORDER BY request_id"):
            try:
                resp = self.store.response(a["request_id"])
                if resp["body_sha256"] != a["sha256"] or response_hash(resp) != a["snapshot"]:
                    raise ValueError("artifact response changed")
                self._body(resp)
            except (ValueError, KeyError) as exc:
                result["problems"].append({"request_id": a["request_id"], "reason": str(exc)})
        for r in self.db.execute("SELECT s.* FROM js_sightings s LEFT JOIN js_artifacts a"
                                 " ON a.request_id=s.request_id WHERE a.request_id IS NULL"
                                 " OR a.sha256!=s.sha256"):
            result["problems"].append({"request_id": r["request_id"],
                                       "reason": "orphaned or changed lead sighting"})
        for r in self.db.execute("SELECT * FROM js_ladder_rungs WHERE response_id IS NOT NULL"):
            try:
                response = self.store.response(r["response_id"])
                if response_hash(response) != r["response_hash"]:
                    raise ValueError("rung response snapshot changed")
                self._body(response)
            except (ValueError, KeyError) as exc:
                result["problems"].append({"response_id": r["response_id"], "reason": str(exc)})
        for r in self.db.execute("SELECT * FROM js_asset_pairs"):
            for label in ("low", "owner"):
                try:
                    response = self.store.response(r[label + "_response"])
                    if response_hash(response) != r[label + "_hash"]:
                        raise ValueError("asset-pair response snapshot changed")
                    self._body(response)
                except (ValueError, KeyError) as exc:
                    result["problems"].append({"response_id": r[label + "_response"], "reason": str(exc)})
        result["ok"] = not result["problems"]
        return result

    def status(self, limit: int = 30, origin: Optional[str] = None) -> dict:
        if not 1 <= limit <= 100:
            raise ValueError("JS status limit must be 1..100")
        builds = self._build_rows(origin)
        origins = {b["origin"] for b in builds} | {r[0] for r in self.db.execute(
            "SELECT DISTINCT origin FROM js_artifacts" + (" WHERE origin=?" if origin else ""),
            (origin,) if origin else ())}
        graphs = {o: self._graph(o) for o in origins}
        ranked = self.plan(origin=origin, top=limit)
        leads = ranked["leads"]
        stages = [dict(r) for r in self.db.execute("SELECT e.* FROM js_stage_events e WHERE e.id IN"
                   " (SELECT max(id) FROM js_stage_events GROUP BY origin,build_id,stage)" +
                   (" AND e.origin=?" if origin else "") + " ORDER BY e.origin,e.build_id,e.stage",
                   (origin,) if origin else ())]
        integrity = self.verify()
        unresolved_top = self.db.execute("SELECT count(*) FROM js_leads WHERE priority=0"
            " AND state IN ('extracted','triaged')" + (" AND origin=?" if origin else ""),
            (origin,) if origin else ()).fetchone()[0]
        complete = (bool(builds) and integrity["ok"] and bool(stages) and
                    all(e["state"] == "complete" for e in stages) and not unresolved_top)
        pairs = [dict(r) for r in self.db.execute("SELECT url,low_response,owner_response,outcome"
            " FROM js_asset_pairs" + (" WHERE url LIKE ?" if origin else "") +
            " ORDER BY id DESC LIMIT 100", (origin + "/%",) if origin else ())]
        return {"artifacts": self.db.execute("SELECT count(*) FROM js_artifacts" +
            (" WHERE origin=?" if origin else ""), (origin,) if origin else ()).fetchone()[0],
                "builds": len(builds), "graphs": graphs, "sets": {o: self._sets(o) for o in graphs},
                "stages": stages, "leads": leads, "leads_total": ranked["total"],
                "asset_pairs": pairs,
                "asset_pair_total": self.db.execute("SELECT count(*) FROM js_asset_pairs" +
                    (" WHERE url LIKE ?" if origin else ""),
                    (origin + "/%",) if origin else ()).fetchone()[0],
                "integrity": integrity,
                "complete": complete, "executed": False}

    def plan(self, family: str = "", lane: str = "all", top: int = 30,
             packets: bool = False, origin: Optional[str] = None) -> dict:
        if not 1 <= top <= 100 or lane not in ("all", "current", "stale") or (family and family not in FAMILIES):
            raise ValueError("invalid JS family, lane or top (1..100)")
        rows = [dict(r) for r in self.db.execute("SELECT * FROM js_leads" +
                (" WHERE origin=?" if origin else "") + " ORDER BY priority,lead_key",
                (origin,) if origin else ())]
        sets = {o: self._sets(o) for o in {r["origin"] for r in rows}}
        result = []
        for row in rows:
            if family and family != row["family"]:
                continue
            s = sets[row["origin"]]
            row["lane"] = ("zombie" if row["subject"] in s["zombie"] else
                           "js_only" if row["subject"] in s["js_only"] else "general")
            if lane == "stale" and row["lane"] == "general" or lane == "current" and row["lane"] != "js_only":
                continue
            if row["lane"] != "general":
                row["priority"] = 0
                row["reason"] = row["lane"] + ": " + row["reason"]
            row["shape"] = json.loads(row["shape"])
            if row["state"] == "handed-off":
                row["destination"] = self._destination(row["lead_key"])
            result.append(row)
        result.sort(key=lambda r: (r["priority"], r["lane"] != "zombie", r["lead_key"]))
        visible = result[:top]
        if packets:
            from .jspackets import packet
            for row in visible:
                if row["family"] in ("J01", "J03", "J04", "J05", "J07", "J12", "J17"):
                    row["packet"] = packet(self.ctx, row)
        return {"leads": visible, "total": len(result), "executed": False}

    def _destination(self, lead_key: str) -> dict:
        event = self.db.execute("SELECT ref FROM js_events WHERE lead_key=?"
                                " AND state='handed-off' ORDER BY id DESC LIMIT 1",
                                (lead_key,)).fetchone()
        match = re.fullmatch(r"cov:(\d+):([a-z0-9-]+)", event["ref"]) if event else None
        if not match:
            return {"status": "missing", "reason": "destination reference unavailable"}
        row = self.db.execute("SELECT status FROM coverage WHERE asset_id=? AND bug_class=?",
                              (int(match[1]), match[2])).fetchone()
        return {"ref": event["ref"], "status": row["status"] if row else "missing",
                "owner": "coverage"}

    def show(self, lead_key: str) -> dict:
        row = self.db.execute("SELECT * FROM js_leads WHERE lead_key=?", (lead_key,)).fetchone()
        if not row:
            raise ValueError("unknown JS lead")
        lead = dict(row)
        lead["shape"] = json.loads(lead["shape"])
        sightings = [dict(r) for r in self.db.execute(
            "SELECT request_id,sha256,offset,rule,extractor FROM js_sightings"
            " WHERE lead_key=? ORDER BY request_id", (lead_key,))]
        rungs = [dict(r) for r in self.db.execute(
            "SELECT rung,outcome,response_id,reason,created FROM js_ladder_rungs"
            " WHERE lead_key=? ORDER BY id", (lead_key,))]
        events = [dict(r) for r in self.db.execute("SELECT state,ref,reason,created FROM js_events"
                                                  " WHERE lead_key=? ORDER BY id", (lead_key,))]
        if lead["state"] == "handed-off":
            lead["destination"] = self._destination(lead_key)
        if lead["family"] in ("J01", "J03", "J04", "J05", "J07", "J12", "J17"):
            from .jspackets import packet
            lead["packet"] = packet(self.ctx, lead)
        # Finding stages are read from their owner; the JS ledger never promotes.
        from .findings import Findings
        lead["downstream"] = [{"id": f["id"], "stage": f["stage"]} for f in Findings(self.ctx).all()
                              if lead_key in f["detail"].get("lineage", [])]
        return {"lead": lead, "sightings": sightings, "rungs": rungs, "events": events,
                "integrity": self.verify(), "executed": False}

    def record(self, lead_key: str, *, state: str = "", ref: str = "", reason: str = "",
               rung: str = "", outcome: str = "", response_id: Optional[int] = None) -> dict:
        row = self.db.execute("SELECT * FROM js_leads WHERE lead_key=?", (lead_key,)).fetchone()
        if not row:
            raise ValueError("unknown JS lead")
        if not self.verify()["ok"]:
            raise ValueError("JS evidence integrity failed; record refused")
        if rung:
            if rung not in RUNGS or row["family"] != "J01" or not outcome:
                raise ValueError("four-rung outcomes require an operation lead and valid rung")
            if response_id is None:
                if outcome not in ("blocked", "inconclusive") or not reason.strip():
                    raise ValueError("without a stored response, explain blocked/inconclusive")
                digest = ""
            else:
                resp = self.store.response(response_id)
                if not self.ctx.scope.is_in(resp["url"]) or origin_of(resp["url"]) != row["origin"]:
                    raise ValueError("rung response must be in scope on the lead origin")
                if resp["status"] is None or outcome != str(resp["status"]):
                    raise ValueError("rung outcome must equal the stored HTTP status")
                # A same-origin response from another operation cannot close a rung.
                subject_url = row["subject"].split(" ", 1)[1]
                if rung == "archived-chunk" and not self.db.execute(
                        "SELECT 1 FROM js_sightings s JOIN js_artifacts a ON a.request_id=s.request_id"
                        " WHERE s.lead_key=? AND a.url=?", (lead_key, resp["url"])).fetchone():
                    raise ValueError("archived-chunk response must name a stored source artifact")
                if rung != "archived-chunk" and endpoint_key(resp["url"]) != subject_url:
                    from .extract import VERSION_SEG
                    if (rung != "version-sibling" or
                            not VERSION_SEG.search(subject_url) or not VERSION_SEG.search(resp["url"]) or
                            VERSION_SEG.sub("/vN", endpoint_key(resp["url"])) !=
                            VERSION_SEG.sub("/vN", subject_url)):
                        raise ValueError("rung response is not this operation/version sibling")
                if row["method"] != "UNKNOWN" and resp["method"] != row["method"] and rung != "archived-chunk":
                    raise ValueError("rung method differs from operation")
                from .factcheck import ResponseFacts, response_hash
                ResponseFacts(self.ctx).add(response_id, {"type": "status_is", "expected": resp["status"]})
                digest = response_hash(resp)
            self.db.execute("INSERT INTO js_ladder_rungs"
                            "(lead_key,rung,outcome,response_id,response_hash,reason,created)"
                            " VALUES(?,?,?,?,?,?,?)", (lead_key, rung, outcome, response_id, digest,
                                                         reason[:300], now()))
            self.db.commit()
            self._stages(row["origin"])
            return {"rung": rung, "outcome": outcome, "state": "live-observed" if outcome == "200" else
                    "unconfirmed", "executed": False}
        if state not in ("triaged", "handed-off", "blocked", "never-submit"):
            raise ValueError("JS records cannot mark tested, negative or confirmed; use destination evidence")
        if state in ("blocked", "never-submit") and not reason.strip():
            raise ValueError("blocked/never-submit require a reason")
        if state == "handed-off":
            match = re.fullmatch(r"cov:(\d+):([a-z0-9-]+)", ref)
            if not match or not self.db.execute("SELECT 1 FROM coverage WHERE asset_id=?"
                    " AND bug_class=?", (int(match[1]), match[2])).fetchone():
                raise ValueError("hand-off requires a real cov:<asset-id>:<class> destination")
        self.db.execute("UPDATE js_leads SET state=? WHERE lead_key=?", (state, lead_key))
        self.db.execute("INSERT INTO js_events(lead_key,state,ref,reason,created) VALUES(?,?,?,?,?)",
                        (lead_key, state, ref[:150], reason[:300], now()))
        self.db.commit()
        return {"lead_key": lead_key, "state": state, "executed": False}

    def asset_pair(self, low_response: int, owner_response: int) -> dict:
        """A paired delivery observation, never an authorization verdict or finding."""
        if not self.verify()["ok"]:
            raise ValueError("JS evidence integrity failed; asset pair refused")
        low, owner = self.store.response(low_response), self.store.response(owner_response)
        url = low["url"]
        parts = urlsplit(url)
        if (url != owner["url"] or not self.ctx.scope.is_in(url) or
                parts.query or parts.fragment or parts.username or parts.password or
                path_ext(parts.path) not in ("js", "mjs", "cjs", "map") or
                low["context"].get("account") == owner["context"].get("account") or
                not owner["context"].get("account") or
                not low["body_complete"] or not owner["body_complete"] or
                not low["body_sha256"] or not owner["body_sha256"]):
            raise ValueError("J17 needs the same scoped query-free asset, complete bodies "
                             "and distinct, labelled accounts (or anonymous low)")
        self._body(low)
        self._body(owner)
        from .factcheck import response_hash
        outcome = "served" if low["status"] == owner["status"] == 200 else (
            "denied" if low["status"] in (401, 403, 404) and owner["status"] == 200 else "inconclusive")
        self.db.execute("INSERT OR IGNORE INTO js_asset_pairs"
                        "(url,low_response,owner_response,low_hash,owner_hash,outcome,created)"
                        " VALUES(?,?,?,?,?,?,?)", (low["url"], low_response, owner_response,
                                                     response_hash(low), response_hash(owner), outcome, now()))
        artifact = self.db.execute("SELECT request_id,sha256,build_id FROM js_artifacts"
                                   " WHERE url=? AND complete=1 ORDER BY request_id LIMIT 1", (url,)).fetchone()
        if artifact:
            self._register(origin_of(url), "J17", parts.path, artifact["request_id"],
                           artifact["sha256"], artifact["build_id"], url, priority=3,
                           reason="paired asset delivery observed; source policy unverified",
                           gain="review whether non-public source was exposed to a lower role")
        self.db.commit()
        return {"url": low["url"], "outcome": outcome,
                "note": "delivery only; non-public source and policy impact not proven", "executed": False}

    def export(self, kind: str, out: Path) -> dict:
        if kind not in ("paths", "params", "graphql", "rpc", "chunkmap", "packets", "stale", "attack-list"):
            raise ValueError("unknown JS export kind")
        if not self.verify()["ok"]:
            raise ValueError("JS evidence integrity failed; export refused")
        rows = [dict(r) for r in self.db.execute("SELECT * FROM js_leads ORDER BY priority,lead_key LIMIT 3001")]
        if len(rows) > 3000:
            raise ValueError("JS export lead cap reached; refuse a silently truncated export")
        if kind == "stale":
            payload = {r["origin"]: self._sets(r["origin"]) for r in self._build_rows()}
        elif kind == "chunkmap":
            payload = [dict(r) for r in self.db.execute("SELECT e.url,e.kind,e.request_id"
                       " FROM js_edges e WHERE e.kind IN ('webpack-runtime','vite-dependency-map',"
                       "'next-manifest','precache','importmap') ORDER BY e.request_id,e.url LIMIT 3001")]
            if len(payload) > 3000:
                raise ValueError("JS chunkmap cap reached; refuse a silently truncated export")
        else:
            wanted = {"paths": ("J01",), "params": ("J01",), "graphql": ("J04",),
                      "rpc": ("J05",), "packets": ("J01", "J03", "J04", "J05", "J07", "J12", "J17")}.get(kind, FAMILIES)
            payload = []
            for row in rows:
                if row["family"] not in wanted:
                    continue
                entry = {k: row[k] for k in
                         ("lead_key", "family", "subject", "method", "url", "reason", "gain")}
                if kind in ("params", "packets"):
                    row["shape"] = json.loads(row["shape"])
                    entry["fields"] = row["shape"].get("fields", [])
                if kind == "packets":
                    from .jspackets import packet
                    entry["packet"] = packet(self.ctx, row)
                payload.append(entry)
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return {"path": str(out), "kind": kind, "executed": False}
