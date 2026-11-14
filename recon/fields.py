"""Field ledger: per-field, per-case coverage with receipts - so no input silently
goes untested.

Offline. Writes only its own tables and reports; live execution stays in the
dedicated browser through Burp. Pieces:

* sync     - one ledger row per endpoint/method/location/field/account x case,
             from HAR/Burp observations, page-standalone inputs, JS body keys
             and OpenAPI spec fields; never guesses hidden parameters.
* canary   - mint a per-field marker, submit it through the real workflow, then
             `trace` searches stored HTTP captures for where the value lands
             and how it is encoded there (the propagation map).
* matrix   - module x trigger (list/search/filter/create/edit/bulk/export/sort)
             completeness gate: a "full parameter coverage" claim cannot be
             recorded while cells are missing - enforced in code.
* packet   - payload context packet (field, location, context map, surviving
             characters, blocked elements, DB fingerprint, CSP, method grants)
             with a completeness check; every payload's author is recorded.
* blind    - blind-XSS surface capture validated on the same primitives as the
             SSRF callback correlator (recon/callbacks.py).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .callbacks import (approved_callback_host, require_callback_url, timestamp,
                        valid_marker, verified_bytes)
from .campaign import HTTP_METHODS
from .extract import ID_SEGMENT, endpoint_key
from .score import applicable_classes
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS field_ledger(
  id INTEGER PRIMARY KEY,
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT NOT NULL,
  location TEXT NOT NULL,
  field TEXT NOT NULL,
  account TEXT,
  role TEXT NOT NULL DEFAULT '',
  tenant TEXT NOT NULL DEFAULT '',
  workflow TEXT NOT NULL DEFAULT '',
  case_id TEXT NOT NULL,
  state TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL,
  updated TEXT NOT NULL,
  UNIQUE(asset_id, method, location, field, account, case_id));
CREATE INDEX IF NOT EXISTS field_ledger_asset ON field_ledger(asset_id, case_id, state);
CREATE TABLE IF NOT EXISTS canary_markers(
  id INTEGER PRIMARY KEY,
  marker TEXT NOT NULL UNIQUE,
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT NOT NULL, location TEXT NOT NULL, field TEXT NOT NULL,
  account TEXT, workflow TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS canary_events(
  id INTEGER PRIMARY KEY,
  marker TEXT NOT NULL,
  asset_id INTEGER REFERENCES assets(id),
  surface TEXT NOT NULL,
  encoding TEXT NOT NULL,
  request_id INTEGER,
  source TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  UNIQUE(marker, surface, encoding, source));
CREATE TABLE IF NOT EXISTS field_fingerprints(
  id INTEGER PRIMARY KEY,
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  updated TEXT NOT NULL,
  UNIQUE(asset_id, kind));
CREATE TABLE IF NOT EXISTS trigger_na(
  module TEXT NOT NULL, trigger TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY(module, trigger));
CREATE TABLE IF NOT EXISTS module_claims(
  module TEXT PRIMARY KEY,
  claim TEXT NOT NULL,
  updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payload_events(
  id INTEGER PRIMARY KEY,
  packet_sha256 TEXT NOT NULL,
  model TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL);
"""

LOCATIONS = ("query", "form", "json", "multipart", "header", "cookie", "path", "page", "unknown")
STATES = ("untested", "probed", "mapped", "observed", "negative", "blocked", "inconclusive", "n-a")
TRIGGERS = ("list", "search", "filter", "create", "edit", "bulk", "export", "sort")
CLAIMS = ("partial", "full")
FINGERPRINT_KINDS = ("db", "csp")
MARKER_PREFIX = "bv_"
REALISM_ANSWERS = ("pass", "fail", "unanswered")

# Per-class test cases the ledger tracks; sync seeds rows for the classes that
# applicable_classes marks on the asset.
CASES_BY_CLASS: Dict[str, Tuple[str, ...]] = {
    "xss": ("xss-reflected", "xss-stored", "xss-dom", "xss-blind"),
    "html-injection": ("htmli-structure",),
    "sqli": ("sqli-error", "sqli-boolean", "sqli-time", "sqli-oob",
             "sqli-union", "sqli-second-order"),
    "ssti": ("ssti-eval",),
    "idor-bola": ("idor-read", "idor-write"),
    "ssrf": ("ssrf-callback",),
    "open-redirect": ("oredir-swap",),
    "file-read": ("fileread-path",),
    "mass-assignment": ("massassign-role",),
    "csrf": ("csrf-state",),
}
MAX_TRACE_SCANS = 5_000
MAX_TRACE_BYTES = 100_000_000

# Markers are chosen from [a-z0-9_] so plain, URL-encoded and HTML-entity forms
# coincide; only base64 and stripping change the bytes.
EXPORTISH = re.compile(r"export|download|format|report|pdf|csv|xlsx|print", re.I)
BULKISH = re.compile(r"bulk|batch|^ids?\b|selected|multiselect|_all$", re.I)
SORTISH = re.compile(r"sort|order_by|orderby|_dir$|^dir$|direction", re.I)
FILTERISH = re.compile(r"filter|status|type$|^type|category|tag|state|range|_min$|_max$"
                       r"|^min$|^max$|from$|to$", re.I)
SEARCHISH = re.compile(r"search|^q$|query|keyword|term|^find", re.I)
PAGINATEISH = re.compile(r"page|limit|offset|per_page|cursor|size", re.I)


def mint_marker() -> str:
    return MARKER_PREFIX + secrets.token_hex(4)


def module_of(url: str) -> str:
    """Endpoint family label for the trigger matrix: first informative path segments."""
    keep = []
    for seg in urlsplit(url).path.split("/"):
        if not seg:
            continue
        low = seg.lower()
        if low in ("api", "rest", "rpc", "graphql", "gql", "service", "services", "v"):
            continue
        if re.fullmatch(r"v\d+", low) or ID_SEGMENT.fullmatch(seg):
            continue
        keep.append(low)
        if len(keep) == 2:
            break
    return "/".join(keep) or "root"


def infer_trigger(method: str, url: str, field_names) -> str:
    """Deterministic heuristic workflow label; `fields record --workflow` overrides."""
    names = " ".join(str(n).lower() for n in field_names)
    path = urlsplit(url).path.lower()
    if EXPORTISH.search(names) or re.search(r"export|download|/report", path):
        return "export"
    if BULKISH.search(names):
        return "bulk"
    if SORTISH.search(names):
        return "sort"
    if FILTERISH.search(names):
        return "filter"
    if SEARCHISH.search(names):
        return "search"
    if method in ("POST", "PUT", "PATCH"):
        return "edit" if (method != "POST" or re.search(r"/\d|/\{id\}", path)) else "create"
    return "list"


def _body_location(content_types) -> str:
    mimes = " ".join(str(c).lower() for c in content_types or [])
    return "json" if "json" in mimes else "form"


def _observation_rows(asset) -> List[Dict[str, Any]]:
    rows = []
    body_loc = _body_location(asset.get("attrs", {}).get("content_types"))
    for o in asset.get("_observations", []):
        params = o.get("params") or {}
        base = {"method": (o.get("method") or "").upper(), "account": o.get("account"),
                "role": (o.get("context") or {}).get("role", ""),
                "tenant": (o.get("context") or {}).get("tenant", ""),
                "workflow": (o.get("context") or {}).get("workflow_state", "")}
        for name in params.get("query") or []:
            rows.append({**base, "location": "query", "field": name})
        for name in params.get("body") or []:
            rows.append({**base, "location": body_loc, "field": name})
        for name in params.get("header") or []:
            rows.append({**base, "location": "header", "field": name})
        for name in params.get("cookie") or []:
            rows.append({**base, "location": "cookie", "field": name})
        for name in (params.get("ids") or {}):
            if str(name).startswith("path["):
                rows.append({**base, "location": "path", "field": str(name)})
    return rows


def _spec_rows(asset) -> List[Dict[str, Any]]:
    rows = []
    for entry in asset.get("attrs", {}).get("spec_fields", []):
        loc = {"query": "query", "path": "path", "header": "header", "cookie": "cookie",
               "body": "json", "form": "form", "multipart": "multipart"}.get(
            entry.get("location"), "unknown")
        rows.append({"method": (entry.get("method") or "").upper(), "location": loc,
                     "field": entry.get("name") or "", "account": None, "role": "",
                     "tenant": "", "workflow": "openapi-spec"})
    return [r for r in rows if r["field"]]


def _standalone_rows(asset) -> List[Dict[str, Any]]:
    rows = []
    for entry in (asset.get("attrs", {}).get("standalone_inputs") or [])[:300]:
        name = entry.get("name") or ""
        label = entry.get("label") or ""
        field = f"{name} (label {label})" if label else name
        if field:
            rows.append({"method": "", "location": "page", "field": field, "account": None,
                         "role": "", "tenant": "", "workflow": "page-standalone"})
    return rows


class FieldLedger:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------------- helpers ----------------
    def _asset(self, asset_id):
        if type(asset_id) is not int or asset_id < 1:
            raise ValueError("asset ID must be a positive integer")
        asset = self.ctx.store.get_asset(asset_id)
        if asset["kind"] not in ("endpoint", "service"):
            raise ValueError("field ledger requires an endpoint or service asset")
        if asset["kind"] == "endpoint":
            self.ctx.scope.check(asset["value"])
        return asset

    def _cases(self, asset) -> List[str]:
        classes = (applicable_classes(asset) if asset["kind"] == "endpoint"
                   else {"xss": "page-level inputs"})
        return [case for cls, cases in CASES_BY_CLASS.items() if cls in classes
                for case in cases]

    def _discovered(self, asset) -> List[Dict[str, Any]]:
        if asset["kind"] == "service":
            return _standalone_rows(asset)
        asset = dict(asset)
        asset["_observations"] = self.ctx.store.observations(asset["id"])
        rows = _observation_rows(asset) + _spec_rows(asset)
        for name in asset.get("attrs", {}).get("params", []):
            rows.append({"method": "", "location": "unknown", "field": str(name),
                         "account": None, "role": "", "tenant": "", "workflow": "merged-attrs"})
        seen, out = set(), []
        for row in rows:
            if not row["field"]:
                continue
            key = (row["method"], row["location"], row["field"], row["account"])
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
        return out

    # ---------------- sync ----------------
    def sync(self, asset_id) -> Dict[str, Any]:
        asset = self._asset(asset_id)
        cases = self._cases(asset)
        if not cases:
            return {"asset_id": asset_id, "cases": [], "fields": 0, "rows_added": 0,
                    "basis": "no applicable input classes for this asset"}
        rows_added = 0
        fields = set()
        for row in self._discovered(asset):
            fields.add(row["field"])
            for case in cases:
                cur = self.db.execute(
                    "INSERT OR IGNORE INTO field_ledger(asset_id, method, location, field,"
                    " account, role, tenant, workflow, case_id, state, created, updated)"
                    " VALUES(?,?,?,?,?,?,?,?,?,'untested',?,?)",
                    (asset_id, row["method"], row["location"], row["field"],
                     row["account"] or "", row["role"], row["tenant"], row["workflow"],
                     case, now(), now()))
                rows_added += cur.rowcount
        self.db.commit()
        return {"asset_id": asset_id, "url": asset["value"], "module": module_of(asset["value"]),
                "cases": cases, "fields": len(fields), "rows_added": rows_added,
                "basis": "discovered inputs only (observations, attrs, spec fields, "
                         "page-standalone inputs); hidden parameters are never guessed",
                "executed": False}

    # ---------------- show / record ----------------
    def show(self, asset_id, case: Optional[str] = None, state: Optional[str] = None
             ) -> Dict[str, Any]:
        asset = self._asset(asset_id)
        q = ("SELECT * FROM field_ledger WHERE asset_id=?"
             + (" AND case_id=?" if case else "") + (" AND state=?" if state else ""))
        args = [asset_id] + ([case] if case else []) + ([state] if state else [])
        rows = [dict(r) for r in self.db.execute(q + " ORDER BY field, case_id", args)]
        fields: Dict[Tuple, Dict[str, Any]] = {}
        for row in rows:
            key = (row["method"], row["location"], row["field"], row["account"])
            slot = fields.setdefault(key, {
                "method": row["method"], "location": row["location"], "field": row["field"],
                "account": row["account"], "role": row["role"], "tenant": row["tenant"],
                "workflow": row["workflow"], "cases": {}, "note": "", "model": ""})
            slot["cases"][row["case_id"]] = row["state"]
            slot["note"], slot["model"] = row["note"], row["model"]
        module = module_of(asset["value"])
        return {"asset_id": asset_id, "url": asset["value"], "module": module,
                "fields": [fields[k] for k in sorted(fields)],
                "field_count": len(fields), "row_count": len(rows),
                "matrix": self.matrix(module), "basis": "ledger states are operator-recorded, "
                "not independently verified; untested rows are work, not absence of bugs",
                "executed": False}

    def record(self, asset_id, field, case_id, state, method="", location="unknown",
               account=None, note="", model="", workflow="") -> Dict[str, Any]:
        asset = self._asset(asset_id)
        if state not in STATES:
            raise ValueError(f"state must be one of {STATES}")
        if location not in LOCATIONS:
            raise ValueError(f"location must be one of {LOCATIONS}")
        if not str(field).strip() or len(str(field)) > 300:
            raise ValueError("field must be a 1..300 character name")
        if case_id not in {c for cases in CASES_BY_CLASS.values() for c in cases}:
            raise ValueError("unknown case; see recon/fields.py CASES_BY_CLASS")
        if not isinstance(note, str) or len(note) > 2000:
            raise ValueError("note must be at most 2000 characters")
        if model and (not isinstance(model, str) or len(model) > 120):
            raise ValueError("model must be an at most 120 character label")
        account = account or ""  # NULL accounts would evade the UNIQUE dedupe
        existing = self.db.execute(
            "SELECT id FROM field_ledger WHERE asset_id=? AND method=? AND location=? AND"
            " field=? AND account IS ? AND case_id=?",
            (asset_id, method, location, str(field), account, case_id)).fetchone()
        ts = now()
        if existing:
            self.db.execute(
                "UPDATE field_ledger SET state=?, note=CASE WHEN ?<>'' THEN ? ELSE note END,"
                " model=CASE WHEN ?<>'' THEN ? ELSE model END,"
                " workflow=CASE WHEN ?<>'' THEN ? ELSE workflow END, updated=? WHERE id=?",
                (state, note, note, model, model, workflow, workflow, ts, existing["id"]))
            row_id = existing["id"]
        else:
            cur = self.db.execute(
                "INSERT INTO field_ledger(asset_id, method, location, field, account, role,"
                " tenant, workflow, case_id, state, note, model, created, updated)"
                " VALUES(?,?,?,?,?,'', '', ?, ?, ?, ?, ?, ?, ?)",
                (asset_id, method, location, str(field), account, workflow, case_id, state,
                 note, model, ts, ts))
            row_id = cur.lastrowid
        self.db.commit()
        gate = self._coverage_gate(asset, state)
        return {"ledger_row": row_id, "asset_id": asset_id, "field": str(field),
                "case_id": case_id, "state": state, "model": model or "(operator)",
                "coverage_gate": gate, "basis": "operator assertion; probes live in the "
                "dedicated browser through Burp", "executed": False}

    # ---------------- trigger matrix + claims ----------------
    def _module_assets(self, module: str) -> List[Dict[str, Any]]:
        out = []
        for kind in ("endpoint", "service"):
            for a in self.ctx.store.assets(kind, in_scope=True):
                if module_of(a["value"]) == module:
                    out.append(a)
        return out

    def matrix(self, module: str) -> Dict[str, Any]:
        if not isinstance(module, str) or not module or len(module) > 200:
            raise ValueError("module must be a 1..200 character label")
        captured: Dict[str, List[int]] = {t: [] for t in TRIGGERS}
        for asset in self._module_assets(module):
            if asset["kind"] != "endpoint":
                continue
            for o in self.ctx.store.observations(asset["id"]):
                params = o.get("params") or {}
                names = list(params.get("query") or []) + list(params.get("body") or []) \
                    + list((params.get("ids") or {}).keys())
                trigger = infer_trigger(o.get("method") or "GET", asset["value"], names)
                captured[trigger].append(o["id"])
        na_rows = {r["trigger"]: r["reason"] for r in self.db.execute(
            "SELECT * FROM trigger_na WHERE module=?", (module,))}
        cells = {}
        for trigger in TRIGGERS:
            if trigger in na_rows:
                cells[trigger] = {"state": "n-a", "reason": na_rows[trigger]}
            elif captured[trigger]:
                cells[trigger] = {"state": "captured", "observations": captured[trigger][:20]}
            else:
                cells[trigger] = {"state": "missing"}
        missing = [t for t, cell in cells.items() if cell["state"] == "missing"]
        claim_row = self.db.execute("SELECT * FROM module_claims WHERE module=?", (module,)).fetchone()
        return {"module": module, "triggers": cells, "missing": missing,
                "complete": not missing,
                "claim": claim_row["claim"] if claim_row else None,
                "claim_updated": claim_row["updated"] if claim_row else None,
                "basis": "cells come from real captured observations per trigger shape; "
                         "some modules legitimately lack a trigger - record it n-a with "
                         "a reason instead of leaving it missing"}

    def set_na(self, module, trigger, reason) -> Dict[str, Any]:
        if trigger not in TRIGGERS:
            raise ValueError(f"trigger must be one of {TRIGGERS}")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
            raise ValueError("an n-a cell requires a 1..500 character reason")
        self.db.execute("INSERT OR REPLACE INTO trigger_na(module, trigger, reason)"
                        " VALUES(?,?,?)", (module, trigger, reason.strip()))
        self.db.commit()
        return {"module": module, "trigger": trigger, "state": "n-a",
                "matrix": self.matrix(module)}

    def claim(self, module, claim_state) -> Dict[str, Any]:
        if claim_state not in CLAIMS:
            raise ValueError(f"claim must be one of {CLAIMS}")
        data = self.matrix(module)
        if claim_state == "full" and not data["complete"]:
            raise ValueError("full coverage cannot be claimed while trigger cells are "
                             f"missing: {data['missing']}; record the observations, or "
                             "mark genuinely absent triggers n-a with a reason")
        self.db.execute("INSERT INTO module_claims(module, claim, updated) VALUES(?,?,?)"
                        " ON CONFLICT(module) DO UPDATE SET claim=excluded.claim,"
                        " updated=excluded.updated", (module, claim_state, now()))
        self.db.commit()
        return {"module": module, "claim": claim_state, "matrix": data}

    def _coverage_gate(self, asset, state) -> Dict[str, Any]:
        module = module_of(asset["value"])
        data = self.matrix(module)
        if state == "observed" and not data["complete"] and data["claim"] is None:
            self.db.execute("INSERT INTO module_claims(module, claim, updated) VALUES(?,?,?)"
                            " ON CONFLICT(module) DO UPDATE SET claim=excluded.claim,"
                            " updated=excluded.updated", (module, "partial", now()))
            self.db.commit()
            data = self.matrix(module)
        return {"module": module, "complete": data["complete"], "missing": data["missing"],
                "claim": data["claim"],
                "rule": "full coverage claimable only when every trigger cell is captured "
                        "or n-a; an observed verdict on an incomplete module stamps 'partial'"}

    def claims_rows(self) -> List[List[Any]]:
        rows = []
        for r in self.db.execute("SELECT * FROM module_claims ORDER BY module"):
            data = self.matrix(r["module"])
            rows.append([r["module"], r["claim"], ", ".join(data["missing"]) or "-",
                         r["updated"]])
        return rows

    # ---------------- canary map ----------------
    def canary(self, asset_id, field, method="", location="unknown", account=None,
               workflow="") -> Dict[str, Any]:
        asset = self._asset(asset_id)
        if not str(field).strip() or len(str(field)) > 300:
            raise ValueError("field must be a 1..300 character name")
        marker = mint_marker()
        self.db.execute(
            "INSERT INTO canary_markers(marker, asset_id, method, location, field, account,"
            " workflow, created) VALUES(?,?,?,?,?,?,?,?)",
            (marker, asset_id, method, location, str(field), account, workflow, now()))
        self.db.commit()
        return {"marker": marker, "asset_id": asset_id, "field": str(field),
                "workflow": workflow or "the field's real save/preview workflow",
                "how": "submit the marker as this field's value once, through the real "
                       "workflow in the dedicated browser through Burp; then run "
                       f"`recon fields trace {self.ctx.campaign.name} --marker {marker}`",
                "executed": False}

    def trace(self, marker) -> Dict[str, Any]:
        row = self.db.execute("SELECT * FROM canary_markers WHERE marker=?", (marker,)).fetchone()
        if row is None:
            raise ValueError("unknown marker; mint one with `recon fields canary`")
        asset = self.ctx.store.get_asset(row["asset_id"])
        home = endpoint_key(asset["value"])
        marker_bytes = marker.encode()
        marker_b64 = base64.b64encode(marker_bytes)
        events, scanned, total_bytes = [], 0, 0
        req_rows = self.db.execute(
            "SELECT id, method, url, body_sha256, status FROM requests ORDER BY id"
        ).fetchall()
        for r in req_rows[:MAX_TRACE_SCANS]:
            if total_bytes > MAX_TRACE_BYTES:
                break
            url = r["url"] or ""
            in_request = marker_bytes in url.encode()
            req_body = b""
            payload = self.db.execute(
                "SELECT body_sha256, content_type FROM request_payload WHERE request_id=?",
                (r["id"],)).fetchone()
            if payload and payload["body_sha256"]:
                path = self.ctx.store.bodies_dir / payload["body_sha256"]
                if path.is_file():
                    req_body = path.read_bytes()[:2_000_000]
                    total_bytes += len(req_body)
            in_request = in_request or marker_bytes in req_body
            resp_body = b""
            if r["body_sha256"]:
                rpath = self.ctx.store.bodies_dir / r["body_sha256"]
                if rpath.is_file():
                    resp_body = rpath.read_bytes()[:5_000_000]
                    total_bytes += len(resp_body)
            scanned += 1
            surface = None
            resp_url_key = endpoint_key(url) if url.startswith(("http://", "https://")) else None
            if resp_url_key and resp_url_key == home:
                surface = "same-response"
            elif resp_url_key:
                surface = f"other-endpoint:{resp_url_key}"
            elif req_body or in_request:
                surface = "submission-capture"
            if in_request:
                enc = "base64" if marker_b64 in req_body and marker_bytes not in req_body else "raw"
                events.append({"marker": marker, "surface": "submission-capture", "encoding": enc,
                               "request_id": r["id"], "source": "request-capture",
                               "note": "marker present in the stored request (URL/body)"})
            if marker_bytes in resp_body or marker_b64 in resp_body:
                enc = "base64" if marker_b64 in resp_body and marker_bytes not in resp_body else "raw"
                surface = surface or "other-endpoint:unknown"
                ctype = ""
                hdr_row = self.db.execute(
                    "SELECT resp_headers FROM requests WHERE id=?", (r["id"],)).fetchone()
                if hdr_row:
                    headers = json.loads(hdr_row["resp_headers"] or "{}")
                    ctype = next((v for k, v in headers.items()
                                  if k.lower() == "content-type"), "")
                surface = surface or "other-endpoint:unknown"
                if "text/csv" in ctype.lower():
                    surface = "export-csv"
                elif "pdf" in ctype.lower():
                    surface = "export-pdf"
                events.append({"marker": marker, "surface": surface, "encoding": enc,
                               "request_id": r["id"], "source": "response-capture",
                               "note": "marker rendered in the stored response body"})
            elif in_request and r["body_sha256"] and surface == "same-response":
                events.append({"marker": marker, "surface": "same-response", "encoding": "stripped",
                               "request_id": r["id"], "source": "response-capture",
                               "note": "marker sent but absent from the stored response"})
        recorded = 0
        for event in events:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO canary_events(marker, asset_id, surface, encoding,"
                " request_id, source, first_seen, note) VALUES(?,?,?,?,?,?,?,?)",
                (marker, row["asset_id"], event["surface"], event["encoding"],
                 event["request_id"], event["source"], now(), event["note"]))
            recorded += cur.rowcount
        self.db.commit()
        return {"marker": marker, "asset_id": row["asset_id"], "field": row["field"],
                "requests_scanned": scanned, "events": events,
                "newly_recorded": recorded,
                "surfaces": sorted({e["surface"] for e in events}),
                "known_gaps": ["HAR imports do not retain response bodies; import the "
                               "surfaces as Burp captures (with responses) or send the "
                               "requests via the dedicated browser + Burp to make them "
                               "traceable",
                               "email and PDF-render surfaces are traceable only when a "
                               "stored HTTP capture contains them"],
                "basis": "marker search over stored captures; presence is a lead, not a "
                         "vulnerability verdict",
                "executed": False}

    # ---------------- fingerprints + context packets ----------------
    def fingerprint(self, asset_id, kind, value, note="") -> Dict[str, Any]:
        self._asset(asset_id)
        if kind not in FINGERPRINT_KINDS:
            raise ValueError(f"kind must be one of {FINGERPRINT_KINDS}")
        if not isinstance(value, str) or not 1 <= len(value) <= 2000:
            raise ValueError("fingerprint value must be 1..2000 characters")
        self.db.execute(
            "INSERT INTO field_fingerprints(asset_id, kind, value, note, updated)"
            " VALUES(?,?,?,?,?) ON CONFLICT(asset_id, kind) DO UPDATE SET"
            " value=excluded.value, note=excluded.note, updated=excluded.updated",
            (asset_id, kind, value, note, now()))
        self.db.commit()
        return {"asset_id": asset_id, "kind": kind, "value": value}

    def _waf_bits(self, host: str) -> Dict[str, Any]:
        # Local import: waf.py imports mint_marker from this module.
        from .waf import SCHEMA as WAF_SCHEMA
        self.db.executescript(WAF_SCHEMA)
        row = self.db.execute("SELECT * FROM waf_profiles WHERE host=?", (host,)).fetchone()
        if row is None:
            return {"waf_ref": None, "surviving_chars": [], "blocked_elements": []}
        elements = json.loads(row["elements"] or "[]")
        surviving = sorted({e["element"] for e in elements
                            if e["outcome"] == "allowed" and len(e["element"]) == 1})
        blocked = sorted({e["element"] for e in elements if e["outcome"] in ("blocked", "stripped")})
        return {"waf_ref": f"{host}@{row['updated']}",
                "surviving_chars": surviving, "blocked_elements": blocked[:80]}

    def _csp(self, asset) -> str:
        fp = self.db.execute("SELECT value FROM field_fingerprints WHERE asset_id=? AND kind='csp'",
                             (asset["id"],)).fetchone()
        if fp:
            return fp["value"]
        prefix = urlsplit(asset["value"]).path.split("?")[0]
        row = self.db.execute(
            "SELECT resp_headers FROM requests WHERE url LIKE ? ORDER BY id DESC LIMIT 50",
            (f"%{prefix}%",)).fetchone()
        for candidate in [row] if row else []:
            headers = json.loads(candidate["resp_headers"] or "{}")
            for k, v in headers.items():
                if k.lower() == "content-security-policy":
                    return v[:600]
        return ""

    def packet(self, asset_id, field, case_id) -> Dict[str, Any]:
        asset = self._asset(asset_id)
        rows = [dict(r) for r in self.db.execute(
            "SELECT * FROM field_ledger WHERE asset_id=? AND field=? AND case_id=?"
            " ORDER BY CASE WHEN method<>'' AND location<>'unknown' THEN 0 ELSE 1 END,"
            " id DESC LIMIT 1", (asset_id, str(field), case_id))]
        if not rows:
            raise ValueError("no ledger row for this field/case; run `recon fields sync` first")
        row = rows[0]
        canaries = [dict(r) for r in self.db.execute(
            "SELECT m.marker, m.created FROM canary_markers m WHERE m.asset_id=? AND m.field=?",
            (asset_id, str(field)))]
        surfaces = [dict(r) for r in self.db.execute(
            "SELECT DISTINCT surface, encoding FROM canary_events WHERE marker IN "
            "(SELECT marker FROM canary_markers WHERE asset_id=? AND field=?)"
            " ORDER BY surface, encoding", (asset_id, str(field)))]
        host = urlsplit(asset["value"]).hostname or ""
        waf = self._waf_bits(host or "")
        db_fp = self.db.execute(
            "SELECT value FROM field_fingerprints WHERE asset_id=? AND kind='db'",
            (asset_id,)).fetchone()
        packet = {
            "schema_version": 1,
            "field": str(field), "method": row["method"], "location": row["location"],
            "account": row["account"], "case_id": case_id, "state": row["state"],
            "context_map": surfaces,
            "surviving_chars": waf["surviving_chars"],
            "blocked_elements": waf["blocked_elements"],
            "db_fingerprint": db_fp["value"] if db_fp else "",
            "csp": self._csp(asset),
            "method_grants": sorted(self.ctx.policy.allowed_methods),
            "sink_surfaces": sorted({s["surface"] for s in surfaces}),
            "waf_ref": waf["waf_ref"],
            "canary_ref": canaries[0]["marker"] if canaries else "",
        }
        missing = [k for k in ("context_map", "surviving_chars", "blocked_elements",
                               "db_fingerprint", "csp", "waf_ref", "canary_ref")
                   if packet.get(k) in (None, "", [], {})]
        if missing:
            raise ValueError("context packet is incomplete; record the missing pieces first: "
                             + "; ".join(
                                 f"{k} (recon fields fingerprint --kind "
                                 f"{'db' if k == 'db_fingerprint' else 'csp'})"
                                 if k in ("db_fingerprint", "csp") else
                                 f"{k} (recon waf observe/record or fields canary/trace)"
                                 for k in missing))
        blob = json.dumps(packet, sort_keys=True).encode()
        packet["packet_sha256"] = hashlib.sha256(blob).hexdigest()
        packet["basis"] = ("evidence-backed context for payload design; the validator still "
                           "checks the resulting evidence, and execution stays in the "
                           "dedicated browser through Burp")
        packet["executed"] = False
        return packet

    def record_payload(self, packet_file, model, provider="", note="") -> Dict[str, Any]:
        with open(packet_file, "rb") as stream:
            blob = stream.read(1_000_001)
        if len(blob) > 1_000_000:
            raise ValueError("packet file exceeds one megabyte")
        data = json.loads(blob)
        # Hash the same core fields packet() hashed, so the recorded sha256 binds
        # the attribution to the packet itself (not to its self-describing keys).
        core = {k: v for k, v in data.items() if k not in ("packet_sha256", "basis", "executed")}
        sha = hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()
        if not isinstance(model, str) or not 1 <= len(model.strip()) <= 120:
            raise ValueError("model attribution is required (1..120 characters)")
        cur = self.db.execute(
            "INSERT INTO payload_events(packet_sha256, model, provider, note, created)"
            " VALUES(?,?,?,?,?)", (sha, model.strip(), provider or "", note or "", now()))
        self.db.commit()
        return {"payload_event": cur.lastrowid, "packet_sha256": sha, "model": model.strip(),
                "provider": provider or "",
                "basis": "attribution record: which model wrote the payload for this packet"}

    # ---------------- blind XSS bundle (shared callback primitives) ----------------
    def blind(self, asset_id, bundle) -> Dict[str, Any]:
        asset = self._asset(asset_id)
        expected = {"schema_version", "asset_id", "attempt_id", "payload_marker",
                    "started_at", "ended_at", "surface", "evidence", "control",
                    "callback_url", "note"}
        if not isinstance(bundle, dict) or set(bundle) != expected \
                or bundle.get("schema_version") != 1:
            raise ValueError("invalid blind-XSS bundle fields/version (schema_version 1)")
        if bundle["asset_id"] != asset_id:
            raise ValueError("bundle belongs to another asset")
        if not valid_marker(bundle["attempt_id"]):
            raise ValueError("attempt_id must be a fresh 16..96-character marker")
        payload_marker = bundle["payload_marker"]
        if not isinstance(payload_marker, str) or not 8 <= len(payload_marker) <= 96:
            raise ValueError("payload_marker must be 8..96 characters")
        start, end = timestamp(bundle["started_at"]), timestamp(bundle["ended_at"])
        if not 0 <= end - start <= 86_400:
            raise ValueError("blind-XSS observation window must be ordered and at most 24 hours")
        surface = bundle["surface"]
        if not isinstance(surface, str) or not 1 <= len(surface) <= 120 \
                or any(ord(c) < 32 for c in surface):
            raise ValueError("surface must be a 1..120 single-line label")
        if bundle["callback_url"]:
            config = self.ctx.campaign.raw.get("xss", {})
            hosts = (config.get("callback_hosts") if isinstance(config, dict) else None) \
                or self.ctx.campaign.raw.get("ssrf", {}).get("callback_hosts", [])
            require_callback_url(bundle["callback_url"], hosts, "xss.callback_hosts",
                                 bundle["attempt_id"])
        evidence = verified_bytes(self.ctx.campaign.root, bundle["evidence"])
        control = verified_bytes(self.ctx.campaign.root, bundle["control"])
        if bundle["evidence"]["sha256"] == bundle["control"]["sha256"]:
            raise ValueError("evidence and control must be distinct captures")
        executed = payload_marker.encode() in evidence and payload_marker.encode() not in control
        assessment = "executed-surface-correlated" if executed else "not-executed-or-inconclusive"
        cur = self.db.execute(
            "INSERT OR IGNORE INTO canary_events(marker, asset_id, surface, encoding,"
            " request_id, source, first_seen, note) VALUES(?,?,?,?,?,?,?,?)",
            (payload_marker, asset_id, f"blind-exec:{surface}", "executed", None, "callbacks",
             now(), bundle.get("note") or ""))
        self.db.commit()
        return {"asset_id": asset_id, "attempt_id": bundle["attempt_id"], "surface": surface,
                "assessment": assessment, "executed_marker_found": executed,
                "canary_event_recorded": bool(cur.rowcount),
                "basis": "operator-supplied surface capture; the validator inspects the "
                         "artifacts; execution proof is the marker in the executing "
                         "surface, absent from the control",
                "warnings": ["A blind surface you cannot observe stays inconclusive.",
                             "Origin and capture are operator-supplied, not independently certified."],
                "finding_promoted": False, "executed": False}


def field_claims_section(ctx) -> List[List[Any]]:
    """Rows for coverage.md: module coverage claims and their missing cells."""
    ledger = FieldLedger(ctx)
    return ledger.claims_rows()
