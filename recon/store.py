"""SQLite operational store for one campaign (plan4 tiers 1-2, minimal).

assets       typed surface: domain, host, ip, service, endpoint, js, sourcemap, route, intel
facts        what was seen (observed) or concluded (inferred), incl. clean negatives
observations one row per real request sample (HAR/runtime): params, account, status
coverage     endpoint x bug-class status matrix
jobs         the event-driven recon queue (resumable)
requests     every request we sent: url, status, headers, body hash (bodies on disk)
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  host TEXT,
  in_scope INTEGER NOT NULL DEFAULT 1,
  attrs TEXT NOT NULL DEFAULT '{}',
  first_seen TEXT,
  last_seen TEXT,
  UNIQUE(kind, value));
CREATE TABLE IF NOT EXISTS facts(
  id INTEGER PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(id),
  kind TEXT,
  summary TEXT NOT NULL,
  detail TEXT,
  confidence TEXT NOT NULL CHECK(confidence IN ('observed','inferred')),
  evidence TEXT,
  source TEXT,
  created TEXT,
  UNIQUE(asset_id, kind, summary));
CREATE TABLE IF NOT EXISTS observations(
  id INTEGER PRIMARY KEY,
  endpoint_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT,
  account TEXT,
  params TEXT,
  status INTEGER,
  source TEXT,
  created TEXT);
CREATE TABLE IF NOT EXISTS coverage(
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  bug_class TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'untested'
    CHECK(status IN ('untested','queued','tested','confirmed','refuted','n-a')),
  reason TEXT,
  note TEXT,
  updated TEXT,
  PRIMARY KEY(asset_id, bug_class));
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  need TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','done','skipped','failed')),
  note TEXT,
  created TEXT,
  updated TEXT,
  UNIQUE(kind, asset_id));
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY,
  ts TEXT, method TEXT, url TEXT, status INTEGER, purpose TEXT,
  req_headers TEXT, resp_headers TEXT, body_sha256 TEXT, body_len INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS endpoint_operations(
  id INTEGER PRIMARY KEY,
  endpoint_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT NOT NULL,
  attrs TEXT NOT NULL DEFAULT '{}',
  UNIQUE(endpoint_id, method));
CREATE TABLE IF NOT EXISTS source_imports(
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  context TEXT NOT NULL DEFAULT '{}',
  created TEXT NOT NULL,
  UNIQUE(source, sha256, context));
CREATE TABLE IF NOT EXISTS asset_provenance(
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  import_id INTEGER NOT NULL REFERENCES source_imports(id),
  record_index INTEGER NOT NULL,
  basis TEXT NOT NULL,
  PRIMARY KEY(asset_id, import_id, record_index));
CREATE TABLE IF NOT EXISTS observation_captures(
  capture_key TEXT PRIMARY KEY,
  observation_id INTEGER NOT NULL REFERENCES observations(id),
  context TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS endpoint_variants(
  endpoint_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query_names TEXT NOT NULL,
  UNIQUE(endpoint_id, method, path, query_names));
CREATE TABLE IF NOT EXISTS import_results(
  import_id INTEGER PRIMARY KEY REFERENCES source_imports(id),
  stats TEXT NOT NULL,
  updated TEXT NOT NULL);
"""

LIST_CAP = 200
COVERAGE_STATES = ("untested", "queued", "tested", "confirmed", "refuted", "n-a")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def merge_attrs(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Lists union (order kept, capped), dicts merge recursively, bools are sticky-true,
    other scalars overwrite."""
    out = dict(old)
    for k, v in new.items():
        if v is None:
            continue
        cur = out.get(k)
        if isinstance(v, list):
            merged = list(cur) if isinstance(cur, list) else []
            for x in v:
                if x not in merged and len(merged) < LIST_CAP:
                    merged.append(x)
            out[k] = merged
        elif isinstance(v, dict) and isinstance(cur, dict):
            out[k] = merge_attrs(cur, v)
        elif isinstance(v, bool) and isinstance(cur, bool):
            out[k] = cur or v
        else:
            out[k] = v
    return out


def _row_to_asset(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["attrs"] = json.loads(d["attrs"] or "{}")
    d["in_scope"] = bool(d["in_scope"])
    return d


class Store:
    def __init__(self, db_path: Path, bodies_dir: Optional[Path] = None):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.bodies_dir = Path(bodies_dir) if bodies_dir else Path(db_path).parent / "bodies"
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ---------------- assets ----------------
    def upsert_asset(self, kind: str, value: str, host: Optional[str] = None,
                     in_scope: bool = True, attrs: Optional[Dict[str, Any]] = None
                     ) -> Tuple[int, bool]:
        attrs = attrs or {}
        ts = now()
        row = self.db.execute("SELECT id, attrs FROM assets WHERE kind=? AND value=?",
                              (kind, value)).fetchone()
        if row:
            merged = merge_attrs(json.loads(row["attrs"] or "{}"), attrs)
            self.db.execute("UPDATE assets SET attrs=?, last_seen=? WHERE id=?",
                            (json.dumps(merged, sort_keys=True), ts, row["id"]))
            self.db.commit()
            return row["id"], False
        cur = self.db.execute(
            "INSERT INTO assets(kind, value, host, in_scope, attrs, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?,?)",
            (kind, value, host, int(in_scope), json.dumps(merge_attrs({}, attrs), sort_keys=True),
             ts, ts))
        self.db.commit()
        return cur.lastrowid, True

    def update_attrs(self, asset_id: int, attrs: Dict[str, Any]) -> None:
        row = self.db.execute("SELECT attrs FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None:
            raise KeyError(asset_id)
        merged = merge_attrs(json.loads(row["attrs"] or "{}"), attrs)
        self.db.execute("UPDATE assets SET attrs=?, last_seen=? WHERE id=?",
                        (json.dumps(merged, sort_keys=True), now(), asset_id))
        self.db.commit()

    def get_asset(self, asset_id: int) -> Dict[str, Any]:
        r = self.db.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if r is None:
            raise KeyError(asset_id)
        return _row_to_asset(r)

    def find_asset(self, kind: str, value: str) -> Optional[Dict[str, Any]]:
        r = self.db.execute("SELECT * FROM assets WHERE kind=? AND value=?",
                            (kind, value)).fetchone()
        return _row_to_asset(r) if r else None

    def assets(self, kind: Optional[str] = None, in_scope: Optional[bool] = None
               ) -> List[Dict[str, Any]]:
        q, args = "SELECT * FROM assets WHERE 1=1", []
        if kind:
            q += " AND kind=?"
            args.append(kind)
        if in_scope is not None:
            q += " AND in_scope=?"
            args.append(int(in_scope))
        return [_row_to_asset(r) for r in self.db.execute(q + " ORDER BY id", args)]

    def count_assets(self, kind: str, prefix: str = "") -> int:
        return self.db.execute("SELECT count(*) FROM assets WHERE kind=? AND value LIKE ?",
                               (kind, prefix + "%")).fetchone()[0]

    # ---------------- facts / observations ----------------
    def add_fact(self, asset_id: Optional[int], summary: str, confidence: str = "observed",
                 kind: Optional[str] = None, detail: Optional[str] = None,
                 evidence: Optional[str] = None, source: Optional[str] = None) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO facts(asset_id, kind, summary, detail, confidence, evidence,"
            " source, created) VALUES(?,?,?,?,?,?,?,?)",
            (asset_id, kind, summary, detail, confidence, evidence, source, now()))
        self.db.commit()

    def facts(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "SELECT f.*, a.value AS asset_value FROM facts f LEFT JOIN assets a ON a.id=f.asset_id"
        args: List[Any] = []
        if kind:
            q += " WHERE f.kind=?"
            args.append(kind)
        return [dict(r) for r in self.db.execute(q + " ORDER BY f.id", args)]

    def add_observation(self, endpoint_id: int, method: str, account: Optional[str],
                        params: Dict[str, Any], status: Optional[int], source: str,
                        capture_key: Optional[str] = None,
                        context: Optional[Dict[str, Any]] = None) -> bool:
        if capture_key and self.db.execute(
                "SELECT 1 FROM observation_captures WHERE capture_key=?", (capture_key,)).fetchone():
            return False
        cur = self.db.execute(
            "INSERT INTO observations(endpoint_id, method, account, params, status, source, created)"
            " VALUES(?,?,?,?,?,?,?)",
            (endpoint_id, method, account, json.dumps(params, sort_keys=True), status, source,
              now()))
        if capture_key:
            self.db.execute("INSERT INTO observation_captures VALUES(?,?,?)",
                            (capture_key, cur.lastrowid, json.dumps(context or {}, sort_keys=True)))
        self.db.commit()
        return True

    def observations(self, endpoint_id: Optional[int] = None) -> List[Dict[str, Any]]:
        q, args = "SELECT * FROM observations", []
        if endpoint_id is not None:
            q += " WHERE endpoint_id=?"
            args.append(endpoint_id)
        out = []
        for r in self.db.execute(q + " ORDER BY id", args):
            d = dict(r)
            d["params"] = json.loads(d["params"] or "{}")
            context = self.db.execute(
                "SELECT context FROM observation_captures WHERE observation_id=?", (d["id"],)).fetchone()
            d["context"] = json.loads(context[0]) if context else {}
            out.append(d)
        return out

    def operation(self, endpoint_id: int, method: Optional[str], attrs: Dict[str, Any]) -> int:
        """An endpoint family may aggregate methods, but GET and POST stay distinct here."""
        method = (method or "UNKNOWN").upper()
        row = self.db.execute("SELECT id,attrs FROM endpoint_operations WHERE endpoint_id=? AND method=?",
                              (endpoint_id, method)).fetchone()
        previous = json.loads(row["attrs"]) if row else {}
        attrs = dict(attrs)
        for metadata in (previous, attrs):
            basis = metadata.pop("basis", None)
            if basis:
                metadata["bases"] = list(metadata.get("bases", [])) + [basis]
        merged = merge_attrs(previous, attrs)
        if row:
            self.db.execute("UPDATE endpoint_operations SET attrs=? WHERE id=?",
                            (json.dumps(merged, sort_keys=True), row["id"]))
            oid = row["id"]
        else:
            oid = self.db.execute("INSERT INTO endpoint_operations(endpoint_id,method,attrs) VALUES(?,?,?)",
                                  (endpoint_id, method, json.dumps(merged, sort_keys=True))).lastrowid
        self.db.commit()
        return oid

    def operations(self) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT o.*, a.value AS endpoint FROM endpoint_operations o "
                               "JOIN assets a ON a.id=o.endpoint_id ORDER BY o.endpoint_id,o.method")
        return [{**dict(r), "attrs": json.loads(r["attrs"])} for r in rows]

    def variant(self, endpoint_id: int, method: Optional[str], path: str,
                query_names: Iterable[str]) -> None:
        self.db.execute("INSERT OR IGNORE INTO endpoint_variants VALUES(?,?,?,?)",
                        (endpoint_id, (method or "UNKNOWN").upper(), path or "/",
                         json.dumps(sorted(set(query_names)))))
        self.db.commit()

    def variants(self) -> List[Dict[str, Any]]:
        return [{**dict(r), "query_names": json.loads(r["query_names"])} for r in
                self.db.execute("SELECT * FROM endpoint_variants ORDER BY endpoint_id,method,path")]

    def register_import(self, source: str, content: bytes, context: Dict[str, Any]) -> int:
        digest = hashlib.sha256(content).hexdigest()
        encoded = json.dumps(context, sort_keys=True)
        self.db.execute("INSERT OR IGNORE INTO source_imports(source,sha256,context,created) VALUES(?,?,?,?)",
                        (source, digest, encoded, now()))
        self.db.commit()
        return self.db.execute("SELECT id FROM source_imports WHERE source=? AND sha256=? AND context=?",
                               (source, digest, encoded)).fetchone()[0]

    def provenance(self, asset_id: int, import_id: int, record_index: int, basis: str) -> bool:
        cur = self.db.execute("INSERT OR IGNORE INTO asset_provenance VALUES(?,?,?,?)",
                              (asset_id, import_id, record_index, basis))
        self.db.commit()
        return cur.rowcount > 0

    def provenance_records(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT p.*,s.source,s.sha256 FROM asset_provenance p "
            "JOIN source_imports s ON s.id=p.import_id ORDER BY p.import_id,p.record_index,p.asset_id")]

    def total_assets(self) -> int:
        return self.db.execute("SELECT count(*) FROM assets").fetchone()[0]

    def imports(self) -> List[Dict[str, Any]]:
        return [{**dict(r), "stats": json.loads(r["stats"] or "{}")} for r in self.db.execute(
            "SELECT s.*,r.stats FROM source_imports s LEFT JOIN import_results r ON r.import_id=s.id ORDER BY s.id")]

    def record_import_result(self, import_id: int, stats: Dict[str, Any]) -> None:
        self.db.execute("INSERT INTO import_results VALUES(?,?,?) ON CONFLICT(import_id) "
                        "DO UPDATE SET stats=excluded.stats,updated=excluded.updated",
                        (import_id, json.dumps(stats, sort_keys=True), now()))
        self.db.commit()

    # ---------------- coverage ----------------
    def seed_coverage(self, asset_id: int, classes: Dict[str, str]) -> int:
        n = 0
        for cls, reason in classes.items():
            cur = self.db.execute(
                "INSERT OR IGNORE INTO coverage(asset_id, bug_class, reason, updated)"
                " VALUES(?,?,?,?)", (asset_id, cls, reason, now()))
            n += cur.rowcount
        self.db.commit()
        return n

    def set_coverage(self, asset_id: int, bug_class: str, status: str,
                     note: Optional[str] = None) -> None:
        if status not in COVERAGE_STATES:
            raise ValueError(f"status must be one of {COVERAGE_STATES}")
        self.db.execute(
            "INSERT INTO coverage(asset_id, bug_class, status, note, updated) VALUES(?,?,?,?,?)"
            " ON CONFLICT(asset_id, bug_class) DO UPDATE SET status=excluded.status,"
            " note=COALESCE(excluded.note, coverage.note), updated=excluded.updated",
            (asset_id, bug_class, status, note, now()))
        self.db.commit()

    def coverage(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT c.*, a.value AS asset_value, a.kind AS asset_kind FROM coverage c"
            " JOIN assets a ON a.id=c.asset_id ORDER BY c.asset_id, c.bug_class")]

    # ---------------- jobs ----------------
    def enqueue(self, kind: str, asset_id: int, need: str) -> bool:
        ts = now()
        cur = self.db.execute(
            "INSERT OR IGNORE INTO jobs(kind, asset_id, need, created, updated) VALUES(?,?,?,?,?)",
            (kind, asset_id, need, ts, ts))
        self.db.commit()
        return cur.rowcount > 0

    def next_job(self) -> Optional[Dict[str, Any]]:
        r = self.db.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY id LIMIT 1").fetchone()
        return dict(r) if r else None

    def finish_job(self, job_id: int, state: str, note: Optional[str] = None) -> None:
        self.db.execute("UPDATE jobs SET state=?, note=?, updated=? WHERE id=?",
                        (state, note, now(), job_id))
        self.db.commit()

    def requeue(self, states: Iterable[str], allowed: Callable[[str], bool],
                kind: Optional[str] = None) -> int:
        n = 0
        states = list(states)
        for r in self.db.execute("SELECT id, need, kind FROM jobs WHERE state IN (%s)"
                                 % ",".join("?" * len(states)), states).fetchall():
            if allowed(r["need"]) and (kind is None or r["kind"] == kind):
                self.db.execute("UPDATE jobs SET state='queued', note=NULL, updated=? WHERE id=?",
                                (now(), r["id"]))
                n += 1
        self.db.commit()
        return n

    def rerun(self, kind: str) -> int:
        cur = self.db.execute("UPDATE jobs SET state='queued', note=NULL, updated=? WHERE kind=?",
                              (now(), kind))
        self.db.commit()
        return cur.rowcount

    def jobs(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT j.*, a.value AS asset_value FROM jobs j JOIN assets a ON a.id=j.asset_id"
            " ORDER BY j.id")]

    # ---------------- request log ----------------
    def save_body(self, body: bytes) -> Optional[str]:
        if not body:
            return None
        sha = hashlib.sha256(body).hexdigest()
        self.bodies_dir.mkdir(parents=True, exist_ok=True)
        p = self.bodies_dir / sha
        if not p.exists():
            p.write_bytes(body)
        return sha

    def record_request(self, method: str, url: str, status: Optional[int], purpose: str,
                       req_headers: Iterable[str], resp_headers: Dict[str, str],
                       body: bytes = b"", error: Optional[str] = None) -> None:
        self.db.execute(
            "INSERT INTO requests(ts, method, url, status, purpose, req_headers, resp_headers,"
            " body_sha256, body_len, error) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (now(), method, url, status, purpose, json.dumps(sorted(req_headers)),
             json.dumps(resp_headers, sort_keys=True), self.save_body(body), len(body or b""),
             error))
        self.db.commit()

    def request_count(self) -> int:
        return self.db.execute("SELECT count(*) FROM requests WHERE error IS NULL").fetchone()[0]
